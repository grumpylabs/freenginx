
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_BUFFER_SIZE  4096


static ngx_chain_t *ngx_quic_split_bufs(ngx_connection_t *c, ngx_chain_t *in,
    size_t len);


ngx_quic_frame_t *
ngx_quic_alloc_frame(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!ngx_queue_empty(&qc->free_frames)) {

        q = ngx_queue_head(&qc->free_frames);
        frame = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_queue_remove(&frame->queue);

#ifdef NGX_QUIC_DEBUG_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic reuse frame n:%ui", qc->nframes);
#endif

    } else if (qc->nframes < 10000) {
        frame = ngx_palloc(c->pool, sizeof(ngx_quic_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        ++qc->nframes;

#ifdef NGX_QUIC_DEBUG_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic alloc frame n:%ui", qc->nframes);
#endif

    } else {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic flood detected");
        return NULL;
    }

    ngx_memzero(frame, sizeof(ngx_quic_frame_t));

    return frame;
}


void
ngx_quic_free_frame(ngx_connection_t *c, ngx_quic_frame_t *frame)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (frame->data) {
        ngx_quic_free_bufs(c, frame->data);
    }

    ngx_queue_insert_head(&qc->free_frames, &frame->queue);

#ifdef NGX_QUIC_DEBUG_ALLOC
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic free frame n:%ui", qc->nframes);
#endif
}


void
ngx_quic_trim_bufs(ngx_chain_t *in, size_t size)
{
    size_t      n;
    ngx_buf_t  *b;

    while (in && size > 0) {
        b = in->buf;
        n = ngx_min((size_t) (b->last - b->pos), size);

        b->pos += n;
        size -= n;

        if (b->pos == b->last) {
            in = in->next;
        }
    }
}


void
ngx_quic_free_bufs(ngx_connection_t *c, ngx_chain_t *in)
{
    ngx_buf_t              *b, *shadow;
    ngx_chain_t            *cl;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    while (in) {
#ifdef NGX_QUIC_DEBUG_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic free buffer n:%ui", qc->nbufs);
#endif

        cl = in;
        in = in->next;
        b = cl->buf;

        if (b->shadow) {
            if (!b->last_shadow) {
                b->recycled = 1;
                ngx_free_chain(c->pool, cl);
                continue;
            }

            do {
                shadow = b->shadow;
                b->shadow = qc->free_shadow_bufs;
                qc->free_shadow_bufs = b;
                b = shadow;
            } while (b->recycled);

            if (b->shadow) {
                b->last_shadow = 1;
                ngx_free_chain(c->pool, cl);
                continue;
            }

            cl->buf = b;
        }

        cl->next = qc->free_bufs;
        qc->free_bufs = cl;
    }
}


void
ngx_quic_free_frames(ngx_connection_t *c, ngx_queue_t *frames)
{
    ngx_queue_t       *q;
    ngx_quic_frame_t  *f;

    do {
        q = ngx_queue_head(frames);

        if (q == ngx_queue_sentinel(frames)) {
            break;
        }

        ngx_queue_remove(q);

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_quic_free_frame(c, f);
    } while (1);
}


void
ngx_quic_queue_frame(ngx_quic_connection_t *qc, ngx_quic_frame_t *frame)
{
    ngx_quic_send_ctx_t  *ctx;

    ctx = ngx_quic_get_send_ctx(qc, frame->level);

    ngx_queue_insert_tail(&ctx->frames, &frame->queue);

    frame->len = ngx_quic_create_frame(NULL, frame);
    /* always succeeds */

    if (qc->closing) {
        return;
    }

    ngx_post_event(&qc->push, &ngx_posted_events);
}


ngx_int_t
ngx_quic_split_frame(ngx_connection_t *c, ngx_quic_frame_t *f, size_t len)
{
    size_t                     shrink;
    ngx_quic_frame_t          *nf;
    ngx_quic_ordered_frame_t  *of, *onf;

    switch (f->type) {
    case NGX_QUIC_FT_CRYPTO:
    case NGX_QUIC_FT_STREAM:
        break;

    default:
        return NGX_DECLINED;
    }

    if ((size_t) f->len <= len) {
        return NGX_OK;
    }

    shrink = f->len - len;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic split frame now:%uz need:%uz shrink:%uz",
                   f->len, len, shrink);

    of = &f->u.ord;

    if (of->length <= shrink) {
        return NGX_DECLINED;
    }

    of->length -= shrink;
    f->len = ngx_quic_create_frame(NULL, f);

    if ((size_t) f->len > len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "could not split QUIC frame");
        return NGX_ERROR;
    }

    nf = ngx_quic_alloc_frame(c);
    if (nf == NULL) {
        return NGX_ERROR;
    }

    *nf = *f;
    onf = &nf->u.ord;
    onf->offset += of->length;
    onf->length = shrink;
    nf->len = ngx_quic_create_frame(NULL, nf);

    nf->data = ngx_quic_split_bufs(c, f->data, of->length);
    if (nf->data == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    ngx_queue_insert_after(&f->queue, &nf->queue);

    return NGX_OK;
}


static ngx_chain_t *
ngx_quic_split_bufs(ngx_connection_t *c, ngx_chain_t *in, size_t len)
{
    size_t                  n;
    ngx_buf_t              *b;
    ngx_chain_t            *out;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    while (in) {
        n = ngx_buf_size(in->buf);

        if (n == len) {
            out = in->next;
            in->next = NULL;
            return out;
        }

        if (n > len) {
            break;
        }

        len -= n;
        in = in->next;
    }

    if (in == NULL) {
        return NULL;
    }

    /* split in->buf by creating shadow bufs which reference it */

    if (in->buf->shadow == NULL) {
        if (qc->free_shadow_bufs) {
            b = qc->free_shadow_bufs;
            qc->free_shadow_bufs = b->shadow;

        } else {
            b = ngx_alloc_buf(c->pool);
            if (b == NULL) {
                return NGX_CHAIN_ERROR;
            }
        }

        *b = *in->buf;
        b->shadow = in->buf;
        b->last_shadow = 1;
        in->buf = b;
    }

    out = ngx_alloc_chain_link(c->pool);
    if (out == NULL) {
        return NGX_CHAIN_ERROR;
    }

    if (qc->free_shadow_bufs) {
        b = qc->free_shadow_bufs;
        qc->free_shadow_bufs = b->shadow;

    } else {
        b = ngx_alloc_buf(c->pool);
        if (b == NULL) {
            ngx_free_chain(c->pool, out);
            return NGX_CHAIN_ERROR;
        }
    }

    out->buf = b;
    out->next = in->next;
    in->next = NULL;

    *b = *in->buf;
    b->last_shadow = 0;
    b->pos = b->pos + len;

    in->buf->shadow = b;
    in->buf->last = in->buf->pos + len;

    return out;
}


ngx_chain_t *
ngx_quic_alloc_buf(ngx_connection_t *c)
{
    ngx_buf_t              *b;
    ngx_chain_t            *cl;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->free_bufs) {
        cl = qc->free_bufs;
        qc->free_bufs = cl->next;

        b = cl->buf;
        b->pos = b->start;
        b->last = b->start;

#ifdef NGX_QUIC_DEBUG_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic reuse buffer n:%ui", qc->nbufs);
#endif

        return cl;
    }

    cl = ngx_alloc_chain_link(c->pool);
    if (cl == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(c->pool, NGX_QUIC_BUFFER_SIZE);
    if (b == NULL) {
        return NULL;
    }

    b->tag = (ngx_buf_tag_t) &ngx_quic_alloc_buf;

    cl->buf = b;

#ifdef NGX_QUIC_DEBUG_ALLOC
    ++qc->nbufs;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic alloc buffer n:%ui", qc->nbufs);
#endif

    return cl;
}


ngx_chain_t *
ngx_quic_copy_buf(ngx_connection_t *c, u_char *data, size_t len)
{
    size_t        n;
    ngx_buf_t    *b;
    ngx_chain_t  *cl, *out, **ll;

    out = NULL;
    ll = &out;

    while (len) {
        cl = ngx_quic_alloc_buf(c);
        if (cl == NULL) {
            return NGX_CHAIN_ERROR;
        }

        b = cl->buf;
        n = ngx_min((size_t) (b->end - b->last), len);

        b->last = ngx_cpymem(b->last, data, n);

        data += n;
        len -= n;

        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return out;
}


ngx_chain_t *
ngx_quic_copy_chain(ngx_connection_t *c, ngx_chain_t *in, size_t limit)
{
    size_t        n;
    ngx_buf_t    *b;
    ngx_chain_t  *cl, *out, **ll;

    out = NULL;
    ll = &out;

    while (in) {
        if (!ngx_buf_in_memory(in->buf) || ngx_buf_size(in->buf) == 0) {
            in = in->next;
            continue;
        }

        cl = ngx_quic_alloc_buf(c);
        if (cl == NULL) {
            return NGX_CHAIN_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        b = cl->buf;

        while (in && b->last != b->end) {

            n = ngx_min(in->buf->last - in->buf->pos, b->end - b->last);

            if (limit > 0 && n > limit) {
                n = limit;
            }

            b->last = ngx_cpymem(b->last, in->buf->pos, n);

            in->buf->pos += n;
            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }

            if (limit > 0) {
                if (limit == n) {
                    goto done;
                }

                limit -= n;
            }
        }
    }

done:

    *ll = NULL;

    return out;
}


ngx_int_t
ngx_quic_order_bufs(ngx_connection_t *c, ngx_chain_t **out, ngx_chain_t *in,
    size_t offset)
{
    u_char       *p;
    size_t        n;
    ngx_buf_t    *b;
    ngx_chain_t  *cl, *sl;

    while (in) {
        cl = *out;

        if (cl == NULL) {
            cl = ngx_quic_alloc_buf(c);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            cl->buf->last = cl->buf->end;
            cl->buf->sync = 1; /* hole */
            cl->next = NULL;
            *out = cl;
        }

        b = cl->buf;
        n = b->last - b->pos;

        if (n <= offset) {
            offset -= n;
            out = &cl->next;
            continue;
        }

        if (b->sync && offset > 0) {
            sl = ngx_quic_split_bufs(c, cl, offset);
            if (sl == NGX_CHAIN_ERROR) {
                return NGX_ERROR;
            }

            cl->next = sl;
            continue;
        }

        for (p = b->pos + offset; p != b->last && in; /* void */ ) {
            n = ngx_min(b->last - p, in->buf->last - in->buf->pos);

            if (b->sync) {
                ngx_memcpy(p, in->buf->pos, n);
            }

            p += n;
            in->buf->pos += n;
            offset += n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        if (b->sync && p != b->pos) {
            sl = ngx_quic_split_bufs(c, cl, p - b->pos);
            if (sl == NGX_CHAIN_ERROR) {
                return NGX_ERROR;
            }

            cl->next = sl;
            cl->buf->sync = 0;
        }
    }

    return NGX_OK;
}


#if (NGX_DEBUG)

void
ngx_quic_log_frame(ngx_log_t *log, ngx_quic_frame_t *f, ngx_uint_t tx)
{
    u_char      *p, *last, *pos, *end;
    ssize_t      n;
    uint64_t     gap, range, largest, smallest;
    ngx_uint_t   i;
    u_char       buf[NGX_MAX_ERROR_STR];

    p = buf;
    last = buf + sizeof(buf);

    switch (f->type) {

    case NGX_QUIC_FT_CRYPTO:
        p = ngx_slprintf(p, last, "CRYPTO len:%uL off:%uL",
                         f->u.crypto.length, f->u.crypto.offset);

#ifdef NGX_QUIC_DEBUG_FRAMES
        {
            ngx_chain_t  *cl;

            p = ngx_slprintf(p, last, " data:");

            for (cl = f->data; cl; cl = cl->next) {
                p = ngx_slprintf(p, last, "%*xs",
                                 cl->buf->last - cl->buf->pos, cl->buf->pos);
            }
        }
#endif

        break;

    case NGX_QUIC_FT_PADDING:
        p = ngx_slprintf(p, last, "PADDING");
        break;

    case NGX_QUIC_FT_ACK:
    case NGX_QUIC_FT_ACK_ECN:

        p = ngx_slprintf(p, last, "ACK n:%ui delay:%uL ",
                         f->u.ack.range_count, f->u.ack.delay);

        if (f->data) {
            pos = f->data->buf->pos;
            end = f->data->buf->last;

        } else {
            pos = NULL;
            end = NULL;
        }

        largest = f->u.ack.largest;
        smallest = f->u.ack.largest - f->u.ack.first_range;

        if (largest == smallest) {
            p = ngx_slprintf(p, last, "%uL", largest);

        } else {
            p = ngx_slprintf(p, last, "%uL-%uL", largest, smallest);
        }

        for (i = 0; i < f->u.ack.range_count; i++) {
            n = ngx_quic_parse_ack_range(log, pos, end, &gap, &range);
            if (n == NGX_ERROR) {
                break;
            }

            pos += n;

            largest = smallest - gap - 2;
            smallest = largest - range;

            if (largest == smallest) {
                p = ngx_slprintf(p, last, " %uL", largest);

            } else {
                p = ngx_slprintf(p, last, " %uL-%uL", largest, smallest);
            }
        }

        if (f->type == NGX_QUIC_FT_ACK_ECN) {
            p = ngx_slprintf(p, last, " ECN counters ect0:%uL ect1:%uL ce:%uL",
                             f->u.ack.ect0, f->u.ack.ect1, f->u.ack.ce);
        }
        break;

    case NGX_QUIC_FT_PING:
        p = ngx_slprintf(p, last, "PING");
        break;

    case NGX_QUIC_FT_NEW_CONNECTION_ID:
        p = ngx_slprintf(p, last,
                         "NEW_CONNECTION_ID seq:%uL retire:%uL len:%ud",
                         f->u.ncid.seqnum, f->u.ncid.retire, f->u.ncid.len);
        break;

    case NGX_QUIC_FT_RETIRE_CONNECTION_ID:
        p = ngx_slprintf(p, last, "RETIRE_CONNECTION_ID seqnum:%uL",
                         f->u.retire_cid.sequence_number);
        break;

    case NGX_QUIC_FT_CONNECTION_CLOSE:
    case NGX_QUIC_FT_CONNECTION_CLOSE_APP:
        p = ngx_slprintf(p, last, "CONNECTION_CLOSE%s err:%ui",
                         f->type == NGX_QUIC_FT_CONNECTION_CLOSE ? "" : "_APP",
                         f->u.close.error_code);

        if (f->u.close.reason.len) {
            p = ngx_slprintf(p, last, " %V", &f->u.close.reason);
        }

        if (f->type == NGX_QUIC_FT_CONNECTION_CLOSE) {
            p = ngx_slprintf(p, last, " ft:%ui", f->u.close.frame_type);
        }

        break;

    case NGX_QUIC_FT_STREAM:
        p = ngx_slprintf(p, last, "STREAM id:0x%xL", f->u.stream.stream_id);

        if (f->u.stream.off) {
            p = ngx_slprintf(p, last, " off:%uL", f->u.stream.offset);
        }

        if (f->u.stream.len) {
            p = ngx_slprintf(p, last, " len:%uL", f->u.stream.length);
        }

        if (f->u.stream.fin) {
            p = ngx_slprintf(p, last, " fin:1");
        }

#ifdef NGX_QUIC_DEBUG_FRAMES
        {
            ngx_chain_t  *cl;

            p = ngx_slprintf(p, last, " data:");

            for (cl = f->data; cl; cl = cl->next) {
                p = ngx_slprintf(p, last, "%*xs",
                                 cl->buf->last - cl->buf->pos, cl->buf->pos);
            }
        }
#endif

        break;

    case NGX_QUIC_FT_MAX_DATA:
        p = ngx_slprintf(p, last, "MAX_DATA max_data:%uL on recv",
                         f->u.max_data.max_data);
        break;

    case NGX_QUIC_FT_RESET_STREAM:
        p = ngx_slprintf(p, last, "RESET_STREAM"
                        " id:0x%xL error_code:0x%xL final_size:0x%xL",
                        f->u.reset_stream.id, f->u.reset_stream.error_code,
                        f->u.reset_stream.final_size);
        break;

    case NGX_QUIC_FT_STOP_SENDING:
        p = ngx_slprintf(p, last, "STOP_SENDING id:0x%xL err:0x%xL",
                         f->u.stop_sending.id, f->u.stop_sending.error_code);
        break;

    case NGX_QUIC_FT_STREAMS_BLOCKED:
    case NGX_QUIC_FT_STREAMS_BLOCKED2:
        p = ngx_slprintf(p, last, "STREAMS_BLOCKED limit:%uL bidi:%ui",
                         f->u.streams_blocked.limit, f->u.streams_blocked.bidi);
        break;

    case NGX_QUIC_FT_MAX_STREAMS:
    case NGX_QUIC_FT_MAX_STREAMS2:
        p = ngx_slprintf(p, last, "MAX_STREAMS limit:%uL bidi:%ui",
                         f->u.max_streams.limit, f->u.max_streams.bidi);
        break;

    case NGX_QUIC_FT_MAX_STREAM_DATA:
        p = ngx_slprintf(p, last, "MAX_STREAM_DATA id:0x%xL limit:%uL",
                         f->u.max_stream_data.id, f->u.max_stream_data.limit);
        break;


    case NGX_QUIC_FT_DATA_BLOCKED:
        p = ngx_slprintf(p, last, "DATA_BLOCKED limit:%uL",
                         f->u.data_blocked.limit);
        break;

    case NGX_QUIC_FT_STREAM_DATA_BLOCKED:
        p = ngx_slprintf(p, last, "STREAM_DATA_BLOCKED id:0x%xL limit:%uL",
                         f->u.stream_data_blocked.id,
                         f->u.stream_data_blocked.limit);
        break;

    case NGX_QUIC_FT_PATH_CHALLENGE:
        p = ngx_slprintf(p, last, "PATH_CHALLENGE data:0x%*xs",
                         sizeof(f->u.path_challenge.data),
                         f->u.path_challenge.data);
        break;

    case NGX_QUIC_FT_PATH_RESPONSE:
        p = ngx_slprintf(p, last, "PATH_RESPONSE data:0x%*xs",
                         sizeof(f->u.path_challenge.data),
                         f->u.path_challenge.data);
        break;

    case NGX_QUIC_FT_NEW_TOKEN:
        p = ngx_slprintf(p, last, "NEW_TOKEN");
        break;

    case NGX_QUIC_FT_HANDSHAKE_DONE:
        p = ngx_slprintf(p, last, "HANDSHAKE DONE");
        break;

    default:
        p = ngx_slprintf(p, last, "unknown type 0x%xi", f->type);
        break;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0, "quic frame %s %s %*s",
                   tx ? "tx" : "rx", ngx_quic_level_name(f->level),
                   p - buf, buf);
}

#endif
