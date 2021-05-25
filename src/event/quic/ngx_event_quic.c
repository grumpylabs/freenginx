
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


static ngx_quic_connection_t *ngx_quic_new_connection(ngx_connection_t *c,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_process_stateless_reset(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static void ngx_quic_input_handler(ngx_event_t *rev);

static ngx_int_t ngx_quic_close_quic(ngx_connection_t *c, ngx_int_t rc);
static void ngx_quic_close_timer_handler(ngx_event_t *ev);

static ngx_int_t ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b,
    ngx_quic_conf_t *conf);
static ngx_int_t ngx_quic_process_packet(ngx_connection_t *c,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_process_payload(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_check_csid(ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_handle_frames(ngx_connection_t *c,
    ngx_quic_header_t *pkt);

static void ngx_quic_push_handler(ngx_event_t *ev);


static ngx_core_module_t  ngx_quic_module_ctx = {
    ngx_string("quic"),
    NULL,
    NULL
};


ngx_module_t  ngx_quic_module = {
    NGX_MODULE_V1,
    &ngx_quic_module_ctx,                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_DEBUG)

void
ngx_quic_connstate_dbg(ngx_connection_t *c)
{
    u_char                 *p, *last;
    ngx_quic_connection_t  *qc;
    u_char                  buf[NGX_MAX_ERROR_STR];

    p = buf;
    last = p + sizeof(buf);

    qc = ngx_quic_get_connection(c);

    p = ngx_slprintf(p, last, "state:");

    if (qc) {

        if (qc->error) {
            p = ngx_slprintf(p, last, "%s", qc->error_app ? " app" : "");
            p = ngx_slprintf(p, last, " error:%ui", qc->error);

            if (qc->error_reason) {
                p = ngx_slprintf(p, last, " \"%s\"", qc->error_reason);
            }
        }

        p = ngx_slprintf(p, last, "%s", qc->shutdown ? " shutdown" : "");
        p = ngx_slprintf(p, last, "%s", qc->closing ? " closing" : "");
        p = ngx_slprintf(p, last, "%s", qc->draining ? " draining" : "");
        p = ngx_slprintf(p, last, "%s", qc->key_phase ? " kp" : "");

    } else {
        p = ngx_slprintf(p, last, " early");
    }

    if (c->read->timer_set) {
        p = ngx_slprintf(p, last,
                         qc && qc->send_timer_set ? " send:%M" : " read:%M",
                         c->read->timer.key - ngx_current_msec);
    }

    if (qc) {

        if (qc->push.timer_set) {
            p = ngx_slprintf(p, last, " push:%M",
                             qc->push.timer.key - ngx_current_msec);
        }

        if (qc->pto.timer_set) {
            p = ngx_slprintf(p, last, " pto:%M",
                             qc->pto.timer.key - ngx_current_msec);
        }

        if (qc->close.timer_set) {
            p = ngx_slprintf(p, last, " close:%M",
                             qc->close.timer.key - ngx_current_msec);
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic %*s", p - buf, buf);
}

#endif


ngx_int_t
ngx_quic_apply_transport_params(ngx_connection_t *c, ngx_quic_tp_t *ctp)
{
    ngx_str_t               scid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    scid.data = qc->socket->cid->id;
    scid.len = qc->socket->cid->len;

    if (scid.len != ctp->initial_scid.len
        || ngx_memcmp(scid.data, ctp->initial_scid.data, scid.len) != 0)
    {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic client initial_source_connection_id mismatch");
        return NGX_ERROR;
    }

    if (ctp->max_udp_payload_size < NGX_QUIC_MIN_INITIAL_SIZE
        || ctp->max_udp_payload_size > NGX_QUIC_MAX_UDP_PAYLOAD_SIZE)
    {
        qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid maximum packet size";

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic maximum packet size is invalid");
        return NGX_ERROR;

    } else if (ctp->max_udp_payload_size > ngx_quic_max_udp_payload(c)) {
        ctp->max_udp_payload_size = ngx_quic_max_udp_payload(c);
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic client maximum packet size truncated");
    }

    if (ctp->active_connection_id_limit < 2) {
        qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid active_connection_id_limit";

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic active_connection_id_limit is invalid");
        return NGX_ERROR;
    }

    if (ctp->ack_delay_exponent > 20) {
        qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid ack_delay_exponent";

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic ack_delay_exponent is invalid");
        return NGX_ERROR;
    }

    if (ctp->max_ack_delay > 16384) {
        qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid max_ack_delay";

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic max_ack_delay is invalid");
        return NGX_ERROR;
    }

    if (ctp->max_idle_timeout > 0
        && ctp->max_idle_timeout < qc->tp.max_idle_timeout)
    {
        qc->tp.max_idle_timeout = ctp->max_idle_timeout;
    }

    qc->streams.server_max_streams_bidi = ctp->initial_max_streams_bidi;
    qc->streams.server_max_streams_uni = ctp->initial_max_streams_uni;

    ngx_memcpy(&qc->ctp, ctp, sizeof(ngx_quic_tp_t));

    return NGX_OK;
}


void
ngx_quic_run(ngx_connection_t *c, ngx_quic_conf_t *conf)
{
    ngx_int_t               rc;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic run");

    rc = ngx_quic_input(c, c->buffer, conf);
    if (rc != NGX_OK) {
        ngx_quic_close_connection(c, rc == NGX_DECLINED ? NGX_DONE : NGX_ERROR);
        return;
    }

    qc = ngx_quic_get_connection(c);

    if (qc == NULL) {
        ngx_quic_close_connection(c, NGX_DONE);
        return;
    }

    ngx_add_timer(c->read, qc->tp.max_idle_timeout);
    ngx_quic_connstate_dbg(c);

    c->read->handler = ngx_quic_input_handler;

    return;
}


static ngx_quic_connection_t *
ngx_quic_new_connection(ngx_connection_t *c, ngx_quic_conf_t *conf,
    ngx_quic_header_t *pkt)
{
    ngx_uint_t              i;
    ngx_quic_tp_t          *ctp;
    ngx_quic_connection_t  *qc;

    qc = ngx_pcalloc(c->pool, sizeof(ngx_quic_connection_t));
    if (qc == NULL) {
        return NULL;
    }

    qc->keys = ngx_quic_keys_new(c->pool);
    if (qc->keys == NULL) {
        return NULL;
    }

    qc->version = pkt->version;

    ngx_rbtree_init(&qc->streams.tree, &qc->streams.sentinel,
                    ngx_quic_rbtree_insert_stream);

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        ngx_queue_init(&qc->send_ctx[i].frames);
        ngx_queue_init(&qc->send_ctx[i].sent);
        qc->send_ctx[i].largest_pn = NGX_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_ack = NGX_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_range = NGX_QUIC_UNSET_PN;
        qc->send_ctx[i].pending_ack = NGX_QUIC_UNSET_PN;
    }

    qc->send_ctx[0].level = ssl_encryption_initial;
    qc->send_ctx[1].level = ssl_encryption_handshake;
    qc->send_ctx[2].level = ssl_encryption_application;

    ngx_queue_init(&qc->free_frames);

    qc->avg_rtt = NGX_QUIC_INITIAL_RTT;
    qc->rttvar = NGX_QUIC_INITIAL_RTT / 2;
    qc->min_rtt = NGX_TIMER_INFINITE;

    /*
     * qc->latest_rtt = 0
     */

    qc->pto.log = c->log;
    qc->pto.data = c;
    qc->pto.handler = ngx_quic_pto_handler;
    qc->pto.cancelable = 1;

    qc->push.log = c->log;
    qc->push.data = c;
    qc->push.handler = ngx_quic_push_handler;
    qc->push.cancelable = 1;

    qc->path_validation.log = c->log;
    qc->path_validation.data = c;
    qc->path_validation.handler = ngx_quic_path_validation_handler;
    qc->path_validation.cancelable = 1;

    qc->conf = conf;
    qc->tp = conf->tp;

    ctp = &qc->ctp;

    /* defaults to be used before actual client parameters are received */
    ctp->max_udp_payload_size = ngx_quic_max_udp_payload(c);
    ctp->ack_delay_exponent = NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT;
    ctp->max_ack_delay = NGX_QUIC_DEFAULT_MAX_ACK_DELAY;
    ctp->active_connection_id_limit = 2;

    qc->streams.recv_max_data = qc->tp.initial_max_data;

    qc->streams.client_max_streams_uni = qc->tp.initial_max_streams_uni;
    qc->streams.client_max_streams_bidi = qc->tp.initial_max_streams_bidi;

    qc->congestion.window = ngx_min(10 * qc->tp.max_udp_payload_size,
                                    ngx_max(2 * qc->tp.max_udp_payload_size,
                                            14720));
    qc->congestion.ssthresh = (size_t) -1;
    qc->congestion.recovery_start = ngx_current_msec;

    if (pkt->validated && pkt->retried) {
        qc->tp.retry_scid.len = pkt->dcid.len;
        qc->tp.retry_scid.data = ngx_pstrdup(c->pool, &pkt->dcid);
        if (qc->tp.retry_scid.data == NULL) {
            return NULL;
        }
    }

    if (ngx_quic_keys_set_initial_secret(c->pool, qc->keys, &pkt->dcid,
                                         qc->version)
        != NGX_OK)
    {
        return NULL;
    }

    qc->validated = pkt->validated;

    if (ngx_quic_open_sockets(c, qc, pkt) != NGX_OK) {
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic connection created");

    return qc;
}


static ngx_int_t
ngx_quic_process_stateless_reset(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char                 *tail, ch;
    ngx_uint_t              i;
    ngx_queue_t            *q;
    ngx_quic_client_id_t   *cid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    /* A stateless reset uses an entire UDP datagram */
    if (pkt->raw->start != pkt->data) {
        return NGX_DECLINED;
    }

    tail = pkt->raw->last - NGX_QUIC_SR_TOKEN_LEN;

    for (q = ngx_queue_head(&qc->client_ids);
         q != ngx_queue_sentinel(&qc->client_ids);
         q = ngx_queue_next(q))
    {
        cid = ngx_queue_data(q, ngx_quic_client_id_t, queue);

        if (cid->seqnum == 0) {
            /* no stateless reset token in initial connection id */
            continue;
        }

        /* constant time comparison */

        for (ch = 0, i = 0; i < NGX_QUIC_SR_TOKEN_LEN; i++) {
            ch |= tail[i] ^ cid->sr_token[i];
        }

        if (ch == 0) {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static void
ngx_quic_input_handler(ngx_event_t *rev)
{
    ngx_int_t               rc;
    ngx_buf_t              *b;
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0, "quic input handler");

    c = rev->data;
    qc = ngx_quic_get_connection(c);

    c->log->action = "handling quic input";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "quic client timed out");
        ngx_quic_close_connection(c, NGX_DONE);
        return;
    }

    if (c->close) {
        qc->error_reason = "graceful shutdown";
        ngx_quic_close_connection(c, NGX_OK);
        return;
    }

    if (!rev->ready) {
        if (qc->closing) {
            ngx_quic_close_connection(c, NGX_OK);
        }
        return;
    }

    b = c->udp->dgram->buffer;

    rc = ngx_quic_input(c, b, NULL);

    if (rc == NGX_ERROR) {
        ngx_quic_close_connection(c, NGX_ERROR);
        return;
    }

    if (rc == NGX_DECLINED) {
        return;
    }

    /* rc == NGX_OK */

    qc->send_timer_set = 0;
    ngx_add_timer(rev, qc->tp.max_idle_timeout);

    ngx_quic_connstate_dbg(c);
}


void
ngx_quic_close_connection(ngx_connection_t *c, ngx_int_t rc)
{
    ngx_pool_t             *pool;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_close_connection rc:%i", rc);

    qc = ngx_quic_get_connection(c);

    if (qc == NULL) {
        if (rc == NGX_ERROR) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic close connection early error");
        }

    } else if (ngx_quic_close_quic(c, rc) == NGX_AGAIN) {
        return;
    }

    if (c->ssl) {
        (void) ngx_ssl_shutdown(c);
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


static ngx_int_t
ngx_quic_close_quic(ngx_connection_t *c, ngx_int_t rc)
{
    ngx_uint_t              i;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!qc->closing) {

        /* drop packets from retransmit queues, no ack is expected */
        for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
            ngx_quic_free_frames(c, &qc->send_ctx[i].sent);
        }

        if (rc == NGX_DONE) {

            /*
             *  10.2.  Idle Timeout
             *
             *  If the idle timeout is enabled by either peer, a connection is
             *  silently closed and its state is discarded when it remains idle
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic closing %s connection",
                           qc->draining ? "drained" : "idle");

        } else {

            /*
             * 10.3.  Immediate Close
             *
             *  An endpoint sends a CONNECTION_CLOSE frame (Section 19.19)
             *  to terminate the connection immediately.
             */

            qc->error_level = c->ssl ? SSL_quic_read_level(c->ssl->connection)
                                     : ssl_encryption_initial;

            if (rc == NGX_OK) {
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "quic immediate close drain:%d",
                               qc->draining);

                qc->close.log = c->log;
                qc->close.data = c;
                qc->close.handler = ngx_quic_close_timer_handler;
                qc->close.cancelable = 1;

                ctx = ngx_quic_get_send_ctx(qc, qc->error_level);

                ngx_add_timer(&qc->close, 3 * ngx_quic_pto(c, ctx));

                qc->error = NGX_QUIC_ERR_NO_ERROR;

            } else {
                if (qc->error == 0 && !qc->error_app) {
                    qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
                }

                ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "quic immediate close due to %s error: %ui %s",
                               qc->error_app ? "app " : "", qc->error,
                               qc->error_reason ? qc->error_reason : "");
            }

            (void) ngx_quic_send_cc(c);

            if (qc->error_level == ssl_encryption_handshake) {
                /* for clients that might not have handshake keys */
                qc->error_level = ssl_encryption_initial;
                (void) ngx_quic_send_cc(c);
            }
        }

        qc->closing = 1;
    }

    if (rc == NGX_ERROR && qc->close.timer_set) {
        /* do not wait for timer in case of fatal error */
        ngx_del_timer(&qc->close);
    }

    if (ngx_quic_close_streams(c, qc) == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (qc->push.timer_set) {
        ngx_del_timer(&qc->push);
    }

    if (qc->pto.timer_set) {
        ngx_del_timer(&qc->pto);
    }

    if (qc->path_validation.timer_set) {
        ngx_del_timer(&qc->path_validation);
    }

    if (qc->push.posted) {
        ngx_delete_posted_event(&qc->push);
    }

    if (qc->close.timer_set) {
        return NGX_AGAIN;
    }

    ngx_quic_close_sockets(c);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic part of connection is terminated");

    /* may be tested from SSL callback during SSL shutdown */
    c->udp = NULL;

    return NGX_OK;
}


void
ngx_quic_finalize_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    qc->error = err;
    qc->error_reason = reason;
    qc->error_app = 1;
    qc->error_ftype = 0;

    ngx_quic_close_connection(c, NGX_ERROR);
}


void
ngx_quic_shutdown_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    qc->shutdown = 1;
    qc->shutdown_code = err;
    qc->shutdown_reason = reason;

    ngx_quic_shutdown_quic(c);
}


static void
ngx_quic_close_timer_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "quic close timer");

    c = ev->data;
    ngx_quic_close_connection(c, NGX_DONE);
}


static ngx_int_t
ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b, ngx_quic_conf_t *conf)
{
    u_char             *p;
    ngx_int_t           rc;
    ngx_uint_t          good;
    ngx_quic_header_t   pkt;

    good = 0;

    p = b->pos;

    while (p < b->last) {

        ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
        pkt.raw = b;
        pkt.data = p;
        pkt.len = b->last - p;
        pkt.log = c->log;
        pkt.flags = p[0];
        pkt.raw->pos++;

        rc = ngx_quic_process_packet(c, conf, &pkt);

#if (NGX_DEBUG)
        if (pkt.parsed) {
            ngx_log_debug5(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic packet %s done decr:%d pn:%L perr:%ui rc:%i",
                           ngx_quic_level_name(pkt.level), pkt.decrypted,
                           pkt.pn, pkt.error, rc);
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic packet done parse failed rc:%i", rc);
        }
#endif

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_DONE) {
            /* stop further processing */
            return NGX_DECLINED;
        }

        if (rc == NGX_OK) {
            good = 1;
        }

        /* NGX_OK || NGX_DECLINED */

        /*
         * we get NGX_DECLINED when there are no keys [yet] available
         * to decrypt packet.
         * Instead of queueing it, we ignore it and rely on the sender's
         * retransmission:
         *
         * 12.2.  Coalescing Packets:
         *
         * For example, if decryption fails (because the keys are
         * not available or any other reason), the receiver MAY either
         * discard or buffer the packet for later processing and MUST
         * attempt to process the remaining packets.
         *
         * We also skip packets that don't match connection state
         * or cannot be parsed properly.
         */

        /* b->pos is at header end, adjust by actual packet length */
        b->pos = pkt.data + pkt.len;

        /* firefox workaround: skip zero padding at the end of quic packet */
        while (b->pos < b->last && *(b->pos) == 0) {
            b->pos++;
        }

        p = b->pos;
    }

    return good ? NGX_OK : NGX_DECLINED;
}


static ngx_int_t
ngx_quic_process_packet(ngx_connection_t *c, ngx_quic_conf_t *conf,
    ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_quic_connection_t  *qc;

    c->log->action = "parsing quic packet";

    rc = ngx_quic_parse_packet(pkt);

    if (rc == NGX_DECLINED || rc == NGX_ERROR) {
        return rc;
    }

    pkt->parsed = 1;

    c->log->action = "processing quic packet";

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet rx dcid len:%uz %xV",
                   pkt->dcid.len, &pkt->dcid);

#if (NGX_DEBUG)
    if (pkt->level != ssl_encryption_application) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic packet rx scid len:%uz %xV",
                       pkt->scid.len, &pkt->scid);
    }

    if (pkt->level == ssl_encryption_initial) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic address validation token len:%uz %xV",
                       pkt->token.len, &pkt->token);
    }
#endif

    qc = ngx_quic_get_connection(c);

    if (qc) {

        if (rc == NGX_ABORT) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "quic unsupported version: 0x%xD", pkt->version);
            return NGX_DECLINED;
        }

        rc = ngx_quic_check_migration(c, pkt);
        if (rc != NGX_OK) {
            return rc;
        }

        if (pkt->level != ssl_encryption_application) {

            if (pkt->version != qc->version) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "quic version mismatch: 0x%xD", pkt->version);
                return NGX_DECLINED;
            }

            if (ngx_quic_check_csid(qc, pkt) != NGX_OK) {
                return NGX_DECLINED;
            }

        } else {

            if (ngx_quic_process_stateless_reset(c, pkt) == NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "quic stateless reset packet detected");

                qc->draining = 1;
                ngx_quic_close_connection(c, NGX_OK);

                return NGX_OK;
            }
        }

        return ngx_quic_process_payload(c, pkt);
    }

    /* packet does not belong to a connection */

    if (rc == NGX_ABORT) {
        return ngx_quic_negotiate_version(c, pkt);
    }

    if (pkt->level == ssl_encryption_application) {
        return ngx_quic_send_stateless_reset(c, conf, pkt);
    }

    if (pkt->level != ssl_encryption_initial) {
        return NGX_ERROR;
    }

    c->log->action = "processing initial packet";

    if (pkt->dcid.len < NGX_QUIC_CID_LEN_MIN) {
        /* 7.2.  Negotiating Connection IDs */
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic too short dcid in initial"
                      " packet: len:%i", pkt->dcid.len);
        return NGX_ERROR;
    }

    /* process retry and initialize connection IDs */

    if (pkt->token.len) {

        rc = ngx_quic_validate_token(c, conf->av_token_key, pkt);

        if (rc == NGX_ERROR) {
            /* internal error */
            return NGX_ERROR;

        } else if (rc == NGX_ABORT) {
            /* token cannot be decrypted */
            return ngx_quic_send_early_cc(c, pkt,
                                          NGX_QUIC_ERR_INVALID_TOKEN,
                                          "cannot decrypt token");
        } else if (rc == NGX_DECLINED) {
            /* token is invalid */

            if (pkt->retried) {
                /* invalid address validation token */
                return ngx_quic_send_early_cc(c, pkt,
                                          NGX_QUIC_ERR_INVALID_TOKEN,
                                          "invalid address validation token");
            } else if (conf->retry) {
                /* invalid NEW_TOKEN */
                return ngx_quic_send_retry(c, conf, pkt);
            }
        }

        /* NGX_OK */

    } else if (conf->retry) {
        return ngx_quic_send_retry(c, conf, pkt);

    } else {
        pkt->odcid = pkt->dcid;
    }

    if (ngx_terminate || ngx_exiting) {
        if (conf->retry) {
            return ngx_quic_send_retry(c, conf, pkt);
        }

        return NGX_ERROR;
    }

    c->log->action = "creating quic connection";

    qc = ngx_quic_new_connection(c, conf, pkt);
    if (qc == NULL) {
        return NGX_ERROR;
    }

    return ngx_quic_process_payload(c, pkt);
}


static ngx_int_t
ngx_quic_process_payload(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = ngx_quic_get_connection(c);

    qc->error = 0;
    qc->error_reason = 0;

    c->log->action = "decrypting packet";

    if (!ngx_quic_keys_available(qc->keys, pkt->level)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic no level %d keys yet, ignoring packet", pkt->level);
        return NGX_DECLINED;
    }

    pkt->keys = qc->keys;
    pkt->key_phase = qc->key_phase;
    pkt->plaintext = buf;

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    rc = ngx_quic_decrypt(pkt, &ctx->largest_pn);
    if (rc != NGX_OK) {
        qc->error = pkt->error;
        qc->error_reason = "failed to decrypt packet";
        return rc;
    }

    pkt->decrypted = 1;

    if (ngx_quic_update_paths(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (c->ssl == NULL) {
        if (ngx_quic_init_connection(c) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (pkt->level == ssl_encryption_handshake) {
        /*
         * 4.10.1. The successful use of Handshake packets indicates
         * that no more Initial packets need to be exchanged
         */
        ngx_quic_discard_ctx(c, ssl_encryption_initial);

        if (qc->socket->path->state != NGX_QUIC_PATH_VALIDATED) {
            qc->socket->path->state = NGX_QUIC_PATH_VALIDATED;
            ngx_post_event(&qc->push, &ngx_posted_events);
        }
    }

    if (qc->closing) {
        /*
         * 10.1  Closing and Draining Connection States
         * ... delayed or reordered packets are properly discarded.
         *
         *  An endpoint retains only enough information to generate
         *  a packet containing a CONNECTION_CLOSE frame and to identify
         *  packets as belonging to the connection.
         */

        qc->error_level = pkt->level;
        qc->error = NGX_QUIC_ERR_NO_ERROR;
        qc->error_reason = "connection is closing, packet discarded";
        qc->error_ftype = 0;
        qc->error_app = 0;

        return ngx_quic_send_cc(c);
    }

    pkt->received = ngx_current_msec;

    c->log->action = "handling payload";

    if (pkt->level != ssl_encryption_application) {
        return ngx_quic_handle_frames(c, pkt);
    }

    if (!pkt->key_update) {
        return ngx_quic_handle_frames(c, pkt);
    }

    /* switch keys and generate next on Key Phase change */

    qc->key_phase ^= 1;
    ngx_quic_keys_switch(c, qc->keys);

    rc = ngx_quic_handle_frames(c, pkt);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_quic_keys_update(c, qc->keys);
}


void
ngx_quic_discard_ctx(ngx_connection_t *c, enum ssl_encryption_level_t level)
{
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_socket_t      *qsock;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!ngx_quic_keys_available(qc->keys, level)) {
        return;
    }

    ngx_quic_keys_discard(qc->keys, level);

    qc->pto_count = 0;

    ctx = ngx_quic_get_send_ctx(qc, level);

    ngx_quic_free_bufs(c, ctx->crypto);

    while (!ngx_queue_empty(&ctx->sent)) {
        q = ngx_queue_head(&ctx->sent);
        ngx_queue_remove(q);

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);
        ngx_quic_congestion_ack(c, f);
        ngx_quic_free_frame(c, f);
    }

    while (!ngx_queue_empty(&ctx->frames)) {
        q = ngx_queue_head(&ctx->frames);
        ngx_queue_remove(q);

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);
        ngx_quic_congestion_ack(c, f);
        ngx_quic_free_frame(c, f);
    }

    if (level == ssl_encryption_initial) {
        /* close temporary listener with odcid */
        qsock = ngx_quic_find_socket(c, NGX_QUIC_UNSET_PN);
        if (qsock) {
            ngx_quic_close_socket(c, qsock);
        }
    }

    ctx->send_ack = 0;

    ngx_quic_set_lost_timer(c);
}


static ngx_int_t
ngx_quic_check_csid(ngx_quic_connection_t *qc, ngx_quic_header_t *pkt)
{
    ngx_queue_t           *q;
    ngx_quic_client_id_t  *cid;

    for (q = ngx_queue_head(&qc->client_ids);
         q != ngx_queue_sentinel(&qc->client_ids);
         q = ngx_queue_next(q))
    {
        cid = ngx_queue_data(q, ngx_quic_client_id_t, queue);

        if (pkt->scid.len == cid->len
            && ngx_memcmp(pkt->scid.data, cid->id, cid->len) == 0)
        {
            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic unexpected quic scid");
    return NGX_ERROR;
}


static ngx_int_t
ngx_quic_handle_frames(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char                 *end, *p;
    ssize_t                 len;
    ngx_buf_t               buf;
    ngx_uint_t              do_close, nonprobing;
    ngx_chain_t             chain;
    ngx_quic_frame_t        frame;
    ngx_quic_socket_t      *qsock;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    p = pkt->payload.data;
    end = p + pkt->payload.len;

    do_close = 0;
    nonprobing = 0;

    while (p < end) {

        c->log->action = "parsing frames";

        ngx_memzero(&frame, sizeof(ngx_quic_frame_t));
        ngx_memzero(&buf, sizeof(ngx_buf_t));
        buf.temporary = 1;

        chain.buf = &buf;
        chain.next = NULL;
        frame.data = &chain;

        len = ngx_quic_parse_frame(pkt, p, end, &frame);

        if (len < 0) {
            qc->error = pkt->error;
            return NGX_ERROR;
        }

        ngx_quic_log_frame(c->log, &frame, 0);

        c->log->action = "handling frames";

        p += len;

        switch (frame.type) {
        /* probing frames */
        case NGX_QUIC_FT_PADDING:
        case NGX_QUIC_FT_PATH_CHALLENGE:
        case NGX_QUIC_FT_PATH_RESPONSE:
        case NGX_QUIC_FT_NEW_CONNECTION_ID:
            break;

        /* non-probing frames */
        default:
            nonprobing = 1;
            break;
        }

        switch (frame.type) {

        case NGX_QUIC_FT_ACK:
            if (ngx_quic_handle_ack_frame(c, pkt, &frame) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;

        case NGX_QUIC_FT_PADDING:
            /* no action required */
            continue;

        case NGX_QUIC_FT_CONNECTION_CLOSE:
        case NGX_QUIC_FT_CONNECTION_CLOSE_APP:
            do_close = 1;
            continue;
        }

        /* got there with ack-eliciting packet */
        pkt->need_ack = 1;

        switch (frame.type) {

        case NGX_QUIC_FT_CRYPTO:

            if (ngx_quic_handle_crypto_frame(c, pkt, &frame) != NGX_OK) {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_PING:
            break;

        case NGX_QUIC_FT_STREAM0:
        case NGX_QUIC_FT_STREAM1:
        case NGX_QUIC_FT_STREAM2:
        case NGX_QUIC_FT_STREAM3:
        case NGX_QUIC_FT_STREAM4:
        case NGX_QUIC_FT_STREAM5:
        case NGX_QUIC_FT_STREAM6:
        case NGX_QUIC_FT_STREAM7:

            if (ngx_quic_handle_stream_frame(c, pkt, &frame) != NGX_OK) {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_MAX_DATA:

            if (ngx_quic_handle_max_data_frame(c, &frame.u.max_data) != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_STREAMS_BLOCKED:
        case NGX_QUIC_FT_STREAMS_BLOCKED2:

            if (ngx_quic_handle_streams_blocked_frame(c, pkt,
                                                      &frame.u.streams_blocked)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_STREAM_DATA_BLOCKED:

            if (ngx_quic_handle_stream_data_blocked_frame(c, pkt,
                                                  &frame.u.stream_data_blocked)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_MAX_STREAM_DATA:

            if (ngx_quic_handle_max_stream_data_frame(c, pkt,
                                                      &frame.u.max_stream_data)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_RESET_STREAM:

            if (ngx_quic_handle_reset_stream_frame(c, pkt,
                                                   &frame.u.reset_stream)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_STOP_SENDING:

            if (ngx_quic_handle_stop_sending_frame(c, pkt,
                                                   &frame.u.stop_sending)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_MAX_STREAMS:
        case NGX_QUIC_FT_MAX_STREAMS2:

            if (ngx_quic_handle_max_streams_frame(c, pkt, &frame.u.max_streams)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_PATH_CHALLENGE:

            if (ngx_quic_handle_path_challenge_frame(c, &frame.u.path_challenge)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_PATH_RESPONSE:

            if (ngx_quic_handle_path_response_frame(c, &frame.u.path_response)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_NEW_CONNECTION_ID:

            if (ngx_quic_handle_new_connection_id_frame(c, &frame.u.ncid)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_RETIRE_CONNECTION_ID:

            if (ngx_quic_handle_retire_connection_id_frame(c,
                                                           &frame.u.retire_cid)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        default:
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic missing frame handler");
            return NGX_ERROR;
        }
    }

    if (p != end) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic trailing garbage in payload:%ui bytes", end - p);

        qc->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
        return NGX_ERROR;
    }

    if (do_close) {
        qc->draining = 1;
        ngx_quic_close_connection(c, NGX_OK);
    }

    qsock = ngx_quic_get_socket(c);

    if (qsock != qc->socket) {

        if (qsock->path != qc->socket->path && nonprobing) {
            /*
             * An endpoint can migrate a connection to a new local
             * address by sending packets containing non-probing frames
             * from that address.
             */
            if (ngx_quic_handle_migration(c, pkt) != NGX_OK) {
                return NGX_ERROR;
            }
        }
        /*
         * else: packet arrived via non-default socket;
         *       no reason to change active path
         */
    }

    if (ngx_quic_ack_packet(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_quic_push_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "quic push timer");

    c = ev->data;

    if (ngx_quic_output(c) != NGX_OK) {
        ngx_quic_close_connection(c, NGX_ERROR);
        return;
    }

    ngx_quic_connstate_dbg(c);
}


void
ngx_quic_shutdown_quic(ngx_connection_t *c)
{
    ngx_rbtree_t           *tree;
    ngx_rbtree_node_t      *node;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->closing) {
        return;
    }

    tree = &qc->streams.tree;

    if (tree->root != tree->sentinel) {
        for (node = ngx_rbtree_min(tree->root, tree->sentinel);
             node;
             node = ngx_rbtree_next(tree, node))
        {
            qs = (ngx_quic_stream_t *) node;

            if (!qs->cancelable) {
                return;
            }
        }
    }

    ngx_quic_finalize_connection(c, qc->shutdown_code, qc->shutdown_reason);
}


uint32_t
ngx_quic_version(ngx_connection_t *c)
{
    uint32_t                version;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    version = qc->version;

    return (version & 0xff000000) == 0xff000000 ? version & 0xff : version;
}
