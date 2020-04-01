
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_HAVE_NONALIGNED)

#define ngx_quic_parse_uint16(p)  ntohs(*(uint16_t *) (p))
#define ngx_quic_parse_uint32(p)  ntohl(*(uint32_t *) (p))

#define ngx_quic_write_uint16  ngx_quic_write_uint16_aligned
#define ngx_quic_write_uint32  ngx_quic_write_uint32_aligned

#else

#define ngx_quic_parse_uint16(p)  ((p)[0] << 8 | (p)[1])
#define ngx_quic_parse_uint32(p)                                              \
    ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#define ngx_quic_write_uint16(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 8),                                            \
     (p)[1] = (u_char)  (s),                                                  \
     (p) + sizeof(uint16_t))

#define ngx_quic_write_uint32(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 24),                                           \
     (p)[1] = (u_char) ((s) >> 16),                                           \
     (p)[2] = (u_char) ((s) >> 8),                                            \
     (p)[3] = (u_char)  (s),                                                  \
     (p) + sizeof(uint32_t))

#endif


#define ngx_quic_write_uint16_aligned(p, s)                                   \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))

#define ngx_quic_write_uint32_aligned(p, s)                                   \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#define ngx_quic_varint_len(value)                                            \
     ((value) <= 63 ? 1                                                       \
     : ((uint32_t) value) <= 16383 ? 2                                        \
     : ((uint64_t) value) <= 1073741823 ?  4                                  \
     : 8)


static u_char *ngx_quic_parse_int(u_char *pos, u_char *end, uint64_t *out);
static u_char *ngx_quic_parse_int_multi(u_char *pos, u_char *end, ...);
static void ngx_quic_build_int(u_char **pos, uint64_t value);

static u_char *ngx_quic_read_uint8(u_char *pos, u_char *end, uint8_t *value);
/*static*/ u_char *ngx_quic_read_uint16(u_char *pos, u_char *end, uint16_t *value); // usage depends on NGX_QUIC_VERSION
static u_char *ngx_quic_read_uint32(u_char *pos, u_char *end, uint32_t *value);
static u_char *ngx_quic_read_bytes(u_char *pos, u_char *end, size_t len,
    u_char **out);
static u_char *ngx_quic_copy_bytes(u_char *pos, u_char *end, size_t len,
    u_char *dst);

static size_t ngx_quic_create_ack(u_char *p, ngx_quic_ack_frame_t *ack);
static size_t ngx_quic_create_crypto(u_char *p,
    ngx_quic_crypto_frame_t *crypto);
static size_t ngx_quic_create_hs_done(u_char *p);
static size_t ngx_quic_create_stream(u_char *p, ngx_quic_stream_frame_t *sf);
static size_t ngx_quic_create_max_streams(u_char *p,
    ngx_quic_max_streams_frame_t *ms);
static size_t ngx_quic_create_max_stream_data(u_char *p,
    ngx_quic_max_stream_data_frame_t *ms);
static size_t ngx_quic_create_close(u_char *p, ngx_quic_close_frame_t *cl);

static ngx_int_t ngx_quic_parse_transport_param(u_char *p, u_char *end,
    uint16_t id, ngx_quic_tp_t *dst);


/* literal errors indexed by corresponding value */
static char *ngx_quic_errors[] = {
    "NO_ERROR",
    "INTERNAL_ERROR",
    "SERVER_BUSY",
    "FLOW_CONTROL_ERROR",
    "STREAM_LIMIT_ERROR",
    "STREAM_STATE_ERROR",
    "FINAL_SIZE_ERROR",
    "FRAME_ENCODING_ERROR",
    "TRANSPORT_PARAMETER_ERROR",
    "CONNECTION_ID_LIMIT_ERROR",
    "PROTOCOL_VIOLATION",
    "INVALID_TOKEN",
    "",
    "CRYPTO_BUFFER_EXCEEDED",
    "",
    "CRYPTO_ERROR",
};


static ngx_inline u_char *
ngx_quic_parse_int(u_char *pos, u_char *end, uint64_t *out)
{
    u_char      *p;
    uint64_t     value;
    ngx_uint_t   len;

    if (pos >= end) {
        printf("OOPS >=\n");
        return NULL;
    }

    p = pos;
    len = 1 << ((*p & 0xc0) >> 6);

    value = *p++ & 0x3f;

    if ((size_t)(end - p) < (len - 1)) {
        printf("LEN TOO BIG: need %ld have %ld\n", len, end - p);
        return NULL;
    }

    while (--len) {
        value = (value << 8) + *p++;
    }

    *out = value;

    return p;
}


static ngx_inline u_char *
ngx_quic_parse_int_multi(u_char *pos, u_char *end, ...)
{
    u_char    *p;
    va_list    ap;
    uint64_t  *item;

    p = pos;

    va_start(ap, end);

    do {
        item = va_arg(ap, uint64_t *);
        if (item == NULL) {
            break;
        }

        p = ngx_quic_parse_int(p, end, item);
        if (p == NULL) {
            return NULL;
        }

    } while (1);

    va_end(ap);

    return p;
}


static ngx_inline u_char *
ngx_quic_read_uint8(u_char *pos, u_char *end, uint8_t *value)
{
    if ((size_t)(end - pos) < 1) {
        return NULL;
    }

    *value = *pos;

    return pos + 1;
}


/*static*/ ngx_inline u_char *
ngx_quic_read_uint16(u_char *pos, u_char *end, uint16_t *value)
{
    if ((size_t)(end - pos) < sizeof(uint16_t)) {
        return NULL;
    }

    *value = ngx_quic_parse_uint16(pos);

    return pos + sizeof(uint16_t);
}


static ngx_inline u_char *
ngx_quic_read_uint32(u_char *pos, u_char *end, uint32_t *value)
{
    if ((size_t)(end - pos) < sizeof(uint32_t)) {
        return NULL;
    }

    *value = ngx_quic_parse_uint32(pos);

    return pos + sizeof(uint32_t);
}


static ngx_inline u_char *
ngx_quic_read_bytes(u_char *pos, u_char *end, size_t len, u_char **out)
{
    if ((size_t)(end - pos) < len) {
        return NULL;
    }

    *out = pos;

    return pos + len;
}


static u_char *
ngx_quic_copy_bytes(u_char *pos, u_char *end, size_t len, u_char *dst)
{
    if ((size_t)(end - pos) < len) {
        return NULL;
    }

    ngx_memcpy(dst, pos, len);

    return pos + len;
}


static void
ngx_quic_build_int(u_char **pos, uint64_t value)
{
    u_char      *p;
    ngx_uint_t   len;//, len2;

    p = *pos;
    len = 0;

    while (value >> ((1 << len) * 8 - 2)) {
        len++;
    }

    *p = len << 6;

//    len2 =
    len = (1 << len);
    len--;
    *p |= value >> (len * 8);
    p++;

    while (len) {
        *p++ = value >> ((len-- - 1) * 8);
    }

    *pos = p;
//    return len2;
}


u_char *
ngx_quic_error_text(uint64_t error_code)
{
    return (u_char *) ngx_quic_errors[error_code];
}


ngx_int_t
ngx_quic_parse_long_header(ngx_quic_header_t *pkt)
{
    u_char  *p, *end;
    uint8_t  idlen;

    p = pkt->data;
    end = pkt->data + pkt->len;

    ngx_quic_hexdump0(pkt->log, "long input", pkt->data, pkt->len);

    p = ngx_quic_read_uint8(p, end, &pkt->flags);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "packet is too small to read flags");
        return NGX_ERROR;
    }

    if (!ngx_quic_long_pkt(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "not a long packet");
        return NGX_ERROR;
    }

    p = ngx_quic_read_uint32(p, end, &pkt->version);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "packet is too small to read version");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic flags:%xi version:%xD", pkt->flags, pkt->version);

    if (pkt->version != NGX_QUIC_VERSION) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "unsupported quic version: 0x%xi", pkt->version);
        return NGX_ERROR;
    }

    p = ngx_quic_read_uint8(p, end, &idlen);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "packet is too small to read dcid len");
        return NGX_ERROR;
    }

    pkt->dcid.len = idlen;

    p = ngx_quic_read_bytes(p, end, idlen, &pkt->dcid.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "packet is too small to read dcid");
        return NGX_ERROR;
    }

    p = ngx_quic_read_uint8(p, end, &idlen);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "packet is too small to read scid len");
        return NGX_ERROR;
    }

    pkt->scid.len = idlen;

    p = ngx_quic_read_bytes(p, end, idlen, &pkt->scid.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "packet is too small to read scid");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;

    return NGX_OK;
}


size_t
ngx_quic_create_long_header(ngx_quic_header_t *pkt, u_char *out,
    size_t pkt_len, u_char **pnp)
{
    u_char  *p, *start;

    p = start = out;

    *p++ = pkt->flags;

    p = ngx_quic_write_uint32(p, NGX_QUIC_VERSION);

    *p++ = pkt->scid.len;
    p = ngx_cpymem(p, pkt->scid.data, pkt->scid.len);

    *p++ = pkt->dcid.len;
    p = ngx_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    if (pkt->level == ssl_encryption_initial) {
        ngx_quic_build_int(&p, pkt->token.len);
    }

    ngx_quic_build_int(&p, pkt_len + 1); // length (inc. pnl)

    *pnp = p;

    *p++ = pkt->number; // XXX: uint64

    return p - start;
}


size_t
ngx_quic_create_short_header(ngx_quic_header_t *pkt, u_char *out,
    size_t pkt_len, u_char **pnp)
{
    u_char  *p, *start;

    p = start = out;

    *p++ = 0x40;

    p = ngx_cpymem(p, pkt->scid.data, pkt->scid.len);

    *pnp = p;

    *p++ = pkt->number; // XXX: uint64

    return p - start;
}


ngx_int_t
ngx_quic_parse_short_header(ngx_quic_header_t *pkt, ngx_str_t *dcid)
{
    u_char  *p, *end;

    p = pkt->data;
    end = pkt->data + pkt->len;

    ngx_quic_hexdump0(pkt->log, "short input", pkt->data, pkt->len);

    p = ngx_quic_read_uint8(p, end, &pkt->flags);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "packet is too small to read flags");
        return NGX_ERROR;
    }

    if (!ngx_quic_short_pkt(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "not a short packet");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic flags:%xi", pkt->flags);

    if (ngx_memcmp(p, dcid->data, dcid->len) != 0) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "unexpected quic dcid");
        return NGX_ERROR;
    }

    pkt->dcid.len = dcid->len;

    p = ngx_quic_read_bytes(p, end, dcid->len, &pkt->dcid.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "packet is too small to read dcid");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;

    return NGX_OK;
}


ngx_int_t
ngx_quic_parse_initial_header(ngx_quic_header_t *pkt)
{
    u_char    *p, *end;
    uint64_t   varint;

    p = pkt->raw->pos;

    end = pkt->raw->last;

    pkt->log->action = "parsing quic initial header";

    p = ngx_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "failed to parse token length");
        return NGX_ERROR;
    }

    pkt->token.len = varint;

    p = ngx_quic_read_bytes(p, end, pkt->token.len, &pkt->token.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "packet too small to read token data");
        return NGX_ERROR;
    }

    p = ngx_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "bad packet length");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet length: %uL", varint);

    if (varint > (uint64_t) ((pkt->data + pkt->len) - p)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "truncated initial packet");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = varint;

    ngx_quic_hexdump0(pkt->log, "DCID", pkt->dcid.data, pkt->dcid.len);
    ngx_quic_hexdump0(pkt->log, "SCID", pkt->scid.data, pkt->scid.len);
    ngx_quic_hexdump0(pkt->log, "token", pkt->token.data, pkt->token.len);

    return NGX_OK;
}


ngx_int_t
ngx_quic_parse_handshake_header(ngx_quic_header_t *pkt)
{
    u_char    *p, *end;
    uint64_t   plen;

    p = pkt->raw->pos;
    end = pkt->raw->last;

    pkt->log->action = "parsing quic handshake header";

    p = ngx_quic_parse_int(p, end, &plen);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "bad packet length");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet length: %uL", plen);

    if (plen > (uint64_t)((pkt->data + pkt->len) - p)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "truncated handshake packet");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = plen;

    return NGX_OK;
}


#define ngx_quic_stream_bit_off(val)  (((val) & 0x04) ? 1 : 0)
#define ngx_quic_stream_bit_len(val)  (((val) & 0x02) ? 1 : 0)
#define ngx_quic_stream_bit_fin(val)  (((val) & 0x01) ? 1 : 0)

ssize_t
ngx_quic_parse_frame(ngx_quic_header_t *pkt, u_char *start, u_char *end,
    ngx_quic_frame_t *f)
{
    u_char    *p;
    uint8_t    flags;
    uint64_t   varint;

    flags = pkt->flags;
    p = start;

    p = ngx_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                     "failed to obtain quic frame type");
        return NGX_ERROR;
    }

    f->type = varint;

    switch (f->type) {

    case NGX_QUIC_FT_CRYPTO:

        if (ngx_quic_pkt_zrtt(flags)) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int(p, end, &f->u.crypto.offset);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse crypto frame offset");
            return NGX_ERROR;
        }

        p = ngx_quic_parse_int(p, end, &f->u.crypto.len);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse crypto frame len");
            return NGX_ERROR;
        }

        p = ngx_quic_read_bytes(p, end, f->u.crypto.len, &f->u.crypto.data);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse crypto frame data");
            return NGX_ERROR;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic CRYPTO frame length: %uL off:%uL pp:%p",
                       f->u.crypto.len, f->u.crypto.offset,
                       f->u.crypto.data);

        ngx_quic_hexdump0(pkt->log, "CRYPTO frame contents",
                          f->u.crypto.data, f->u.crypto.len);
        break;

    case NGX_QUIC_FT_PADDING:

        /* allowed in any packet type */

        while (p < end && *p == NGX_QUIC_FT_PADDING) {
            p++;
        }

        break;

    case NGX_QUIC_FT_ACK:
    case NGX_QUIC_FT_ACK_ECN:

        if (ngx_quic_pkt_zrtt(flags)) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int_multi(p, end, &f->u.ack.largest,
                                     &f->u.ack.delay, &f->u.ack.range_count,
                                     &f->u.ack.first_range, NULL);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse ack frame");
            return NGX_ERROR;
        }

        if (f->u.ack.range_count) {
            p = ngx_quic_parse_int(p, end, &f->u.ack.ranges[0]);
            if (p == NULL) {
                ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                              "failed to parse ack frame first range");
                return NGX_ERROR;
            }
        }

        if (f->type == NGX_QUIC_FT_ACK_ECN) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "TODO: parse ECN ack frames");
            /* TODO: add parsing of such frames */
            return NGX_ERROR;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "ACK: { largest=%ui delay=%ui count=%ui first=%ui}",
                       f->u.ack.largest,
                       f->u.ack.delay,
                       f->u.ack.range_count,
                       f->u.ack.first_range);

        break;

    case NGX_QUIC_FT_PING:

        /* allowed in any packet type */

        break;

    case NGX_QUIC_FT_NEW_CONNECTION_ID:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int_multi(p, end, &f->u.ncid.seqnum,
                                     &f->u.ncid.retire, NULL);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse new connection id frame");
            return NGX_ERROR;
        }

        p = ngx_quic_read_uint8(p, end, &f->u.ncid.len);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse new connection id length");
            return NGX_ERROR;
        }

        p = ngx_quic_copy_bytes(p, end, f->u.ncid.len, f->u.ncid.cid);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse new connection id cid");
            return NGX_ERROR;
        }

        p = ngx_quic_copy_bytes(p, end, 16, f->u.ncid.srt);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse new connection id srt");
            return NGX_ERROR;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "NCID: { seq=%ui retire=%ui len=%ui}",
                       f->u.ncid.seqnum, f->u.ncid.retire, f->u.ncid.len);
        break;

    case NGX_QUIC_FT_CONNECTION_CLOSE2:

        if (!ngx_quic_short_pkt(flags)) {
            goto not_allowed;
        }

        /* fall through */

    case NGX_QUIC_FT_CONNECTION_CLOSE:

        if (ngx_quic_pkt_zrtt(flags)) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int(p, end, &f->u.close.error_code);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse close connection frame error code");
            return NGX_ERROR;
        }

        if (f->type == NGX_QUIC_FT_CONNECTION_CLOSE) {
            p = ngx_quic_parse_int(p, end, &f->u.close.frame_type);
            if (p == NULL) {
                ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                              "failed to parse close connection frame type");
                return NGX_ERROR;
            }
        }

        p = ngx_quic_parse_int(p, end, &varint);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse close reason length");
            return NGX_ERROR;
        }

        f->u.close.reason.len = varint;

        p = ngx_quic_read_bytes(p, end, f->u.close.reason.len,
                                &f->u.close.reason.data);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse close reason");
            return NGX_ERROR;
        }

        if (f->type == NGX_QUIC_FT_CONNECTION_CLOSE) {

            if (f->u.close.error_code >= NGX_QUIC_ERR_LAST) {
                ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                              "unkown error code: %ui, truncated",
                              f->u.close.error_code);
                f->u.close.error_code = NGX_QUIC_ERR_LAST - 1;
            }

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                          "CONN.CLOSE: { %s (0x%xi) type=0x%xi reason='%V'}",
                           ngx_quic_error_text(f->u.close.error_code),
                           f->u.close.error_code, f->u.close.frame_type,
                           &f->u.close.reason);
        } else {

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                          "CONN.CLOSE2: { (0x%xi) reason '%V'}",
                           f->u.close.error_code, &f->u.close.reason);
        }

        break;

    case NGX_QUIC_FT_STREAM0:
    case NGX_QUIC_FT_STREAM1:
    case NGX_QUIC_FT_STREAM2:
    case NGX_QUIC_FT_STREAM3:
    case NGX_QUIC_FT_STREAM4:
    case NGX_QUIC_FT_STREAM5:
    case NGX_QUIC_FT_STREAM6:
    case NGX_QUIC_FT_STREAM7:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        f->u.stream.type = f->type;

        f->u.stream.off = ngx_quic_stream_bit_off(f->type);
        f->u.stream.len = ngx_quic_stream_bit_len(f->type);
        f->u.stream.fin = ngx_quic_stream_bit_fin(f->type);

        p = ngx_quic_parse_int(p, end, &f->u.stream.stream_id);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse stream frame id");
            return NGX_ERROR;
        }

        if (f->type & 0x04) {
            p = ngx_quic_parse_int(p, end, &f->u.stream.offset);
            if (p == NULL) {
                 ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                               "failed to parse stream frame offset");
                return NGX_ERROR;
            }

        } else {
            f->u.stream.offset = 0;
        }

        if (f->type & 0x02) {
            p = ngx_quic_parse_int(p, end, &f->u.stream.length);
            if (p == NULL) {
                ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                              "failed to parse stream frame length");
                return NGX_ERROR;
            }

        } else {
            f->u.stream.length = end - p; /* up to packet end */
        }

        p = ngx_quic_read_bytes(p, end, f->u.stream.length,
                                &f->u.stream.data);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse stream frame data");
            return NGX_ERROR;
        }

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "STREAM frame { 0x%xi id 0x%xi offset 0x%xi "
                       "len 0x%xi bits:off=%d len=%d fin=%d }",
                       f->type, f->u.stream.stream_id, f->u.stream.offset,
                       f->u.stream.length, f->u.stream.off, f->u.stream.len,
                       f->u.stream.fin);

            ngx_quic_hexdump0(pkt->log, "STREAM frame contents",
                              f->u.stream.data, f->u.stream.length);
        break;

    case NGX_QUIC_FT_MAX_DATA:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int(p, end, &f->u.max_data.max_data);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse max data frame");
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "MAX_DATA frame { Maximum Data %ui }",
                       f->u.max_data.max_data);
        break;

    case NGX_QUIC_FT_RESET_STREAM:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int_multi(p, end, &f->u.reset_stream.id,
                                     &f->u.reset_stream.error_code,
                                     &f->u.reset_stream.final_size, NULL);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse reset stream frame");
            return NGX_ERROR;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "RESET STREAM frame"
                       " { id 0x%xi error_code 0x%xi final_size 0x%xi }",
                       f->u.reset_stream.id, f->u.reset_stream.error_code,
                       f->u.reset_stream.final_size);
        break;

    case NGX_QUIC_FT_STOP_SENDING:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int_multi(p, end, &f->u.stop_sending.id,
                                     &f->u.stop_sending.error_code, NULL);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse stop sending frame");
            return NGX_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "STOP SENDING frame { id 0x%xi error_code 0x%xi}",
                       f->u.stop_sending.id, f->u.stop_sending.error_code);

        break;

    case NGX_QUIC_FT_STREAMS_BLOCKED:
    case NGX_QUIC_FT_STREAMS_BLOCKED2:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int(p, end, &f->u.streams_blocked.limit);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse streams blocked frame limit");
            return NGX_ERROR;
        }

        f->u.streams_blocked.bidi =
                              (f->type == NGX_QUIC_FT_STREAMS_BLOCKED) ? 1 : 0;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "STREAMS BLOCKED frame { limit %ui bidi: %d }",
                       f->u.streams_blocked.limit,
                       f->u.streams_blocked.bidi);

        break;

    case NGX_QUIC_FT_HANDSHAKE_DONE:
        /* only sent by server, not by client */
        goto not_allowed;

    case NGX_QUIC_FT_NEW_TOKEN:

        if (!ngx_quic_short_pkt(flags)) {
            goto not_allowed;
        }

        /* TODO: implement */

        ngx_log_error(NGX_LOG_ALERT, pkt->log, 0,
                      "unimplemented frame type 0x%xi in packet", f->type);

        break;

    case NGX_QUIC_FT_MAX_STREAMS:
    case NGX_QUIC_FT_MAX_STREAMS2:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int(p, end, &f->u.max_streams.limit);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse max streams frame limit");
            return NGX_ERROR;
        }

        f->u.max_streams.bidi = (f->type == NGX_QUIC_FT_MAX_STREAMS) ? 1 : 0;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "MAX STREAMS frame { limit %ui bidi: %d }",
                       f->u.max_streams.limit,
                       f->u.max_streams.bidi);
        break;

    case NGX_QUIC_FT_MAX_STREAM_DATA:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int_multi(p, end, &f->u.max_stream_data.id,
                                     &f->u.max_stream_data.limit, NULL);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse max stream data frame");
            return NGX_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "MAX STREAM DATA frame { id: %ui limit: %ui }",
                       f->u.max_stream_data.id,
                       f->u.max_stream_data.limit);
        break;

    case NGX_QUIC_FT_DATA_BLOCKED:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int(p, end, &f->u.data_blocked.limit);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse data blocked frame limit");
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "DATA BLOCKED frame { limit %ui }",
                       f->u.data_blocked.limit);
        break;

    case NGX_QUIC_FT_STREAM_DATA_BLOCKED:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int_multi(p, end, &f->u.stream_data_blocked.id,
                                     &f->u.stream_data_blocked.limit, NULL);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse tream data blocked frame");
            return NGX_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "STREAM DATA BLOCKED frame { id: %ui limit: %ui }",
                       f->u.stream_data_blocked.id,
                       f->u.stream_data_blocked.limit);
        break;

    case NGX_QUIC_FT_RETIRE_CONNECTION_ID:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_parse_int(p, end, &f->u.retire_cid.sequence_number);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to parse retire connection id"
                          " frame sequence number");
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "RETIRE CONNECTION ID frame { sequence_number %ui }",
                       f->u.retire_cid.sequence_number);
        break;

    case NGX_QUIC_FT_PATH_CHALLENGE:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_copy_bytes(p, end, 8, f->u.path_challenge.data);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to get path challenge frame data");
            return NGX_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "PATH CHALLENGE frame");

        ngx_quic_hexdump0(pkt->log, "path challenge data",
                          f->u.path_challenge.data, 8);
        break;

    case NGX_QUIC_FT_PATH_RESPONSE:

        if (!(ngx_quic_short_pkt(flags) || ngx_quic_pkt_zrtt(flags))) {
            goto not_allowed;
        }

        p = ngx_quic_copy_bytes(p, end, 8, f->u.path_response.data);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "failed to get path response frame data");
            return NGX_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "PATH RESPONSE frame");

        ngx_quic_hexdump0(pkt->log, "path response data",
                          f->u.path_response.data, 8);
        break;

    default:
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "unknown frame type 0x%xi in packet", f->type);

        return NGX_ERROR;
    }

    return p - start;

not_allowed:

    ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                  "frame type 0x%xi is not allowed in packet with flags 0x%xi",
                  f->type, pkt->flags);

    return NGX_DECLINED;
}


ssize_t
ngx_quic_create_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    // TODO: handle end arg

    switch (f->type) {
    case NGX_QUIC_FT_ACK:
        return ngx_quic_create_ack(p, &f->u.ack);

    case NGX_QUIC_FT_CRYPTO:
        return ngx_quic_create_crypto(p, &f->u.crypto);

    case NGX_QUIC_FT_HANDSHAKE_DONE:
        return ngx_quic_create_hs_done(p);

    case NGX_QUIC_FT_STREAM0:
    case NGX_QUIC_FT_STREAM1:
    case NGX_QUIC_FT_STREAM2:
    case NGX_QUIC_FT_STREAM3:
    case NGX_QUIC_FT_STREAM4:
    case NGX_QUIC_FT_STREAM5:
    case NGX_QUIC_FT_STREAM6:
    case NGX_QUIC_FT_STREAM7:
        return ngx_quic_create_stream(p, &f->u.stream);

    case NGX_QUIC_FT_CONNECTION_CLOSE:
        return ngx_quic_create_close(p, &f->u.close);

    case NGX_QUIC_FT_MAX_STREAMS:
        return ngx_quic_create_max_streams(p, &f->u.max_streams);

    case NGX_QUIC_FT_MAX_STREAM_DATA:
        return ngx_quic_create_max_stream_data(p, &f->u.max_stream_data);

    default:
        /* BUG: unsupported frame type generated */
        return NGX_ERROR;
    }
}


static size_t
ngx_quic_create_ack(u_char *p, ngx_quic_ack_frame_t *ack)
{
    size_t   len;
    u_char  *start;

    /* minimal ACK packet */

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_ACK);
        len += ngx_quic_varint_len(ack->pn);
        len += ngx_quic_varint_len(0);
        len += ngx_quic_varint_len(0);
        len += ngx_quic_varint_len(0);

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_ACK);
    ngx_quic_build_int(&p, ack->pn);
    ngx_quic_build_int(&p, 0);
    ngx_quic_build_int(&p, 0);
    ngx_quic_build_int(&p, 0);

    return p - start;
}


static size_t
ngx_quic_create_crypto(u_char *p, ngx_quic_crypto_frame_t *crypto)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_CRYPTO);
        len += ngx_quic_varint_len(crypto->offset);
        len += ngx_quic_varint_len(crypto->len);
        len += crypto->len;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_CRYPTO);
    ngx_quic_build_int(&p, crypto->offset);
    ngx_quic_build_int(&p, crypto->len);
    p = ngx_cpymem(p, crypto->data, crypto->len);

    return p - start;
}


static size_t
ngx_quic_create_hs_done(u_char *p)
{
    u_char  *start;

    if (p == NULL) {
        return ngx_quic_varint_len(NGX_QUIC_FT_HANDSHAKE_DONE);
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_HANDSHAKE_DONE);

    return p - start;
}


static size_t
ngx_quic_create_stream(u_char *p, ngx_quic_stream_frame_t *sf)
{
    size_t   len;
    u_char  *start;

    if (!sf->len) {
#if 0
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "attempt to generate a stream frame without length");
#endif
        // XXX: handle error in caller
        return NGX_ERROR;
    }

    if (p == NULL) {
        len = ngx_quic_varint_len(sf->type);

        if (sf->off) {
            len += ngx_quic_varint_len(sf->offset);
        }

        len += ngx_quic_varint_len(sf->stream_id);

        /* length is always present in generated frames */
        len += ngx_quic_varint_len(sf->length);

        len += sf->length;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, sf->type);
    ngx_quic_build_int(&p, sf->stream_id);

    if (sf->off) {
        ngx_quic_build_int(&p, sf->offset);
    }

    /* length is always present in generated frames */
    ngx_quic_build_int(&p, sf->length);

    p = ngx_cpymem(p, sf->data, sf->length);

    return p - start;
}


static size_t
ngx_quic_create_max_streams(u_char *p, ngx_quic_max_streams_frame_t *ms)
{
    size_t       len;
    u_char      *start;
    ngx_uint_t   type;

    type = ms->bidi ?  NGX_QUIC_FT_MAX_STREAMS : NGX_QUIC_FT_MAX_STREAMS2;

    if (p == NULL) {
        len = ngx_quic_varint_len(type);
        len += ngx_quic_varint_len(ms->limit);
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, type);
    ngx_quic_build_int(&p, ms->limit);

    return p - start;
}


static ngx_int_t
ngx_quic_parse_transport_param(u_char *p, u_char *end, uint16_t id,
    ngx_quic_tp_t *dst)
{
    uint64_t   varint;

    switch (id) {
    case NGX_QUIC_TP_ORIGINAL_CONNECTION_ID:
    case NGX_QUIC_TP_STATELESS_RESET_TOKEN:
    case NGX_QUIC_TP_PREFERRED_ADDRESS:
        // TODO
        return NGX_DECLINED;
    }

    switch (id) {

    case NGX_QUIC_TP_DISABLE_ACTIVE_MIGRATION:
        /* zero-length option */
        if (end - p != 0) {
            return NGX_ERROR;
        }
        dst->disable_active_migration = 1;
        return NGX_OK;

    case NGX_QUIC_TP_MAX_IDLE_TIMEOUT:
    case NGX_QUIC_TP_MAX_PACKET_SIZE:
    case NGX_QUIC_TP_INITIAL_MAX_DATA:
    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
    case NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
    case NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI:
    case NGX_QUIC_TP_ACK_DELAY_EXPONENT:
    case NGX_QUIC_TP_MAX_ACK_DELAY:
    case NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:

        p = ngx_quic_parse_int(p, end, &varint);
        if (p == NULL) {
            return NGX_ERROR;
        }
        break;

    default:
        return NGX_DECLINED;
    }

    switch (id) {

    case NGX_QUIC_TP_MAX_IDLE_TIMEOUT:
        dst->max_idle_timeout = varint;
        break;

    case NGX_QUIC_TP_MAX_PACKET_SIZE:
        dst->max_packet_size = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_DATA:
        dst->initial_max_data = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
        dst->initial_max_stream_data_bidi_local = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
        dst->initial_max_stream_data_bidi_remote = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
        dst->initial_max_stream_data_uni = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
        dst->initial_max_streams_bidi = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI:
        dst->initial_max_streams_uni = varint;
        break;

    case NGX_QUIC_TP_ACK_DELAY_EXPONENT:
        dst->ack_delay_exponent = varint;
        break;

    case NGX_QUIC_TP_MAX_ACK_DELAY:
        dst->max_ack_delay = varint;
        break;

    case NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
        dst->active_connection_id_limit = varint;
        break;

    default:
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_parse_transport_params(u_char *p, u_char *end, ngx_quic_tp_t *tp,
    ngx_log_t *log)
{
    ngx_int_t  rc;

#if (NGX_QUIC_DRAFT_VERSION < 27)

    uint16_t  id, len, tp_len;

    p = ngx_quic_read_uint16(p, end, &tp_len);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "failed to parse total transport params length");
        return NGX_ERROR;
    }

    while (p < end) {

        p = ngx_quic_read_uint16(p, end, &id);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "failed to parse transport param id");
            return NGX_ERROR;
        }

        p = ngx_quic_read_uint16(p, end, &len);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                         "failed to parse transport param id 0x%xi length", id);
            return NGX_ERROR;
        }

        rc = ngx_quic_parse_transport_param(p, p + len, id, tp);

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "failed to parse transport param id 0x%xi data", id);
            return NGX_ERROR;
        }

        if (rc == NGX_DECLINED) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "unknown transport param id 0x%xi, skipped", id);
        }

        p += len;
    };

#else

    uint64_t  id, len;

    while (p < end) {
        p = ngx_quic_parse_int(p, end, &id);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "failed to parse transport param id");
            return NGX_ERROR;
        }

        p = ngx_quic_parse_int(p, end, &len);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                         "failed to parse transport param id 0x%xi length", id);
            return NGX_ERROR;
        }

        rc = ngx_quic_parse_transport_param(p, p + len, id, tp);

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "failed to parse transport param id 0x%xi data", id);
            return NGX_ERROR;
        }

        if (rc == NGX_DECLINED) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "unknown transport param id 0x%xi,skipped", id);
        }

        p += len;

    }

#endif

    if (p != end) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "trailing garbage in transport parameters: %ui bytes",
                      end - p);
        return NGX_ERROR;
    }


    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, log, 0,
                   "client transport parameters parsed successfully");

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "disable active migration: %ui",
                   tp->disable_active_migration);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "idle timeout: %ui",
                   tp->max_idle_timeout);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "max packet size: %ui",
                   tp->max_packet_size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "max data: %ui",
                   tp->initial_max_data);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "max stream data bidi local: %ui",
                   tp->initial_max_stream_data_bidi_local);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "max stream data bidi remote: %ui",
                   tp->initial_max_stream_data_bidi_remote);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "max stream data uni: %ui",
                   tp->initial_max_stream_data_uni);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "initial max streams bidi: %ui",
                   tp->initial_max_streams_bidi);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "initial max streams uni: %ui",
                   tp->initial_max_streams_uni);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "ack delay exponent: %ui",
                   tp->ack_delay_exponent);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "max ack delay: %ui",
                   tp->max_ack_delay);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "active connection id limit: %ui",
                   tp->active_connection_id_limit);

    return NGX_OK;
}


static size_t
ngx_quic_create_max_stream_data(u_char *p, ngx_quic_max_stream_data_frame_t *ms)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_MAX_STREAM_DATA);
        len += ngx_quic_varint_len(ms->id);
        len += ngx_quic_varint_len(ms->limit);
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_MAX_STREAM_DATA);
    ngx_quic_build_int(&p, ms->id);
    ngx_quic_build_int(&p, ms->limit);

    return p - start;
}


ssize_t
ngx_quic_create_transport_params(u_char *pos, u_char *end, ngx_quic_tp_t *tp)
{
    u_char  *p;
    size_t   len;

#if (NGX_QUIC_DRAFT_VERSION < 27)

/* older drafts with static transport parameters encoding */

#define ngx_quic_tp_len(id, value)                                            \
    4 + ngx_quic_varint_len(value)

#define ngx_quic_tp_vint(id, value)                                           \
    do {                                                                      \
        p = ngx_quic_write_uint16(p, id);                                     \
        p = ngx_quic_write_uint16(p, ngx_quic_varint_len(value));             \
        ngx_quic_build_int(&p, value);                                        \
    } while (0)

#else

/* recent drafts with variable integer transport parameters encoding */

#define ngx_quic_tp_len(id, value)                                            \
    ngx_quic_varint_len(id)                                                   \
    + ngx_quic_varint_len(value)                                              \
    + ngx_quic_varint_len(ngx_quic_varint_len(value))

#define ngx_quic_tp_vint(id, value)                                           \
    do {                                                                      \
        ngx_quic_build_int(&p, id);                                           \
        ngx_quic_build_int(&p, ngx_quic_varint_len(value));                   \
        ngx_quic_build_int(&p, value);                                        \
    } while (0)

#endif

    p = pos;

    len = ngx_quic_tp_len(NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
                          tp->active_connection_id_limit);

    len += ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_DATA,tp->initial_max_data);

    len += ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                           tp->initial_max_streams_uni);

    len += ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                           tp->initial_max_streams_bidi);

    len += ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                           tp->initial_max_stream_data_bidi_local);

    len += ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                           tp->initial_max_stream_data_bidi_remote);

    len += ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
                           tp->initial_max_stream_data_uni);

    len += ngx_quic_tp_len(NGX_QUIC_TP_MAX_IDLE_TIMEOUT,
                           tp->max_idle_timeout);

    if (pos == NULL) {
#if (NGX_QUIC_DRAFT_VERSION < 27)
        len += 2;
#endif
        return len;
    }

#if (NGX_QUIC_DRAFT_VERSION < 27)
    /* TLS extension length */
    p = ngx_quic_write_uint16(p, len);
#endif

    ngx_quic_tp_vint(NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
                     tp->active_connection_id_limit);

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_DATA,
                     tp->initial_max_data);

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                     tp->initial_max_streams_uni);

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                     tp->initial_max_streams_bidi);

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                     tp->initial_max_stream_data_bidi_local);

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                     tp->initial_max_stream_data_bidi_remote);

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
                     tp->initial_max_stream_data_uni);

    ngx_quic_tp_vint(NGX_QUIC_TP_MAX_IDLE_TIMEOUT,
                     tp->max_idle_timeout);

    ngx_quic_hexdump0(ngx_cycle->log, "transport parameters", pos, p - pos);

    return p - pos;
}


static size_t
ngx_quic_create_close(u_char *p, ngx_quic_close_frame_t *cl)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_CONNECTION_CLOSE);
        len += ngx_quic_varint_len(cl->error_code);
        len += ngx_quic_varint_len(cl->frame_type);
        len += ngx_quic_varint_len(cl->reason.len);
        len += cl->reason.len;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_CONNECTION_CLOSE);
    ngx_quic_build_int(&p, cl->error_code);
    ngx_quic_build_int(&p, cl->frame_type);
    ngx_quic_build_int(&p, cl->reason.len);
    p = ngx_cpymem(p, cl->reason.data, cl->reason.len);

    return p - start;
}
