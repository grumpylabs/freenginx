
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*  0-RTT and 1-RTT data exist in the same packet number space,
 *  so we have 3 packet number spaces:
 *
 *  0 - Initial
 *  1 - Handshake
 *  2 - 0-RTT and 1-RTT
 */
#define ngx_quic_get_send_ctx(qc, level)                                      \
    ((level) == ssl_encryption_initial) ? &((qc)->send_ctx[0])                \
        : (((level) == ssl_encryption_handshake) ? &((qc)->send_ctx[1])       \
                                                 : &((qc)->send_ctx[2]))

#define NGX_QUIC_SEND_CTX_LAST  (NGX_QUIC_ENCRYPTION_LAST - 1)

#define NGX_QUIC_STREAMS_INC     16
#define NGX_QUIC_STREAMS_LIMIT   (1ULL < 60)

/*
 * 7.4.  Cryptographic Message Buffering
 *       Implementations MUST support buffering at least 4096 bytes of data
 */
#define NGX_QUIC_MAX_BUFFERED    65535


typedef enum {
    NGX_QUIC_ST_INITIAL,     /* connection just created */
    NGX_QUIC_ST_HANDSHAKE,   /* handshake started */
    NGX_QUIC_ST_EARLY_DATA,  /* handshake in progress */
    NGX_QUIC_ST_APPLICATION  /* handshake complete */
} ngx_quic_state_t;


typedef struct {
    ngx_rbtree_t                      tree;
    ngx_rbtree_node_t                 sentinel;
    ngx_connection_handler_pt         handler;

    ngx_uint_t                        id_counter;
} ngx_quic_streams_t;


/*
 * 12.3.  Packet Numbers
 *
 *  Conceptually, a packet number space is the context in which a packet
 *  can be processed and acknowledged.  Initial packets can only be sent
 *  with Initial packet protection keys and acknowledged in packets which
 *  are also Initial packets.
*/
typedef struct {
    ngx_quic_secret_t                 client_secret;
    ngx_quic_secret_t                 server_secret;

    uint64_t                          pnum;
    uint64_t                          largest_ack; /* number received from peer */

    ngx_queue_t                       frames;
    ngx_queue_t                       sent;
} ngx_quic_send_ctx_t;


struct ngx_quic_connection_s {
    ngx_str_t                         scid;
    ngx_str_t                         dcid;
    ngx_str_t                         token;

    ngx_uint_t                        client_tp_done;
    ngx_quic_tp_t                     tp;
    ngx_quic_tp_t                     ctp;

    ngx_quic_state_t                  state;

    ngx_quic_send_ctx_t               send_ctx[NGX_QUIC_SEND_CTX_LAST];
    ngx_quic_secrets_t                keys[NGX_QUIC_ENCRYPTION_LAST];
    ngx_quic_secrets_t                next_key;
    ngx_quic_frames_stream_t          crypto[NGX_QUIC_ENCRYPTION_LAST];

    ngx_ssl_t                        *ssl;

    ngx_event_t                       push;
    ngx_event_t                       retry;
    ngx_queue_t                       free_frames;

#if (NGX_DEBUG)
    ngx_uint_t                        nframes;
#endif

    ngx_quic_streams_t                streams;
    ngx_uint_t                        max_data;

    uint64_t                          cur_streams;
    uint64_t                          max_streams;

    unsigned                          send_timer_set:1;
    unsigned                          closing:1;
    unsigned                          key_phase:1;
};


typedef ngx_int_t (*ngx_quic_frame_handler_pt)(ngx_connection_t *c,
    ngx_quic_frame_t *frame);


#if BORINGSSL_API_VERSION >= 10
static int ngx_quic_set_read_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
static int ngx_quic_set_write_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
#else
static int ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *read_secret,
    const uint8_t *write_secret, size_t secret_len);
#endif

static int ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len);
static int ngx_quic_flush_flight(ngx_ssl_conn_t *ssl_conn);
static int ngx_quic_send_alert(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, uint8_t alert);


static ngx_int_t ngx_quic_new_connection(ngx_connection_t *c, ngx_ssl_t *ssl,
    ngx_quic_tp_t *tp, ngx_quic_header_t *pkt,
    ngx_connection_handler_pt handler);
static ngx_int_t ngx_quic_init_connection(ngx_connection_t *c);
static void ngx_quic_input_handler(ngx_event_t *rev);
static void ngx_quic_close_connection(ngx_connection_t *c);

static ngx_int_t ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b);
static ngx_int_t ngx_quic_initial_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_handshake_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_early_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_app_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_payload_handler(ngx_connection_t *c,
    ngx_quic_header_t *pkt);

static ngx_int_t ngx_quic_handle_ack_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_ack_frame_t *f);
static ngx_int_t ngx_quic_handle_ack_frame_range(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, uint64_t min, uint64_t max);

static ngx_int_t ngx_quic_handle_ordered_frame(ngx_connection_t *c,
    ngx_quic_frames_stream_t *fs, ngx_quic_frame_t *frame,
    ngx_quic_frame_handler_pt handler);
static ngx_int_t ngx_quic_adjust_frame_offset(ngx_connection_t *c,
    ngx_quic_frame_t *f, uint64_t offset_in);
static ngx_int_t ngx_quic_buffer_frame(ngx_connection_t *c,
    ngx_quic_frames_stream_t *stream, ngx_quic_frame_t *f);

static ngx_int_t ngx_quic_handle_crypto_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_frame_t *frame);
static ngx_int_t ngx_quic_crypto_input(ngx_connection_t *c,
    ngx_quic_frame_t *frame);
static ngx_int_t ngx_quic_handle_stream_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_frame_t *frame);
static ngx_int_t ngx_quic_stream_input(ngx_connection_t *c,
    ngx_quic_frame_t *frame);
static ngx_quic_stream_t *ngx_quic_add_stream(ngx_connection_t *c,
    ngx_quic_stream_frame_t *f);

static ngx_int_t ngx_quic_handle_max_streams(ngx_connection_t *c);
static ngx_int_t ngx_quic_handle_streams_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_streams_blocked_frame_t *f);
static ngx_int_t ngx_quic_handle_stream_data_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stream_data_blocked_frame_t *f);

static void ngx_quic_queue_frame(ngx_quic_connection_t *qc,
    ngx_quic_frame_t *frame);

static ngx_int_t ngx_quic_output(ngx_connection_t *c);
static ngx_int_t ngx_quic_output_frames(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx);
static void ngx_quic_free_frames(ngx_connection_t *c, ngx_queue_t *frames);
static ngx_int_t ngx_quic_send_frames(ngx_connection_t *c, ngx_queue_t *frames);

static void ngx_quic_set_packet_number(ngx_quic_header_t *pkt,
    ngx_quic_send_ctx_t *ctx);
static void ngx_quic_retransmit_handler(ngx_event_t *ev);
static ngx_int_t ngx_quic_retransmit(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, ngx_msec_t *waitp);
static void ngx_quic_push_handler(ngx_event_t *ev);

static void ngx_quic_rbtree_insert_stream(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_quic_stream_t *ngx_quic_find_stream(ngx_rbtree_t *rbtree,
    uint64_t id);
static ngx_quic_stream_t *ngx_quic_create_stream(ngx_connection_t *c,
    uint64_t id, size_t rcvbuf_size);
static ssize_t ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf,
    size_t size);
static ssize_t ngx_quic_stream_send(ngx_connection_t *c, u_char *buf,
    size_t size);
static void ngx_quic_stream_cleanup_handler(void *data);
static ngx_chain_t *ngx_quic_stream_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static ngx_quic_frame_t *ngx_quic_alloc_frame(ngx_connection_t *c, size_t size);
static void ngx_quic_free_frame(ngx_connection_t *c, ngx_quic_frame_t *frame);


static SSL_QUIC_METHOD quic_method = {
#if BORINGSSL_API_VERSION >= 10
    ngx_quic_set_read_secret,
    ngx_quic_set_write_secret,
#else
    ngx_quic_set_encryption_secrets,
#endif
    ngx_quic_add_handshake_data,
    ngx_quic_flush_flight,
    ngx_quic_send_alert,
};


#if BORINGSSL_API_VERSION >= 10

static int
ngx_quic_set_read_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *rsecret, size_t secret_len)
{
    ngx_connection_t    *c;
    ngx_quic_secrets_t  *keys;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d read secret",
                     rsecret, secret_len, level);

    keys = &c->quic->keys[level];

    if (level == ssl_encryption_early_data) {
        c->quic->state = NGX_QUIC_ST_EARLY_DATA;
    }

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          rsecret, secret_len,
                                          &keys->client);
}


static int
ngx_quic_set_write_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_connection_t    *c;
    ngx_quic_secrets_t  *keys;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d write secret",
                     wsecret, secret_len, level);

    keys = &c->quic->keys[level];

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          wsecret, secret_len,
                                          &keys->server);
}

#else

static int
ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *rsecret,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_int_t            rc;
    ngx_connection_t    *c;
    ngx_quic_secrets_t  *keys;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d read", rsecret, secret_len, level);

    keys = &c->quic->keys[level];

    rc = ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                        rsecret, secret_len,
                                        &keys->client);
    if (rc != 1) {
        return rc;
    }

    if (level == ssl_encryption_early_data) {
        c->quic->state = NGX_QUIC_ST_EARLY_DATA;
        return 1;
    }

    ngx_quic_hexdump(c->log, "level:%d write", wsecret, secret_len, level);

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          wsecret, secret_len,
                                          &keys->server);
}

#endif


static int
ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len)
{
    u_char                    *p, *end;
    size_t                     client_params_len;
    const uint8_t             *client_params;
    ngx_quic_frame_t          *frame;
    ngx_connection_t          *c;
    ngx_quic_connection_t     *qc;
    ngx_quic_frames_stream_t  *fs;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
    qc = c->quic;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_quic_add_handshake_data");

    /* XXX: obtain client parameters after the handshake? */
    if (!qc->client_tp_done) {

        SSL_get_peer_quic_transport_params(ssl_conn, &client_params,
                                           &client_params_len);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_get_peer_quic_transport_params(): params_len %ui",
                       client_params_len);

        if (client_params_len != 0) {
            p = (u_char *) client_params;
            end = p + client_params_len;

            if (ngx_quic_parse_transport_params(p, end, &qc->ctp, c->log)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (qc->ctp.max_idle_timeout > 0
                && qc->ctp.max_idle_timeout < qc->tp.max_idle_timeout)
            {
                qc->tp.max_idle_timeout = qc->ctp.max_idle_timeout;
            }

            qc->client_tp_done = 1;
        }
    }

    fs = &qc->crypto[level];

    frame = ngx_quic_alloc_frame(c, len);
    if (frame == NULL) {
        return 0;
    }

    ngx_memcpy(frame->data, data, len);

    frame->level = level;
    frame->type = NGX_QUIC_FT_CRYPTO;
    frame->u.crypto.offset += fs->sent;
    frame->u.crypto.length = len;
    frame->u.crypto.data = frame->data;

    fs->sent += len;

    ngx_sprintf(frame->info, "crypto, generated by SSL len=%ui level=%d", len, level);

    ngx_quic_queue_frame(qc, frame);

    return 1;
}


static int
ngx_quic_flush_flight(ngx_ssl_conn_t *ssl_conn)
{
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_quic_flush_flight()");

    return 1;
}


static int
ngx_quic_send_alert(ngx_ssl_conn_t *ssl_conn, enum ssl_encryption_level_t level,
    uint8_t alert)
{
    ngx_connection_t  *c;
    ngx_quic_frame_t  *frame;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_quic_send_alert(), lvl=%d, alert=%d",
                   (int) level, (int) alert);

    frame = ngx_quic_alloc_frame(c, 0);
    if (frame == NULL) {
        return 0;
    }

    frame->level = level;
    frame->type = NGX_QUIC_FT_CONNECTION_CLOSE;
    frame->u.close.error_code = 0x100 + alert;
    ngx_sprintf(frame->info, "cc from send_alert level=%d", frame->level);

    ngx_quic_queue_frame(c->quic, frame);

    if (ngx_quic_output(c) != NGX_OK) {
        return 0;
    }

    return 1;
}


void
ngx_quic_run(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_quic_tp_t *tp,
    ngx_connection_handler_pt handler)
{
    ngx_buf_t          *b;
    ngx_quic_header_t   pkt;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic run");

    c->log->action = "QUIC initialization";

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    b = c->buffer;

    pkt.log = c->log;
    pkt.raw = b;
    pkt.data = b->start;
    pkt.len = b->last - b->start;

    if (ngx_quic_new_connection(c, ssl, tp, &pkt, handler) != NGX_OK) {
        ngx_quic_close_connection(c);
        return;
    }

    ngx_add_timer(c->read, c->quic->tp.max_idle_timeout);

    c->read->handler = ngx_quic_input_handler;

    return;
}


static ngx_int_t
ngx_quic_new_connection(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_quic_tp_t *tp,
    ngx_quic_header_t *pkt, ngx_connection_handler_pt handler)
{
    ngx_uint_t              i;
    ngx_quic_tp_t          *ctp;
    ngx_quic_secrets_t     *keys;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_DEFAULT_MAX_PACKET_SIZE];

    if (ngx_buf_size(pkt->raw) < 1200) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "too small UDP datagram");
        return NGX_ERROR;
    }

    if (ngx_quic_parse_long_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!ngx_quic_pkt_in(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "invalid initial packet: 0x%xi", pkt->flags);
        return NGX_ERROR;
    }

    if (ngx_quic_parse_initial_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    c->log->action = "creating new quic connection";

    qc = ngx_pcalloc(c->pool, sizeof(ngx_quic_connection_t));
    if (qc == NULL) {
        return NGX_ERROR;
    }

    qc->state = NGX_QUIC_ST_INITIAL;

    ngx_rbtree_init(&qc->streams.tree, &qc->streams.sentinel,
                    ngx_quic_rbtree_insert_stream);

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        ngx_queue_init(&qc->send_ctx[i].frames);
        ngx_queue_init(&qc->send_ctx[i].sent);
    }

    for (i = 0; i < NGX_QUIC_ENCRYPTION_LAST; i++) {
        ngx_queue_init(&qc->crypto[i].frames);
    }

    ngx_queue_init(&qc->free_frames);

    qc->retry.log = c->log;
    qc->retry.data = c;
    qc->retry.handler = ngx_quic_retransmit_handler;
    qc->retry.cancelable = 1;

    qc->push.log = c->log;
    qc->push.data = c;
    qc->push.handler = ngx_quic_push_handler;
    qc->push.cancelable = 1;

    c->quic = qc;
    qc->ssl = ssl;
    qc->tp = *tp;
    qc->streams.handler = handler;

    ctp = &qc->ctp;
    ctp->max_packet_size = NGX_QUIC_DEFAULT_MAX_PACKET_SIZE;
    ctp->ack_delay_exponent = NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT;
    ctp->max_ack_delay = NGX_QUIC_DEFAULT_MAX_ACK_DELAY;

    qc->dcid.len = pkt->dcid.len;
    qc->dcid.data = ngx_pnalloc(c->pool, pkt->dcid.len);
    if (qc->dcid.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(qc->dcid.data, pkt->dcid.data, qc->dcid.len);

    qc->scid.len = pkt->scid.len;
    qc->scid.data = ngx_pnalloc(c->pool, qc->scid.len);
    if (qc->scid.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(qc->scid.data, pkt->scid.data, qc->scid.len);

    qc->token.len = pkt->token.len;
    qc->token.data = ngx_pnalloc(c->pool, qc->token.len);
    if (qc->token.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(qc->token.data, pkt->token.data, qc->token.len);

    keys = &c->quic->keys[ssl_encryption_initial];

    if (ngx_quic_set_initial_secret(c->pool, &keys->client, &keys->server,
                                    &qc->dcid)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    pkt->secret = &keys->client;
    pkt->level = ssl_encryption_initial;
    pkt->plaintext = buf;

    if (ngx_quic_decrypt(pkt, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pkt->pn != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "invalid initial packet number %L", pkt->pn);
        return NGX_ERROR;
    }

    if (ngx_quic_init_connection(c) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_payload_handler(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    /* pos is at header end, adjust by actual packet length */
    pkt->raw->pos += pkt->len;

    return ngx_quic_input(c, pkt->raw);
}


static ngx_int_t
ngx_quic_init_connection(ngx_connection_t *c)
{
    int                     n, sslerr;
    u_char                 *p;
    ssize_t                 len;
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (ngx_ssl_create_connection(qc->ssl, c, NGX_SSL_BUFFER) != NGX_OK) {
        return NGX_ERROR;
    }

    ssl_conn = c->ssl->connection;

    if (SSL_set_quic_method(ssl_conn, &quic_method) == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "SSL_set_quic_method() failed");
        return NGX_ERROR;
    }

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (SSL_CTX_get_max_early_data(qc->ssl->ctx)) {
        SSL_set_quic_early_data_enabled(ssl_conn, 1);
    }
#endif

    len = ngx_quic_create_transport_params(NULL, NULL, &qc->tp);
    /* always succeeds */

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    len = ngx_quic_create_transport_params(p, p + len, &qc->tp);
    if (len < 0) {
        return NGX_ERROR;
    }

    if (SSL_set_quic_transport_params(ssl_conn, p, len) == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "SSL_set_quic_transport_params() failed");
        return NGX_ERROR;
    }

    qc->max_streams = qc->tp.initial_max_streams_bidi;
    qc->state = NGX_QUIC_ST_HANDSHAKE;

    n = SSL_do_handshake(ssl_conn);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == -1) {
        sslerr = SSL_get_error(ssl_conn, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);

        if (sslerr != SSL_ERROR_WANT_READ) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "SSL_do_handshake() failed");
            return NGX_ERROR;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    return NGX_OK;
}


static void
ngx_quic_input_handler(ngx_event_t *rev)
{
    ssize_t                 n;
    ngx_buf_t               b;
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_DEFAULT_MAX_PACKET_SIZE];

    b.start = buf;
    b.end = buf + sizeof(buf);
    b.pos = b.last = b.start;

    c = rev->data;
    qc = c->quic;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0, "quic input handler");

    if (qc->closing) {
        ngx_quic_close_connection(c);
        return;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_quic_close_connection(c);
        return;
    }

    if (c->close) {
        ngx_quic_close_connection(c);
        return;
    }

    n = c->recv(c, b.start, b.end - b.start);

    if (n == NGX_AGAIN) {
        return;
    }

    if (n == NGX_ERROR) {
        c->read->eof = 1;
        ngx_quic_close_connection(c);
        return;
    }

    b.last += n;

    if (ngx_quic_input(c, &b) != NGX_OK) {
        ngx_quic_close_connection(c);
        return;
    }

    qc->send_timer_set = 0;
    ngx_add_timer(rev, qc->tp.max_idle_timeout);
}


static void
ngx_quic_close_connection(ngx_connection_t *c)
{
#if (NGX_DEBUG)
    ngx_uint_t              ns;
#endif
    ngx_uint_t              i;
    ngx_pool_t             *pool;
    ngx_event_t            *rev;
    ngx_rbtree_t           *tree;
    ngx_rbtree_node_t      *node;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "close quic connection");

    qc = c->quic;

    if (qc) {

        qc->closing = 1;
        tree = &qc->streams.tree;

        if (tree->root != tree->sentinel) {
            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }

#if (NGX_DEBUG)
            ns = 0;
#endif

            for (node = ngx_rbtree_min(tree->root, tree->sentinel);
                 node;
                 node = ngx_rbtree_next(tree, node))
            {
                qs = (ngx_quic_stream_t *) node;

                rev = qs->c->read;
                rev->ready = 1;
                rev->pending_eof = 1;

                ngx_post_event(rev, &ngx_posted_events);

                if (rev->timer_set) {
                    ngx_del_timer(rev);
                }

#if (NGX_DEBUG)
                ns++;
#endif
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic connection has %ui active streams", ns);

            return;
        }

        for (i = 0; i < NGX_QUIC_ENCRYPTION_LAST; i++) {
            ngx_quic_free_frames(c, &qc->crypto[i].frames);
        }

        for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
            ngx_quic_free_frames(c, &qc->send_ctx[i].frames);
            ngx_quic_free_frames(c, &qc->send_ctx[i].sent);
        }

        if (qc->push.timer_set) {
            ngx_del_timer(&qc->push);
        }

        if (qc->retry.timer_set) {
            ngx_del_timer(&qc->retry);
        }
    }

    if (c->ssl) {
        (void) ngx_ssl_shutdown(c);
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
ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b)
{
    u_char             *p;
    ngx_int_t           rc;
    ngx_quic_header_t   pkt;

    p = b->pos;

    while (p < b->last) {
        c->log->action = "processing quic packet";

        ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
        pkt.raw = b;
        pkt.data = p;
        pkt.len = b->last - p;
        pkt.log = c->log;
        pkt.flags = p[0];

        if (pkt.flags == 0) {
            /* XXX: no idea WTF is this, just ignore */
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "FIREFOX: ZEROES");
            break;
        }

        // TODO: check current state
        if (ngx_quic_long_pkt(pkt.flags)) {

            if (ngx_quic_pkt_in(pkt.flags)) {
                rc = ngx_quic_initial_input(c, &pkt);

            } else if (ngx_quic_pkt_hs(pkt.flags)) {
                rc = ngx_quic_handshake_input(c, &pkt);

            } else if (ngx_quic_pkt_zrtt(pkt.flags)) {
                rc = ngx_quic_early_input(c, &pkt);

            } else {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "BUG: unknown quic state");
                return NGX_ERROR;
            }

        } else {
            rc = ngx_quic_app_input(c, &pkt);
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
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
         */

        /* b->pos is at header end, adjust by actual packet length */
        p = b->pos + pkt.len;
        b->pos = p;       /* reset b->pos to the next packet start */
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_initial_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_ssl_conn_t      *ssl_conn;
    ngx_quic_secrets_t  *keys;
    static u_char        buf[NGX_QUIC_DEFAULT_MAX_PACKET_SIZE];

    c->log->action = "processing initial quic packet";

    ssl_conn = c->ssl->connection;

    if (ngx_quic_parse_long_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_parse_initial_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    keys = &c->quic->keys[ssl_encryption_initial];

    pkt->secret = &keys->client;
    pkt->level = ssl_encryption_initial;
    pkt->plaintext = buf;

    if (ngx_quic_decrypt(pkt, ssl_conn) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_handshake_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_quic_secrets_t     *keys;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_DEFAULT_MAX_PACKET_SIZE];

    c->log->action = "processing handshake quic packet";

    qc = c->quic;

    keys = &c->quic->keys[ssl_encryption_handshake];

    if (keys->client.key.len == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "no read keys yet, packet ignored");
        return NGX_DECLINED;
    }

    /* extract cleartext data into pkt */
    if (ngx_quic_parse_long_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pkt->dcid.len != qc->dcid.len) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic dcidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(pkt->dcid.data, qc->dcid.data, qc->dcid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic dcid");
        return NGX_ERROR;
    }

    if (pkt->scid.len != qc->scid.len) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic scidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(pkt->scid.data, qc->scid.data, qc->scid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic scid");
        return NGX_ERROR;
    }

    if (!ngx_quic_pkt_hs(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "invalid packet type: 0x%xi", pkt->flags);
        return NGX_ERROR;
    }

    if (ngx_quic_parse_handshake_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    pkt->secret = &keys->client;
    pkt->level = ssl_encryption_handshake;
    pkt->plaintext = buf;

    if (ngx_quic_decrypt(pkt, c->ssl->connection) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_early_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_quic_secrets_t     *keys;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_DEFAULT_MAX_PACKET_SIZE];

    c->log->action = "processing early data quic packet";

    qc = c->quic;

    /* extract cleartext data into pkt */
    if (ngx_quic_parse_long_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pkt->dcid.len != qc->dcid.len) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic dcidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(pkt->dcid.data, qc->dcid.data, qc->dcid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic dcid");
        return NGX_ERROR;
    }

    if (pkt->scid.len != qc->scid.len) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic scidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(pkt->scid.data, qc->scid.data, qc->scid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic scid");
        return NGX_ERROR;
    }

    if (!ngx_quic_pkt_zrtt(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "invalid packet type: 0x%xi", pkt->flags);
        return NGX_ERROR;
    }

    if (ngx_quic_parse_handshake_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (c->quic->state != NGX_QUIC_ST_EARLY_DATA) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected 0-RTT packet");
        return NGX_OK;
    }

    keys = &c->quic->keys[ssl_encryption_early_data];

    pkt->secret = &keys->client;
    pkt->level = ssl_encryption_early_data;
    pkt->plaintext = buf;

    if (ngx_quic_decrypt(pkt, c->ssl->connection) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_app_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_quic_secrets_t     *keys, *next, tmp;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_DEFAULT_MAX_PACKET_SIZE];

    c->log->action = "processing application data quic packet";

    qc = c->quic;

    keys = &c->quic->keys[ssl_encryption_application];
    next = &c->quic->next_key;

    if (keys->client.key.len == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "no read keys yet, packet ignored");
        return NGX_DECLINED;
    }

    if (ngx_quic_parse_short_header(pkt, &qc->dcid) != NGX_OK) {
        return NGX_ERROR;
    }

    pkt->secret = &keys->client;
    pkt->next = &next->client;
    pkt->key_phase = c->quic->key_phase;
    pkt->level = ssl_encryption_application;
    pkt->plaintext = buf;

    if (ngx_quic_decrypt(pkt, c->ssl->connection) != NGX_OK) {
        return NGX_ERROR;
    }

    /* switch keys on Key Phase change */

    if (pkt->key_update) {
        c->quic->key_phase ^= 1;

        tmp = *keys;
        *keys = *next;
        *next = tmp;
    }

    rc = ngx_quic_payload_handler(c, pkt);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* generate next keys */

    if (pkt->key_update) {
        if (ngx_quic_key_update(c, keys, next) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return rc;
}


static ngx_int_t
ngx_quic_payload_handler(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char                 *end, *p;
    ssize_t                 len;
    ngx_uint_t              ack_this, do_close;
    ngx_quic_frame_t        frame, *ack_frame;
    ngx_quic_connection_t  *qc;


    qc = c->quic;

    p = pkt->payload.data;
    end = p + pkt->payload.len;

    ack_this = 0;
    do_close = 0;

    while (p < end) {

        c->log->action = "parsing frames";

        len = ngx_quic_parse_frame(pkt, p, end, &frame);

        if (len == NGX_DECLINED) {
            /* TODO: handle protocol violation:
             *       such frame not allowed in this packet
             */
            return NGX_ERROR;
        }

        if (len < 0) {
            return NGX_ERROR;
        }

        c->log->action = "handling frames";

        p += len;

        switch (frame.type) {

        case NGX_QUIC_FT_ACK:
            if (ngx_quic_handle_ack_frame(c, pkt, &frame.u.ack) != NGX_OK) {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_CRYPTO:

            if (ngx_quic_handle_crypto_frame(c, pkt, &frame) != NGX_OK) {
                return NGX_ERROR;
            }

            ack_this = 1;
            break;

        case NGX_QUIC_FT_PADDING:
            /* no action required */
            break;

        case NGX_QUIC_FT_PING:
            ack_this = 1;
            break;

        case NGX_QUIC_FT_CONNECTION_CLOSE:
        case NGX_QUIC_FT_CONNECTION_CLOSE2:
            do_close = 1;
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

            ack_this = 1;
            break;

        case NGX_QUIC_FT_MAX_DATA:
            c->quic->max_data = frame.u.max_data.max_data;
            ack_this = 1;
            break;

        case NGX_QUIC_FT_STREAMS_BLOCKED:
        case NGX_QUIC_FT_STREAMS_BLOCKED2:

            if (ngx_quic_handle_streams_blocked_frame(c, pkt,
                                                      &frame.u.streams_blocked)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            ack_this = 1;
            break;

        case NGX_QUIC_FT_STREAM_DATA_BLOCKED:

            if (ngx_quic_handle_stream_data_blocked_frame(c, pkt,
                                                  &frame.u.stream_data_blocked)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            ack_this = 1;
            break;

        case NGX_QUIC_FT_NEW_CONNECTION_ID:
        case NGX_QUIC_FT_RETIRE_CONNECTION_ID:
        case NGX_QUIC_FT_NEW_TOKEN:
        case NGX_QUIC_FT_RESET_STREAM:
        case NGX_QUIC_FT_STOP_SENDING:
        case NGX_QUIC_FT_PATH_CHALLENGE:
        case NGX_QUIC_FT_PATH_RESPONSE:

            /* TODO: handle */
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "frame handler not implemented");
            ack_this = 1;
            break;

        default:
            return NGX_ERROR;
        }
    }

    if (p != end) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "trailing garbage in payload: %ui bytes", end - p);
        return NGX_ERROR;
    }

    if (do_close) {
        return NGX_DONE;
    }

    if (ack_this == 0) {
        /* do not ack packets with ACKs and PADDING */
        return NGX_OK;
    }

    c->log->action = "generating acknowledgment";

    // packet processed, ACK it now if required
    // TODO: if (ack_required) ...  - currently just ack each packet

    ack_frame = ngx_quic_alloc_frame(c, 0);
    if (ack_frame == NULL) {
        return NGX_ERROR;
    }

    ack_frame->level = (pkt->level == ssl_encryption_early_data)
                       ? ssl_encryption_application
                       : pkt->level;

    ack_frame->type = NGX_QUIC_FT_ACK;
    ack_frame->u.ack.largest = pkt->pn;
    /* only ack immediate packet ]*/
    ack_frame->u.ack.first_range = 0;

    ngx_sprintf(ack_frame->info, "ACK for PN=%d from frame handler level=%d", pkt->pn, ack_frame->level);
    ngx_quic_queue_frame(qc, ack_frame);

    // TODO: call output() after processing some special frames?
    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_ack_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_ack_frame_t *ack)
{
    ssize_t               n;
    u_char               *pos, *end;
    uint64_t              gap, range;
    ngx_uint_t            i, min, max;
    ngx_quic_send_ctx_t  *ctx;

    ctx = ngx_quic_get_send_ctx(c->quic, pkt->level);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_quic_handle_ack_frame level %d", pkt->level);

    /*
     * TODO: If any computed packet number is negative, an endpoint MUST
     *       generate a connection error of type FRAME_ENCODING_ERROR.
     *       (19.3.1)
     */

    if (ack->first_range > ack->largest) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "invalid first range in ack frame");
        return NGX_ERROR;
    }

    min = ack->largest - ack->first_range;
    max = ack->largest;

    if (ngx_quic_handle_ack_frame_range(c, ctx, min, max) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 13.2.3.  Receiver Tracking of ACK Frames */
    if (ctx->largest_ack < max) {
        ctx->largest_ack = max;
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "updated largest received: %ui", max);
    }

    pos = ack->ranges_start;
    end = ack->ranges_end;

    for (i = 0; i < ack->range_count; i++) {

        n = ngx_quic_parse_ack_range(pkt, pos, end, &gap, &range);
        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }
        pos += n;

        if (gap >= min) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                         "invalid range %ui in ack frame", i);
            return NGX_ERROR;
        }

        max = min - 1 - gap;

        if (range > max + 1) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                         "invalid range %ui in ack frame", i);
            return NGX_ERROR;
        }

        min = max - range + 1;

        if (ngx_quic_handle_ack_frame_range(c, ctx, min, max) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_ack_frame_range(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    uint64_t min, uint64_t max)
{
    ngx_uint_t         found;
    ngx_queue_t       *q;
    ngx_quic_frame_t  *f;

    found = 0;

    q = ngx_queue_head(&ctx->sent);

    while (q != ngx_queue_sentinel(&ctx->sent)) {

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (f->pnum >= min && f->pnum <= max) {
            q = ngx_queue_next(q);
            ngx_queue_remove(&f->queue);
            ngx_quic_free_frame(c, f);
            found = 1;

        } else {
            q = ngx_queue_next(q);
        }
    }

    if (!found) {

        if (max <= ctx->pnum) {
            /* duplicate ACK or ACK for non-ack-eliciting frame */
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "ACK for the packet not in sent queue ");
        // TODO: handle error properly: PROTOCOL VIOLATION?
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_ordered_frame(ngx_connection_t *c, ngx_quic_frames_stream_t *fs,
    ngx_quic_frame_t *frame, ngx_quic_frame_handler_pt handler)
{
    size_t                     full_len;
    ngx_int_t                  rc;
    ngx_queue_t               *q;
    ngx_quic_ordered_frame_t  *f;

    f = &frame->u.ord;

    if (f->offset > fs->received) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "out-of-order frame: expecting %ui got %ui",
                       fs->received, f->offset);

        return ngx_quic_buffer_frame(c, fs, frame);
    }

    if (f->offset < fs->received) {

        if (ngx_quic_adjust_frame_offset(c, frame, fs->received)
            == NGX_DONE)
        {
            /* old/duplicate data range */
            return NGX_OK;
        }

        /* intersecting data range, frame modified */
    }

    /* f->offset == fs->received */

    rc = handler(c, frame);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;

    } else if (rc == NGX_DONE) {
        /* handler destroyed stream, queue no longer exists */
        return NGX_OK;
    }

    /* rc == NGX_OK */

    fs->received += f->length;

    /* now check the queue if we can continue with buffered frames */

    do {
        q = ngx_queue_head(&fs->frames);
        if (q == ngx_queue_sentinel(&fs->frames)) {
            break;
        }

        frame = ngx_queue_data(q, ngx_quic_frame_t, queue);
        f = &frame->u.ord;

        if (f->offset > fs->received) {
            /* gap found, nothing more to do */
            break;
        }

        full_len = f->length;

        if (f->offset < fs->received) {

            if (ngx_quic_adjust_frame_offset(c, frame, fs->received)
                == NGX_DONE)
            {
                /* old/duplicate data range */
                ngx_queue_remove(q);
                fs->total -= f->length;

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "skipped buffered frame, total %ui", fs->total);
                ngx_quic_free_frame(c, frame);
                continue;
            }

            /* frame was adjusted, proceed to input */
        }

        /* f->offset == fs->received */

        rc = handler(c, frame);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;

        } else if (rc == NGX_DONE) {
            /* handler destroyed stream, queue no longer exists */
            return NGX_OK;
        }

        fs->received += f->length;
        fs->total -= full_len;

        ngx_queue_remove(q);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                      "consumed buffered frame, total %ui", fs->total);

        ngx_quic_free_frame(c, frame);

    } while (1);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_adjust_frame_offset(ngx_connection_t *c, ngx_quic_frame_t *frame,
    uint64_t offset_in)
{
    size_t                     tail;
    ngx_quic_ordered_frame_t  *f;

    f = &frame->u.ord;

    tail = offset_in - f->offset;

    if (tail >= f->length) {
        /* range preceeding already received data or duplicate, ignore */

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "old or duplicate data in ordered frame, ignored");
        return NGX_DONE;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "adjusted ordered frame data start to expected offset");

    /* intersecting range: adjust data size */

    f->offset += tail;
    f->data += tail;
    f->length -= tail;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_buffer_frame(ngx_connection_t *c, ngx_quic_frames_stream_t *fs,
    ngx_quic_frame_t *frame)
{
    u_char                    *data;
    ngx_queue_t               *q;
    ngx_quic_frame_t          *dst, *item;
    ngx_quic_ordered_frame_t  *f, *df;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_quic_buffer_frame");

    f = &frame->u.ord;

    /* frame start offset is in the future, buffer it */

    /* check limit on total size used by all buffered frames, not actual data */
    if (NGX_QUIC_MAX_BUFFERED - fs->total < f->length) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "ordered input buffer limit exceeded");
        return NGX_ERROR;
    }

    dst = ngx_quic_alloc_frame(c, f->length);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    data = dst->data;
    ngx_memcpy(dst, frame, sizeof(ngx_quic_frame_t));
    dst->data = data;

    ngx_memcpy(dst->data, f->data, f->length);

    df = &dst->u.ord;
    df->data = dst->data;

    fs->total += f->length;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "ordered frame with unexpected offset: buffered, total %ui",
                  fs->total);

    /* TODO: do we need some timeout for this queue ?  */

    if (ngx_queue_empty(&fs->frames)) {
        ngx_queue_insert_after(&fs->frames, &dst->queue);
        return NGX_OK;
    }

    for (q = ngx_queue_last(&fs->frames);
         q != ngx_queue_sentinel(&fs->frames);
         q = ngx_queue_prev(q))
    {
        item = ngx_queue_data(q, ngx_quic_frame_t, queue);
        f = &item->u.ord;

        if (f->offset < df->offset) {
            ngx_queue_insert_after(q, &dst->queue);
            return NGX_OK;
        }
    }

    ngx_queue_insert_after(&fs->frames, &dst->queue);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_crypto_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *frame)
{
    ngx_quic_connection_t     *qc;
    ngx_quic_frames_stream_t  *fs;

    qc = c->quic;
    fs = &qc->crypto[pkt->level];

    return ngx_quic_handle_ordered_frame(c, fs, frame, ngx_quic_crypto_input);
}


static ngx_int_t
ngx_quic_crypto_input(ngx_connection_t *c, ngx_quic_frame_t *frame)
{
    int                       sslerr;
    ssize_t                   n;
    ngx_ssl_conn_t           *ssl_conn;
    ngx_quic_crypto_frame_t  *f;

    f = &frame->u.crypto;

    ssl_conn = c->ssl->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    if (!SSL_provide_quic_data(ssl_conn, SSL_quic_read_level(ssl_conn),
                               f->data, f->length))
    {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0,
                      "SSL_provide_quic_data() failed");
        return NGX_ERROR;
    }

    n = SSL_do_handshake(ssl_conn);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == -1) {
        sslerr = SSL_get_error(ssl_conn, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);

        if (sslerr != SSL_ERROR_WANT_READ) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "SSL_do_handshake() failed");
            return NGX_ERROR;
        }

    } else if (n == 1 && !SSL_in_init(ssl_conn)) {
        c->quic->state = NGX_QUIC_ST_APPLICATION;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic ssl cipher: %s", SSL_get_cipher(ssl_conn));

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "handshake completed successfully");

#if (NGX_QUIC_DRAFT_VERSION >= 27)
        {
        ngx_quic_frame_t  *frame;

        frame = ngx_quic_alloc_frame(c, 0);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        /* 12.4 Frames and frame types, figure 8 */
        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_HANDSHAKE_DONE;
        ngx_sprintf(frame->info, "HANDSHAKE DONE on handshake completed");
        ngx_quic_queue_frame(c->quic, frame);
        }
#endif

        /*
         * Generating next keys before a key update is received.
         * See quic-tls 9.4 Header Protection Timing Side-Channels.
         */

        if (ngx_quic_key_update(c, &c->quic->keys[ssl_encryption_application],
                                &c->quic->next_key)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_stream_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *frame)
{
    ngx_quic_stream_t         *sn;
    ngx_quic_connection_t     *qc;
    ngx_quic_stream_frame_t   *f;
    ngx_quic_frames_stream_t  *fs;

    qc = c->quic;
    f = &frame->u.stream;

    sn = ngx_quic_find_stream(&qc->streams.tree, f->stream_id);

    if (sn == NULL) {
        sn = ngx_quic_add_stream(c, f);
        if (sn == NULL) {
            return NGX_ERROR;
        }
    }

    fs = &sn->fs;

    return ngx_quic_handle_ordered_frame(c, fs, frame, ngx_quic_stream_input);
}


static ngx_int_t
ngx_quic_stream_input(ngx_connection_t *c, ngx_quic_frame_t *frame)
{
    ngx_buf_t                *b;
    ngx_event_t              *rev;
    ngx_quic_stream_t        *sn;
    ngx_quic_connection_t    *qc;
    ngx_quic_stream_frame_t  *f;

    qc = c->quic;

    f = &frame->u.stream;

    sn = ngx_quic_find_stream(&qc->streams.tree, f->stream_id);

    if (sn == NULL) {
        // TODO: possible?
        // deleted while stream is in reordering queue?
        return NGX_ERROR;
    }

    if (sn->fs.received != 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "existing stream");
        b = sn->b;

        if ((size_t) ((b->pos - b->start) + (b->end - b->last)) < f->length) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "no space in stream buffer");
            return NGX_ERROR;
        }

        if ((size_t) (b->end - b->last) < f->length) {
            b->last = ngx_movemem(b->start, b->pos, b->last - b->pos);
            b->pos = b->start;
        }

        b->last = ngx_cpymem(b->last, f->data, f->length);

        rev = sn->c->read;
        rev->ready = 1;

        if (f->fin) {
            rev->pending_eof = 1;
        }

        if (rev->active) {
            rev->handler(rev);
        }

        /* check if stream was destroyed */
        if (ngx_quic_find_stream(&qc->streams.tree, f->stream_id) == NULL) {
            return NGX_DONE;
        }

        return NGX_OK;
    }

    b = sn->b;
    b->last = ngx_cpymem(b->last, f->data, f->length);

    rev = sn->c->read;
    rev->ready = 1;

    if (f->fin) {
        rev->pending_eof = 1;
    }

    if ((f->stream_id & NGX_QUIC_STREAM_UNIDIRECTIONAL) == 0) {
        ngx_quic_handle_max_streams(c);
    }

    qc->streams.handler(sn->c);

    /* check if stream was destroyed */
    if (ngx_quic_find_stream(&qc->streams.tree, f->stream_id) == NULL) {
        return NGX_DONE;
    }

    return NGX_OK;
}


static ngx_quic_stream_t *
ngx_quic_add_stream(ngx_connection_t *c, ngx_quic_stream_frame_t *f)
{
    size_t                  n;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    // TODO: check increasing IDs

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "stream is new");

    n = (f->stream_id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        ? qc->tp.initial_max_stream_data_uni
        : qc->tp.initial_max_stream_data_bidi_remote;

    if (n < NGX_QUIC_STREAM_BUFSIZE) {
        n = NGX_QUIC_STREAM_BUFSIZE;
    }

    if (n < f->length) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "no space in stream buffer");
        return NULL;
    }

    sn = ngx_quic_create_stream(c, f->stream_id, n);
    if (sn == NULL) {
        return NULL;
    }

    return sn;
}


static ngx_int_t
ngx_quic_handle_max_streams(ngx_connection_t *c)
{
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = c->quic;
    qc->cur_streams++;

    if (qc->cur_streams + NGX_QUIC_STREAMS_INC / 2 < qc->max_streams) {
        return NGX_OK;
    }

    frame = ngx_quic_alloc_frame(c, 0);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    qc->max_streams = ngx_max(qc->max_streams + NGX_QUIC_STREAMS_INC,
                              NGX_QUIC_STREAMS_LIMIT);

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_MAX_STREAMS;
    frame->u.max_streams.limit = qc->max_streams;
    frame->u.max_streams.bidi = 1;

    ngx_sprintf(frame->info, "MAX_STREAMS limit:%d bidi:%d level=%d",
                (int) frame->u.max_streams.limit,
                (int) frame->u.max_streams.bidi,
                frame->level);

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_streams_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_streams_blocked_frame_t *f)
{
    ngx_quic_frame_t  *frame;

    frame = ngx_quic_alloc_frame(c, 0);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = pkt->level;
    frame->type = NGX_QUIC_FT_MAX_STREAMS;
    frame->u.max_streams.limit = ngx_max(f->limit * 2, NGX_QUIC_STREAMS_LIMIT);
    frame->u.max_streams.bidi = f->bidi;

    c->quic->max_streams = frame->u.max_streams.limit;

    ngx_sprintf(frame->info, "MAX_STREAMS limit:%d bidi:%d level=%d",
                (int) frame->u.max_streams.limit,
                (int) frame->u.max_streams.bidi,
                frame->level);

    ngx_quic_queue_frame(c->quic, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_stream_data_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stream_data_blocked_frame_t *f)
{
    size_t                  n;
    ngx_buf_t              *b;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = c->quic;
    sn = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (sn == NULL) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unknown stream id:%uL", f->id);
        return NGX_ERROR;
    }

    b = sn->b;
    n = (b->pos - b->start) + (b->end - b->last);

    frame = ngx_quic_alloc_frame(c, 0);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = pkt->level;
    frame->type = NGX_QUIC_FT_MAX_STREAM_DATA;
    frame->u.max_stream_data.id = f->id;
    frame->u.max_stream_data.limit = n;

    ngx_sprintf(frame->info, "MAX_STREAM_DATA id:%d limit:%d level=%d",
                (int) frame->u.max_stream_data.id,
                (int) frame->u.max_stream_data.limit,
                frame->level);

    ngx_quic_queue_frame(c->quic, frame);

    return NGX_OK;
}


static void
ngx_quic_queue_frame(ngx_quic_connection_t *qc, ngx_quic_frame_t *frame)
{
    ngx_quic_send_ctx_t  *ctx;

    ctx = ngx_quic_get_send_ctx(qc, frame->level);

    ngx_queue_insert_tail(&ctx->frames, &frame->queue);

    /* TODO: check PUSH flag on stream and call output */

    if (!qc->push.timer_set && !qc->closing) {
        ngx_add_timer(&qc->push, qc->tp.max_ack_delay);
    }
}


static ngx_int_t
ngx_quic_output(ngx_connection_t *c)
{
    ngx_uint_t              i;
    ngx_quic_connection_t  *qc;

    c->log->action = "sending frames";

    qc = c->quic;

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        if (ngx_quic_output_frames(c, &qc->send_ctx[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (!qc->send_timer_set && !qc->closing) {
        qc->send_timer_set = 1;
        ngx_add_timer(c->read, qc->tp.max_idle_timeout);
    }

    if (!qc->retry.timer_set && !qc->closing) {
        ngx_add_timer(&qc->retry, qc->tp.max_ack_delay);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_output_frames(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    size_t                  len, hlen, n;
    ngx_int_t               rc;
    ngx_queue_t            *q, range;
    ngx_quic_frame_t       *f;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (ngx_queue_empty(&ctx->frames)) {
        return NGX_OK;
    }

    q = ngx_queue_head(&ctx->frames);
    f = ngx_queue_data(q, ngx_quic_frame_t, queue);

    /* all frames in same send_ctx share same level */
    hlen = (f->level == ssl_encryption_application) ? NGX_QUIC_MAX_SHORT_HEADER
                                                    : NGX_QUIC_MAX_LONG_HEADER;
    hlen += EVP_GCM_TLS_TAG_LEN;

    do {
        len = 0;
        ngx_queue_init(&range);

        do {
            /* process group of frames that fits into packet */
            f = ngx_queue_data(q, ngx_quic_frame_t, queue);

            n = ngx_quic_create_frame(NULL, f);

            if (len && hlen + len + n > qc->ctp.max_packet_size) {
                break;
            }

            q = ngx_queue_next(q);

            f->first = ngx_current_msec;

            ngx_queue_remove(&f->queue);
            ngx_queue_insert_tail(&range, &f->queue);

            len += n;

        } while (q != ngx_queue_sentinel(&ctx->frames));

        rc = ngx_quic_send_frames(c, &range);

        if (rc == NGX_OK) {
            /*
             * frames are moved into the sent queue
             * to wait for ack/be retransmitted
            */
            ngx_queue_add(&ctx->sent, &range);

        } else if (rc == NGX_DONE) {

            /* no ack is expected for this frames, can free them */
            ngx_quic_free_frames(c, &range);

        } else {
            return NGX_ERROR;
        }

    } while (q != ngx_queue_sentinel(&ctx->frames));

    return NGX_OK;
}


static void
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


/* pack a group of frames [start; end) into memory p and send as single packet */
static ngx_int_t
ngx_quic_send_frames(ngx_connection_t *c, ngx_queue_t *frames)
{
    ssize_t                 len;
    u_char                 *p;
    ngx_msec_t              now;
    ngx_str_t               out, res;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f, *start;
    ngx_quic_header_t       pkt;
    ngx_quic_secrets_t     *keys;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;
    static ngx_str_t        initial_token = ngx_null_string;
    static u_char           src[NGX_QUIC_DEFAULT_MAX_PACKET_SIZE];
    static u_char           dst[NGX_QUIC_DEFAULT_MAX_PACKET_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_quic_send_frames");

    q = ngx_queue_head(frames);
    start = ngx_queue_data(q, ngx_quic_frame_t, queue);

    ctx = ngx_quic_get_send_ctx(c->quic, start->level);

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    p = src;
    out.data = src;

    for (q = ngx_queue_head(frames);
         q != ngx_queue_sentinel(frames);
         q = ngx_queue_next(q))
    {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "frame: %s", f->info);

        len = ngx_quic_create_frame(p, f);
        if (len == -1) {
            return NGX_ERROR;
        }

        if (f->need_ack) {
            pkt.need_ack = 1;
        }

        p += len;
        f->pnum = ctx->pnum;
    }

    if (start->level == ssl_encryption_initial) {
        /* ack will not be sent in initial packets due to initial keys being
         * discarded when handshake start.
         * Thus consider initial packets as non-ack-eliciting
         */
        pkt.need_ack = 0;
    }

    out.len = p - out.data;

    while (out.len < 4) {
        *p++ = NGX_QUIC_FT_PADDING;
        out.len++;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "packet ready: %ui bytes at level %d need_ack: %ui",
                   out.len, start->level, pkt.need_ack);

    qc = c->quic;

    keys = &c->quic->keys[start->level];

    pkt.secret = &keys->server;

    if (start->level == ssl_encryption_initial) {
        pkt.flags = NGX_QUIC_PKT_INITIAL;
        pkt.token = initial_token;

    } else if (start->level == ssl_encryption_handshake) {
        pkt.flags = NGX_QUIC_PKT_HANDSHAKE;

    } else {
        // TODO: macro, set FIXED bit
        pkt.flags = 0x40 | (c->quic->key_phase ? NGX_QUIC_PKT_KPHASE : 0);
    }

    ngx_quic_set_packet_number(&pkt, ctx);

    pkt.log = c->log;
    pkt.level = start->level;
    pkt.dcid = qc->dcid;
    pkt.scid = qc->scid;
    pkt.payload = out;

    res.data = dst;

    if (ngx_quic_encrypt(&pkt, c->ssl->connection, &res) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(c->log, "packet to send", res.data, res.len);

    len = c->send(c, res.data, res.len);
    if (len == NGX_ERROR || (size_t) len != res.len) {
        return NGX_ERROR;
    }

    /* len == NGX_OK || NGX_AGAIN */
    ctx->pnum++;

    now = ngx_current_msec;
    start->last = now;

    return pkt.need_ack ? NGX_OK : NGX_DONE;
}


static void
ngx_quic_set_packet_number(ngx_quic_header_t *pkt, ngx_quic_send_ctx_t *ctx)
{
    uint64_t  delta;

    delta = ctx->pnum - ctx->largest_ack;
    pkt->number = ctx->pnum;

    if (delta <= 0x7F) {
        pkt->num_len = 1;
        pkt->trunc = ctx->pnum & 0xff;

    } else if (delta <= 0x7FFF) {
        pkt->num_len = 2;
        pkt->flags |= 0x1;
        pkt->trunc = ctx->pnum & 0xffff;

    } else if (delta <= 0x7FFFFF) {
        pkt->num_len = 3;
        pkt->flags |= 0x2;
        pkt->trunc = ctx->pnum & 0xffffff;

    } else {
        pkt->num_len = 4;
        pkt->flags |= 0x3;
        pkt->trunc = ctx->pnum & 0xffffffff;
    }
}


static void
ngx_quic_retransmit_handler(ngx_event_t *ev)
{
    ngx_uint_t              i;
    ngx_msec_t              wait, nswait;
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "retransmit timer");

    c = ev->data;
    qc = c->quic;

    wait = 0;

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        if (ngx_quic_retransmit(c, &qc->send_ctx[i], &nswait) != NGX_OK) {
            ngx_quic_close_connection(c);
            return;
        }

        if (i == 0) {
            wait = nswait;

        } else if (nswait > 0 && nswait < wait) {
            wait = nswait;
        }
    }

    if (wait > 0) {
        ngx_add_timer(&qc->retry, wait);
    }
}


static void
ngx_quic_push_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "push timer");

    c = ev->data;

    if (ngx_quic_output(c) != NGX_OK) {
        ngx_quic_close_connection(c);
        return;
    }
}


static ngx_int_t
ngx_quic_retransmit(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    ngx_msec_t *waitp)
{
    uint64_t                pn;
    ngx_msec_t              now, wait;
    ngx_queue_t            *q, range;
    ngx_quic_frame_t       *f, *start;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    now = ngx_current_msec;
    wait = 0;

    if (ngx_queue_empty(&ctx->sent)) {
        *waitp = 0;
        return NGX_OK;
    }

    q = ngx_queue_head(&ctx->sent);
    start = ngx_queue_data(q, ngx_quic_frame_t, queue);
    pn = start->pnum;
    f = start;

    do {
        ngx_queue_init(&range);

        /* send frames with same packet number to the wire */
        do {
            f = ngx_queue_data(q, ngx_quic_frame_t, queue);

            if (start->first + qc->tp.max_idle_timeout < now) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "retransmission timeout");
                return NGX_DECLINED;
            }

            if (f->pnum != pn) {
                break;
            }

            q = ngx_queue_next(q);

            ngx_queue_remove(&f->queue);
            ngx_queue_insert_tail(&range, &f->queue);

        } while (q != ngx_queue_sentinel(&ctx->sent));

        wait = start->last + qc->tp.max_ack_delay - now;

        if ((ngx_msec_int_t) wait > 0) {
            break;
        }

        /* NGX_DONE is impossible here, such frames don't get into this queue */
        if (ngx_quic_send_frames(c, &range) != NGX_OK) {
            return NGX_ERROR;
        }

        /* move frames group to the end of queue */
        ngx_queue_add(&ctx->sent, &range);

    } while (q != ngx_queue_sentinel(&ctx->sent));

    *waitp = wait;

    return NGX_OK;
}


ngx_connection_t *
ngx_quic_create_uni_stream(ngx_connection_t *c)
{
    ngx_uint_t              id;
    ngx_quic_stream_t      *qs, *sn;
    ngx_quic_connection_t  *qc;

    qs = c->qs;
    qc = qs->parent->quic;

    id = (qc->streams.id_counter << 2)
         | NGX_QUIC_STREAM_SERVER_INITIATED
         | NGX_QUIC_STREAM_UNIDIRECTIONAL;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "creating server uni stream #%ui id %ui",
                   qc->streams.id_counter, id);

    qc->streams.id_counter++;

    sn = ngx_quic_create_stream(qs->parent, id, 0);
    if (sn == NULL) {
        return NULL;
    }

    return sn->c;
}


static void
ngx_quic_rbtree_insert_stream(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;
    ngx_quic_stream_t   *qn, *qnt;

    for ( ;; ) {
        qn = (ngx_quic_stream_t *) node;
        qnt = (ngx_quic_stream_t *) temp;

        p = (qn->id < qnt->id) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_quic_stream_t *
ngx_quic_find_stream(ngx_rbtree_t *rbtree, uint64_t id)
{
    ngx_rbtree_node_t  *node, *sentinel;
    ngx_quic_stream_t  *qn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {
        qn = (ngx_quic_stream_t *) node;

        if (id == qn->id) {
            return qn;
        }

        node = (id < qn->id) ? node->left : node->right;
    }

    return NULL;
}


static ngx_quic_stream_t *
ngx_quic_create_stream(ngx_connection_t *c, uint64_t id, size_t rcvbuf_size)
{
    ngx_log_t           *log;
    ngx_pool_t          *pool;
    ngx_quic_stream_t   *sn;
    ngx_pool_cleanup_t  *cln;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, c->log);
    if (pool == NULL) {
        return NULL;
    }

    sn = ngx_pcalloc(pool, sizeof(ngx_quic_stream_t));
    if (sn == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    sn->node.key = id;
    sn->parent = c;
    sn->id = id;

    sn->b = ngx_create_temp_buf(pool, rcvbuf_size);
    if (sn->b == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ngx_queue_init(&sn->fs.frames);

    log = ngx_palloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    *log = *c->log;
    pool->log = log;

    sn->c = ngx_get_connection(-1, log);
    if (sn->c == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    sn->c->qs = sn;
    sn->c->pool = pool;
    sn->c->ssl = c->ssl;
    sn->c->sockaddr = c->sockaddr;
    sn->c->listening = c->listening;
    sn->c->addr_text = c->addr_text;
    sn->c->local_sockaddr = c->local_sockaddr;
    sn->c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    sn->c->recv = ngx_quic_stream_recv;
    sn->c->send = ngx_quic_stream_send;
    sn->c->send_chain = ngx_quic_stream_send_chain;

    sn->c->read->log = c->log;
    sn->c->write->log = c->log;

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        ngx_close_connection(sn->c);
        ngx_destroy_pool(pool);
        return NULL;
    }

    cln->handler = ngx_quic_stream_cleanup_handler;
    cln->data = sn->c;

    ngx_rbtree_insert(&c->quic->streams.tree, &sn->node);

    return sn;
}


static ssize_t
ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t             len;
    ngx_buf_t          *b;
    ngx_event_t        *rev;
    ngx_quic_stream_t  *qs;

    qs = c->qs;
    b = qs->b;
    rev = c->read;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic recv: eof:%d, avail:%z",
                   rev->pending_eof, b->last - b->pos);

    if (b->pos == b->last) {
        rev->ready = 0;

        if (rev->pending_eof) {
            rev->eof = 1;
            return 0;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic recv() not ready");
        return NGX_AGAIN;
    }

    len = ngx_min(b->last - b->pos, (ssize_t) size);

    ngx_memcpy(buf, b->pos, len);

    b->pos += len;

    if (b->pos == b->last) {
        b->pos = b->start;
        b->last = b->start;
        rev->ready = rev->pending_eof;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic recv: %z of %uz", len, size);

    return len;
}


static ssize_t
ngx_quic_stream_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->qs;
    pc = qs->parent;
    qc = pc->quic;

    if (qc->closing) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic send: %uz", size);

    frame = ngx_quic_alloc_frame(pc, size);
    if (frame == NULL) {
        return 0;
    }

    ngx_memcpy(frame->data, buf, size);

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STREAM6; /* OFF=1 LEN=1 FIN=0 */
    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = 0;

    frame->u.stream.type = frame->type;
    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = c->sent;
    frame->u.stream.length = size;
    frame->u.stream.data = frame->data;

    c->sent += size;

    ngx_sprintf(frame->info, "stream %xi len=%ui level=%d",
                qs->id, size, frame->level);

    ngx_quic_queue_frame(qc, frame);

    return size;
}


static void
ngx_quic_stream_cleanup_handler(void *data)
{
    ngx_connection_t *c = data;

    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->qs;
    pc = qs->parent;
    qc = pc->quic;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic stream cleanup");

    ngx_rbtree_delete(&qc->streams.tree, &qs->node);

    if (qc->closing) {
        ngx_post_event(pc->read, &ngx_posted_events);
        return;
    }

    ngx_quic_free_frames(pc, &qs->fs.frames);

    if ((qs->id & 0x03) == NGX_QUIC_STREAM_UNIDIRECTIONAL) {
        /* do not send fin for client unidirectional streams */
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic send fin");

    frame = ngx_quic_alloc_frame(pc, 0);
    if (frame == NULL) {
        return;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STREAM7; /* OFF=1 LEN=1 FIN=1 */
    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = 1;

    frame->u.stream.type = frame->type;
    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = c->sent;
    frame->u.stream.length = 0;
    frame->u.stream.data = NULL;

    ngx_sprintf(frame->info, "stream %xi fin=1 level=%d", qs->id, frame->level);

    ngx_quic_queue_frame(qc, frame);

    (void) ngx_quic_output(pc);
}


static ngx_chain_t *
ngx_quic_stream_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit)
{
    size_t      len;
    ssize_t     n;
    ngx_buf_t  *b;

    for ( /* void */; in; in = in->next) {
        b = in->buf;

        if (!ngx_buf_in_memory(b)) {
            continue;
        }

        if (ngx_buf_size(b) == 0) {
            continue;
        }

        len = b->last - b->pos;

        n = ngx_quic_stream_send(c, b->pos, len);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            return in;
        }

        if (n != (ssize_t) len) {
            b->pos += n;
            return in;
        }
    }

    return NULL;
}


static ngx_quic_frame_t *
ngx_quic_alloc_frame(ngx_connection_t *c, size_t size)
{
    u_char                 *p;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    if (size) {
        p = ngx_alloc(size, c->log);
        if (p == NULL) {
            return NULL;
        }

    } else {
        p = NULL;
    }

    qc = c->quic;

    if (!ngx_queue_empty(&qc->free_frames)) {

        q = ngx_queue_head(&qc->free_frames);
        frame = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_queue_remove(&frame->queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "reuse quic frame n:%ui", qc->nframes);

    } else {
        frame = ngx_pcalloc(c->pool, sizeof(ngx_quic_frame_t));
        if (frame == NULL) {
            ngx_free(p);
            return NULL;
        }

#if (NGX_DEBUG)
        ++qc->nframes;
#endif

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "alloc quic frame n:%ui", qc->nframes);
    }

    ngx_memzero(frame, sizeof(ngx_quic_frame_t));

    frame->data = p;

    return frame;
}


static void
ngx_quic_free_frame(ngx_connection_t *c, ngx_quic_frame_t *frame)
{
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (frame->data) {
        ngx_free(frame->data);
    }

    ngx_queue_insert_head(&qc->free_frames, &frame->queue);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "free quic frame n:%ui", qc->nframes);
}
