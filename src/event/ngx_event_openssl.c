
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct {
    ngx_str_t  engine;
} ngx_openssl_conf_t;


static void ngx_ssl_handshake_handler(ngx_event_t *ev);
static ngx_int_t ngx_ssl_handle_recv(ngx_connection_t *c, int n);
static void ngx_ssl_write_handler(ngx_event_t *wev);
static void ngx_ssl_read_handler(ngx_event_t *rev);
static void ngx_ssl_shutdown_handler(ngx_event_t *ev);
static void ngx_ssl_connection_error(ngx_connection_t *c, int sslerr,
    ngx_err_t err, char *text);
static void *ngx_openssl_create_conf(ngx_cycle_t *cycle);
static char *ngx_openssl_init_conf(ngx_cycle_t *cycle, void *conf);
static void ngx_openssl_exit(ngx_cycle_t *cycle);

#if !(NGX_SSL_ENGINE)
static char *ngx_openssl_noengine(ngx_conf_t *cf, ngx_command_t *cmd,
     void *conf);
#endif


static ngx_command_t  ngx_openssl_commands[] = {

    { ngx_string("ssl_engine"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
#if (NGX_SSL_ENGINE)
      ngx_conf_set_str_slot,
#else
      ngx_openssl_noengine,
#endif
      0,
      offsetof(ngx_openssl_conf_t, engine),
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_openssl_module_ctx = {
    ngx_string("openssl"),
    ngx_openssl_create_conf,
    ngx_openssl_init_conf
};


ngx_module_t  ngx_openssl_module = {
    NGX_MODULE_V1,
    &ngx_openssl_module_ctx,               /* module context */
    ngx_openssl_commands,                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    ngx_openssl_exit,                      /* exit master */
    NGX_MODULE_V1_PADDING
};


static long  ngx_ssl_protocols[] = {
    SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1,
    SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1,
    SSL_OP_NO_SSLv2|SSL_OP_NO_TLSv1,
    SSL_OP_NO_TLSv1,
    SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3,
    SSL_OP_NO_SSLv3,
    SSL_OP_NO_SSLv2,
    0,
};


ngx_int_t
ngx_ssl_init(ngx_log_t *log)
{
    SSL_library_init();
    SSL_load_error_strings();

#if (NGX_SSL_ENGINE)
    ENGINE_load_builtin_engines();
#endif

    return NGX_OK;
}


ngx_int_t
ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols)
{
    ssl->ctx = SSL_CTX_new(SSLv23_method());

    if (ssl->ctx == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "SSL_CTX_new() failed");
        return NGX_ERROR;
    }

    /* client side options */

    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG);

    /* server side options */

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);

    /* this option allow a potential SSL 2.0 rollback (CAN-2005-2969) */
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MSIE_SSLV2_RSA_PADDING);

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_D5_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ssl->ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif


    if (ngx_ssl_protocols[protocols >> 1] != 0) {
        SSL_CTX_set_options(ssl->ctx, ngx_ssl_protocols[protocols >> 1]);
    }

    SSL_CTX_set_mode(ssl->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    SSL_CTX_set_read_ahead(ssl->ctx, 1);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_str_t *key)
{
    if (ngx_conf_full_name(cf->cycle, cert) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (SSL_CTX_use_certificate_chain_file(ssl->ctx, (char *) cert->data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_certificate_chain_file(\"%s\") failed",
                      cert->data);
        return NGX_ERROR;
    }

    if (ngx_conf_full_name(cf->cycle, key) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl->ctx, (char *) key->data,
                                    SSL_FILETYPE_PEM) == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_PrivateKey_file(\"%s\") failed", key->data);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_generate_rsa512_key(ngx_ssl_t *ssl)
{
    if (SSL_CTX_need_tmp_RSA(ssl->ctx) == 0) {
        return NGX_OK;
    }

    ssl->rsa512_key = RSA_generate_key(512, RSA_F4, NULL, NULL);

    if (ssl->rsa512_key) {
        SSL_CTX_set_tmp_rsa(ssl->ctx, ssl->rsa512_key);
        return NGX_OK;
    }

    ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "RSA_generate_key(512) failed");

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c, ngx_uint_t flags)
{
    ngx_ssl_connection_t  *sc;

    sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
    if (sc == NULL) {
        return NGX_ERROR;
    }

    if (flags & NGX_SSL_BUFFER) {
        sc->buffer = 1;

        sc->buf = ngx_create_temp_buf(c->pool, NGX_SSL_BUFSIZE);
        if (sc->buf == NULL) {
            return NGX_ERROR;
        }
    }

    sc->connection = SSL_new(ssl->ctx);

    if (sc->connection == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_new() failed");
        return NGX_ERROR;
    }

    if (SSL_set_fd(sc->connection, c->fd) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_fd() failed");
        return NGX_ERROR;
    }

    if (flags & NGX_SSL_CLIENT) {
        SSL_set_connect_state(sc->connection);

    } else {
        SSL_set_accept_state(sc->connection);
    }

    c->ssl = sc;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session)
{
    if (session) {
        if (SSL_set_session(c->ssl->connection, session) == 0) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_session() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_handshake(ngx_connection_t *c)
{
    int        n, sslerr;
    ngx_err_t  err;

    n = SSL_do_handshake(c->ssl->connection);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == 1) {

        if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

#if (NGX_DEBUG)
        {
        char         buf[129], *s, *d;
        SSL_CIPHER  *cipher;

        cipher = SSL_get_current_cipher(c->ssl->connection);

        if (cipher) {
            SSL_CIPHER_description(cipher, &buf[1], 128);

            for (s = &buf[1], d = buf; *s; s++) {
                if (*s == ' ' && *d == ' ') {
                    continue;
                }

                if (*s == LF || *s == CR) {
                    continue;
                }

                *++d = *s;
            }

            if (*d != ' ') {
                d++;
            }

            *d = '\0';

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL: %s, cipher: \"%s\"",
                           SSL_get_version(c->ssl->connection), &buf[1]);

            if (SSL_session_reused(c->ssl->connection)) {
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "SSL reused session");
            }

        } else {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL no shared ciphers");
        }
        }
#endif

        c->ssl->handshaked = 1;

        c->recv = ngx_ssl_recv;
        c->send = ngx_ssl_write;
        c->recv_chain = ngx_ssl_recv_chain;
        c->send_chain = ngx_ssl_send_chain;

        return NGX_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {
        c->read->ready = 0;
        c->read->handler = ngx_ssl_handshake_handler;

        if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        c->write->handler = ngx_ssl_handshake_handler;

        if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, err,
                      "peer closed connection in SSL handshake");

        return NGX_ERROR;
    }

    ngx_ssl_connection_error(c, sslerr, err, "SSL_do_handshake() failed");

    return NGX_ERROR;
}


static void
ngx_ssl_handshake_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL handshake handler: %d", ev->write);

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {
        return;
    }

    c->ssl->handler(c);
}


ssize_t
ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl)
{
    ssize_t     n, bytes;
    ngx_buf_t  *b;

    bytes = 0;

    while (cl) {
        b = cl->buf;

        n = ngx_ssl_recv(c, b->last, b->end - b->last);

        if (n > 0) {
            b->last += n;
            bytes += n;

            if (b->last == b->end) {
                cl = cl->next;
            }

            continue;
        }

        if (bytes) {
            return bytes;
        }

        return n;
    }

    return bytes;
}


ssize_t
ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int  n, bytes;

    if (c->ssl->last == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (c->ssl->last == NGX_DONE) {
        return 0;
    }

    bytes = 0;

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    for ( ;; ) {

        n = SSL_read(c->ssl->connection, buf, size);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_read: %d", n);

        if (n > 0) {
            bytes += n;
        }

        c->ssl->last = ngx_ssl_handle_recv(c, n);

        if (c->ssl->last != NGX_OK) {

            if (bytes) {
                return bytes;
            }

            if (c->ssl->last == NGX_DONE) {
                return 0;
            }

            return c->ssl->last;
        }

        size -= n;

        if (size == 0) {
            return bytes;
        }

        buf += n;
    }
}


static ngx_int_t
ngx_ssl_handle_recv(ngx_connection_t *c, int n)
{
    int        sslerr;
    ngx_err_t  err;

    if (n > 0) {

        if (c->ssl->saved_write_handler) {

            c->write->handler = c->ssl->saved_write_handler;
            c->ssl->saved_write_handler = NULL;
            c->write->ready = 1;

            if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            ngx_post_event(c->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {
        c->read->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "peer started SSL renegotiation");

        c->write->ready = 0;

        if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already the read event timer
         */

        if (c->ssl->saved_write_handler == NULL) {
            c->ssl->saved_write_handler = c->write->handler;
            c->write->handler = ngx_ssl_write_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "peer shutdown SSL cleanly");
        return NGX_DONE;
    }

    ngx_ssl_connection_error(c, sslerr, err, "SSL_read() failed");

    return NGX_ERROR;
}


static void
ngx_ssl_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *c;

    c = wev->data;

    c->read->handler(c->read);
}


/*
 * OpenSSL has no SSL_writev() so we copy several bufs into our 16K buffer
 * before the SSL_write() call to decrease a SSL overhead.
 *
 * Besides for protocols such as HTTP it is possible to always buffer
 * the output to decrease a SSL overhead some more.
 */

ngx_chain_t *
ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int          n;
    ngx_uint_t   flush;
    ssize_t      send, size;
    ngx_buf_t   *buf;

    if (!c->ssl->buffer || (in && in->next == NULL && !c->buffered)) {

        /*
         * we avoid a buffer copy if
         *     we do not need to buffer the output
         *     or the incoming buf is a single and our buffer is empty
         */

        while (in) {
            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            n = ngx_ssl_write(c, in->buf->pos, in->buf->last - in->buf->pos);

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            if (n == NGX_AGAIN) {
                c->buffered = 1;
                return in;
            }

            in->buf->pos += n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        return in;
    }


    /* the maximum limit size is the maximum uint32_t value - the page size */

    if (limit == 0 || limit > NGX_MAX_UINT32_VALUE - ngx_pagesize) {
        limit = NGX_MAX_UINT32_VALUE - ngx_pagesize;
    }


    buf = c->ssl->buf;
    send = 0;
    flush = (in == NULL) ? 1 : 0;

    for ( ;; ) {

        while (in && buf->last < buf->end) {
            if (in->buf->last_buf) {
                flush = 1;
            }

            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            size = in->buf->last - in->buf->pos;

            if (size > buf->end - buf->last) {
                size = buf->end - buf->last;
            }

            /*
             * TODO: the taking in->buf->flush into account can be
             *       implemented using the limit on the higher level
             */

            if (send + size > limit) {
                size = (ssize_t) (limit - send);
                flush = 1;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL buf copy: %d", size);

            ngx_memcpy(buf->last, in->buf->pos, size);

            buf->last += size;

            in->buf->pos += size;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        size = buf->last - buf->pos;

        if (!flush && buf->last < buf->end && c->ssl->buffer) {
            break;
        }

        n = ngx_ssl_write(c, buf->pos, size);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            c->buffered = 1;
            return in;
        }

        buf->pos += n;
        send += n;
        c->sent += n;

        if (n < size) {
            break;
        }

        if (buf->pos == buf->last) {
            buf->pos = buf->start;
            buf->last = buf->start;
        }

        if (in == NULL || send == limit) {
            break;
        }
    }

    c->buffered = (buf->pos < buf->last) ? 1 : 0;

    return in;
}


ssize_t
ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size)
{
    int        n, sslerr;
    ngx_err_t  err;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %d", size);

    n = SSL_write(c->ssl->connection, data, size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_write: %d", n);

    if (n > 0) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            ngx_post_event(c->read, &ngx_posted_events);
        }

        return n;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "peer started SSL renegotiation");

        c->read->ready = 0;

        if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = ngx_ssl_read_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;

    ngx_ssl_connection_error(c, sslerr, err, "SSL_write() failed");

    return NGX_ERROR;
}


static void
ngx_ssl_read_handler(ngx_event_t *rev)
{
    ngx_connection_t  *c;

    c = rev->data;

    c->write->handler(c->write);
}


ngx_int_t
ngx_ssl_shutdown(ngx_connection_t *c)
{
    int         n, sslerr, mode;
    ngx_uint_t  again;

    if (c->timedout) {
        mode = SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN;

    } else {
        mode = SSL_get_shutdown(c->ssl->connection);

        if (c->ssl->no_wait_shutdown) {
            mode |= SSL_RECEIVED_SHUTDOWN;
        }

        if (c->ssl->no_send_shutdown) {
            mode |= SSL_SENT_SHUTDOWN;
        }
    }

    SSL_set_shutdown(c->ssl->connection, mode);

    again = 0;
#if (NGX_SUPPRESS_WARN)
    sslerr = 0;
#endif

    for ( ;; ) {
        n = SSL_shutdown(c->ssl->connection);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_shutdown: %d", n);

        if (n == 1 || (n == 0 && c->timedout)) {
            SSL_free(c->ssl->connection);
            c->ssl = NULL;

            return NGX_OK;
        }

        if (n == 0) {
            again = 1;
            break;
        }

        break;
    }

    if (!again) {
        sslerr = SSL_get_error(c->ssl->connection, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_get_error: %d", sslerr);
    }

    if (again || sslerr == SSL_ERROR_WANT_READ) {

        ngx_add_timer(c->read, 30000);

        c->read->handler = ngx_ssl_shutdown_handler;

        if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        c->write->handler = ngx_ssl_shutdown_handler;

        if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_shutdown() failed");

    SSL_free(c->ssl->connection);
    c->ssl = NULL;

    return NGX_ERROR;
}


static void
ngx_ssl_shutdown_handler(ngx_event_t *ev)
{
    ngx_connection_t           *c;
    ngx_connection_handler_pt   handler;

    c = ev->data;
    handler = c->ssl->handler;

    if (ev->timedout) {
        c->timedout = 1;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "SSL shutdown handler");

    if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
        return;
    }

    handler(c);
}


static void
ngx_ssl_connection_error(ngx_connection_t *c, int sslerr, ngx_err_t err,
    char *text)
{
    ngx_uint_t  level;

    level = NGX_LOG_CRIT;

    if (sslerr == SSL_ERROR_SYSCALL) {

        if (err == NGX_ECONNRESET
            || err == NGX_EPIPE
            || err == NGX_ENOTCONN
            || err == NGX_ECONNREFUSED
            || err == NGX_EHOSTUNREACH)
        {
            switch (c->log_error) {

            case NGX_ERROR_IGNORE_ECONNRESET:
            case NGX_ERROR_INFO:
                level = NGX_LOG_INFO;
                break;

            case NGX_ERROR_ERR:
                level = NGX_LOG_ERR;
                break;

            default:
                break;
            }
        }
    }

    ngx_ssl_error(level, c->log, err, text);
}


void
ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, char *fmt, ...)
{
    u_long   n;
    va_list  args;
    u_char   errstr[NGX_MAX_CONF_ERRSTR], *p, *last;

    last = errstr + NGX_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = ngx_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
    va_end(args);

    p = ngx_cpystrn(p, (u_char *) " (SSL:", last - p);

    while (p < last && (n = ERR_get_error())) {

        *p++ = ' ';

        ERR_error_string_n(n, (char *) p, last - p);

        while (p < last && *p) {
            p++;
        }
    }

    ngx_log_error(level, log, err, "%s)", errstr);
}


void
ngx_ssl_cleanup_ctx(void *data)
{
   ngx_ssl_t  *ssl = data;

   if (ssl->rsa512_key) {
       RSA_free(ssl->rsa512_key);
   }

   SSL_CTX_free(ssl->ctx);
}


static void *
ngx_openssl_create_conf(ngx_cycle_t *cycle)
{
    ngx_openssl_conf_t  *oscf;

    oscf = ngx_pcalloc(cycle->pool, sizeof(ngx_openssl_conf_t));
    if (oscf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     oscf->engine.len = 0;
     *     oscf->engine.data = NULL;
     */

    return oscf;
}


static char *
ngx_openssl_init_conf(ngx_cycle_t *cycle, void *conf)
{
#if (NGX_SSL_ENGINE)
    ngx_openssl_conf_t *oscf = conf;

    ENGINE  *engine;

    if (oscf->engine.len == 0) {
        return NGX_CONF_OK;
    }

    engine = ENGINE_by_id((const char *) oscf->engine.data);

    if (engine == NULL) {
        ngx_ssl_error(NGX_LOG_WARN, cycle->log, 0,
                      "ENGINE_by_id(\"%V\") failed", &oscf->engine);
        return NGX_CONF_ERROR;
    }

    if (ENGINE_set_default(engine, ENGINE_METHOD_ALL) == 0) {
        ngx_ssl_error(NGX_LOG_WARN, cycle->log, 0,
                      "ENGINE_set_default(\"%V\", ENGINE_METHOD_ALL) failed",
                      &oscf->engine);
        return NGX_CONF_ERROR;
    }

    ENGINE_free(engine);

#endif

    return NGX_CONF_OK;
}


#if !(NGX_SSL_ENGINE)

static char *
ngx_openssl_noengine(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"ssl_engine\" directive is available only in "
                       "OpenSSL 0.9.7 and higher,");

    return NGX_CONF_ERROR;
}

#endif


static void
ngx_openssl_exit(ngx_cycle_t *cycle)
{
#if (NGX_SSL_ENGINE)
    ENGINE_cleanup();
#endif
}
