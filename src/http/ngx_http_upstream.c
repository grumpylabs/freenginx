
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_upstream_rd_check_broken_connection(ngx_http_request_t *r);
static void ngx_http_upstream_wr_check_broken_connection(ngx_http_request_t *r);
static void ngx_http_upstream_check_broken_connection(ngx_http_request_t *r,
    ngx_event_t *ev);
static void ngx_http_upstream_connect(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_reinit(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_send_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_send_request_handler(ngx_event_t *wev);
static void ngx_http_upstream_process_header(ngx_event_t *rev);
static void ngx_http_upstream_send_response(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void
    ngx_http_upstream_process_non_buffered_downstream(ngx_http_request_t *r);
static void ngx_http_upstream_process_non_buffered_body(ngx_event_t *ev);
static ngx_int_t ngx_http_upstream_non_buffered_filter_init(void *data);
static ngx_int_t ngx_http_upstream_non_buffered_filter(void *data,
    ssize_t bytes);
static void ngx_http_upstream_process_downstream(ngx_http_request_t *r);
static void ngx_http_upstream_process_body(ngx_event_t *ev);
static void ngx_http_upstream_dummy_handler(ngx_event_t *wev);
static void ngx_http_upstream_next(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_uint_t ft_type);
static void ngx_http_upstream_cleanup(void *data);
static void ngx_http_upstream_finalize_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_int_t rc);

static ngx_int_t ngx_http_upstream_process_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t
    ngx_http_upstream_process_multi_header_lines(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_ignore_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_limit_rate(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_copy_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t
    ngx_http_upstream_conditional_copy_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t
    ngx_http_upstream_copy_multi_header_lines(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_copy_content_type(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_copy_content_length(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_rewrite_location(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_rewrite_refresh(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
#if (NGX_HTTP_GZIP)
static ngx_int_t ngx_http_upstream_copy_content_encoding(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
#endif

static size_t ngx_http_upstream_log_status_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_upstream_log_status(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);
static size_t ngx_http_upstream_log_response_time_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_upstream_log_response_time(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);

static u_char *ngx_http_upstream_log_error(ngx_http_request_t *r, u_char *buf,
    size_t len);

static ngx_int_t ngx_http_upstream_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_response_time_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_upstream_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_core_init_main_conf(ngx_conf_t *cf, void *conf);

#if (NGX_HTTP_SSL)
static void ngx_http_upstream_ssl_init_connection(ngx_http_request_t *,
    ngx_http_upstream_t *u, ngx_connection_t *c);
static void ngx_http_upstream_ssl_handshake(ngx_connection_t *c);
static void ngx_http_upstream_ssl_shutdown(ngx_connection_t *c,
    ngx_peer_t *peer);
#endif


ngx_http_upstream_header_t  ngx_http_upstream_headers_in[] = {

    { ngx_string("Status"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, status),
                 /* STUB */ ngx_http_upstream_ignore_header_line, 0, 0 },

    { ngx_string("Content-Type"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, content_type),
                 ngx_http_upstream_copy_content_type, 0, 0 },

    { ngx_string("Content-Length"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, content_length),
                 ngx_http_upstream_copy_content_length, 0, 0 },

    { ngx_string("Date"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, date),
                 ngx_http_upstream_conditional_copy_header_line,
                 offsetof(ngx_http_upstream_conf_t, pass_date), 0 },

    { ngx_string("Server"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, server),
                 ngx_http_upstream_conditional_copy_header_line,
                 offsetof(ngx_http_upstream_conf_t, pass_server), 0 },

    { ngx_string("WWW-Authenticate"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, www_authenticate),
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("Location"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_rewrite_location, 0, 0 },

    { ngx_string("Refresh"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_rewrite_refresh, 0, 0 },

    { ngx_string("Set-Cookie"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_copy_header_line, 0, 1 },

    { ngx_string("Content-Disposition"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_copy_header_line, 0, 1 },

    { ngx_string("Cache-Control"),
                 ngx_http_upstream_process_multi_header_lines,
                 offsetof(ngx_http_upstream_headers_in_t, cache_control),
                 ngx_http_upstream_copy_multi_header_lines,
                 offsetof(ngx_http_headers_out_t, cache_control), 1 },

    { ngx_string("Expires"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, expires),
                 ngx_http_upstream_copy_header_line,
                 offsetof(ngx_http_headers_out_t, expires), 1 },

    { ngx_string("Accept-Ranges"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, accept_ranges),
                 ngx_http_upstream_copy_header_line,
                 offsetof(ngx_http_headers_out_t, accept_ranges), 1 },

    { ngx_string("Connection"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_ignore_header_line, 0, 0 },

    { ngx_string("X-Pad"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_ignore_header_line, 0, 0 },

    { ngx_string("X-Powered-By"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_conditional_copy_header_line,
                 offsetof(ngx_http_upstream_conf_t, pass_x_powered_by), 0 },

    { ngx_string("X-Accel-Expires"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, x_accel_expires),
                 ngx_http_upstream_conditional_copy_header_line,
                 offsetof(ngx_http_upstream_conf_t, pass_x_accel_expires), 0 },

    { ngx_string("X-Accel-Redirect"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, x_accel_redirect),
                 ngx_http_upstream_ignore_header_line, 0, 0 },

    { ngx_string("X-Accel-Limit-Rate"),
                 ngx_http_upstream_process_limit_rate, 0,
                 ngx_http_upstream_ignore_header_line, 0, 0 },

#if (NGX_HTTP_GZIP)
    { ngx_string("Content-Encoding"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, content_encoding),
                 ngx_http_upstream_copy_content_encoding, 0, 0 },
#endif

    { ngx_null_string, NULL, 0, NULL, 0, 0 }
};


ngx_http_module_t  ngx_http_upstream_module_ctx = {
    ngx_http_upstream_add_variables,       /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_upstream_create_main_conf,    /* create main configuration */
    ngx_http_core_init_main_conf,          /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_module_ctx,         /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_log_op_name_t  ngx_http_upstream_log_fmt_ops[] = {
    { ngx_string("upstream_status"), 0, NULL,
                                    ngx_http_upstream_log_status_getlen,
                                    ngx_http_upstream_log_status },
    { ngx_string("upstream_response_time"), 0, NULL,
                                    ngx_http_upstream_log_response_time_getlen,
                                    ngx_http_upstream_log_response_time },
    { ngx_null_string, 0, NULL, NULL, NULL }
};


static ngx_http_variable_t  ngx_http_upstream_vars[] = {

    { ngx_string("upstream_status"),
      ngx_http_upstream_status_variable, 0, NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upstream_response_time"),
      ngx_http_upstream_response_time_variable, 0, NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, 0, 0, 0 }
};


void
ngx_http_upstream_init(ngx_http_request_t *r)
{
    ngx_time_t                *tp;
    ngx_connection_t          *c;
    ngx_http_cleanup_t        *cln;
    ngx_http_upstream_t       *u;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http init upstream, client timer: %d", c->read->timer_set);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (!(r->http_version == NGX_HTTP_VERSION_9 && r->header_only)) {
        /* not a post_action */

        r->read_event_handler = ngx_http_upstream_rd_check_broken_connection;
        r->write_event_handler = ngx_http_upstream_wr_check_broken_connection;
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        if (!c->write->active) {
            if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT)
                == NGX_ERROR)
            {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }

    u = r->upstream;

    if (r->request_body) {
        u->request_bufs = r->request_body->bufs;
    }

    if (u->create_request(r) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.log = r->connection->log;
    u->saved_log_handler = r->log_handler;
    r->log_handler = ngx_http_upstream_log_error;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    u->output.sendfile = r->connection->sendfile;
    u->output.pool = r->pool;
    u->output.bufs.num = 1;
    u->output.bufs.size = clcf->client_body_buffer_size;
    u->output.output_filter = ngx_chain_writer;
    u->output.filter_ctx = &u->writer;

    u->writer.pool = r->pool;

    if (ngx_array_init(&u->states, r->pool, u->peer.peers->number,
                       sizeof(ngx_http_upstream_state_t))
        != NGX_OK)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state = ngx_array_push(&u->states);
    if (u->state == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));

    tp = ngx_timeofday();

    u->state->response_time = tp->sec * 1000 + tp->msec;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = ngx_http_upstream_cleanup;
    cln->data = r;
    u->cleanup = &cln->handler;

    ngx_http_upstream_connect(r, u);
}


static void
ngx_http_upstream_rd_check_broken_connection(ngx_http_request_t *r)
{
    ngx_http_upstream_check_broken_connection(r, r->connection->read);
}


static void
ngx_http_upstream_wr_check_broken_connection(ngx_http_request_t *r)
{
    ngx_http_upstream_check_broken_connection(r, r->connection->write);
}


static void
ngx_http_upstream_check_broken_connection(ngx_http_request_t *r,
    ngx_event_t *ev)
{
    int                  n;
    char                 buf[1];
    ngx_err_t            err;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http upstream check client, write event:%d, \"%V\"",
                   ev->write, &r->uri);

    c = r->connection;
    u = r->upstream;

    if (c->error) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    if (u->peer.connection == NULL) {
        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (!u->cachable && u->peer.connection) {
            ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                          "kevent() reported that client closed prematurely "
                          "connection, so upstream connection is closed too");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client closed "
                      "prematurely connection");

        if (u->peer.connection == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        return;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    /*
     * we do not need to disable the write event because
     * that event has NGX_USE_CLEAR_EVENT type
     */

    if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
        return;
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {
        if (ngx_del_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (n > 0) {
        return;
    }

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

    if (!u->cachable && u->peer.connection) {
        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "client closed prematurely connection, "
                      "so upstream connection is closed too");
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, err,
                  "client closed prematurely connection");

    if (u->peer.connection == NULL) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }
}


static void
ngx_http_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    r->connection->log->action = "connecting to upstream";

    r->connection->single_connection = 0;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = &u->peer.peers->peer[u->peer.cur_peer].name;

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no live upstreams");
    }

    if (rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    /* rc == NGX_OK || rc == NGX_AGAIN */

    c = u->peer.connection;

    c->data = r;

    c->write->handler = ngx_http_upstream_send_request_handler;
    c->read->handler = ngx_http_upstream_process_header;

    c->sendfile = r->connection->sendfile;

    c->pool = r->pool;
    c->read->log = c->write->log = c->log = r->connection->log;

    /* init or reinit the ngx_output_chain() and ngx_chain_writer() contexts */

    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
    u->writer.connection = c;
    u->writer.limit = 0;

    if (u->request_sent) {
        if (ngx_http_upstream_reinit(r, u) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (r->request_body && r->request_body->temp_file && r == r->main) {

        /*
         * the r->request_body->buf can be reused for one request only,
         * the subrequests should allocate their own temporay bufs
         */

        u->output.free = ngx_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->output.free->buf = r->request_body->buf;
        u->output.free->next = NULL;
        u->output.allocated = 1;

        r->request_body->buf->pos = r->request_body->buf->start;
        r->request_body->buf->last = r->request_body->buf->start;
        r->request_body->buf->tag = u->output.tag;
    }

    u->request_sent = 0;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

#if (NGX_HTTP_SSL)

    if (u->conf->ssl && c->ssl == NULL) {
        ngx_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    ngx_http_upstream_send_request(r, u);
}


#if (NGX_HTTP_SSL)

static void
ngx_http_upstream_ssl_init_connection(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c)
{
    ngx_int_t    rc;
    ngx_peer_t  *peer;

    if (ngx_ssl_create_connection(u->conf->ssl, c,
                                  NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        == NGX_ERROR)
    {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    c->sendfile = 0;
    u->output.sendfile = 0;

    peer = &u->peer.peers->peer[u->peer.cur_peer];

    if (ngx_ssl_set_session(c, peer->ssl_session) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {
        c->ssl->handler = ngx_http_upstream_ssl_handshake;
        return;
    }

    ngx_http_upstream_ssl_handshake(c);
}


static void
ngx_http_upstream_ssl_handshake(ngx_connection_t *c)
{
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    r = c->data;
    u = r->upstream;

    if (c->ssl->handshaked) {

        c->write->handler = ngx_http_upstream_send_request_handler;
        c->read->handler = ngx_http_upstream_process_header;

        ngx_http_upstream_send_request(r, u);

        return;
    }

    ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);

}

#endif


static ngx_int_t
ngx_http_upstream_reinit(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_chain_t  *cl;

    if (u->reinit_request(r) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(&r->upstream->headers_in,
                sizeof(ngx_http_upstream_headers_in_t));

    if (ngx_list_init(&r->upstream->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* reinit the request chain */

    for (cl = u->request_bufs; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->start;
        cl->buf->file_pos = 0;
    }

    /* reinit the subrequest's ngx_output_chain() context */

    if (r->request_body && r->request_body->temp_file
        && r != r->main && u->output.buf)
    {
        u->output.free = ngx_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            return NGX_ERROR;
        }

        u->output.free->buf = u->output.buf;
        u->output.free->next = NULL;

        u->output.buf->pos = u->output.buf->start;
        u->output.buf->last = u->output.buf->start;
    }

    u->output.buf = NULL;
    u->output.in = NULL;
    u->output.busy = NULL;

    /* reinit u->buffer */

#if 0
    if (u->cache) {
        u->buffer.pos = u->buffer.start + u->cache->ctx.header_size;
        u->buffer.last = u->buffer.pos;

    } else {
        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;
    }
#else

        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;

#endif

    /* add one more state */

    u->state = ngx_array_push(&u->states);
    if (u->state == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));

    return NGX_OK;
}


static void
ngx_http_upstream_send_request(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    int                rc;
    ngx_connection_t  *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream send request");

#if (NGX_HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT)
        && !u->request_sent
        && c->write->pending_eof)
    {
        (void) ngx_connection_error(c, c->write->kq_errno,
                                    "kevent() reported that connect() failed");
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

#endif

    c->log->action = "sending request to upstream";

    rc = ngx_output_chain(&u->output, u->request_sent ? NULL : u->request_bufs);

    u->request_sent = 1;

    if (rc == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->send_timeout);

        if (ngx_handle_write_event(c->write, u->conf->send_lowat) == NGX_ERROR)
        {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    /* rc == NGX_OK */

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                          ngx_tcp_push_n " failed");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
    }

    ngx_add_timer(c->read, u->conf->read_timeout);

#if 1
    if (c->read->ready) {

        /* post aio operation */

        /*
         * TODO comment
         * although we can post aio operation just in the end
         * of ngx_http_upstream_connect() CHECK IT !!!
         * it's better to do here because we postpone header buffer allocation
         */

        ngx_http_upstream_process_header(c->read);
        return;
    }
#endif

    c->write->handler = ngx_http_upstream_dummy_handler;

    if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
}


static void
ngx_http_upstream_send_request_handler(ngx_event_t *wev)
{
    ngx_connection_t     *c;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    c = wev->data;
    r = c->data;
    u = r->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http upstream send request handler");

    if (wev->timedout) {
        c->log->action = "sending request to upstream";
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

#if (NGX_HTTP_SSL)

    if (u->conf->ssl && c->ssl == NULL) {
        ngx_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    ngx_http_upstream_send_request(r, u);
}


static void
ngx_http_upstream_process_header(ngx_event_t *rev)
{
    ssize_t                         n;
    ngx_int_t                       rc;
    ngx_str_t                      *uri, args;
    ngx_uint_t                      i, key, flags;
    ngx_list_part_t                *part;
    ngx_table_elt_t                *h;
    ngx_connection_t               *c;
    ngx_http_request_t             *r;
    ngx_http_upstream_t            *u;
    ngx_http_err_page_t            *err_page;
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    c = rev->data;
    r = c->data;
    u = r->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http upstream process header");

    c->log->action = "reading response header from upstream";

    if (rev->timedout) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    if (u->buffer.start == NULL) {
        u->buffer.start = ngx_palloc(r->pool, u->conf->buffer_size);
        if (u->buffer.start == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;
        u->buffer.end = u->buffer.start + u->conf->buffer_size;
        u->buffer.temporary = 1;

        u->buffer.tag = u->output.tag;

        if (ngx_list_init(&r->upstream->headers_in.headers, r->pool, 8,
                          sizeof(ngx_table_elt_t))
            != NGX_OK)
        {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

#if 0
        if (u->cache) {
            u->buffer.pos += u->cache->ctx.header_size;
            u->buffer.last = u->buffer.pos;
        }
#endif
    }

    n = u->peer.connection->recv(u->peer.connection, u->buffer.last,
                                 u->buffer.end - u->buffer.last);

    if (n == NGX_AGAIN) {
#if 0
        ngx_add_timer(rev, u->read_timeout);
#endif

        if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "upstream prematurely closed connection");
    }

    if (n == NGX_ERROR || n == 0) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    u->buffer.last += n;

#if 0
    u->valid_header_in = 0;

    u->peer.cached = 0;
#endif

    rc = u->process_header(r);

    if (rc == NGX_AGAIN) {
#if 0
        ngx_add_timer(rev, u->read_timeout);
#endif

        if (u->buffer.pos == u->buffer.end) {
            ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                          "upstream sent too big header");

            ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
            return;
        }

        if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
        return;
    }

    if (rc == NGX_ERROR || rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* rc == NGX_OK */

    if (u->headers_in.status_n == NGX_HTTP_INTERNAL_SERVER_ERROR) {

        if (u->peer.tries > 1
            && (u->conf->next_upstream & NGX_HTTP_UPSTREAM_FT_HTTP_500))
        {
            ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_HTTP_500);
            return;
        }

#if (NGX_HTTP_CACHE)

        if (u->peer.tries == 0
            && u->stale
            && (u->conf->use_stale & NGX_HTTP_UPSTREAM_FT_HTTP_500))
        {
            ngx_http_upstream_finalize_request(r, u,
                                              ngx_http_send_cached_response(r));
            return;
        }

#endif
    }

    if (u->headers_in.status_n == NGX_HTTP_NOT_FOUND) {

        if (u->peer.tries > 1
            && u->conf->next_upstream & NGX_HTTP_UPSTREAM_FT_HTTP_404)
        {
            ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_HTTP_404);
            return;
        }

        if (u->conf->redirect_404) {
            rc = (r->err_ctx == NULL) ? 404 : 204;
            ngx_http_upstream_finalize_request(r, u, rc);
            return;
        }
    }


    if (u->headers_in.status_n >= NGX_HTTP_BAD_REQUEST
        && u->conf->redirect_errors
        && r->err_ctx == NULL)
    {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->error_pages) {

            err_page = clcf->error_pages->elts;
            for (i = 0; i < clcf->error_pages->nelts; i++) {
                if (err_page[i].status == (ngx_int_t) u->headers_in.status_n) {

                    if (u->headers_in.status_n == NGX_HTTP_UNAUTHORIZED) {

                        r->headers_out.www_authenticate =
                                        ngx_list_push(&r->headers_out.headers);

                        if (r->headers_out.www_authenticate == NULL) {
                            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                            return;
                        }

                        *r->headers_out.www_authenticate =
                                               *u->headers_in.www_authenticate;
                    }

                    ngx_http_upstream_finalize_request(r, u,
                                                       u->headers_in.status_n);
                    return;
                }
            }
        }
    }

    if (r->upstream->headers_in.x_accel_redirect) {
        ngx_http_upstream_finalize_request(r, u, NGX_DECLINED);

        umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
        hh = (ngx_http_upstream_header_t *) umcf->headers_in_hash.buckets;

        part = &r->upstream->headers_in.headers.part;
        h = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                h = part->elts;
                i = 0;
            }

            key = h[i].hash % umcf->headers_in_hash.hash_size;

            if (hh[key].redirect
                && hh[key].name.len == h[i].key.len
                && ngx_strcasecmp(hh[key].name.data, h[i].key.data) == 0)
            {
                if (hh[key].copy_handler(r, &h[i], hh[key].conf) != NGX_OK) {
                    ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }

            }
        }

        uri = &r->upstream->headers_in.x_accel_redirect->value;
        args.len = 0;
        args.data = NULL;
        flags = 0;

        if (ngx_http_parse_unsafe_uri(r, uri, &args, &flags) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_NOT_FOUND);
            return;
        }

        if (flags & NGX_HTTP_ZERO_IN_URI) {
            r->zero_in_uri = 1;
        }

        ngx_http_internal_redirect(r, uri, &args);
        return;
    }

    ngx_http_upstream_send_response(r, u);
}


static void
ngx_http_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    int                             tcp_nodelay;
    ssize_t                         size;
    ngx_int_t                       rc;
    ngx_uint_t                      i, key;
    ngx_list_part_t                *part;
    ngx_table_elt_t                *h;
    ngx_event_pipe_t               *p;
    ngx_connection_t               *c;
    ngx_pool_cleanup_t             *cl;
    ngx_pool_cleanup_file_t        *clf;
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    hh = (ngx_http_upstream_header_t *) umcf->headers_in_hash.buckets;

    part = &r->upstream->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        key = h[i].hash % umcf->headers_in_hash.hash_size;

        if (hh[key].name.len == h[i].key.len
            && ngx_strcasecmp(hh[key].name.data, h[i].key.data) == 0)
        {
            if (hh[key].copy_handler(r, &h[i], hh[key].conf) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            continue;
        }

        if (ngx_http_upstream_copy_header_line(r, &h[i], 0) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    r->headers_out.status = u->headers_in.status_n;
    r->headers_out.status_line = u->headers_in.status_line;

    if (r->headers_out.content_length_n != -1) {
        u->length = (size_t) r->headers_out.content_length_n;

    } else {
        u->length = NGX_MAX_SIZE_T_VALUE;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR
        || rc > NGX_OK
                          /* post_action */
        || (r->http_version == NGX_HTTP_VERSION_9 && r->header_only)) {
        ngx_http_upstream_finalize_request(r, u, rc);
        return;
    }

    u->header_sent = 1;

    if (r->request_body && r->request_body->temp_file) {
        for (cl = r->pool->cleanup; cl; cl = cl->next) {
            if (cl->handler == ngx_pool_cleanup_file) {
                clf = cl->data;

                if (clf->fd == r->request_body->temp_file->file.fd) {
                    cl->handler(clf);
                    cl->handler = NULL;
                    break;
                }
            }
        }
    }

    c = r->connection;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (u->pipe == NULL) {

        if (u->input_filter == NULL) {
            u->input_filter_init = ngx_http_upstream_non_buffered_filter_init;
            u->input_filter = ngx_http_upstream_non_buffered_filter;
            u->input_filter_ctx = r;
        }

        u->peer.connection->read->handler =
                                   ngx_http_upstream_process_non_buffered_body;
        r->write_event_handler =
                             ngx_http_upstream_process_non_buffered_downstream;

        r->limit_rate = 0;

        if (u->input_filter_init(u->input_filter_ctx) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }

        if (clcf->tcp_nodelay && c->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "tcp_nodelay");

            tcp_nodelay = 1;

            if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                               (const void *) &tcp_nodelay, sizeof(int)) == -1)
            {
                ngx_connection_error(c, ngx_socket_errno,
                                     "setsockopt(TCP_NODELAY) failed");
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }

            c->tcp_nodelay = NGX_TCP_NODELAY_SET;
        }

        size = u->buffer.last - u->buffer.pos;

        if (size) {
            u->buffer.last = u->buffer.pos;

            if (u->input_filter(u->input_filter_ctx, size) == NGX_ERROR) {
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }

            ngx_http_upstream_process_non_buffered_body(c->write);

        } else {
            u->buffer.pos = u->buffer.start;
            u->buffer.last = u->buffer.start;

            if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }
        }

        return;
    }

    /* TODO: preallocate event_pipe bufs, look "Content-Length" */

#if 0

    if (u->cache && u->cache->ctx.file.fd != NGX_INVALID_FILE) {
        if (ngx_close_file(u->cache->ctx.file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          u->cache->ctx.file.name.data);
        }
    }

    if (u->cachable) {
        header = (ngx_http_cache_header_t *) u->buffer->start;

        header->expires = u->cache->ctx.expires;
        header->last_modified = u->cache->ctx.last_modified;
        header->date = u->cache->ctx.date;
        header->length = r->headers_out.content_length_n;
        u->cache->ctx.length = r->headers_out.content_length_n;

        header->key_len = u->cache->ctx.key0.len;
        ngx_memcpy(&header->key, u->cache->ctx.key0.data, header->key_len);
        header->key[header->key_len] = LF;
    }

#endif

    p = u->pipe;

    p->output_filter = (ngx_event_pipe_output_filter_pt) ngx_http_output_filter;
    p->output_ctx = r;
    p->tag = u->output.tag;
    p->bufs = u->conf->bufs;
    p->busy_size = u->conf->busy_buffers_size;
    p->upstream = u->peer.connection;
    p->downstream = c;
    p->pool = r->pool;
    p->log = c->log;

    p->cachable = u->cachable;

    p->temp_file = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
    if (p->temp_file == NULL) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

    p->temp_file->file.fd = NGX_INVALID_FILE;
    p->temp_file->file.log = c->log;
    p->temp_file->path = u->conf->temp_path;
    p->temp_file->pool = r->pool;

    if (u->cachable) {
        p->temp_file->persistent = 1;
    } else {
        p->temp_file->warn = "an upstream response is buffered "
                             "to a temporary file";
    }

    p->max_temp_file_size = u->conf->max_temp_file_size;
    p->temp_file_write_size = u->conf->temp_file_write_size;

    p->preread_bufs = ngx_alloc_chain_link(r->pool);
    if (p->preread_bufs == NULL) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }
    p->preread_bufs->buf = &u->buffer;
    p->preread_bufs->next = NULL;
    u->buffer.recycled = 1;

    p->preread_size = u->buffer.last - u->buffer.pos;

    if (u->cachable) {
        p->buf_to_file = ngx_calloc_buf(r->pool);
        if (p->buf_to_file == NULL) {
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
        p->buf_to_file->pos = u->buffer.start;
        p->buf_to_file->last = u->buffer.pos;
        p->buf_to_file->temporary = 1;
    }

    if (ngx_event_flags & NGX_USE_AIO_EVENT) {
        /* the posted aio operation may currupt a shadow buffer */
        p->single_buf = 1;
    }

    /* TODO: p->free_bufs = 0 if use ngx_create_chain_of_bufs() */
    p->free_bufs = 1;

    /*
     * event_pipe would do u->buffer.last += p->preread_size
     * as though these bytes were read
     */
    u->buffer.last = u->buffer.pos;

    if (u->conf->cyclic_temp_file) {

        /*
         * we need to disable the use of sendfile() if we use cyclic temp file
         * because the writing a new data may interfere with sendfile()
         * that uses the same kernel file pages (at least on FreeBSD)
         */

        p->cyclic_temp_file = 1;
        c->sendfile = 0;

    } else {
        p->cyclic_temp_file = 0;
    }

    p->read_timeout = u->conf->read_timeout;
    p->send_timeout = clcf->send_timeout;
    p->send_lowat = clcf->send_lowat;

    u->peer.connection->read->handler = ngx_http_upstream_process_body;
    r->write_event_handler = ngx_http_upstream_process_downstream;

    ngx_http_upstream_process_body(u->peer.connection->read);
}


static void
ngx_http_upstream_process_non_buffered_downstream(ngx_http_request_t *r)
{
    ngx_http_upstream_process_non_buffered_body(r->connection->write);
}


static void
ngx_http_upstream_process_non_buffered_body(ngx_event_t *ev)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_int_t                  rc;
    ngx_uint_t                 do_write;
    ngx_connection_t          *c, *client;
    ngx_http_request_t        *r;
    ngx_http_upstream_t       *u;
    ngx_http_core_loc_conf_t  *clcf;

    c = ev->data;

    if (ev->write) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream process non buffered downstream");
        c->log->action = "sending to client";

    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream process non buffered upstream");
        c->log->action = "reading upstream";
    }

    if (ev->timedout) {
        if (ev->write) {
            c->timedout = 1;
            ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");

        } else {
            ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
        }
    }

    r = c->data;
    u = r->upstream;
    client = r->connection;

    b = &u->buffer;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    do_write = ev->write;

    for ( ;; ) {

        if (do_write) {

            if (u->out_bufs || u->busy_bufs) {
                rc = ngx_http_output_filter(r, u->out_bufs);

                if (client->destroyed) {
                    return;
                }

                if (rc == NGX_ERROR) {
                    ngx_http_upstream_finalize_request(r, u, 0);
                    return;
                }

                ngx_chain_update_chains(&u->free_bufs, &u->busy_bufs,
                                        &u->out_bufs, u->output.tag);
            }

            if (u->busy_bufs == NULL) {

                if (u->length == 0
                    || u->peer.connection->read->eof
                    || u->peer.connection->read->error)
                {
                    ngx_http_upstream_finalize_request(r, u, 0);
                    return;
                }

                b->pos = b->start;
                b->last = b->start;
            }
        }

        size = b->end - b->last;

        if (size > u->length) {
            size = u->length;
        }

        if (size && u->peer.connection->read->ready) {
            n = u->peer.connection->recv(u->peer.connection, b->last, size);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n > 0) {
                if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) {
                    ngx_http_upstream_finalize_request(r, u, 0);
                    return;
                }
            }

            do_write = 1;

            continue;
        }

        break;
    }

    if (client->data == r) {
        if (ngx_handle_write_event(client->write, clcf->send_lowat)
            == NGX_ERROR)
        {
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
    }

    if (client->write->active) {
        ngx_add_timer(client->write, clcf->send_timeout);

    } else if (client->write->timer_set) {
        ngx_del_timer(client->write);
    }

    if (ngx_handle_read_event(u->peer.connection->read, 0) == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

    if (u->peer.connection->read->active) {
        ngx_add_timer(u->peer.connection->read, u->conf->read_timeout);

    } else if (u->peer.connection->read->timer_set) {
        ngx_del_timer(u->peer.connection->read);
    }
}


static ngx_int_t
ngx_http_upstream_non_buffered_filter_init(void *data)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_non_buffered_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t  *r = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    b = &u->buffer;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;

    if (u->length == NGX_MAX_SIZE_T_VALUE) {
        return NGX_OK;
    }

    u->length -= bytes;

    return NGX_OK;
}


static void
ngx_http_upstream_process_downstream(ngx_http_request_t *r)
{
    ngx_http_upstream_process_body(r->connection->write);
}


static void
ngx_http_upstream_process_body(ngx_event_t *ev)
{
    ngx_event_pipe_t     *p;
    ngx_connection_t     *c, *downstream;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    c = ev->data;
    r = c->data;
    u = r->upstream;
    downstream = r->connection;

    if (ev->write) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream process downstream");
        c->log->action = "sending to client";

    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream process upstream");
        c->log->action = "reading upstream";
    }

    p = u->pipe;

    if (ev->timedout) {
        if (ev->write) {
            if (ev->delayed) {

                ev->timedout = 0;
                ev->delayed = 0;

                if (!ev->ready) {
                    ngx_add_timer(ev, p->send_timeout);

                    if (ngx_handle_write_event(ev, p->send_lowat) == NGX_ERROR)
                    {
                        ngx_http_upstream_finalize_request(r, u, 0);
                        return;
                    }

                    return;
                }

                if (ngx_event_pipe(p, ev->write) == NGX_ABORT) {

                    if (downstream->destroyed) {
                        return;
                    }

                    ngx_http_upstream_finalize_request(r, u, 0);
                    return;
                }

            } else {
                p->downstream_error = 1;
                c->timedout = 1;
                ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
            }

        } else {
            p->upstream_error = 1;
            ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
        }

    } else {
        if (ev->write && ev->delayed) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http downstream delayed");

            if (ngx_handle_write_event(ev, p->send_lowat) == NGX_ERROR) {
                return;
            }

            return;
        }

        if (ngx_event_pipe(p, ev->write) == NGX_ABORT) {

            if (downstream->destroyed) {
                return;
            }

            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
    }

    if (u->peer.connection) {

#if (NGX_HTTP_FILE_CACHE)

        if (p->upstream_done && u->cachable) {
            if (ngx_http_cache_update(r) == NGX_ERROR) {
                ngx_http_busy_unlock(u->conf->busy_lock, &u->busy_lock);
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }

        } else if (p->upstream_eof && u->cachable) {

            /* TODO: check length & update cache */

            if (ngx_http_cache_update(r) == NGX_ERROR) {
                ngx_http_busy_unlock(u->conf->busy_lock, &u->busy_lock);
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }
        }

#endif

        if (p->upstream_done || p->upstream_eof || p->upstream_error) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http upstream exit: %p", p->out);
#if 0
            ngx_http_busy_unlock(u->conf->busy_lock, &u->busy_lock);
#endif
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
    }

    if (p->downstream_error) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream downstream error");

        if (!u->cachable && u->peer.connection) {
            ngx_http_upstream_finalize_request(r, u, 0);
        }
    }
}


static void
ngx_http_upstream_dummy_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http upstream dummy handler");
}


static void
ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_uint_t ft_type)
{
    ngx_uint_t  status, down;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http next upstream, %xD", ft_type);

#if 0
    ngx_http_busy_unlock(u->conf->busy_lock, &u->busy_lock);
#endif

    if (ft_type == NGX_HTTP_UPSTREAM_FT_HTTP_404) {
        down = 0;
    } else {
        down = 1;
    }

    ngx_event_connect_peer_failed(&u->peer, down);

    if (ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT,
                      "upstream timed out");
    }

    if (u->peer.cached && ft_type == NGX_HTTP_UPSTREAM_FT_ERROR) {
        status = 0;

    } else {
        switch(ft_type) {

        case NGX_HTTP_UPSTREAM_FT_TIMEOUT:
            status = NGX_HTTP_GATEWAY_TIME_OUT;
            break;

        case NGX_HTTP_UPSTREAM_FT_HTTP_500:
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;

        case NGX_HTTP_UPSTREAM_FT_HTTP_404:
            status = NGX_HTTP_NOT_FOUND;
            break;

        /*
         * NGX_HTTP_UPSTREAM_FT_BUSY_LOCK and NGX_HTTP_UPSTREAM_FT_MAX_WAITING
         * never reach here
         */

        default:
            status = NGX_HTTP_BAD_GATEWAY;
        }
    }

    if (r->connection->error) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    if (status) {
        u->state->status = status;

        if (u->peer.tries == 0 || !(u->conf->next_upstream & ft_type)) {

#if (NGX_HTTP_CACHE)

            if (u->stale && (u->conf->use_stale & ft_type)) {
                ngx_http_upstream_finalize_request(r, u,
                                             ngx_http_send_cached_response(r));
                return;
            }

#endif

            ngx_http_upstream_finalize_request(r, u, status);
            return;
        }
    }

    if (u->peer.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);
#if (NGX_HTTP_SSL)
        if (u->peer.connection->ssl) {
            ngx_http_upstream_ssl_shutdown(u->peer.connection,
                                       &u->peer.peers->peer[u->peer.cur_peer]);
        }
#endif
        ngx_close_connection(u->peer.connection);
    }

#if 0
    if (u->conf->busy_lock && !u->busy_locked) {
        ngx_http_upstream_busy_lock(p);
        return;
    }
#endif

    ngx_http_upstream_connect(r, u);
}


static void
ngx_http_upstream_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cleanup http upstream request: \"%V\"", &r->uri);

    ngx_http_upstream_finalize_request(r, r->upstream, NGX_DONE);
}


static void
ngx_http_upstream_finalize_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_int_t rc)
{
    ngx_time_t  *tp;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http upstream request: %i", rc);

    *u->cleanup = NULL;

    if (u->state->response_time) {
        tp = ngx_timeofday();
        u->state->response_time = tp->sec * 1000 + tp->msec
                                  - u->state->response_time;
    }

    u->finalize_request(r, rc);

    if (u->peer.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);
#if (NGX_HTTP_SSL)

        /* TODO: do not shutdown persistent connection */

        if (u->peer.connection->ssl) {
            ngx_http_upstream_ssl_shutdown(u->peer.connection,
                                       &u->peer.peers->peer[u->peer.cur_peer]);
        }
#endif
        ngx_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    if (u->header_sent && (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE))
    {
        rc = 0;
    }

    if (u->pipe && u->pipe->temp_file) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream temp fd: %d",
                       u->pipe->temp_file->file.fd);
    }

#if 0
    if (u->cache) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream cache fd: %d",
                       u->cache->ctx.file.fd);
    }
#endif

    r->log_handler = u->saved_log_handler;

    if (rc == NGX_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";

    if (rc == 0 && r == r->main) {
        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    ngx_http_finalize_request(r, rc);
}


#if (NGX_HTTP_SSL)

static void
ngx_http_upstream_ssl_shutdown(ngx_connection_t *c, ngx_peer_t *peer)
{
    /* lock peer mutex */

    if (peer->ssl_session) {
        ngx_ssl_free_session(peer->ssl_session);
    }

    peer->ssl_session = ngx_ssl_get_session(c);

    /* unlock peer mutex */

    /*
     * We send the "close notify" shutdown alert to the upstream only
     * and do not wait its "close notify" shutdown alert.
     * It is acceptable according to the TLS standard.
     */

    c->ssl->no_wait_shutdown = 1;

    (void) ngx_ssl_shutdown(c);
}

#endif


static ngx_int_t
ngx_http_upstream_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  **ph;

    ph = (ngx_table_elt_t **) ((char *) &r->upstream->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_multi_header_lines(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_array_t       *pa;
    ngx_table_elt_t  **ph;

    pa = (ngx_array_t *) ((char *) &r->upstream->headers_in + offset);

    if (pa->elts == NULL) {
       if (ngx_array_init(pa, r->pool, 2, sizeof(ngx_table_elt_t *)) != NGX_OK)
       {
           return NGX_ERROR;
       }
    }

    ph = ngx_array_push(pa);
    if (ph == NULL) {
        return NGX_ERROR;
    }

    *ph = h;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_ignore_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_limit_rate(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_int_t  n;

    r->upstream->headers_in.x_accel_limit_rate = h;

    n = ngx_atoi(h->value.data, h->value.len);

    if (n != NGX_ERROR) {
        r->limit_rate = (size_t) n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_copy_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  *ho, **ph;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (offset) {
        ph = (ngx_table_elt_t **) ((char *) &r->headers_out + offset);
        *ph = ho;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_conditional_copy_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_flag_t       *f;
    ngx_table_elt_t  *ho;

    f = (ngx_flag_t *) ((char *) r->upstream->conf + offset);

    if (*f == 0) {
        return NGX_OK;
    }

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_copy_multi_header_lines(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_array_t      *pa;
    ngx_table_elt_t  *ho, **ph;

    pa = (ngx_array_t *) ((char *) &r->headers_out + offset);

    if (pa->elts == NULL) {
        if (ngx_array_init(pa, r->pool, 2, sizeof(ngx_table_elt_t *)) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ph = ngx_array_push(pa);
    if (ph == NULL) {
        return NGX_ERROR;
    }

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;
    *ph = ho;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_copy_content_type(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    r->headers_out.content_type = h->value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_copy_content_length(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    r->headers_out.content_length = ho;
    r->headers_out.content_length_n = ngx_atoof(h->value.data, h->value.len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_rewrite_location(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_int_t         rc;
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (r->upstream->rewrite_redirect) {
        rc = r->upstream->rewrite_redirect(r, ho, 0);

        if (rc == NGX_DECLINED) {
            return NGX_OK;
        }

        if (rc == NGX_OK) {
            r->headers_out.location = ho;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten location: \"%V\"", &ho->value);
        }

        return rc;
    }

    /*
     * we do not set r->headers_out.location here to avoid the handling
     * the local redirects without a host name by ngx_http_header_filter()
     */

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_rewrite_refresh(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    u_char           *p;
    ngx_int_t         rc;
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (r->upstream->rewrite_redirect) {

        p = (u_char *) ngx_strstr(ho->value.data, "url=");

        if (p) {
            rc = r->upstream->rewrite_redirect(r, ho, p + 4 - ho->value.data);

        } else {
            return NGX_OK;
        }

        if (rc == NGX_DECLINED) {
            return NGX_OK;
        }

#if (NGX_DEBUG)
        if (rc == NGX_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten refresh: \"%V\"", &ho->value);
        }
#endif

        return rc;
    }

    return NGX_OK;
}


#if (NGX_HTTP_GZIP)

static ngx_int_t
ngx_http_upstream_copy_content_encoding(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    r->headers_out.content_encoding = ho;

    return NGX_OK;
}

#endif


static size_t
ngx_http_upstream_log_status_getlen(ngx_http_request_t *r, uintptr_t data)
{
    if (r->upstream) {
        return r->upstream->states.nelts * (3 + 2);
    }

    return 1;
}


static u_char *
ngx_http_upstream_log_status(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_uint_t                  i;
    ngx_http_upstream_t        *u;
    ngx_http_upstream_state_t  *state;

    u = r->upstream;

    if (u == NULL || u->states.nelts == 0) {
        *buf = '-';
        return buf + 1;
    }

    i = 0;
    state = u->states.elts;

    for ( ;; ) {
        if (state[i].status == 0) {
            *buf++ = '-';

        } else {
            buf = ngx_sprintf(buf, "%ui", state[i].status);
        }

        if (++i == u->states.nelts) {
            return buf;
        }

        *buf++ = ',';
        *buf++ = ' ';
    }
}


static size_t
ngx_http_upstream_log_response_time_getlen(ngx_http_request_t *r,
    uintptr_t data)
{
    if (r->upstream) {
        return r->upstream->states.nelts * (NGX_TIME_T_LEN + 4 + 2);
    }

    return 1;
}


static u_char *
ngx_http_upstream_log_response_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_uint_t                  i;
    ngx_http_upstream_t        *u;
    ngx_http_upstream_state_t  *state;

    u = r->upstream;

    if (u == NULL || u->states.nelts == 0) {
        *buf = '-';
        return buf + 1;
    }

    i = 0;
    state = u->states.elts;

    for ( ;; ) {
        if (state[i].status == 0) {
            *buf++ = '-';

        } else {
            buf = ngx_sprintf(buf, "%d.%03d",
                               state[i].response_time / 1000,
                               state[i].response_time % 1000);
        }

        if (++i == u->states.nelts) {
            return buf;
        }

        *buf++ = ',';
        *buf++ = ' ';
    }
}


static u_char *
ngx_http_upstream_log_error(ngx_http_request_t *r, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_http_upstream_t    *u;
    ngx_peer_connection_t  *peer;

    u = r->upstream;
    peer = &u->peer;

    p = ngx_snprintf(buf, len,
                     ", server: %V, URL: \"%V\","
                     " upstream: \"%V%V%s%V\"",
                     &r->server_name,
                     &r->unparsed_uri,
                     &u->conf->schema,
                     &peer->peers->peer[peer->cur_peer].name,
                     peer->peers->peer[peer->cur_peer].uri_separator,
                     &u->uri);
    len -= p - buf;
    buf = p;

    return ngx_http_log_error_info(r, buf, len);
}


static ngx_int_t
ngx_http_upstream_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t     *var, *v;
    ngx_http_log_op_name_t  *op;

    for (v = ngx_http_upstream_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->handler = v->handler;
        var->data = v->data;
    }

    for (op = ngx_http_upstream_log_fmt_ops; op->name.len; op++) { /* void */ }
    op->run = NULL;

    for (op = ngx_http_log_fmt_ops; op->run; op++) {
        if (op->name.len == 0) {
            op = (ngx_http_log_op_name_t *) op->run;
        }
    }

    op->run = (ngx_http_log_op_run_pt) ngx_http_upstream_log_fmt_ops;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    ngx_uint_t                  i;
    ngx_http_upstream_t        *u;
    ngx_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cachable = 0;
    v->not_found = 0;

    u = r->upstream;

    if (u == NULL || u->states.nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = u->states.nelts * (3 + 2);

    p = ngx_palloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;
    state = u->states.elts;

    for ( ;; ) {
        if (state[i].status == 0) {
            *p++ = '-';

        } else {
            p = ngx_sprintf(p, "%ui", state[i].status);
        }

        if (++i == u->states.nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_response_time_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    ngx_uint_t                  i;
    ngx_http_upstream_t        *u;
    ngx_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cachable = 0;
    v->not_found = 0;

    u = r->upstream;

    if (u == NULL || u->states.nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = u->states.nelts * (NGX_TIME_T_LEN + 4 + 2);

    p = ngx_palloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;
    state = u->states.elts;

    for ( ;; ) {
        if (state[i].status == 0) {
            *p++ = '-';

        } else {
            p = ngx_sprintf(p, "%d.%03d",
                            state[i].response_time / 1000,
                            state[i].response_time % 1000);
        }

        if (++i == u->states.nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return NGX_OK;
}


static void *
ngx_http_upstream_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    return umcf;
}


static char *
ngx_http_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_upstream_main_conf_t  *umcf = conf;

    umcf->headers_in_hash.max_size = 100;
    umcf->headers_in_hash.bucket_limit = 1;
    umcf->headers_in_hash.bucket_size = sizeof(ngx_http_upstream_header_t);
    umcf->headers_in_hash.name = "upstream_headers_in";

    if (ngx_hash0_init(&umcf->headers_in_hash, cf->pool,
                      ngx_http_upstream_headers_in, 0) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "http upstream headers_in hash size: %ui, "
                   "max buckets per entry: %ui",
                   umcf->headers_in_hash.hash_size,
                   umcf->headers_in_hash.min_buckets);

    return NGX_CONF_OK;
}
