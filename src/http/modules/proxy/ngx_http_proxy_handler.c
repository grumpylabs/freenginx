
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>
#include <ngx_http_proxy_handler.h>



static int ngx_http_proxy_handler(ngx_http_request_t *r);
static void ngx_http_proxy_init_request(void *data);
static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_send_request_handler(ngx_event_t *wev);
static void ngx_http_proxy_send_request(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_process_upstream_status_line(ngx_event_t *rev);
static void ngx_http_proxy_process_upstream_headers(ngx_event_t *rev);
static ssize_t ngx_http_proxy_read_upstream_header(ngx_http_proxy_ctx_t *);
static void ngx_http_proxy_send_response(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_process_body(ngx_event_t *ev);

static int ngx_http_proxy_parse_status_line(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_next_upstream(ngx_http_proxy_ctx_t *p, int ft_type);
static void ngx_http_proxy_finalize_request(ngx_http_proxy_ctx_t *p, int rc);
static void ngx_http_proxy_close_connection(ngx_connection_t *c);

static size_t ngx_http_proxy_log_error(void *data, char *buf, size_t len);

static int ngx_http_proxy_init(ngx_cycle_t *cycle);
static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf,
                                           void *parent, void *child);

static char *ngx_http_proxy_set_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);
static char *ngx_http_proxy_parse_upstream(ngx_str_t *url,
                                           ngx_http_proxy_upstream_t *u);


static ngx_command_t ngx_http_proxy_commands[] = {

    {ngx_string("proxy_pass"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_http_proxy_set_pass,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("proxy_request_buffer_size"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_proxy_loc_conf_t, request_buffer_size),
     NULL},

    {ngx_string("proxy_connect_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_proxy_loc_conf_t, connect_timeout),
     NULL},

    {ngx_string("proxy_send_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_proxy_loc_conf_t, send_timeout),
     NULL},

    {ngx_string("proxy_header_buffer_size"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_proxy_loc_conf_t, header_buffer_size),
     NULL},

    {ngx_string("proxy_read_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_proxy_loc_conf_t, read_timeout),
     NULL},

    {ngx_string("proxy_buffers"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
     ngx_conf_set_bufs_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_proxy_loc_conf_t, bufs),
     NULL},

    {ngx_string("proxy_busy_buffers_size"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_proxy_loc_conf_t, busy_buffers_size),
     NULL},

    {ngx_string("proxy_temp_path"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
     ngx_conf_set_path_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_proxy_loc_conf_t, temp_path),
     NULL},

    {ngx_string("proxy_temp_file_write_size"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_proxy_loc_conf_t, temp_file_write_size),
     NULL},

    ngx_null_command
};


ngx_http_module_t  ngx_http_proxy_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_proxy_create_loc_conf,        /* create location configration */
    ngx_http_proxy_merge_loc_conf          /* merge location configration */
};


ngx_module_t  ngx_http_proxy_module = {
    NGX_MODULE,
    &ngx_http_proxy_module_ctx,            /* module context */
    ngx_http_proxy_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static ngx_str_t http_methods[] = {
    ngx_string("GET "),
    ngx_string("HEAD "),
    ngx_string("POST ")
};


static char *upstream_header_errors[] = {
    "upstream sent invalid header",
    "upstream sent too long header line"
};


static ngx_http_header_t headers_in[] = {
    { ngx_string("Date"), offsetof(ngx_http_proxy_headers_in_t, date) },
    { ngx_string("Server"), offsetof(ngx_http_proxy_headers_in_t, server) },
    { ngx_string("Connection"),
                           offsetof(ngx_http_proxy_headers_in_t, connection) },
    { ngx_string("Content-Type"),
                         offsetof(ngx_http_proxy_headers_in_t, content_type) },
    { ngx_string("Content-Length"),
                       offsetof(ngx_http_proxy_headers_in_t, content_length) },
    { ngx_string("Last-Modified"),
                        offsetof(ngx_http_proxy_headers_in_t, last_modified) },
    { ngx_string("Accept-Ranges"),
                        offsetof(ngx_http_proxy_headers_in_t, accept_ranges) },

    { ngx_null_string, 0 }
};


static char http_version[] = " HTTP/1.0" CRLF;
static char host_header[] = "Host: ";
static char connection_close_header[] = "Connection: close" CRLF;



static int ngx_http_proxy_handler(ngx_http_request_t *r)
{
    int                    rc;
    ngx_http_proxy_ctx_t  *p;

    ngx_http_create_ctx(r, p, ngx_http_proxy_module,
                        sizeof(ngx_http_proxy_ctx_t),
                        NGX_HTTP_INTERNAL_SERVER_ERROR);

    p->lcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    p->upstream.peers = p->lcf->peers;
    p->upstream.tries = p->lcf->peers->number;

    p->request = r;
    p->method = r->method;

    /* TODO: we currently support reverse proxy only */
    p->accel = 1;

    if (r->headers_in.content_length_n > 0) {
        ngx_test_null(r->temp_file,
                      ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t)),
                      NGX_HTTP_INTERNAL_SERVER_ERROR);

        r->temp_file->file.fd = NGX_INVALID_FILE;
        r->temp_file->file.log = r->connection->log;
        r->temp_file->path = *p->lcf->temp_path;
        r->temp_file->pool = r->pool;
        r->temp_file->warn = "a client request body is buffered "
                             "to a temporary file";
        /* STUB */ r->temp_file->persistent = 1;

        r->request_body_handler = ngx_http_proxy_init_request;
        r->data = p;

        rc = ngx_http_read_client_request_body(r, p->lcf->request_buffer_size);

        if (rc != NGX_OK) {
            return rc;
        }
    }

    ngx_http_proxy_init_request(p);

    return NGX_DONE;
}


static void ngx_http_proxy_init_request(void *data)
{
    ngx_http_proxy_ctx_t *p = data;

    ngx_chain_t             *cl;
    ngx_http_request_t      *r;
    ngx_output_chain_ctx_t  *ctx;


    r = p->request;

    cl = ngx_http_proxy_create_request(p);
    if (cl == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (r->request_hunks) {
        cl->next = r->request_hunks;
    }

    r->request_hunks = cl;

    p->upstream.log = r->connection->log;
    p->saved_ctx = r->connection->log->data;
    p->saved_handler = r->connection->log->handler;
    r->connection->log->data = p;
    r->connection->log->handler = ngx_http_proxy_log_error;
    p->action = "connecting to upstream";

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_output_chain_ctx_t));
    if (ctx == NULL) {
        ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    p->output_chain_ctx = ctx;

    if (r->request_body_hunk) {
        ctx->free = ngx_alloc_chain_link(r->pool);
        if (ctx->free == NULL) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        ctx->free->hunk = r->request_body_hunk;
        ctx->free->next = NULL;
    }

    ctx->sendfile = r->sendfile;
    ctx->copy_chain = 1;
    ctx->pool = r->pool;
    ctx->bufs.num = 1;
    ctx->tag = (ngx_hunk_tag_t) &ngx_http_proxy_module;
    ctx->output_filter = (ngx_output_chain_filter_pt) ngx_write_chain;

    ngx_http_proxy_send_request(p);
}


static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_proxy_ctx_t *p)
{
    int                         i;
    size_t                      len;
    ngx_hunk_t                 *h;
    ngx_chain_t                *chain;
    ngx_table_elt_t            *header;
    ngx_http_request_t         *r;
    ngx_http_proxy_upstream_t  *u;

    r = p->request;
    u = p->lcf->upstream;

    len = http_methods[p->method - 1].len
          + u->uri.len
          + r->uri.len - u->location->len
          + 1 + r->args.len                                  /* 1 is for "?" */
          + sizeof(http_version) - 1
          + sizeof(host_header) - 1 + u->host_header.len + 2
                                                          /* 2 is for "\r\n" */
          + sizeof(connection_close_header) - 1
          + 2;                          /* 2 is for "\r\n" at the header end */

    header = (ngx_table_elt_t *) r->headers_in.headers->elts;
    for (i = 0; i < r->headers_in.headers->nelts; i++) {

        if (&header[i] == r->headers_in.host) {
            continue;
        }

        if (&header[i] == r->headers_in.connection) {
            continue;
        }

        /* 2 is for ": " and 2 is for "\r\n" */
        len += header[i].key.len + 2 + header[i].value.len + 2;
    }

    /* STUB */ len++;

    ngx_test_null(h, ngx_create_temp_hunk(r->pool, len, 0, 0), NULL);
    ngx_alloc_link_and_set_hunk(chain, h, r->pool, NULL);


    /* the request line */

    h->last = ngx_cpymem(h->last, http_methods[p->method - 1].data,
                         http_methods[p->method - 1].len);

    h->last = ngx_cpymem(h->last, u->uri.data, u->uri.len);

    h->last = ngx_cpymem(h->last,
                         r->uri.data + u->location->len,
                         r->uri.len - u->location->len);

    if (r->args.len > 0) {
        *(h->last++) = '?';
        h->last = ngx_cpymem(h->last, r->args.data, r->args.len);
    }

    h->last = ngx_cpymem(h->last, http_version, sizeof(http_version) - 1);


    /* "Host" header */

    h->last = ngx_cpymem(h->last, host_header, sizeof(host_header) - 1);
    h->last = ngx_cpymem(h->last, u->host_header.data, u->host_header.len);
    *(h->last++) = CR; *(h->last++) = LF;


    /* "Connection: close" header */

    h->last = ngx_cpymem(h->last, connection_close_header,
                         sizeof(connection_close_header) - 1);


    for (i = 0; i < r->headers_in.headers->nelts; i++) {

        if (&header[i] == r->headers_in.host) {
            continue;
        }

        if (&header[i] == r->headers_in.connection) {
            continue;
        }

        if (&header[i] == r->headers_in.keep_alive) {
            continue;
        }

        h->last = ngx_cpymem(h->last, header[i].key.data, header[i].key.len);

        *(h->last++) = ':'; *(h->last++) = ' ';

        h->last = ngx_cpymem(h->last, header[i].value.data,
                             header[i].value.len);

        *(h->last++) = CR; *(h->last++) = LF;

        ngx_log_debug(r->connection->log, "proxy: '%s: %s'" _
                      header[i].key.data _ header[i].value.data);
    }

    /* add "\r\n" at the header end */
    *(h->last++) = CR; *(h->last++) = LF;

    /* STUB */ *(h->last) = '\0';
    ngx_log_debug(r->connection->log, "PROXY:\n'%s'" _ h->pos);

    return chain;
}


static void ngx_http_proxy_send_request_handler(ngx_event_t *wev)
{
    ngx_connection_t      *c;
    ngx_http_proxy_ctx_t  *p;

    c = wev->data;
    p = c->data;

    p->action = "sending request to upstream";

    if (wev->timedout) {
        p->timedout = 1;
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_TIMEOUT);
        return;
    }

    ngx_http_proxy_send_request(p);

    return;
}


static void ngx_http_proxy_send_request(ngx_http_proxy_ctx_t *p)
{
    int                      rc;
    ngx_chain_t             *cl;
    ngx_connection_t        *c;

    c = p->upstream.connection;

    for ( ;; ) {

        if (c) {
            p->output_chain_ctx->output_ctx = c;
            rc = ngx_output_chain(p->output_chain_ctx,
                                  p->request->request_hunks);

            if (rc != NGX_ERROR) {
                p->request_sent = 1;

                if (c->write->timer_set) {
                    ngx_del_timer(c->write);
                }

                if (rc == NGX_AGAIN) {
                    ngx_add_timer(c->write, p->lcf->send_timeout);

                } else {
                    /* TODO: del event */

                    if (c->tcp_nopush) {
                        if (ngx_tcp_push(c->fd) == NGX_ERROR) {
                            ngx_log_error(NGX_LOG_CRIT, c->log,
                                          ngx_socket_errno,
                                          ngx_tcp_push_n " failed");
                            ngx_http_proxy_finalize_request(p,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                            return; 
                        }
                        c->tcp_nopush = 0;
                    }
                }

                return;
            }

            ngx_event_connect_peer_failed(&p->upstream);
            ngx_http_proxy_close_connection(c);
        }

        for ( ;; ) {
            rc = ngx_event_connect_peer(&p->upstream);

            if (rc == NGX_ERROR) {
                ngx_http_proxy_finalize_request(p,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (rc == NGX_CONNECT_ERROR) {
                ngx_event_connect_peer_failed(&p->upstream);

                if (p->upstream.tries == 0) {
                    ngx_http_proxy_finalize_request(p, NGX_HTTP_BAD_GATEWAY);
                    return;
                }

                continue;
            }

            p->upstream.connection->data = p;
            p->upstream.connection->write->event_handler =
                                           ngx_http_proxy_send_request_handler;
            p->upstream.connection->read->event_handler =
                                   ngx_http_proxy_process_upstream_status_line;

            c = p->upstream.connection;
            c->pool = p->request->pool;
            c->read->log = c->write->log = c->log = p->request->connection->log;

            if (p->upstream.tries > 1 && p->request_sent) {

                /* reinit the request chain */

                for (cl = p->request->request_hunks; cl; cl = cl->next) {
                    cl->hunk->pos = cl->hunk->start;
                }
            }

            p->request_sent = 0;
            p->timedout = 0;

            if (rc == NGX_OK) {
                break;
            }

            /* rc == NGX_AGAIN */

            ngx_add_timer(c->write, p->lcf->connect_timeout);

            return;
        }
    }
}


static void ngx_http_proxy_process_upstream_status_line(ngx_event_t *rev)
{
    int                    rc;
    ssize_t                n;
    ngx_connection_t      *c;
    ngx_http_proxy_ctx_t  *p;

    c = rev->data;
    p = c->data;

    p->action = "reading upstream status line";

    ngx_log_debug(rev->log, "http proxy process status line");

    if (rev->timedout) {
        p->timedout = 1;
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_TIMEOUT);
        return;
    }

    if (p->header_in == NULL) {
        p->header_in = ngx_create_temp_hunk(p->request->pool,
                                            p->lcf->header_buffer_size,
                                            0, 0);
        if (p->header_in == NULL) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        p->header_in->tag = (ngx_hunk_tag_t) &ngx_http_proxy_module;
    }

    n = ngx_http_proxy_read_upstream_header(p);

    if (n == NGX_ERROR) {
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_ERROR);
        return;
    }

    if (n == NGX_AGAIN) {
        return;
    }

    rc = ngx_http_proxy_parse_status_line(p);

    if (rc == NGX_AGAIN) {
        if (p->header_in->pos == p->header_in->last) {
            ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                          "upstream sent too long status line");
            ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_HTTP_HEADER);
        }

        return;
    }

    if (rc == NGX_HTTP_PROXY_PARSE_NO_HEADER) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "upstream sent no valid HTTP/1.0 header");

        if (p->accel) {
            ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_HTTP_HEADER);

        } else {
            p->request->http_version = NGX_HTTP_VERSION_9;
            p->status = NGX_HTTP_OK;
            ngx_http_proxy_send_response(p);
        }

        return;
    }

    /* rc == NGX_OK */

    if (p->status == NGX_HTTP_INTERNAL_SERVER_ERROR
        && p->upstream.tries > 1
        && (p->lcf->next_upstream & NGX_HTTP_PROXY_FT_HTTP_500))
    {
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_HTTP_500);
        return;
    }

    p->status_line.len = p->status_end - p->status_start;
    p->status_line.data = ngx_palloc(p->request->pool, p->status_line.len + 1);
    if (p->status_line.data == NULL) {
        ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_cpystrn(p->status_line.data, p->status_start, p->status_line.len + 1);

    ngx_log_debug(rev->log, "http proxy status %d '%s'" _
                  p->status _ p->status_line.data);

    if (p->headers_in.headers) {
        p->headers_in.headers->nelts = 0;
    } else {
        p->headers_in.headers = ngx_create_table(p->request->pool, 10);
    }

    c->read->event_handler = ngx_http_proxy_process_upstream_headers;
    ngx_http_proxy_process_upstream_headers(rev);

    return;
}


static void ngx_http_proxy_process_upstream_headers(ngx_event_t *rev)
{
    int                    i, rc;
    ssize_t                n;
    ngx_table_elt_t       *h;
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    c = rev->data;
    p = c->data;
    r = p->request;

    p->action = "reading upstream headers";

    ngx_log_debug(rev->log, "http proxy process header line");

    if (rev->timedout) {
        p->timedout = 1;
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_TIMEOUT);
        return;
    }

    rc = NGX_AGAIN;

    for ( ;; ) {
        if (rc == NGX_AGAIN) {
            n = ngx_http_proxy_read_upstream_header(p);

            if (n == NGX_ERROR) {
                ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_ERROR);
                return;
            }

            if (n == NGX_AGAIN) {
                return;
            }
        }

        rc = ngx_http_parse_header_line(p->request, p->header_in);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_push_table(p->headers_in.headers);
            if (h == NULL) {
                ngx_http_proxy_finalize_request(p,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_palloc(p->request->pool,
                                     h->key.len + 1 + h->value.len + 1);
            if (h->key.data == NULL) {
                ngx_http_proxy_finalize_request(p,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            h->value.data = h->key.data + h->key.len + 1;
            ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);
            ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

            for (i = 0; headers_in[i].name.len != 0; i++) {
                if (headers_in[i].name.len != h->key.len) {
                    continue;
                }

                if (ngx_strcasecmp(headers_in[i].name.data, h->key.data) == 0) {
                    *((ngx_table_elt_t **)
                        ((char *) &p->headers_in + headers_in[i].offset)) = h;
                    break;
                }
            }

            ngx_log_debug(c->log, "HTTP proxy header: '%s: %s'" _
                          h->key.data _ h->value.data);

            continue;

        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug(c->log, "HTTP header done");

            ngx_http_proxy_send_response(p);

            return;

        } else if (rc != NGX_AGAIN) {

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      upstream_header_errors[rc - NGX_HTTP_PARSE_HEADER_ERROR]);

            ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_HTTP_HEADER);
            return;
        }

        /* NGX_AGAIN: a header line parsing is still not complete */

        if (p->header_in->last == p->header_in->end) {
            ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                          "upstream sent too big header");

            ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_HTTP_HEADER);
            return;
        }
    }
}


static ssize_t ngx_http_proxy_read_upstream_header(ngx_http_proxy_ctx_t *p)
{
    ssize_t       n;
    ngx_event_t  *rev;

    rev = p->upstream.connection->read;

    n = p->header_in->last - p->header_in->pos;

    if (n > 0) {
#if 0
        /* TODO THINK */
        rev->ready = 0;
#endif
        return n;
    }

    n = ngx_recv(p->upstream.connection, p->header_in->last,
                 p->header_in->end - p->header_in->last);

    if (n == NGX_AGAIN) {
        ngx_add_timer(rev, p->lcf->read_timeout);

        if (ngx_handle_read_event(rev) == NGX_ERROR) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "upstream closed prematurely connection");
    }

    if (n == 0 || n == NGX_ERROR) {
        return NGX_ERROR;
    }

    p->header_in->last += n;

    return n;
}


static void ngx_http_proxy_send_response(ngx_http_proxy_ctx_t *p)
{
    int                  rc, i;
    ngx_table_elt_t     *ch, *ph;
    ngx_event_pipe_t    *ep;
    ngx_http_request_t  *r;

    r = p->request;

    r->headers_out.content_length_n = -1;
    r->headers_out.content_length = NULL;

    /* copy an upstream header to r->headers_out */

    ph = (ngx_table_elt_t *) p->headers_in.headers->elts;
    for (i = 0; i < p->headers_in.headers->nelts; i++) {

        if (&ph[i] == p->headers_in.connection) {
            continue;
        }

        if (p->accel) {
            if (&ph[i] == p->headers_in.date
                || &ph[i] == p->headers_in.accept_ranges) {
                continue;
            }
        }

        ch = ngx_push_table(r->headers_out.headers);
        if (ch == NULL) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        *ch = ph[i];

        if (&ph[i] == p->headers_in.content_type) {
            r->headers_out.content_type = ch;
            r->headers_out.content_type->key.len = 0;
            continue;
        }

        if (&ph[i] == p->headers_in.content_length) {
            r->headers_out.content_length_n =
                             ngx_atoi(p->headers_in.content_length->value.data,
                                      p->headers_in.content_length->value.len);
            r->headers_out.content_length = ch;
            continue;
        }
    }

    /* STUB */

    if (p->headers_in.server) {
        r->headers_out.server = p->headers_in.server;
    }

    if (!p->accel && p->headers_in.date) {
        r->headers_out.date = p->headers_in.date;
    }

    /* */


    /* TODO: preallocate event_pipe hunks, look "Content-Length" */

    r->headers_out.status = p->status;

    rc = ngx_http_send_header(r);

    p->header_sent = 1;

    ep = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (ep == NULL) {
        ngx_http_proxy_finalize_request(p, 0);
        return;
    }

    ep->input_filter = ngx_event_pipe_copy_input_filter;
    ep->output_filter = (ngx_event_pipe_output_filter_pt)
                                                        ngx_http_output_filter;
    ep->output_ctx = r;
    ep->tag = (ngx_hunk_tag_t) &ngx_http_proxy_module;
    ep->bufs = p->lcf->bufs;
    ep->busy_size = p->lcf->busy_buffers_size;
    ep->upstream = p->upstream.connection;
    ep->downstream = r->connection;
    ep->pool = r->pool;
    ep->log = r->connection->log;
    ep->temp_path = p->lcf->temp_path;

    ep->temp_file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (ep->temp_file == NULL) {
        ngx_http_proxy_finalize_request(p, 0);
        return;
    }

    ep->temp_file->fd = NGX_INVALID_FILE;
    ep->temp_file->log = r->connection->log;

    ep->max_temp_file_size = p->lcf->max_temp_file_size;
    ep->temp_file_write_size = p->lcf->temp_file_write_size;
    ep->temp_file_warn = "an upstream response is buffered "
                         "to a temporary file";

    ep->preread_hunks = ngx_alloc_chain_link(r->pool);
    if (ep->preread_hunks == NULL) {
        ngx_http_proxy_finalize_request(p, 0);
        return;
    }
    ep->preread_hunks->hunk = p->header_in;
    ep->preread_hunks->next = NULL;

    ep->preread_size = p->header_in->last - p->header_in->pos;

    /*
     * event_pipe would do p->header_in->last += ep->preread_size
     * as though these bytes were read.
     */
    p->header_in->last = p->header_in->pos;

    /* STUB */ ep->cachable = 0;

    if (p->lcf->cyclic_temp_file) {

        /*
         * we need to disable the use of sendfile() if we use cyclic temp file
         * because the writing a new data can interfere with sendfile()
         * that uses the same kernel file pages (at least on FreeBSD)
         */

        ep->cyclic_temp_file = 1;
        r->sendfile = 0;

    } else {
        ep->cyclic_temp_file = 0;
        r->sendfile = 1;
    }

    p->event_pipe = ep;

    p->upstream.connection->read->event_handler = ngx_http_proxy_process_body;
    r->connection->write->event_handler = ngx_http_proxy_process_body;

    ngx_http_proxy_process_body(p->upstream.connection->read);

    return;
}


static void ngx_http_proxy_process_body(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;
    ngx_event_pipe_t      *ep;

    c = ev->data;

    if (ev->write) {
        ngx_log_debug(ev->log, "http proxy process downstream");
        r = c->data;
        p = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
        p->action = "sending to client";

    } else {
        ngx_log_debug(ev->log, "http proxy process upstream");
        p = c->data;
        r = p->request;
        p->action = "reading upstream body";
    }

    ep = p->event_pipe;

    if (ev->timedout) {
        if (ev->write) {
            ep->downstream_error = 1;
            ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                          "client timed out");

        } else {
            ep->upstream_error = 1;
            ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                          "upstream timed out");
        }

    } else {
        if (ngx_event_pipe(ep, ev->write) == NGX_ABORT) {
            ngx_http_proxy_finalize_request(p, 0);
            return;
        }
    }

    if (p->upstream.connection) {
        if (ep->upstream_done) {
            /* TODO: update cache */

        } else if (ep->upstream_eof) {
            /* TODO: check length & update cache */
        }

        if (ep->upstream_done || ep->upstream_eof || ep->upstream_error) {
            ngx_http_proxy_close_connection(p->upstream.connection);
            p->upstream.connection = NULL;
        }
    }

    if (ep->downstream_done) {
        ngx_log_debug(ev->log, "http proxy downstream done");
        ngx_http_proxy_finalize_request(p, r->main ? 0 : ngx_http_send_last(r));
        return;
    }

    if (ep->downstream_error) {
        if (!p->cachable && p->upstream.connection) {
            ngx_http_proxy_close_connection(p->upstream.connection);
            p->upstream.connection = NULL;
        }
 
        if (p->upstream.connection == NULL) {
            ngx_http_close_connection(c);
        }
    }

    return;
}


static int ngx_http_proxy_parse_status_line(ngx_http_proxy_ctx_t *p)
{
    char   ch;
    char  *pos;
    enum  {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done,
        sw_done
    } state;

    state = p->state;
    pos = p->header_in->pos;

    while (pos < p->header_in->last && state < sw_done) {
        ch = *pos++;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            p->status = p->status * 10 + ch - '0';

            if (++p->status_count == 3) {
                state = sw_space_after_status;
                p->status_start = pos - 3;
            }

            break;

         /* space or end of line */
         case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                state = sw_done;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                state = sw_done;
                break;
            }
            break;

        /* end of request line */
        case sw_almost_done:
            p->status_end = pos - 2;
            switch (ch) {
            case LF:
                state = sw_done;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;
        }
    }

    p->header_in->pos = pos;

    if (state == sw_done) {
        if (p->status_end == NULL) {
            p->status_end = pos - 1;
        }

        p->state = sw_start;
        return NGX_OK;
    }

    p->state = state;
    return NGX_AGAIN;
}


static void ngx_http_proxy_next_upstream(ngx_http_proxy_ctx_t *p, int ft_type)
{
    ngx_event_connect_peer_failed(&p->upstream);

    if (p->timedout) {
        ngx_log_error(NGX_LOG_ERR, p->request->connection->log, NGX_ETIMEDOUT,
                      "upstream timed out");
    }

    if (p->upstream.connection) {
        ngx_http_proxy_close_connection(p->upstream.connection);
        p->upstream.connection = NULL;
    }

    if (p->upstream.tries == 0 || !(p->lcf->next_upstream & ft_type)) {
        ngx_http_proxy_finalize_request(p,
                                        p->timedout ? NGX_HTTP_GATEWAY_TIME_OUT:
                                                      NGX_HTTP_BAD_GATEWAY);
        return;
    }

    if (!p->fatal_error) {
        ngx_http_proxy_send_request(p);
        return;
    }

ngx_log_debug(p->request->connection->log, "FATAL ERROR IN NEXT UPSTREAM");

    return;
}

static void ngx_http_proxy_finalize_request(ngx_http_proxy_ctx_t *p, int rc)
{
    if (p->upstream.connection) {
        ngx_http_proxy_close_connection(p->upstream.connection);
        p->upstream.connection = NULL;
    }

    if (p->header_sent
        && (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE))
    {
        rc = 0;
    }

    p->request->connection->log->data = p->saved_ctx;
    p->request->connection->log->handler = p->saved_handler;

    ngx_http_finalize_request(p->request, rc);

    p->fatal_error = 1;

    return;
}



static void ngx_http_proxy_close_connection(ngx_connection_t *c)
{
    ngx_log_debug(c->log, "close connection: %d" _ c->fd);

    if (c->fd == -1) {
#if 0
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "connection already closed");
#endif
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    /* TODO: move connection to the connection pool */

    if (ngx_del_conn) {
        ngx_del_conn(c);

    } else {
        if (c->read->active) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
        }

        if (c->write->active) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
    }

    if (ngx_close_socket(c->fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    c->fd = -1;

    return;
}


static size_t ngx_http_proxy_log_error(void *data, char *buf, size_t len)
{
    ngx_http_proxy_ctx_t *p = data;

    return ngx_snprintf(buf, len,
            " while %s, client: %s, URL: %s, upstream: %s%s%s%s%s",
            p->action,
            p->request->connection->addr_text.data,
            p->request->unparsed_uri.data,
            p->upstream.peers->peers[p->upstream.cur_peer].addr_port_text.data,
            p->lcf->upstream->uri.data,
            p->request->uri.data + p->lcf->upstream->location->len,
            p->request->args.len ? "?" : "",
            p->request->args.len ? p->request->args.data : "");
}


static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_loc_conf_t  *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_loc_conf_t)),
                  NGX_CONF_ERROR);

    /* set by ngx_pcalloc():

    conf->bufs.num = 0;

    conf->path = NULL;

    conf->upstreams = NULL;
    conf->peers = NULL;

    */

    conf->request_buffer_size = NGX_CONF_UNSET;
    conf->connect_timeout = NGX_CONF_UNSET;
    conf->send_timeout = NGX_CONF_UNSET;
    conf->header_buffer_size = NGX_CONF_UNSET;
    conf->read_timeout = NGX_CONF_UNSET;
    conf->busy_buffers_size = NGX_CONF_UNSET;

    /*
     * "proxy_max_temp_file_size" is hardcoded to 1G for reverse proxy,
     * it should be configurable in the generic proxy
     */
    conf->max_temp_file_size = 1024 * 1024 * 1024;

    conf->temp_file_write_size = NGX_CONF_UNSET;

    /* "proxy_cyclic_temp_file" is disabled */
    conf->cyclic_temp_file = 0;

    conf->next_upstream = NGX_CONF_UNSET;

    return conf;
}


static char *ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf,
                                           void *parent, void *child)
{
    ngx_http_proxy_loc_conf_t *prev = parent;
    ngx_http_proxy_loc_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->request_buffer_size,
                              prev->request_buffer_size, 8192);
    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 30000);
    ngx_conf_merge_size_value(conf->header_buffer_size,
                              prev->header_buffer_size, 4096);
    ngx_conf_merge_msec_value(conf->read_timeout, prev->read_timeout, 30000);
    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 8, 4096);
    ngx_conf_merge_size_value(conf->busy_buffers_size,
                              prev->busy_buffers_size, 8192);

#if 0
    if (conf->max_temp_file_size > conf->bufs.size) {
        return "\"proxy_max_temp_file\" must be greater "
               "than one of the \"proxy_buffers\"";
    }
#endif

    ngx_conf_merge_size_value(conf->temp_file_write_size,
                              prev->temp_file_write_size, 16384);

    ngx_conf_merge_value(conf->next_upstream, prev->next_upstream,
                         (NGX_HTTP_PROXY_FT_ERROR|NGX_HTTP_PROXY_FT_TIMEOUT));

    ngx_conf_merge_path_value(conf->temp_path, prev->temp_path,
                              "temp", 1, 2, 0, cf->pool);

    return NULL;
}



static char *ngx_http_proxy_set_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf)
{
    ngx_http_proxy_loc_conf_t *lcf = conf;

    int                        i, len;
    char                      *err, *host;
    ngx_str_t                 *value;
    struct hostent            *h;
    u_int32_t                  addr;
    ngx_http_conf_ctx_t       *ctx;
    ngx_http_core_loc_conf_t  *clcf;


    value = cf->args->elts;

    if (ngx_strncasecmp(value[1].data, "http://", 7) != 0) {
        return "invalid URL prefix";
    }

    ngx_test_null(lcf->upstream,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_upstream_t)),
                  NGX_CONF_ERROR);

    value[1].data += 7;
    value[1].len -= 7;

    err = ngx_http_proxy_parse_upstream(&value[1], lcf->upstream);

    if (err) {
        return err;
    }

    ngx_test_null(host, ngx_palloc(cf->pool, lcf->upstream->host.len + 1),
                  NGX_CONF_ERROR);
    ngx_cpystrn(host, lcf->upstream->host.data, lcf->upstream->host.len + 1);

    addr = inet_addr(host);

    if (addr == INADDR_NONE) {
        h = gethostbyname(host);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "host %s not found", host);
            return NGX_CONF_ERROR;
        }

        for (i = 0; h->h_addr_list[i] != NULL; i++) { /* void */ }

        /* MP: ngx_shared_palloc() */

        ngx_test_null(lcf->peers,
                      ngx_pcalloc(cf->pool,
                                  sizeof(ngx_peers_t)
                                  + sizeof(ngx_peer_t) * (i - 1)),
                      NGX_CONF_ERROR);

        lcf->peers->number = i;

        for (i = 0; h->h_addr_list[i] != NULL; i++) {
            lcf->peers->peers[i].host.data = host;
            lcf->peers->peers[i].host.len = lcf->upstream->host.len;
            lcf->peers->peers[i].addr = *(u_int32_t *)(h->h_addr_list[i]);
            lcf->peers->peers[i].port = lcf->upstream->port;

            len = INET_ADDRSTRLEN + lcf->upstream->port_text.len + 1;
            ngx_test_null(lcf->peers->peers[i].addr_port_text.data,
                          ngx_palloc(cf->pool, len),
                          NGX_CONF_ERROR);

            len = ngx_inet_ntop(AF_INET,
                                (char *) &lcf->peers->peers[i].addr,
                                lcf->peers->peers[i].addr_port_text.data,
                                len);

            lcf->peers->peers[i].addr_port_text.data[len++] = ':';

            ngx_cpystrn(lcf->peers->peers[i].addr_port_text.data + len,
                        lcf->upstream->port_text.data,
                        lcf->upstream->port_text.len + 1);

            lcf->peers->peers[i].addr_port_text.len =
                                        len + lcf->upstream->port_text.len + 1;
        }

    } else {

        /* MP: ngx_shared_palloc() */

        ngx_test_null(lcf->peers, ngx_pcalloc(cf->pool, sizeof(ngx_peers_t)),
                      NGX_CONF_ERROR);

        lcf->peers->number = 1;

        lcf->peers->peers[0].host.data = host;
        lcf->peers->peers[0].host.len = lcf->upstream->host.len;
        lcf->peers->peers[0].addr = addr;
        lcf->peers->peers[0].port = lcf->upstream->port;

        len = lcf->upstream->host.len + lcf->upstream->port_text.len + 1;

        ngx_test_null(lcf->peers->peers[0].addr_port_text.data,
                      ngx_palloc(cf->pool, len + 1),
                      NGX_CONF_ERROR);

        len = lcf->upstream->host.len;

        ngx_memcpy(lcf->peers->peers[0].addr_port_text.data,
                   lcf->upstream->host.data, len);

        lcf->peers->peers[0].addr_port_text.data[len++] = ':';

        ngx_cpystrn(lcf->peers->peers[0].addr_port_text.data + len,
                    lcf->upstream->port_text.data,
                    lcf->upstream->port_text.len + 1);
    }

    ctx = cf->ctx;
    clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
    lcf->upstream->location = &clcf->name;
    clcf->handler = ngx_http_proxy_handler;

    return NULL;
}


static char *ngx_http_proxy_parse_upstream(ngx_str_t *url,
                                           ngx_http_proxy_upstream_t *u)
{
    size_t  i;

    if (url->data[0] == ':' || url->data[0] == '/') {
        return "invalid upstream URL";
    }

    u->host.data = url->data;
    u->host_header.data = url->data;

    for (i = 1; i < url->len; i++) {
        if (url->data[i] == ':') {
            u->port_text.data = &url->data[i] + 1;
            u->host.len = i;
        }

        if (url->data[i] == '/') {
            u->uri.data = &url->data[i];
            u->uri.len = url->len - i;
            u->host_header.len = i;

            if (u->host.len == 0) {
                u->host.len = i;
            }

            if (u->port_text.data == NULL) {
                u->port = htons(80);
                u->port_text.len = 2;
                u->port_text.data = "80";
                return NULL;
            }

            u->port_text.len = &url->data[i] - u->port_text.data;

            if (u->port_text.len > 0) {
                u->port = ngx_atoi(u->port_text.data, u->port_text.len);
                if (u->port > 0) {
                    u->port = htons((u_short) u->port);
                    return NULL;
                }
            }

            return "invalid port in upstream URL";
        }
    }

    if (u->host.len == 0) {
        u->host.len = i;
    }

    u->host_header.len = i;

    u->uri.data = "/";
    u->uri.len = 1;

    if (u->port_text.data == NULL) {
        u->port = htons(80);
        u->port_text.len = 2;
        u->port_text.data = "80";
        return NULL;
    }

    u->port_text.len = &url->data[i] - u->port_text.data;

    if (u->port_text.len > 0) {
        u->port = ngx_atoi(u->port_text.data, u->port_text.len);
        if (u->port > 0) {
            u->port = htons((u_short) u->port);
            return NULL;
        }
    }

    return "invalid port in upstream URL";
}
