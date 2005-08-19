
/*  
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


typedef struct ngx_http_proxy_redirect_s  ngx_http_proxy_redirect_t;

typedef ngx_int_t (*ngx_http_proxy_redirect_pt)(ngx_http_request_t *r,
    ngx_table_elt_t *h, size_t prefix, ngx_http_proxy_redirect_t *pr);

struct ngx_http_proxy_redirect_s {
    ngx_http_proxy_redirect_pt   handler;
    ngx_str_t                    redirect;

    union {
        ngx_str_t                text;

        struct {
            void                *lengths;
            void                *values;
        } vars;

        void                    *regex;
    } replacement;
};


typedef struct {
    ngx_http_upstream_conf_t     upstream;

    ngx_peers_t                 *peers;

    ngx_array_t                 *headers_set_len;
    ngx_array_t                 *headers_set;
    ngx_hash_t                  *headers_set_hash;

    ngx_array_t                 *headers_source;
    ngx_array_t                 *headers_names;

    ngx_array_t                 *redirects;

    ngx_str_t                    host_header;
    ngx_str_t                    port_text;

    ngx_flag_t                   redirect;
} ngx_http_proxy_loc_conf_t;


typedef struct {
    ngx_uint_t                   status;
    ngx_uint_t                   status_count;
    u_char                      *status_start;
    u_char                      *status_end;
} ngx_http_proxy_ctx_t;


#define NGX_HTTP_PROXY_PARSE_NO_HEADER  20


static ngx_int_t ngx_http_proxy_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_parse_status_line(ngx_http_request_t *r,
    ngx_http_proxy_ctx_t *p);
static ngx_int_t ngx_http_proxy_process_header(ngx_http_request_t *r);
static void ngx_http_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http_proxy_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_http_variable_value_t *
    ngx_http_proxy_host_variable(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_proxy_port_variable(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_proxy_add_x_forwarded_for_variable(ngx_http_request_t *r,
    uintptr_t data);
static ngx_int_t ngx_http_proxy_rewrite_redirect(ngx_http_request_t *r,
    ngx_table_elt_t *h, size_t prefix);

static ngx_int_t ngx_http_proxy_add_variables(ngx_conf_t *cf);
static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data);


static ngx_conf_post_t  ngx_http_proxy_lowat_post =
    { ngx_http_proxy_lowat_check };

static ngx_conf_enum_t  ngx_http_proxy_set_methods[] = {
    { ngx_string("get"), NGX_HTTP_GET },
    { ngx_null_string, 0 }
};

static ngx_conf_bitmask_t  ngx_http_proxy_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_proxy_commands[] = {

    { ngx_string("proxy_pass"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_redirect"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_proxy_redirect,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("proxy_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("proxy_send_lowat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.send_lowat),
      &ngx_http_proxy_lowat_post },

    { ngx_string("proxy_redirect_errors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.redirect_errors),
      NULL },

    { ngx_string("proxy_pass_unparsed_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_unparsed_uri),
      NULL },

    { ngx_string("proxy_set_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_table_elt_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, headers_source),
      NULL },

    { ngx_string("proxy_method"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.method),
      ngx_http_proxy_set_methods },

    { ngx_string("proxy_pass_request_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { ngx_string("proxy_pass_request_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_request_body),
      NULL },

    { ngx_string("proxy_header_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.header_buffer_size),
      NULL },

    { ngx_string("proxy_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("proxy_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.bufs),
      NULL },

    { ngx_string("proxy_busy_buffers_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { ngx_string("proxy_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.temp_path),
      (void *) ngx_garbage_collector_temp_handler },

    { ngx_string("proxy_max_temp_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { ngx_string("proxy_temp_file_write_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { ngx_string("proxy_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.next_upstream),
      &ngx_http_proxy_next_upstream_masks },

    { ngx_string("proxy_pass_x_powered_by"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_x_powered_by),
      NULL },

    { ngx_string("proxy_pass_server"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_server),
      NULL },

    { ngx_string("proxy_pass_x_accel_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_x_accel_expires),
      NULL },

      ngx_null_command
};


ngx_http_module_t  ngx_http_proxy_module_ctx = {
    ngx_http_proxy_add_variables,          /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_proxy_create_loc_conf,        /* create location configration */
    ngx_http_proxy_merge_loc_conf          /* merge location configration */
};


ngx_module_t  ngx_http_proxy_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_module_ctx,            /* module context */
    ngx_http_proxy_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init process */
};


static ngx_str_t ngx_http_proxy_methods[] = {
    ngx_string("GET "),
    ngx_string("HEAD "),
    ngx_string("POST ")
};


static char  ngx_http_proxy_version[] = " HTTP/1.0" CRLF;


static ngx_table_elt_t  ngx_http_proxy_headers[] = {
    { 0, ngx_string("Host"), ngx_string("$proxy_host") },
    { 0, ngx_string("Connection"), ngx_string("close") },
    { 0, ngx_null_string, ngx_null_string }
};


static ngx_http_variable_t  ngx_http_proxy_vars[] = {

    { ngx_string("proxy_host"), ngx_http_proxy_host_variable, 0,
      NGX_HTTP_VAR_CHANGABLE, 0 },

    { ngx_string("proxy_port"), ngx_http_proxy_port_variable, 0,
      NGX_HTTP_VAR_CHANGABLE, 0 },

    { ngx_string("proxy_add_x_forwarded_for"),
      ngx_http_proxy_add_x_forwarded_for_variable, 0, 0, 0 },

#if 0
    { ngx_string("proxy_add_via"), NULL, 0, 0, 0 },
#endif

    { ngx_null_string, NULL, 0, 0, 0 }
};


#if (NGX_PCRE)
static ngx_str_t ngx_http_proxy_uri = ngx_string("/");
#endif


static ngx_int_t
ngx_http_proxy_handler(ngx_http_request_t *r)
{   
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_loc_conf_t  *plcf;
    
    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    
    u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
    if (u == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;
    u->peer.peers = plcf->peers;
    u->peer.tries = plcf->peers->number;
#if (NGX_THREADS)
    u->peer.lock = &r->connection->lock;
#endif

    u->output.tag = (ngx_buf_tag_t) &ngx_http_proxy_module;

    u->conf = &plcf->upstream;

    u->create_request = ngx_http_proxy_create_request;
    u->reinit_request = ngx_http_proxy_reinit_request;
    u->process_header = ngx_http_proxy_process_status_line;
    u->abort_request = ngx_http_proxy_abort_request;
    u->finalize_request = ngx_http_proxy_finalize_request;

    if (plcf->redirects) {
        u->rewrite_redirect = ngx_http_proxy_rewrite_redirect;
    }

    u->pipe.input_filter = ngx_event_pipe_copy_input_filter;

    u->accel = 1;
    
    r->upstream = u;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_proxy_create_request(ngx_http_request_t *r)
{
    size_t                        len, loc_len;
    ngx_uint_t                    i, key;
    uintptr_t                     escape;
    ngx_buf_t                    *b;
    ngx_str_t                    *hh;
    ngx_chain_t                  *cl, *body;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_upstream_t          *u;
    ngx_http_script_code_pt       code;
    ngx_http_script_engine_t      e, le;
    ngx_http_proxy_loc_conf_t    *plcf;
    ngx_http_script_len_code_pt   lcode;

    u = r->upstream;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    len = sizeof(ngx_http_proxy_version) - 1 + sizeof(CRLF) - 1;

    if (u->method) {
        len += ngx_http_proxy_methods[u->method - 1].len + u->conf->uri.len;
    } else {
        len += r->method_name.len + 1 + u->conf->uri.len;
    }

    escape = 0;

    loc_len = r->valid_location ? u->conf->location->len : 1;

    if (plcf->upstream.pass_unparsed_uri && r->valid_unparsed_uri) {
        len += r->unparsed_uri.len - 1;

    } else {
        if (r->quoted_uri) {
            escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
                                        r->uri.len - loc_len, NGX_ESCAPE_URI);
        }

        len += r->uri.len - loc_len + escape + sizeof("?") - 1 + r->args.len;
    }

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    le.ip = plcf->headers_set_len->elts;
    le.request = r;

    while (*(uintptr_t *) le.ip) {
        while (*(uintptr_t *) le.ip) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            len += lcode(&le);
        }
        le.ip += sizeof(uintptr_t);
    }


    hh = (ngx_str_t *) plcf->headers_set_hash->buckets;

    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0; 
            }

            key = header[i].hash % plcf->headers_set_hash->hash_size;

            if (hh[key].len == header[i].key.len
                && ngx_strcasecmp(hh[key].data, header[i].key.data) == 0)
            {
                continue;
            }

            len += header[i].key.len + sizeof(": ") - 1
                + header[i].value.len + sizeof(CRLF) - 1;
        }
    }


    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;


    /* the request line */

    if (u->method) {
        b->last = ngx_cpymem(b->last,
                             ngx_http_proxy_methods[u->method - 1].data,
                             ngx_http_proxy_methods[u->method - 1].len);
    } else {
        b->last = ngx_cpymem(b->last, r->method_name.data,
                             r->method_name.len + 1);
    }

    b->last = ngx_cpymem(b->last, u->conf->uri.data, u->conf->uri.len);

    if (plcf->upstream.pass_unparsed_uri && r->valid_unparsed_uri) {
        b->last = ngx_cpymem(b->last, r->unparsed_uri.data + 1,
                             r->unparsed_uri.len - 1);
    } else {
        if (escape) {
            ngx_escape_uri(b->last, r->uri.data + loc_len,
                           r->uri.len - loc_len, NGX_ESCAPE_URI);
            b->last += r->uri.len - loc_len + escape;

        } else { 
            b->last = ngx_cpymem(b->last, r->uri.data + loc_len,
                                 r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *b->last++ = '?';
            b->last = ngx_cpymem(b->last, r->args.data, r->args.len);
        }
    }

    b->last = ngx_cpymem(b->last, ngx_http_proxy_version,
                         sizeof(ngx_http_proxy_version) - 1);


    e.ip = plcf->headers_set->elts;
    e.pos = b->last;
    e.request = r;

    le.ip = plcf->headers_set_len->elts;

    while (*(uintptr_t *) le.ip) {
        lcode = *(ngx_http_script_len_code_pt *) le.ip;

        /* skip the header line name length */
        (void) lcode(&le);

        if (*(ngx_http_script_len_code_pt *) le.ip) {

            for (len = 0; *(uintptr_t *) le.ip; len += lcode(&le)) {
                lcode = *(ngx_http_script_len_code_pt *) le.ip;
            }

            e.skip = (len == sizeof(CRLF) - 1) ? 1 : 0;

        } else {
            e.skip = 0;
        }

        le.ip += sizeof(uintptr_t);

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        } 
        e.ip += sizeof(uintptr_t);
    }

    b->last = e.pos;


    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;
    
        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0; 
            }

            key = header[i].hash % plcf->headers_set_hash->hash_size;

            if (hh[key].len == header[i].key.len
                && ngx_strcasecmp(hh[key].data, header[i].key.data) == 0)
            {
                continue;
            }

            b->last = ngx_cpymem(b->last, header[i].key.data,
                                 header[i].key.len);

            *b->last++ = ':'; *b->last++ = ' ';

            b->last = ngx_cpymem(b->last, header[i].value.data,
                                 header[i].value.len);

            *b->last++ = CR; *b->last++ = LF;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
    }

    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

#if (NGX_DEBUG)
    {
    ngx_str_t  s;

    s.len = b->last - b->pos;
    s.data = b->pos;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header:\n\"%V\"", &s);
    }
#endif

    if (plcf->upstream.pass_request_body) {

        body = u->request_bufs;
        u->request_bufs = cl;

        while (body) {
            b = ngx_alloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

            cl->next = ngx_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

    } else {
        u->request_bufs = cl;
    }

    cl->next = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_reinit_request(ngx_http_request_t *r)
{
    ngx_http_proxy_ctx_t  *p;

    p = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (p == NULL) {
        return NGX_OK;
    }

    p->status = 0;
    p->status_count = 0;
    p->status_start = NULL;
    p->status_end = NULL;

    r->upstream->process_header = ngx_http_proxy_process_status_line;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_process_status_line(ngx_http_request_t *r)
{
    ngx_int_t              rc;
    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *p;

    p = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (p == NULL) {
        p = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_ctx_t));
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, p, ngx_http_proxy_module);
    }

    rc = ngx_http_proxy_parse_status_line(r, p);

    if (rc == NGX_AGAIN) {
        return rc;
    }

    u = r->upstream;

    if (rc == NGX_HTTP_PROXY_PARSE_NO_HEADER) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent no valid HTTP/1.0 header"); 

        if (u->accel) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        r->http_version = NGX_HTTP_VERSION_9;
        p->status = NGX_HTTP_OK;
    
        return NGX_OK;
    }

    u->headers_in.status_n = p->status;
    u->state->status = p->status;

    u->headers_in.status_line.len = p->status_end - p->status_start;
    u->headers_in.status_line.data = ngx_palloc(r->pool,
                                                u->headers_in.status_line.len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(u->headers_in.status_line.data, p->status_start,
               u->headers_in.status_line.len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy status %ui \"%V\"",
                   u->headers_in.status, &u->headers_in.status_line);

    u->process_header = ngx_http_proxy_process_header;

    return ngx_http_proxy_process_header(r);
}


static ngx_int_t
ngx_http_proxy_parse_status_line(ngx_http_request_t *r, ngx_http_proxy_ctx_t *p)
{
    u_char                ch;
    u_char               *pos;
    ngx_http_upstream_t  *u;
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
        sw_almost_done
    } state; 

    u = r->upstream;

    state = r->state;

    for (pos = u->header_in.pos; pos < u->header_in.last; pos++) {
        ch = *pos;

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
                p->status_start = pos - 2;
            }

            break;

         /* space or end of line */
         case sw_space_after_status:
            switch (ch) {
            case ' ': 
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
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
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            p->status_end = pos - 1;
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
        }
    }

    u->header_in.pos = pos;
    r->state = state;

    return NGX_AGAIN;

done:

    u->header_in.pos = pos + 1;

    if (p->status_end == NULL) {
        p->status_end = pos;
    }

    r->state = sw_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_process_header(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_uint_t                      key;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    hh = (ngx_http_upstream_header_t *) umcf->headers_in_hash.buckets;

    for ( ;;  ) {

        rc = ngx_http_parse_header_line(r, &r->upstream->header_in);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_palloc(r->pool,
                                     h->key.len + 1 + h->value.len + 1);
            if (h->key.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;

            ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);
            ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

            key = h->hash % umcf->headers_in_hash.hash_size;

            if (hh[key].name.len == h->key.len
                && ngx_strcasecmp(hh[key].name.data, h->key.data) == 0)
            {
                if (hh[key].handler(r, h, hh[key].offset) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header done");

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* there was error while a header line parsing */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      ngx_http_upstream_header_errors[rc
                                               - NGX_HTTP_PARSE_HEADER_ERROR]);

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}


static void
ngx_http_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http proxy request");
    
    return;
}


static void
ngx_http_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{   
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http proxy request");

    return;
}


static ngx_http_variable_value_t *
ngx_http_proxy_host_variable(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *vv;
    ngx_http_proxy_loc_conf_t  *plcf;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    vv->value = 0;
    vv->text = plcf->host_header;

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_proxy_port_variable(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *vv;
    ngx_http_proxy_loc_conf_t  *plcf;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    vv->value = 0;
    vv->text = plcf->port_text;

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_proxy_add_x_forwarded_for_variable(ngx_http_request_t *r,
    uintptr_t data)
{
    u_char                     *p;
    ngx_http_variable_value_t  *vv;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;

    if (r->headers_in.x_forwarded_for == NULL) {
        vv->text = r->connection->addr_text;
        return vv;
    }

    vv->text.len = r->headers_in.x_forwarded_for->value.len
                   + sizeof(", ") - 1 + r->connection->addr_text.len;

    p = ngx_palloc(r->pool, vv->text.len);
    if (p == NULL) {
        return NULL;
    }

    vv->text.data = p;

    p = ngx_cpymem(p, r->headers_in.x_forwarded_for->value.data,
                   r->headers_in.x_forwarded_for->value.len);

    *p++ = ','; *p++ = ' ';

    ngx_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);

    return vv;
}


static ngx_int_t
ngx_http_proxy_rewrite_redirect(ngx_http_request_t *r, ngx_table_elt_t *h,
    size_t prefix)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_http_proxy_loc_conf_t  *plcf;
    ngx_http_proxy_redirect_t  *pr;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    pr = plcf->redirects->elts;

    if (pr == NULL) {
        return NGX_DECLINED;
    }

    for (i = 0; i < plcf->redirects->nelts; i++) {
        rc = pr->handler(r, h, prefix, pr);

        if (rc != NGX_DECLINED) {
            return rc;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_proxy_rewrite_redirect_text(ngx_http_request_t *r, ngx_table_elt_t *h,
    size_t prefix, ngx_http_proxy_redirect_t *pr)
{
    size_t   len;
    u_char  *data, *p;

    if (pr->redirect.len > h->value.len - prefix
        || ngx_rstrncmp(h->value.data + prefix, pr->redirect.data,
                        pr->redirect.len) != 0)
    {
        return NGX_DECLINED;
    }

    len = prefix + pr->replacement.text.len + h->value.len - pr->redirect.len;

    data = ngx_palloc(r->pool, len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;

    if (prefix) {
        p = ngx_cpymem(p, h->value.data, prefix);
    }

    p = ngx_cpymem(p, pr->replacement.text.data, pr->replacement.text.len);

    ngx_memcpy(p, h->value.data + prefix + pr->redirect.len,
               h->value.len - pr->redirect.len - prefix);

    h->value.len = len;
    h->value.data = data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_rewrite_redirect_vars(ngx_http_request_t *r, ngx_table_elt_t *h,
    size_t prefix, ngx_http_proxy_redirect_t *pr)
{
    size_t                        len;
    u_char                       *data, *p;
    ngx_http_script_code_pt       code;
    ngx_http_script_engine_t      e;
    ngx_http_script_len_code_pt   lcode;

    if (pr->redirect.len > h->value.len - prefix
        || ngx_rstrncmp(h->value.data + prefix, pr->redirect.data,
                        pr->redirect.len) != 0)
    {
        return NGX_DECLINED;
    }

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    e.ip = pr->replacement.vars.lengths;
    e.request = r;

    for (len = prefix; *(uintptr_t *) e.ip; len += lcode(&e)) {
        lcode = *(ngx_http_script_len_code_pt *) e.ip;
    }

    data = ngx_palloc(r->pool, len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;

    if (prefix) {
        p = ngx_cpymem(p, h->value.data, prefix);
    }

    e.ip = pr->replacement.vars.values;
    e.pos = p;

    while (*(uintptr_t *) e.ip) {
        code = *(ngx_http_script_code_pt *) e.ip;
        code(&e);
    }

    h->value.len = len;
    h->value.data = data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_proxy_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->handler = v->handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_proxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.path = NULL;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.schema = { 0, NULL };
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     *
     *     conf->headers_source = NULL;
     *     conf->headers_set_len = NULL;
     *     conf->headers_set = NULL;
     *     conf->headers_set_hash = NULL;
     *     conf->rewrite_locations = NULL;
     */
    
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.header_buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;  
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_unparsed_uri = NGX_CONF_UNSET;
    conf->upstream.method = NGX_CONF_UNSET_UINT;
    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;
    
    conf->upstream.redirect_errors = NGX_CONF_UNSET;

    /* "proxy_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.pass_x_powered_by = NGX_CONF_UNSET;
    conf->upstream.pass_server = NGX_CONF_UNSET;
    conf->upstream.pass_date = 0;
    conf->upstream.pass_x_accel_expires = NGX_CONF_UNSET;

    conf->redirect = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_proxy_loc_conf_t *prev = parent;
    ngx_http_proxy_loc_conf_t *conf = child;

    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    ngx_str_t                    *name;
    ngx_uint_t                    i;
    ngx_table_elt_t              *src, *s, *h;
    ngx_http_proxy_redirect_t    *pr;
    ngx_http_script_compile_t     sc;
    ngx_http_script_copy_code_t  *copy;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    ngx_conf_merge_size_value(conf->upstream.header_buffer_size,
                              prev->upstream.header_buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
                           "there must be at least 2 \"proxy_buffers\"");
        return NGX_CONF_ERROR;
    }
    

    size = conf->upstream.header_buffer_size;
    if (size < conf->upstream.bufs.size) { 
        size = conf->upstream.bufs.size;
    }


    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
                                         conf->upstream.busy_buffers_size_conf;
    }
    
    if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be equal or bigger than "
             "maximum of the value of \"proxy_header_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be less than "
             "the size of all \"proxy_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
                                      conf->upstream.temp_file_write_size_conf;
    }
    
    if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_temp_file_write_size\" must be equal or bigger than "
             "maximum of the value of \"proxy_header_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
                                        conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_max_temp_file_size\" must be equal to zero to disable "
             "the temporary files usage or must be equal or bigger than "
             "maximum of the value of \"fastcgi_header_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    ngx_conf_merge_path_value(conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              NGX_HTTP_PROXY_TEMP_PATH, 1, 2, 0,
                              ngx_garbage_collector_temp_handler, cf);

    ngx_conf_merge_value(conf->upstream.pass_unparsed_uri,
                              prev->upstream.pass_unparsed_uri, 0);

    if (conf->upstream.pass_unparsed_uri && conf->upstream.location->len > 1) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "\"proxy_pass_unparsed_uri\" can be set for "
                      "location \"/\" or given by regular expression.");
        return NGX_CONF_ERROR;
    }

    if (conf->upstream.method == NGX_CONF_UNSET_UINT) {
        conf->upstream.method = prev->upstream.method;
    }

    ngx_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    ngx_conf_merge_value(conf->upstream.redirect_errors,
                              prev->upstream.redirect_errors, 0);

    ngx_conf_merge_value(conf->upstream.pass_x_powered_by,
                              prev->upstream.pass_x_powered_by, 1);
    ngx_conf_merge_value(conf->upstream.pass_server,
                              prev->upstream.pass_server, 0);
    ngx_conf_merge_value(conf->upstream.pass_x_accel_expires,
                              prev->upstream.pass_x_accel_expires, 0);


    ngx_conf_merge_value(conf->redirect, prev->redirect, 1);

    if (conf->redirect) {

        if (conf->redirects == NULL) {
            conf->redirects = prev->redirects;
        }

        if (conf->redirects == NULL && conf->upstream.url.data) {

            conf->redirects = ngx_array_create(cf->pool, 1,
                                            sizeof(ngx_http_proxy_redirect_t));
            if (conf->redirects == NULL) {
                return NGX_CONF_ERROR;
            }

            pr = ngx_array_push(conf->redirects);
            if (pr == NULL) {
                return NGX_CONF_ERROR;
            }

            pr->handler = ngx_http_proxy_rewrite_redirect_text;
            pr->redirect = conf->upstream.url;
            pr->replacement.text = *conf->upstream.location;
        }
    }


    if (conf->peers == NULL) {
        conf->peers = prev->peers;
    }

    if (conf->headers_source == NULL) {
        conf->headers_source = prev->headers_source;
        conf->headers_set_len = prev->headers_set_len;
        conf->headers_set = prev->headers_set;
        conf->headers_set_hash = prev->headers_set_hash;
    }

    if (conf->headers_set_hash) {
        return NGX_CONF_OK;
    }


    conf->headers_names = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
    if (conf->headers_names == NULL) {
        return NGX_CONF_ERROR;
    }

    if (conf->headers_source == NULL) {
        conf->headers_source = ngx_array_create(cf->pool, 4,
                                                sizeof(ngx_table_elt_t));
        if (conf->headers_source == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    conf->headers_set_len = ngx_array_create(cf->pool, 64, 1);
    if (conf->headers_set_len == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->headers_set = ngx_array_create(cf->pool, 512, 1);
    if (conf->headers_set == NULL) {
        return NGX_CONF_ERROR;
    }


    src = conf->headers_source->elts;

    for (h = ngx_http_proxy_headers; h->key.len; h++) {

        for (i = 0; i < conf->headers_source->nelts; i++) {
            if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
                goto next;
            }
        }

        s = ngx_array_push(conf->headers_source);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }

        *s = *h;

        src = conf->headers_source->elts;

    next:

        continue;
    }

    for (i = 0; i < conf->headers_source->nelts; i++) {

        name = ngx_array_push(conf->headers_names);
        if (name == NULL) {
            return NGX_CONF_ERROR;
        }

        *name = src[i].key;

        if (src[i].value.len == 0) {
            continue;
        }

        if (ngx_http_script_variables_count(&src[i].value) == 0) {
            copy = ngx_array_push_n(conf->headers_set_len,
                                    sizeof(ngx_http_script_copy_code_t));
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = (ngx_http_script_code_pt)
                                                 ngx_http_script_copy_len_code;
            copy->len = src[i].key.len + sizeof(": ") - 1
                        + src[i].value.len + sizeof(CRLF) - 1;


            size = (sizeof(ngx_http_script_copy_code_t)
                       + src[i].key.len + sizeof(": ") - 1
                       + src[i].value.len + sizeof(CRLF) - 1
                       + sizeof(uintptr_t) - 1)
                    & ~(sizeof(uintptr_t) - 1);

            copy = ngx_array_push_n(conf->headers_set, size);
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = ngx_http_script_copy_code;
            copy->len = src[i].key.len + sizeof(": ") - 1
                        + src[i].value.len + sizeof(CRLF) - 1;

            p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);

            p = ngx_cpymem(p, src[i].key.data, src[i].key.len);
            *p++ = ':'; *p++ = ' ';
            p = ngx_cpymem(p, src[i].value.data, src[i].value.len);
            *p++ = CR; *p = LF;

        } else {
            copy = ngx_array_push_n(conf->headers_set_len,
                                    sizeof(ngx_http_script_copy_code_t));
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = (ngx_http_script_code_pt)
                                                 ngx_http_script_copy_len_code;
            copy->len = src[i].key.len + sizeof(": ") - 1;


            size = (sizeof(ngx_http_script_copy_code_t)
                    + src[i].key.len + sizeof(": ") - 1 + sizeof(uintptr_t) - 1)
                    & ~(sizeof(uintptr_t) - 1);

            copy = ngx_array_push_n(conf->headers_set, size);
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = ngx_http_script_copy_code;
            copy->len = src[i].key.len + sizeof(": ") - 1;

            p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
            p = ngx_cpymem(p, src[i].key.data, src[i].key.len);
            *p++ = ':'; *p = ' ';


            ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

            sc.cf = cf;
            sc.source = &src[i].value;
            sc.lengths = &conf->headers_set_len;
            sc.values = &conf->headers_set;

            if (ngx_http_script_compile(&sc) != NGX_OK) {
                return NGX_CONF_ERROR;
            }


            copy = ngx_array_push_n(conf->headers_set_len,
                                    sizeof(ngx_http_script_copy_code_t));
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = (ngx_http_script_code_pt)
                                                 ngx_http_script_copy_len_code;
            copy->len = sizeof(CRLF) - 1;


            size = (sizeof(ngx_http_script_copy_code_t)
                    + sizeof(CRLF) - 1 + sizeof(uintptr_t) - 1)
                    & ~(sizeof(uintptr_t) - 1);

            copy = ngx_array_push_n(conf->headers_set, size);
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = ngx_http_script_copy_code;
            copy->len = sizeof(CRLF) - 1;

            p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
            *p++ = CR; *p = LF;
        }

        code = ngx_array_push_n(conf->headers_set_len, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_CONF_ERROR;
        }

        *code = (uintptr_t) NULL;

        code = ngx_array_push_n(conf->headers_set, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_CONF_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = ngx_array_push_n(conf->headers_set_len, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_CONF_ERROR;
    }

    *code = (uintptr_t) NULL;


    conf->headers_set_hash = ngx_pcalloc(cf->pool, sizeof(ngx_hash_t));
    if (conf->headers_set_hash == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->headers_set_hash->max_size = 100;
    conf->headers_set_hash->bucket_limit = 1;
    conf->headers_set_hash->bucket_size = sizeof(ngx_str_t);
    conf->headers_set_hash->name = "proxy_headers";

    if (ngx_hash_init(conf->headers_set_hash, cf->pool,
              conf->headers_names->elts, conf->headers_names->nelts) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "proxy_headers hash size: %ui, "
                   "max buckets per entry: %ui",
                   conf->headers_set_hash->hash_size,
                   conf->headers_set_hash->min_buckets);

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_uint_t                   i;
    ngx_str_t                   *value, *url;
    ngx_inet_upstream_t          inet_upstream;
    ngx_http_core_loc_conf_t    *clcf;
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_unix_domain_upstream_t   unix_upstream;
#endif

    value = cf->args->elts;

    url = &value[1];

    if (ngx_strncasecmp(url->data, "http://", 7) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL prefix");
        return NGX_CONF_ERROR;
    }

    if (ngx_strncasecmp(url->data + 7, "unix:", 5) == 0) {

#if (NGX_HAVE_UNIX_DOMAIN)

        ngx_memzero(&unix_upstream, sizeof(ngx_unix_domain_upstream_t));

        unix_upstream.name = *url;
        unix_upstream.url.len = url->len - 7;
        unix_upstream.url.data = url->data + 7;
        unix_upstream.uri_part = 1;

        plcf->peers = ngx_unix_upstream_parse(cf, &unix_upstream);
        if (plcf->peers == NULL) {
            return NGX_CONF_ERROR;
        }

        plcf->peers->peer[0].uri_separator = ":";

        plcf->host_header.len = sizeof("localhost") - 1;
        plcf->host_header.data = (u_char *) "localhost";
        plcf->upstream.uri = unix_upstream.uri;

#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the unix domain sockets are not supported "
                           "on this platform");
        return NGX_CONF_ERROR;

#endif

    } else {
        ngx_memzero(&inet_upstream, sizeof(ngx_inet_upstream_t));

        inet_upstream.name = *url;
        inet_upstream.url.len = url->len - 7;
        inet_upstream.url.data = url->data + 7;
        inet_upstream.default_port_value = 80;
        inet_upstream.uri_part = 1;

        plcf->peers = ngx_inet_upstream_parse(cf, &inet_upstream);
        if (plcf->peers == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < plcf->peers->number; i++) {
            plcf->peers->peer[i].uri_separator = "";
        }

        plcf->host_header = inet_upstream.host_header;
        plcf->port_text = inet_upstream.port_text;
        plcf->upstream.uri = inet_upstream.uri;
    }

    plcf->upstream.schema.len = sizeof("http://") - 1;
    plcf->upstream.schema.data = (u_char *) "http://";

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_proxy_handler;

#if (NGX_PCRE)
    plcf->upstream.location = clcf->regex ? &ngx_http_proxy_uri : &clcf->name;
#else
    plcf->upstream.location = &clcf->name;
#endif

    plcf->upstream.url = *url;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_str_t                  *value;
    ngx_array_t                *vars_lengths, *vars_values;
    ngx_http_script_compile_t   sc;
    ngx_http_proxy_redirect_t  *pr;

    if (plcf->redirect == 0) {
        return NGX_CONF_OK;
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        plcf->redirect = 0;
        plcf->redirects = NULL;
        return NGX_CONF_OK;
    }

    if (plcf->redirects == NULL) {
        plcf->redirects = ngx_array_create(cf->pool, 1,
                                           sizeof(ngx_http_proxy_redirect_t));
        if (plcf->redirects == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pr = ngx_array_push(plcf->redirects);
    if (pr == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "default") == 0) {
        if (plcf->upstream.url.data == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"proxy_rewrite_location default\" must go "
                               "after the \"proxy_pass\" directive");
            return NGX_CONF_ERROR;
        }

        pr->handler = ngx_http_proxy_rewrite_redirect_text;
        pr->redirect = plcf->upstream.url;
        pr->replacement.text = *plcf->upstream.location;

        return NGX_CONF_OK;
    }

    if (ngx_http_script_variables_count(&value[2]) == 0) {
        pr->handler = ngx_http_proxy_rewrite_redirect_text;
        pr->redirect = value[1];
        pr->replacement.text = value[2];

        return NGX_CONF_OK;
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    vars_lengths = NULL;
    vars_values = NULL;

    sc.cf = cf;
    sc.source = &value[2];
    sc.lengths = &vars_lengths;
    sc.values = &vars_values;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    pr->handler = ngx_http_proxy_rewrite_redirect_vars;
    pr->redirect = value[1];
    pr->replacement.vars.lengths = vars_lengths->elts;
    pr->replacement.vars.values = vars_values->elts;

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if (*np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"proxy_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"proxy_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}
