
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>



typedef struct {
    ngx_str_t                   name;
    ngx_array_t                *ops;        /* array of ngx_http_log_op_t */
} ngx_http_log_fmt_t;


typedef struct {
    ngx_array_t                 formats;    /* array of ngx_http_log_fmt_t */
    ngx_uint_t                  combined_used; /* unsigned  combined_used:1 */
} ngx_http_log_main_conf_t;


typedef struct {
    ngx_open_file_t            *file;
    time_t                      disk_full_time;
    ngx_array_t                *ops;        /* array of ngx_http_log_op_t */
} ngx_http_log_t;


typedef struct {
    ngx_array_t                *logs;       /* array of ngx_http_log_t */
    ngx_uint_t                  off;        /* unsigned  off:1 */
} ngx_http_log_loc_conf_t;


typedef struct {
    ngx_str_t                   name;
    size_t                      len;
    ngx_http_log_op_run_pt      run;
} ngx_http_log_var_t;


static u_char *ngx_http_log_addr(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_connection(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_pipe(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_msec(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_request_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_status(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_bytes_sent(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_body_bytes_sent(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);
static u_char *ngx_http_log_request_length(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);

static size_t ngx_http_log_request_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_request(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);

static ngx_int_t ngx_http_log_header_in_compile(ngx_conf_t *cf,
    ngx_http_log_op_t *op, ngx_str_t *value);
static size_t ngx_http_log_header_in_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_header_in(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static size_t ngx_http_log_unknown_header_in_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_unknown_header_in(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);

static ngx_int_t ngx_http_log_header_out_compile(ngx_conf_t *cf,
    ngx_http_log_op_t *op, ngx_str_t *value);
static size_t ngx_http_log_header_out_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_header_out(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static size_t ngx_http_log_unknown_header_out_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_unknown_header_out(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);

static u_char *ngx_http_log_connection_header_out(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);
static u_char *ngx_http_log_transfer_encoding_header_out(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);

static ngx_table_elt_t *ngx_http_log_unknown_header(ngx_list_t *headers,
    ngx_str_t *value);

static ngx_int_t ngx_http_log_variable_compile(ngx_conf_t *cf,
    ngx_http_log_op_t *op, ngx_str_t *value);
static size_t ngx_http_log_variable_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_variable(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);


static ngx_int_t ngx_http_log_set_formats(ngx_conf_t *cf);
static void *ngx_http_log_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_log_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_log_compile_format(ngx_conf_t *cf,
    ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s);
static ngx_int_t ngx_http_log_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_log_commands[] = {

    { ngx_string("log_format"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_log_set_format,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("access_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE123,
      ngx_http_log_set_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


ngx_http_module_t  ngx_http_log_module_ctx = {
    ngx_http_log_set_formats,              /* preconfiguration */
    ngx_http_log_init,                     /* postconfiguration */

    ngx_http_log_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_log_create_loc_conf,          /* create location configration */
    ngx_http_log_merge_loc_conf            /* merge location configration */
};


ngx_module_t  ngx_http_log_module = {
    NGX_MODULE_V1,
    &ngx_http_log_module_ctx,              /* module context */
    ngx_http_log_commands,                 /* module directives */
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


static ngx_str_t  http_access_log = ngx_string(NGX_HTTP_LOG_PATH);


static ngx_str_t  ngx_http_combined_fmt =
    ngx_string("$remote_addr - $remote_user [$time_local] "
               "\"$request\" $status $body_bytes_sent "
               "\"$http_referer\" \"$http_user_agent\"");


static ngx_http_log_var_t  ngx_http_log_vars[] = {
    { ngx_string("connection"), NGX_ATOMIC_T_LEN, ngx_http_log_connection },
    { ngx_string("pipe"), 1, ngx_http_log_pipe },
    { ngx_string("time_local"), sizeof("28/Sep/1970:12:00:00 +0600") - 1,
                          ngx_http_log_time },
    { ngx_string("msec"), NGX_TIME_T_LEN + 4, ngx_http_log_msec },
    { ngx_string("request_time"), NGX_TIME_T_LEN, ngx_http_log_request_time },
    { ngx_string("status"), 3, ngx_http_log_status },
    { ngx_string("bytes_sent"), NGX_OFF_T_LEN, ngx_http_log_bytes_sent },
    { ngx_string("body_bytes_sent"), NGX_OFF_T_LEN,
                          ngx_http_log_body_bytes_sent },
    { ngx_string("apache_bytes_sent"), NGX_OFF_T_LEN,
                          ngx_http_log_body_bytes_sent },
    { ngx_string("request_length"), NGX_SIZE_T_LEN,
                          ngx_http_log_request_length },

    { ngx_null_string, 0, NULL }
};


ngx_http_log_op_name_t  ngx_http_log_fmt_ops[] = {
    { ngx_string("addr"), INET_ADDRSTRLEN - 1, NULL, NULL, ngx_http_log_addr },
    { ngx_string("conn"), NGX_ATOMIC_T_LEN, NULL, NULL,
                          ngx_http_log_connection },
    { ngx_string("pipe"), 1, NULL, NULL, ngx_http_log_pipe },
    { ngx_string("time"), sizeof("28/Sep/1970:12:00:00 +0600") - 1,
                          NULL, NULL, ngx_http_log_time },
    { ngx_string("msec"), NGX_TIME_T_LEN + 4, NULL, NULL, ngx_http_log_msec },
    { ngx_string("request_time"), NGX_TIME_T_LEN, NULL, NULL,
                          ngx_http_log_request_time },
    { ngx_string("status"), 3, NULL, NULL, ngx_http_log_status },
    { ngx_string("length"), NGX_OFF_T_LEN,
                          NULL, NULL, ngx_http_log_bytes_sent },
    { ngx_string("apache_length"), NGX_OFF_T_LEN,
                          NULL, NULL, ngx_http_log_body_bytes_sent },
    { ngx_string("request_length"), NGX_SIZE_T_LEN,
                          NULL, NULL, ngx_http_log_request_length },

    { ngx_string("request"), 0, NULL,
                          ngx_http_log_request_getlen,
                          ngx_http_log_request },

    { ngx_string("i"), 0, ngx_http_log_header_in_compile, NULL,
                          ngx_http_log_header_in },
    { ngx_string("o"), 0, ngx_http_log_header_out_compile, NULL,
                          ngx_http_log_header_out },
    { ngx_string("v"), 0, ngx_http_log_variable_compile, NULL,
                          ngx_http_log_variable },

    { ngx_null_string, 0, NULL, NULL, NULL }
};


ngx_int_t
ngx_http_log_handler(ngx_http_request_t *r)
{
    ngx_uint_t                i, l;
    u_char                   *line, *p;
    size_t                    len;
    ngx_http_log_t           *log;
    ngx_open_file_t          *file;
    ngx_http_log_op_t        *op;
    ngx_http_log_loc_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http log handler");

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_log_module);

    if (lcf->off) {
        return NGX_OK;
    }

    log = lcf->logs->elts;
    for (l = 0; l < lcf->logs->nelts; l++) {

        if (ngx_time() == log[l].disk_full_time) {

            /*
             * On FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing the log for one second.
             */

            continue;
        }

        len = 0;
        op = log[l].ops->elts;
        for (i = 0; i < log[l].ops->nelts; i++) {
            if (op[i].len == 0) {
                len += op[i].getlen(r, op[i].data);

            } else {
                len += op[i].len;
            }
        }

        len += NGX_LINEFEED_SIZE;

        file = log[l].file;

        if (file->buffer) {

            if (len > (size_t) (file->last - file->pos)) {

                if (ngx_write_fd(file->fd, file->buffer,
                                 file->pos - file->buffer)
                    == -1
                    && ngx_errno == NGX_ENOSPC)
                {
                    log[l].disk_full_time = ngx_time();
                }

                file->pos = file->buffer;
            }

            if (len <= (size_t) (file->last - file->pos)) {

                p = file->pos;

                for (i = 0; i < log[l].ops->nelts; i++) {
                    p = op[i].run(r, p, &op[i]);
                }

                ngx_linefeed(p);

                file->pos = p;

                continue;
            }
        }

        line = ngx_palloc(r->pool, len);
        if (line == NULL) {
            return NGX_ERROR;
        }

        p = line;

        for (i = 0; i < log[l].ops->nelts; i++) {
            p = op[i].run(r, p, &op[i]);
        }

        ngx_linefeed(p);

        if (ngx_write_fd(file->fd, line, p - line) == -1
            && ngx_errno == NGX_ENOSPC)
        {
            log[l].disk_full_time = ngx_time();
        }
    }

    return NGX_OK;
}


static u_char *
ngx_http_log_copy_short(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    size_t     len;
    uintptr_t  data;

    len = op->len;
    data = op->data;

    while (len--) {
        *buf++ = (u_char) (data & 0xff);
        data >>= 8;
    }

    return buf;
}


static u_char *
ngx_http_log_copy_long(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    return ngx_cpymem(buf, (u_char *) op->data, op->len);
}


static u_char *
ngx_http_log_addr(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    return ngx_cpymem(buf, r->connection->addr_text.data,
                      r->connection->addr_text.len);
}


static u_char *
ngx_http_log_connection(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    return ngx_sprintf(buf, "%ui", r->connection->number);
}


static u_char *
ngx_http_log_pipe(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    if (r->pipeline) {
        *buf = 'p';
    } else {
        *buf = '.';
    }

    return buf + 1;
}


static u_char *
ngx_http_log_time(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    return ngx_cpymem(buf, ngx_cached_http_log_time.data,
                      ngx_cached_http_log_time.len);
}


static u_char *
ngx_http_log_msec(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    ngx_time_t  *tp;

    tp = ngx_timeofday();

    return ngx_sprintf(buf, "%T.%03M", tp->sec, tp->msec);
}


static u_char *
ngx_http_log_request_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    time_t  elapsed;

    elapsed = ngx_time() - r->start_time;

    return ngx_sprintf(buf, "%T", elapsed);
}


static size_t
ngx_http_log_request_getlen(ngx_http_request_t *r, uintptr_t data)
{
    return r->request_line.len;
}


static u_char *
ngx_http_log_request(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    return ngx_cpymem(buf, r->request_line.data, r->request_line.len);
}


static u_char *
ngx_http_log_status(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    return ngx_sprintf(buf, "%ui",
                       r->err_status ? r->err_status : r->headers_out.status);
}


static u_char *
ngx_http_log_bytes_sent(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    return ngx_sprintf(buf, "%O", r->connection->sent);
}


static u_char *
ngx_http_log_body_bytes_sent(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    off_t  length;

    length = r->connection->sent - r->header_size;

    if (length > 0) {
        return ngx_sprintf(buf, "%O", length);
    }

    *buf = '0';

    return buf + 1;
}


static u_char *
ngx_http_log_request_length(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    return ngx_sprintf(buf, "%z", r->request_length);
}


static ngx_int_t
ngx_http_log_header_in_compile(ngx_conf_t *cf, ngx_http_log_op_t *op,
    ngx_str_t *value)
{
    ngx_uint_t  i;

    op->len = 0;

    for (i = 0; ngx_http_headers_in[i].name.len != 0; i++) {

        if (ngx_http_headers_in[i].name.len != value->len) {
            continue;
        }

        /* STUB: "Cookie" speacial handling */
        if (ngx_http_headers_in[i].offset == 0) {
            continue;
        }

        if (ngx_strncasecmp(ngx_http_headers_in[i].name.data, value->data,
                            value->len) == 0)
        {
            op->getlen = ngx_http_log_header_in_getlen;
            op->run = ngx_http_log_header_in;
            op->data = ngx_http_headers_in[i].offset;

            return NGX_OK;
        }
    }

    op->getlen = ngx_http_log_unknown_header_in_getlen;
    op->run = ngx_http_log_unknown_header_in;
    op->data = (uintptr_t) value;

    return NGX_OK;
}


static size_t
ngx_http_log_header_in_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_table_elt_t  *h;

    h = *(ngx_table_elt_t **) ((char *) &r->headers_in + data);

    if (h) {
        return h->value.len;
    }

    return 1;
}


static u_char *
ngx_http_log_header_in(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_table_elt_t  *h;

    h = *(ngx_table_elt_t **) ((char *) &r->headers_in + op->data);

    if (h) {
        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    *buf = '-';

    return buf + 1;
}


static size_t
ngx_http_log_unknown_header_in_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_table_elt_t  *h;

    h = ngx_http_log_unknown_header(&r->headers_in.headers, (ngx_str_t *) data);

    if (h) {
        return h->value.len;
    }

    return 1;
}


static u_char *
ngx_http_log_unknown_header_in(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_table_elt_t  *h;

    h = ngx_http_log_unknown_header(&r->headers_in.headers,
                                    (ngx_str_t *) op->data);

    if (h) {
        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    *buf = '-';

    return buf + 1;
}


static ngx_int_t
ngx_http_log_header_out_compile(ngx_conf_t *cf, ngx_http_log_op_t *op,
    ngx_str_t *value)
{
    ngx_uint_t  i;

    op->len = 0;

    for (i = 0; ngx_http_headers_out[i].name.len != 0; i++) {

        if (ngx_http_headers_out[i].name.len != value->len) {
            continue;
        }

        if (ngx_strncasecmp(ngx_http_headers_out[i].name.data, value->data,
                            value->len) == 0)
        {
            op->getlen = ngx_http_log_header_out_getlen;
            op->run = ngx_http_log_header_out;
            op->data = ngx_http_headers_out[i].offset;

            return NGX_OK;
        }
    }

    if (value->len == sizeof("Connection") - 1
        && ngx_strncasecmp(value->data, "Connection", value->len) == 0)
    {
        op->len = sizeof("keep-alive") - 1;
        op->getlen = NULL;
        op->run = ngx_http_log_connection_header_out;
        op->data = 0;
        return NGX_OK;
    }

    if (value->len == sizeof("Transfer-Encoding") - 1
        && ngx_strncasecmp(value->data, "Transfer-Encoding", value->len) == 0)
    {
        op->len = sizeof("chunked") - 1;
        op->getlen = NULL;
        op->run = ngx_http_log_transfer_encoding_header_out;
        op->data = 0;
        return NGX_OK;
    }

    op->getlen = ngx_http_log_unknown_header_out_getlen;
    op->run = ngx_http_log_unknown_header_out;
    op->data = (uintptr_t) value;

    return NGX_OK;
}


static size_t
ngx_http_log_header_out_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_table_elt_t  *h;

    h = *(ngx_table_elt_t **) ((char *) &r->headers_out + data);

    if (h) {
        return h->value.len;
    }

    /*
     * No header pointer was found.
     * However, some headers: "Date", "Server", "Content-Length",
     * and "Last-Modified" have a special handling in the header filter,
     * but we do not set up their pointers in the filter,
     * because they are too seldom needed to be logged.
     */

    if (data == offsetof(ngx_http_headers_out_t, date)) {
        return ngx_cached_http_time.len;
    }

    if (data == offsetof(ngx_http_headers_out_t, server)) {
        return (sizeof(NGINX_VER) - 1);
    }

    if (data == offsetof(ngx_http_headers_out_t, content_length)) {
        if (r->headers_out.content_length_n == -1) {
            return 1;
        }

        return NGX_OFF_T_LEN;
    }

    if (data == offsetof(ngx_http_headers_out_t, last_modified)) {
        if (r->headers_out.last_modified_time == -1) {
            return 1;
        }

        return sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;
    }

    return 1;
}


static u_char *
ngx_http_log_header_out(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_table_elt_t  *h;

    h = *(ngx_table_elt_t **) ((char *) &r->headers_out + op->data);

    if (h) {
        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    /*
     * No header pointer was found.
     * However, some headers: "Date", "Server", "Content-Length",
     * and "Last-Modified" have a special handling in the header filter,
     * but we do not set up their pointers in the filter,
     * because they are too seldom needed to be logged.
     */

    if (op->data == offsetof(ngx_http_headers_out_t, date)) {
        return ngx_cpymem(buf, ngx_cached_http_time.data,
                          ngx_cached_http_time.len);
    }

    if (op->data == offsetof(ngx_http_headers_out_t, server)) {
        return ngx_cpymem(buf, NGINX_VER, sizeof(NGINX_VER) - 1);
    }

    if (op->data == offsetof(ngx_http_headers_out_t, content_length)) {
        if (r->headers_out.content_length_n == -1) {
            *buf = '-';

            return buf + 1;
        }

        return ngx_sprintf(buf, "%O", r->headers_out.content_length_n);
    }

    if (op->data == offsetof(ngx_http_headers_out_t, last_modified)) {
        if (r->headers_out.last_modified_time == -1) {
            *buf = '-';

            return buf + 1;
        }

        return ngx_http_time(buf, r->headers_out.last_modified_time);
    }

    *buf = '-';

    return buf + 1;
}


static size_t
ngx_http_log_unknown_header_out_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_table_elt_t  *h;

    h = ngx_http_log_unknown_header(&r->headers_out.headers,
                                    (ngx_str_t *) data);

    if (h) {
        return h->value.len;
    }

    return 1;
}


static u_char *
ngx_http_log_unknown_header_out(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_table_elt_t  *h;

    h = ngx_http_log_unknown_header(&r->headers_out.headers,
                                    (ngx_str_t *) op->data);

    if (h) {
        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    *buf = '-';

    return buf + 1;
}


static ngx_table_elt_t *
ngx_http_log_unknown_header(ngx_list_t *headers, ngx_str_t *value)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &headers->part;
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

        if (h[i].key.len != value->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, value->data, value->len) == 0) {
            return &h[i];
        }
    }

    return NULL;
}


static u_char *
ngx_http_log_connection_header_out(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    if (r->keepalive) {
        return ngx_cpymem(buf, "keep-alive", sizeof("keep-alive") - 1);

    } else {
        return ngx_cpymem(buf, "close", sizeof("close") - 1);
    }
}


static u_char *
ngx_http_log_transfer_encoding_header_out(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    if (r->chunked) {
        return ngx_cpymem(buf, "chunked", sizeof("chunked") - 1);
    }

    *buf = '-';

    return buf + 1;
}


static ngx_int_t
ngx_http_log_variable_compile(ngx_conf_t *cf, ngx_http_log_op_t *op,
    ngx_str_t *value)
{
    ngx_int_t  index;

    index = ngx_http_get_variable_index(cf, value);
    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    op->len = 0;
    op->getlen = ngx_http_log_variable_getlen;
    op->run = ngx_http_log_variable;
    op->data = index;

    return NGX_OK;
}


static size_t
ngx_http_log_variable_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, data);

    if (value == NULL || value->not_found) {
        return 1;
    }

    return value->len;
}


static u_char *
ngx_http_log_variable(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, op->data);

    if (value == NULL || value->not_found) {
        *buf = '-';
        return buf + 1;
    }

    return ngx_cpymem(buf, value->data, value->len);
}


static ngx_int_t
ngx_http_log_set_formats(ngx_conf_t *cf)
{
    ngx_http_log_op_name_t  *op;

    for (op = ngx_http_log_fmt_ops; op->name.len; op++) { /* void */ }
    op->run = NULL;

    return NGX_OK;
}


static void *
ngx_http_log_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_log_main_conf_t  *conf;

    ngx_http_log_fmt_t  *fmt;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_main_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&conf->formats, cf->pool, 4, sizeof(ngx_http_log_fmt_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    fmt = ngx_array_push(&conf->formats);
    if (fmt == NULL) {
        return NGX_CONF_ERROR;
    }

    fmt->name.len = sizeof("combined") - 1;
    fmt->name.data = (u_char *) "combined";

    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_http_log_op_t));
    if (fmt->ops == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}


static void *
ngx_http_log_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_log_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}


static char *
ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_log_loc_conf_t *prev = parent;
    ngx_http_log_loc_conf_t *conf = child;

    ngx_http_log_t            *log;
    ngx_http_log_fmt_t        *fmt;
    ngx_http_log_main_conf_t  *lmcf;

    if (conf->logs == NULL) {

        if (conf->off) {
            return NGX_CONF_OK;
        }

        if (prev->logs) {
            conf->logs = prev->logs;

        } else {

            if (prev->off) {
                conf->off = prev->off;
                return NGX_CONF_OK;
            }

            conf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_log_t));
            if (conf->logs == NULL) {
                return NGX_CONF_ERROR;
            }

            log = ngx_array_push(conf->logs);
            if (log == NULL) {
                return NGX_CONF_ERROR;
            }

            log->file = ngx_conf_open_file(cf->cycle, &http_access_log);
            if (log->file == NULL) {
                return NGX_CONF_ERROR;
            }

            lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);
            fmt = lmcf->formats.elts;

            /* the default "combined" format */
            log->ops = fmt[0].ops;
            lmcf->combined_used = 1;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_log_loc_conf_t *llcf = conf;

    ssize_t                    buf;
    ngx_uint_t                 i;
    ngx_str_t                 *value, name;
    ngx_http_log_t            *log;
    ngx_http_log_fmt_t        *fmt;
    ngx_http_log_main_conf_t  *lmcf;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        llcf->off = 1;
        return NGX_CONF_OK;
    }

    if (llcf->logs == NULL) {
        llcf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_log_t));
        if (llcf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);

    log = ngx_array_push(llcf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    log->file = ngx_conf_open_file(cf->cycle, &value[1]);
    if (log->file == NULL) {
        return NGX_CONF_ERROR;
    }

    log->disk_full_time = 0;

    if (cf->args->nelts >= 3) {
        name = value[2];

        if (ngx_strcmp(name.data, "combined") == 0) {
            lmcf->combined_used = 1;
        }

    } else {
        name.len = sizeof("combined") - 1;
        name.data = (u_char *) "combined";
        lmcf->combined_used = 1;
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->ops = fmt[i].ops;
            goto buffer;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown log format \"%V\"", &name);
    return NGX_CONF_ERROR;

buffer:

    if (cf->args->nelts == 4) {
        if (ngx_strncmp(value[3].data, "buffer=", 7) != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return NGX_CONF_ERROR;
        }

        name.len = value[3].len - 7;
        name.data = value[3].data + 7;

        buf = ngx_parse_size(&name);

        if (buf == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return NGX_CONF_ERROR;
        }

        if (log->file->buffer && log->file->last - log->file->pos != buf) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "access_log \"%V\" already defined "
                               "with different buffer size", &value[1]);
            return NGX_CONF_ERROR;
        }

        log->file->buffer = ngx_palloc(cf->pool, buf);
        if (log->file->buffer == NULL) {
            return NGX_CONF_ERROR;
        }

        log->file->pos = log->file->buffer;
        log->file->last = log->file->buffer + buf;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_log_main_conf_t *lmcf = conf;

    ngx_str_t           *value;
    ngx_uint_t           i;
    ngx_http_log_fmt_t  *fmt;

    value = cf->args->elts;

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == value[1].len
            && ngx_strcmp(fmt[i].name.data, value[1].data) == 0)
        {
            return "duplicate \"log_format\" name";
        }
    }

    fmt = ngx_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return NGX_CONF_ERROR;
    }

    fmt->name = value[1];

    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_http_log_op_t));
    if (fmt->ops == NULL) {
        return NGX_CONF_ERROR;
    }

    return ngx_http_log_compile_format(cf, fmt->ops, cf->args, 2);
}


static char *
ngx_http_log_compile_format(ngx_conf_t *cf, ngx_array_t *ops,
    ngx_array_t *args, ngx_uint_t s)
{
    u_char                  *data, *p, *fname, *arg_data, ch;
    size_t                   i, len, fname_len, arg_len;
    ngx_str_t               *value, var, *a;
    ngx_uint_t               bracket;
    ngx_http_log_op_t       *op;
    ngx_http_log_var_t      *v;
    ngx_http_log_op_name_t  *name;
    static ngx_uint_t        warn;

    value = args->elts;
    arg_data = NULL;

    for ( /* void */ ; s < args->nelts; s++) {

        i = 0;

        while (i < value[s].len) {

            op = ngx_array_push(ops);
            if (op == NULL) {
                return NGX_CONF_ERROR;
            }

            data = &value[s].data[i];

            if (value[s].data[i] == '%') {
                i++;

                if (i == value[s].len) {
                    goto invalid;
                }

                if (value[s].data[i] == '{') {
                    i++;

                    arg_data = &value[s].data[i];

                    while (i < value[s].len && value[s].data[i] != '}') {
                        i++;
                    }

                    arg_len = &value[s].data[i] - arg_data;

                    if (i == value[s].len || arg_len == 0) {
                        goto invalid;
                    }

                    i++;

                } else {
                    arg_len = 0;
                }

                if (warn == 0) {
                    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                        "the parameters in the \"%%name\" form are deprecated, "
                        "use the \"$variable\" instead");
                    warn = 1;
                }

                fname = &value[s].data[i];

                while (i < value[s].len
                       && ((value[s].data[i] >= 'a' && value[s].data[i] <= 'z')
                           || value[s].data[i] == '_'))
                {
                    i++;
                }

                fname_len = &value[s].data[i] - fname;

                if (fname_len == 0) {
                    goto invalid;
                }

                for (name = ngx_http_log_fmt_ops; name->run; name++) {
                    if (name->name.len == 0) {
                        name = (ngx_http_log_op_name_t *) name->run;
                    }

                    if (name->name.len == fname_len
                        && ngx_strncmp(name->name.data, fname, fname_len) == 0)
                    {
                        if (name->compile == NULL) {
                            if (arg_len) {
                                fname[fname_len] = '\0';
                                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                               "\"%s\" must not have argument",
                                               data);
                                return NGX_CONF_ERROR;
                            }

                            op->len = name->len;
                            op->getlen = name->getlen;
                            op->run = name->run;
                            op->data = 0;

                            break;
                        }

                        if (arg_len == 0) {
                            fname[fname_len] = '\0';
                            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                               "\"%s\" requires argument",
                                               data);
                            return NGX_CONF_ERROR;
                        }

                        a = ngx_palloc(cf->pool, sizeof(ngx_str_t));
                        if (a == NULL) {
                            return NGX_CONF_ERROR;
                        }

                        a->len = arg_len;
                        a->data = arg_data;

                        if (name->compile(cf, op, a) == NGX_ERROR) {
                            return NGX_CONF_ERROR;
                        }

                        break;
                    }
                }

                if (name->name.len == 0) {
                    goto invalid;
                }

                continue;

            } else if (value[s].data[i] == '$') {

                if (++i == value[s].len) {
                    goto invalid;
                }

                if (value[s].data[i] == '{') {
                    bracket = 1;

                    if (++i == value[s].len) {
                        goto invalid;
                    }

                    var.data = &value[s].data[i];

                } else {
                    bracket = 0;
                    var.data = &value[s].data[i];
                }

                for (var.len = 0; i < value[s].len; i++, var.len++) {
                    ch = value[s].data[i];

                    if (ch == '}' && bracket) {
                        i++;
                        bracket = 0;
                        break;
                    }

                    if ((ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9')
                        || ch == '_')
                    {
                        continue;
                    }

                    break;
                }

                if (bracket) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "the closing bracket in \"%V\" "
                                       "variable is missing", &var);
                    return NGX_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                if (ngx_strncmp(var.data, "apache_bytes_sent", 17) == 0) {
                    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                        "use \"$body_bytes_sent\" instead of "
                        "\"$apache_bytes_sent\"");
                }

                for (v = ngx_http_log_vars; v->name.len; v++) {

                    if (v->name.len == var.len
                        && ngx_strncmp(v->name.data, var.data, var.len) == 0)
                    {
                        op->len = v->len;
                        op->getlen = NULL;
                        op->run = v->run;
                        op->data = 0;

                        goto found;
                    }
                }

                if (ngx_http_log_variable_compile(cf, op, &var) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }

            found:

                continue;
            }

            i++;

            while (i < value[s].len
                   && value[s].data[i] != '$'
                   && value[s].data[i] != '%')
            {
                i++;
            }

            len = &value[s].data[i] - data;

            if (len) {

                op->len = len;
                op->getlen = NULL;

                if (len <= sizeof(uintptr_t)) {
                    op->run = ngx_http_log_copy_short;
                    op->data = 0;

                    while (len--) {
                        op->data <<= 8;
                        op->data |= data[len];
                    }

                } else {
                    op->run = ngx_http_log_copy_long;

                    p = ngx_palloc(cf->pool, len);
                    if (p == NULL) {
                        return NGX_CONF_ERROR;
                    }

                    ngx_memcpy(p, data, len);
                    op->data = (uintptr_t) p;
                }
            }
        }
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_http_log_init(ngx_conf_t *cf)
{
    ngx_str_t                  *value;
    ngx_array_t                 a;
    ngx_http_handler_pt        *h;
    ngx_http_log_fmt_t         *fmt;
    ngx_http_log_main_conf_t   *lmcf;
    ngx_http_core_main_conf_t  *cmcf;

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);

    if (lmcf->combined_used) {
        if (ngx_array_init(&a, cf->pool, 1, sizeof(ngx_str_t)) != NGX_OK) {
            return NGX_ERROR;
        }

        value = ngx_array_push(&a);
        if (value == NULL) {
            return NGX_ERROR;
        }

        *value = ngx_http_combined_fmt;
        fmt = lmcf->formats.elts;

        if (ngx_http_log_compile_format(cf, fmt->ops, &a, 0)
            != NGX_CONF_OK)
        {
            return NGX_ERROR;
        }
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_log_handler;

    return NGX_OK;
}
