
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static char *ngx_http_log_addr(ngx_http_request_t *r, char *buf,
                               uintptr_t data);
static char *ngx_http_log_connection(ngx_http_request_t *r, char *buf,
                                     uintptr_t data);
static char *ngx_http_log_pipe(ngx_http_request_t *r, char *buf,
                               uintptr_t data);
static char *ngx_http_log_time(ngx_http_request_t *r, char *buf,
                               uintptr_t data);
static char *ngx_http_log_request(ngx_http_request_t *r, char *buf,
                                  uintptr_t data);
static char *ngx_http_log_status(ngx_http_request_t *r, char *buf,
                                 uintptr_t data);
static char *ngx_http_log_length(ngx_http_request_t *r, char *buf,
                                 uintptr_t data);
static char *ngx_http_log_header_in(ngx_http_request_t *r, char *buf,
                                    uintptr_t data);
static char *ngx_http_log_unknown_header_in(ngx_http_request_t *r, char *buf,
                                            uintptr_t data);
static char *ngx_http_log_header_out(ngx_http_request_t *r, char *buf,
                                    uintptr_t data);
static char *ngx_http_log_unknown_header_out(ngx_http_request_t *r, char *buf,
                                             uintptr_t data);

static void *ngx_http_log_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_log_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                         void *child);
static char *ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
static char *ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);
static int ngx_http_log_parse_format(ngx_conf_t *cf, ngx_array_t *ops,
                                     ngx_str_t *line);


static ngx_command_t  ngx_http_log_commands[] = {

    {ngx_string("log_format"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
     ngx_http_log_set_format,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("access_log"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
     ngx_http_log_set_log,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    ngx_null_command
};


ngx_http_module_t  ngx_http_log_module_ctx = {
    ngx_http_log_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_log_create_loc_conf,          /* create location configration */
    ngx_http_log_merge_loc_conf            /* merge location configration */
};


ngx_module_t  ngx_http_log_module = {
    NGX_MODULE,
    &ngx_http_log_module_ctx,              /* module context */
    ngx_http_log_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static ngx_str_t http_access_log = ngx_string("access.log");


static char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

static ngx_str_t ngx_http_combined_fmt =
    ngx_string("%addr - - [%time] \"%request\" %status %length "
               "\"%{Referer}i\" %{User-Agent}i\"");


static ngx_http_log_op_name_t ngx_http_log_fmt_ops[] = {
    { ngx_string("addr"), INET_ADDRSTRLEN - 1, ngx_http_log_addr },
    { ngx_string("conn"), NGX_INT32_LEN, ngx_http_log_connection },
    { ngx_string("pipe"), 1, ngx_http_log_pipe },
    { ngx_string("time"), sizeof("28/Sep/1970:12:00:00") - 1,
                          ngx_http_log_time },
    { ngx_string("request"), 0, ngx_http_log_request },
    { ngx_string("status"), 3, ngx_http_log_status },
    { ngx_string("length"), NGX_OFF_LEN, ngx_http_log_length },
    { ngx_string("i"), NGX_HTTP_LOG_ARG, ngx_http_log_header_in },
    { ngx_string("o"), NGX_HTTP_LOG_ARG, ngx_http_log_header_out },
    { ngx_null_string, 0, NULL }
};


int ngx_http_log_handler(ngx_http_request_t *r)
{
    int                       i, l;
    u_int                     data;
    char                     *line, *p;
    size_t                    len;
    ngx_http_log_t           *log;
    ngx_http_log_op_t        *op;
    ngx_http_log_loc_conf_t  *lcf;
#if (WIN32)
    u_int                     written;
#endif

    ngx_log_debug(r->connection->log, "log handler");

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_log_module);

    log = lcf->logs->elts;
    for (l = 0; l < lcf->logs->nelts; l++) {

        len = 0;
        op = log[l].ops->elts;
        for (i = 0; i < log[l].ops->nelts; i++) {
            if (op[i].len == 0) {
                len += (size_t) op[i].op(r, NULL, op[i].data);

            } else {
                len += op[i].len;
            }
        }

#if (WIN32)
        len += 2;
#else
        len++;
#endif

        ngx_test_null(line, ngx_palloc(r->pool, len), NGX_ERROR);
        p = line;

        for (i = 0; i < log[l].ops->nelts; i++) {
            if (op[i].op == NGX_HTTP_LOG_COPY_SHORT) {
                len = op[i].len;
                data = op[i].data;
                while (len--) {
                    *p++ = data & 0xff;
                    data >>= 8;
                }

            } else if (op[i].op == NGX_HTTP_LOG_COPY_LONG) {
                p = ngx_cpymem(p, (void *) op[i].data, op[i].len);

            } else {
                p = op[i].op(r, p, op[i].data);
            }
        }

#if (WIN32)
        *p++ = CR; *p++ = LF;
        WriteFile(log[l].file->fd, line, p - line, &written, NULL);
#else
        *p++ = LF;
        write(log[l].file->fd, line, p - line);
#endif
    }

    return NGX_OK;
}


static char *ngx_http_log_addr(ngx_http_request_t *r, char *buf, uintptr_t data)
{
    return ngx_cpymem(buf, r->connection->addr_text.data,
                      r->connection->addr_text.len);
}


static char *ngx_http_log_connection(ngx_http_request_t *r, char *buf,
                                     uintptr_t data)
{
    return buf + ngx_snprintf(buf, NGX_INT32_LEN + 1, "%u",
                              r->connection->number);
}


static char *ngx_http_log_pipe(ngx_http_request_t *r, char *buf, uintptr_t data)
{
    if (r->pipeline) {
        *buf = 'p';
    } else {
        *buf = '.';
    }

    return buf + 1;
}


static char *ngx_http_log_time(ngx_http_request_t *r, char *buf, uintptr_t data)
{
    ngx_tm_t  tm;

    ngx_localtime(&tm);

    return buf + ngx_snprintf(buf, sizeof("28/Sep/1970:12:00:00"),
                              "%02d/%s/%d:%02d:%02d:%02d",
                              tm.ngx_tm_mday, months[tm.ngx_tm_mon - 1],
                              tm.ngx_tm_year,
                              tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);
}


static char *ngx_http_log_request(ngx_http_request_t *r, char *buf,
                                  uintptr_t data)
{
    if (buf == NULL) {
        /* find the request line length */
        return (char *) r->request_line.len;
    }

    return ngx_cpymem(buf, r->request_line.data, r->request_line.len);
}


static char *ngx_http_log_status(ngx_http_request_t *r, char *buf,
                                 uintptr_t data)
{
    return buf + ngx_snprintf(buf, 4, "%d", r->headers_out.status);
}


static char *ngx_http_log_length(ngx_http_request_t *r, char *buf,
                                 uintptr_t data)
{
    return buf + ngx_snprintf(buf, NGX_OFF_LEN + 1, OFF_FMT,
                              r->connection->sent);
}


static char *ngx_http_log_header_in(ngx_http_request_t *r, char *buf,
                                    uintptr_t data)
{
    int                 i;
    ngx_str_t          *s;
    ngx_table_elt_t    *h;
    ngx_http_log_op_t  *op;

    if (r) {
        h = *(ngx_table_elt_t **) ((char *) &r->headers_in + data);

        if (h == NULL) {

            /* no header */

            if (buf) {
                *buf = '-';
            }

            return buf + 1;
        }

        if (buf == NULL) {
            /* find the header length */
            return (char *) h->value.len;
        }

        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    /* find an offset while a format string compilation */

    op = (ngx_http_log_op_t *) buf;
    s = (ngx_str_t *) data;

    op->len = 0;

    for (i = 0; ngx_http_headers_in[i].name.len != 0; i++) {
        if (ngx_http_headers_in[i].name.len != s->len) {
            continue;
        }

        if (ngx_strncasecmp(ngx_http_headers_in[i].name.data, s->data, s->len)
                                                                          == 0)
        {
            op->op = ngx_http_log_header_in;
            op->data = ngx_http_headers_in[i].offset;
            return NULL;
        }
    }

    op->op = ngx_http_log_unknown_header_in;
    op->data = (uintptr_t) s;

    return NULL;
}


static char *ngx_http_log_unknown_header_in(ngx_http_request_t *r, char *buf,
                                            uintptr_t data)
{
    int               i;
    ngx_str_t        *s;
    ngx_table_elt_t  *h;

    s = (ngx_str_t *) data;

    h = r->headers_in.headers->elts;
    for (i = 0; i < r->headers_in.headers->nelts; i++) {
        if (h[i].key.len != s->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, s->data, s->len) == 0) {
            if (buf == NULL) {
                /* find the header length */
                return (char *) h[i].value.len;
            }

            return ngx_cpymem(buf, h[i].value.data, h[i].value.len);
        }
    }

    /* no header */

    if (buf) {
        *buf = '-';
    }

    return buf + 1;
}


static char *ngx_http_log_header_out(ngx_http_request_t *r, char *buf,
                                     uintptr_t data)
{
    int                 i;
    ngx_str_t          *s;
    ngx_table_elt_t    *h;
    ngx_http_log_op_t  *op;

    if (r) {
        h = *(ngx_table_elt_t **) ((char *) &r->headers_out + data);

        if (h == NULL) {

            /* no header */

            if (data == offsetof(ngx_http_headers_out_t, server)) {
                if (buf == NULL) {
                    return (char *) (sizeof(NGINX_VER) - 1);
                }
                return ngx_cpymem(buf, NGINX_VER, sizeof(NGINX_VER) - 1);
            }

            if (buf) {
                *buf = '-';
            }

            return buf + 1;
        }

        if (buf == NULL) {
            /* find the header length */
            return (char *) h->value.len;
        }

        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    /* find an offset while a format string compilation */

    op = (ngx_http_log_op_t *) buf;
    s = (ngx_str_t *) data;

    op->len = 0;

    for (i = 0; ngx_http_headers_out[i].name.len != 0; i++) {
        if (ngx_http_headers_out[i].name.len != s->len) {
            continue;
        }

        if (ngx_strncasecmp(ngx_http_headers_out[i].name.data, s->data, s->len)
                                                                          == 0)
        {
            op->op = ngx_http_log_header_out;
            op->data = ngx_http_headers_out[i].offset;
            return NULL;
        }
    }

    op->op = ngx_http_log_unknown_header_out;
    op->data = (uintptr_t) s;

    return NULL;
}


static char *ngx_http_log_unknown_header_out(ngx_http_request_t *r, char *buf,
                                             uintptr_t data)
{
    int               i;
    ngx_str_t        *s;
    ngx_table_elt_t  *h;

    s = (ngx_str_t *) data;

    h = r->headers_out.headers->elts;
    for (i = 0; i < r->headers_out.headers->nelts; i++) {
        if (h[i].key.len != s->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, s->data, s->len) == 0) {
            if (buf == NULL) {
                /* find the header length */
                return (char *) h[i].value.len;
            }

            return ngx_cpymem(buf, h[i].value.data, h[i].value.len);
        }
    }

    /* no header */

    if (buf) {
        *buf = '-';
    }

    return buf + 1;
}


static void *ngx_http_log_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_log_main_conf_t  *conf;

    char       *rc;
    ngx_str_t  *value;

    if (!(conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_main_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    ngx_init_array(conf->formats, cf->pool, 5, sizeof(ngx_http_log_fmt_t),
                  NGX_CONF_ERROR);

    cf->args->nelts = 0;

    if (!(value = ngx_push_array(cf->args))) {
        return NGX_CONF_ERROR;
    }

    if (!(value = ngx_push_array(cf->args))) {
        return NGX_CONF_ERROR;
    }

    value->len = sizeof("combined") - 1;
    value->data = "combined";

    if (!(value = ngx_push_array(cf->args))) {
        return NGX_CONF_ERROR;
    }

    *value = ngx_http_combined_fmt;

    rc = ngx_http_log_set_format(cf, NULL, conf);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    return conf;
}


static void *ngx_http_log_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_log_loc_conf_t  *conf;

    ngx_test_null(conf, ngx_pcalloc(cf->pool, sizeof(ngx_http_log_loc_conf_t)),
                  NGX_CONF_ERROR);

    return conf;
}


static char *ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                         void *child)
{
    ngx_http_log_loc_conf_t *prev = parent;
    ngx_http_log_loc_conf_t *conf = child;

    ngx_http_log_t            *log;
    ngx_http_log_fmt_t        *fmt;
    ngx_http_log_main_conf_t  *lmcf;

    if (conf->logs == NULL) {
        if (prev->logs) {
            conf->logs = prev->logs;

        } else {

            conf->logs = ngx_create_array(cf->pool, 2, sizeof(ngx_http_log_t));
            if (conf->logs == NULL) {
                return NGX_CONF_ERROR;
            }

            if (!(log = ngx_push_array(conf->logs))) {
                return NGX_CONF_ERROR;
            }

            log->file = ngx_conf_open_file(cf->cycle, &http_access_log);
            if (log->file == NULL) {
                return NGX_CONF_ERROR;
            }

            lmcf = ngx_http_conf_module_main_conf(cf, ngx_http_log_module);
            fmt = lmcf->formats.elts;
            /* the default "combined" format */
            log->ops = fmt[0].ops;
        }
    }

    return NGX_CONF_OK;
}


static char *ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf)
{
    ngx_http_log_loc_conf_t *llcf = conf;

    int                        i;
    ngx_str_t                 *value, name;
    ngx_http_log_t            *log;
    ngx_http_log_fmt_t        *fmt;
    ngx_http_log_main_conf_t  *lmcf;

    if (llcf->logs == NULL) {
        if (!(llcf->logs = ngx_create_array(cf->pool, 2,
                                            sizeof(ngx_http_log_t)))) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    lmcf = ngx_http_conf_module_main_conf(cf, ngx_http_log_module);

    if (!(log = ngx_push_array(llcf->logs))) {
        return NGX_CONF_ERROR;
    }

    if (!(log->file = ngx_conf_open_file(cf->cycle, &value[1]))) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        name = value[2];
    } else {
        name.len = sizeof("combined") - 1;
        name.data = "combined";
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->ops = fmt[i].ops;
            return NGX_CONF_OK;
        }
    }

    return NGX_CONF_OK;
}


static char *ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf)
{
    ngx_http_log_main_conf_t *lmcf = conf;

    int                         s, f, invalid;
    char                       *data, *p, *fname;
    size_t                      i, len, fname_len;
    ngx_str_t                  *value, arg, *a;
    ngx_http_log_op_t          *op;
    ngx_http_log_fmt_t         *fmt;
    ngx_http_log_op_name_t     *name;

    value = cf->args->elts;
#if 0
    lmcf = ngx_http_conf_module_main_conf(cf, ngx_http_log_module);
#endif

    fmt = lmcf->formats.elts;
    for (f = 0; f < lmcf->formats.nelts; f++) {
        if (fmt[f].name.len == value[1].len
            && ngx_strcmp(fmt->name.data, value[1].data) == 0)
        {
            return "duplicate \"log_format\" name";
        }
    }

    if (!(fmt = ngx_push_array(&lmcf->formats))) {
        return NGX_CONF_ERROR;
    }

    fmt->name = value[1];

    if (!(fmt->ops = ngx_create_array(cf->pool, 20,
                                      sizeof(ngx_http_log_op_t)))) {
        return NGX_CONF_ERROR;
    }

    invalid = 0;
    data = NULL;

    for (s = 2; s < cf->args->nelts && !invalid; s++) {

        i = 0;

        while (i < value[s].len) {

            if (!(op = ngx_push_array(fmt->ops))) {
                return NGX_CONF_ERROR;
            }

            data = &value[s].data[i];

            if (value[s].data[i] == '%') {
                i++;

                if (i == value[s].len) {
                    invalid = 1;
                    break;
                }

                if (value[s].data[i] == '{') {
                    i++;

                    arg.data = &value[s].data[i];

                    while (i < value[s].len && value[s].data[i] != '}') {
                        i++;
                    }

                    arg.len = &value[s].data[i] - arg.data;

                    if (i == value[s].len || arg.len == 0) {
                        invalid = 1;
                        break;
                    }

                    i++;

                } else {
                    arg.len = 0;
                }

                fname = &value[s].data[i];

                while (i < value[s].len
                       && value[s].data[i] >= 'a'
                       && value[s].data[i] <= 'z')
                {
                    i++;
                }

                fname_len = &value[s].data[i] - fname;

                if (fname_len == 0) {
                    invalid = 1;
                    break;
                }

                for (name = ngx_http_log_fmt_ops; name->name.len; name++) {
                    if (name->name.len == fname_len
                        && ngx_strncmp(name->name.data, fname, fname_len) == 0)
                    {
                        if (name->len != NGX_HTTP_LOG_ARG) {
                            if (arg.len) {
                                fname[fname_len] = '\0';
                                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                               "\"%s\" must not have argument",
                                               data);
                                return NGX_CONF_ERROR;
                            }

                            op->len = name->len;
                            op->op = name->op;
                            op->data = 0;

                            break;
                        }

                        if (arg.len == 0) {
                            fname[fname_len] = '\0';
                            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                               "\"%s\" requires argument", 
                                               data);
                            return NGX_CONF_ERROR;
                        }

                        if (!(a = ngx_palloc(cf->pool, sizeof(ngx_str_t)))) {
                            return NGX_CONF_ERROR;
                        }

                        *a = arg;
                        name->op(NULL, (char *) op, (uintptr_t) a);

                        break;
                    }
                }

                if (name->name.len == 0) {
                    invalid = 1;
                    break;
                }

            } else {
                i++;

                while (i < value[s].len && value[s].data[i] != '%') {
                    i++;
                }

                len = &value[s].data[i] - data;

                if (len) {

                    op->len = len;

                    if (len <= sizeof(uintptr_t)) {
                        op->op = NGX_HTTP_LOG_COPY_SHORT;
                        op->data = 0;

                        while (len--) {
                            op->data <<= 8;
                            op->data |= data[len];
                        }

                    } else {
                        op->op = NGX_HTTP_LOG_COPY_LONG;

                        if (!(p = ngx_palloc(cf->pool, len))) {
                            return NGX_CONF_ERROR;
                        }

                        ngx_memcpy(p, data, len);
                        op->data = (uintptr_t) p;
                    }
                }
            }
        }
    }

    if (invalid) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%s\"", data);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
