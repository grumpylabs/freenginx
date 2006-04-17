
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_NO_CHARSET  -2


typedef struct {
    u_char     **tables;
    ngx_str_t     name;

    ngx_uint_t    utf8;   /* unsigned     utf8:1; */
} ngx_http_charset_t;


typedef struct {
    ngx_int_t     src;
    ngx_int_t     dst;
} ngx_http_charset_recode_t;


typedef struct {
    ngx_int_t     src;
    ngx_int_t     dst;
    u_char       *src2dst;
    u_char       *dst2src;
} ngx_http_charset_tables_t;


typedef struct {
    ngx_array_t   charsets;               /* ngx_http_charset_t */
    ngx_array_t   tables;                 /* ngx_http_charset_tables_t */
    ngx_array_t   recodes;                /* ngx_http_charset_recode_t */
} ngx_http_charset_main_conf_t;


typedef struct {
    ngx_int_t     charset;
    ngx_int_t     source_charset;
    ngx_flag_t    override_charset;
} ngx_http_charset_loc_conf_t;


typedef struct {
    u_char       *table;
    ngx_int_t     charset;
} ngx_http_charset_ctx_t;


static ngx_uint_t ngx_http_charset_recode(ngx_buf_t *b, u_char *table);

static char *ngx_charset_map_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_charset_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);

static char *ngx_http_set_charset_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_add_charset(ngx_array_t *charsets, ngx_str_t *name);

static ngx_int_t ngx_http_charset_filter_init(ngx_cycle_t *cycle);

static void *ngx_http_charset_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_charset_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_charset_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_charset_postconfiguration(ngx_conf_t *cf);


static ngx_command_t  ngx_http_charset_filter_commands[] = {

    { ngx_string("charset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_set_charset_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_charset_loc_conf_t, charset),
      NULL },

    { ngx_string("source_charset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_set_charset_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_charset_loc_conf_t, source_charset),
      NULL },

    { ngx_string("override_charset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_charset_loc_conf_t, override_charset),
      NULL },

    { ngx_string("charset_map"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
      ngx_charset_map_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_charset_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_charset_postconfiguration,    /* postconfiguration */

    ngx_http_charset_create_main_conf,     /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_charset_create_loc_conf,      /* create location configuration */
    ngx_http_charset_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_charset_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_charset_filter_module_ctx,   /* module context */
    ngx_http_charset_filter_commands,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_http_charset_filter_init,          /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_charset_header_filter(ngx_http_request_t *r)
{
    size_t                         len;
    u_char                        *p;
    ngx_int_t                      charset, source_charset;
    ngx_uint_t                     i;
    ngx_http_charset_t            *charsets;
    ngx_http_charset_ctx_t        *ctx;
    ngx_http_charset_loc_conf_t   *lcf;
    ngx_http_charset_main_conf_t  *mcf;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_charset_filter_module);

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_charset_filter_module);

    if (ctx == NULL) {
        lcf = ngx_http_get_module_loc_conf(r->main,
                                           ngx_http_charset_filter_module);
        charset = lcf->charset;

        if (charset == NGX_HTTP_NO_CHARSET) {
            return ngx_http_next_header_filter(r);
        }

    } else {
        charset = ctx->charset;
    }

    if (r->headers_out.content_type.len == 0) {
        return ngx_http_next_header_filter(r);
    }

    if (ngx_strncasecmp(r->headers_out.content_type.data, "text/", 5) != 0
        && ngx_strncasecmp(r->headers_out.content_type.data,
                           "application/x-javascript", 24) != 0)
    {
        return ngx_http_next_header_filter(r);
    }

    charsets = mcf->charsets.elts;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_charset_filter_module);

    len = 0;

    for (p = r->headers_out.content_type.data; *p; p++) {
        if (*p == ';') {
            len = p - r->headers_out.content_type.data;
        }

        if (ngx_strncasecmp(p, "charset=", 8) != 0) {
            continue;
        }

        p += 8;

        for (i = 0; i < mcf->charsets.nelts; i++) {

            if (ngx_strcasecmp(p, charsets[i].name.data) == 0) {

                if (r == r->main && lcf->override_charset == 0) {
                    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_charset_ctx_t));
                    if (ctx == NULL) {
                        return NGX_ERROR;
                    }

                    ngx_http_set_ctx(r, ctx, ngx_http_charset_filter_module);

                    ctx->charset = i;

                    return ngx_http_next_header_filter(r);
                }

                if (i != (ngx_uint_t) charset
                    && (charsets[i].tables == NULL
                        || charsets[i].tables[charset] == NULL))
                {
                    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                                  "no \"charset_map\" between the charsets "
                                  "\"%V\" and \"%V\"",
                                  &charsets[i].name, &charsets[charset].name);

                    return ngx_http_next_header_filter(r);
                }

                r->headers_out.content_type.len = len;

                if (r->headers_out.status == NGX_HTTP_MOVED_PERMANENTLY
                    || r->headers_out.status == NGX_HTTP_MOVED_TEMPORARILY)
                {
                    /*
                     * do not set charset for the redirect because NN 4.x
                     * uses this charset instead of the next page charset
                     */

                    r->headers_out.charset.len = 0;
                    return ngx_http_next_header_filter(r);
                }

                source_charset = i;

                goto found;
            }
        }

        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.status == NGX_HTTP_MOVED_PERMANENTLY
        || r->headers_out.status == NGX_HTTP_MOVED_TEMPORARILY)
    {
        /*
         * do not set charset for the redirect because NN 4.x
         * use this charset instead of the next page charset
         */

        r->headers_out.charset.len = 0;
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.charset.len) {
        return ngx_http_next_header_filter(r);
    }

    source_charset = lcf->source_charset;

found:

    r->headers_out.charset = charsets[charset].name;
    r->utf8 = charsets[charset].utf8;

    if (source_charset == NGX_CONF_UNSET || source_charset == charset) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_charset_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_charset_filter_module);

    ctx->table = charsets[source_charset].tables[charset];
    ctx->charset = charset;

    r->filter_need_in_memory = 1;

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_charset_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t             *cl;
    ngx_http_charset_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_charset_filter_module);

    if (ctx == NULL || ctx->table == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {
        (void) ngx_http_charset_recode(cl->buf, ctx->table);
    }

    return ngx_http_next_body_filter(r, in);
}


static ngx_uint_t
ngx_http_charset_recode(ngx_buf_t *b, u_char *table)
{
    u_char  *p;

    for (p = b->pos; p < b->last; p++) {

        if (*p == table[*p]) {
            continue;
        }

        while (p < b->last) {
            *p = table[*p];
            p++;
        }

        b->in_file = 0;

        return 1;
    }

    return 0;
}


static char *
ngx_charset_map_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_charset_main_conf_t  *mcf = conf;

    char                       *rv;
    ngx_int_t                   src, dst;
    ngx_uint_t                  i;
    ngx_str_t                  *value;
    ngx_conf_t                  pvcf;
    ngx_http_charset_tables_t  *table;

    value = cf->args->elts;

    src = ngx_http_add_charset(&mcf->charsets, &value[1]);
    if (src == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    dst = ngx_http_add_charset(&mcf->charsets, &value[2]);
    if (dst == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (src == dst) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"charset_map\" between the same charsets "
                           "\"%V\" and \"%V\"", &value[1], &value[2]);
        return NGX_CONF_ERROR;
    }

    table = mcf->tables.elts;
    for (i = 0; i < mcf->tables.nelts; i++) {
        if ((src == table->src && dst == table->dst)
             || (src == table->dst && dst == table->src))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"charset_map\" between "
                               "\"%V\" and \"%V\"", &value[1], &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    table = ngx_array_push(&mcf->tables);
    if (table == NULL) {
        return NGX_CONF_ERROR;
    }

    table->src = src;
    table->dst = dst;

    table->src2dst = ngx_palloc(cf->pool, 256);
    if (table->src2dst == NULL) {
        return NGX_CONF_ERROR;
    }

    table->dst2src = ngx_palloc(cf->pool, 256);
    if (table->dst2src == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; i < 128; i++) {
        table->src2dst[i] = (u_char) i;
        table->dst2src[i] = (u_char) i;
    }

    for (/* void */; i < 256; i++) {
        table->src2dst[i] = '?';
        table->dst2src[i] = '?';
    }

    pvcf = *cf;
    cf->ctx = table;
    cf->handler = ngx_charset_map;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pvcf;

    return rv;
}


static char *
ngx_charset_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_int_t                   src, dst;
    ngx_str_t                  *value;
    ngx_http_charset_tables_t  *table;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameters number");
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    src = ngx_hextoi(value[0].data, value[0].len);
    if (src == NGX_ERROR || src > 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\"", &value[0]);
        return NGX_CONF_ERROR;
    }

    dst = ngx_hextoi(value[1].data, value[1].len);
    if (dst == NGX_ERROR || dst > 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    table = cf->ctx;

    table->src2dst[src] = (u_char) dst;
    table->dst2src[dst] = (u_char) src;

    return NGX_CONF_OK;
}


static char *
ngx_http_set_charset_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_int_t                     *cp;
    ngx_str_t                     *value;
    ngx_http_charset_main_conf_t  *mcf;

    cp = (ngx_int_t *) (p + cmd->offset);

    if (*cp != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cmd->offset == offsetof(ngx_http_charset_loc_conf_t, charset)
        && ngx_strcmp(value[1].data, "off") == 0)
    {
        *cp = NGX_HTTP_NO_CHARSET;
        return NGX_CONF_OK;
    }

    mcf = ngx_http_conf_get_module_main_conf(cf,
                                             ngx_http_charset_filter_module);

    *cp = ngx_http_add_charset(&mcf->charsets, &value[1]);
    if (*cp == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_add_charset(ngx_array_t *charsets, ngx_str_t *name)
{
    ngx_uint_t           i;
    ngx_http_charset_t  *c;

    c = charsets->elts;
    for (i = 0; i < charsets->nelts; i++) {
        if (name->len != c[i].name.len) {
            continue;
        }

        if (ngx_strcasecmp(name->data, c[i].name.data) == 0) {
            break;
        }
    }

    if (i < charsets->nelts) {
        return i;
    }

    c = ngx_array_push(charsets);
    if (c == NULL) {
        return NGX_ERROR;
    }

    c->tables = NULL;
    c->name = *name;

    if (ngx_strcasecmp(name->data, "utf-8") == 0) {
        c->utf8 = 1;
    }

    return i;
}


static ngx_int_t
ngx_http_charset_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_charset_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_charset_body_filter;

    return NGX_OK;
}


static void *
ngx_http_charset_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_charset_main_conf_t  *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_charset_main_conf_t));
    if (mcf == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&mcf->charsets, cf->pool, 2, sizeof(ngx_http_charset_t))
        == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&mcf->tables, cf->pool, 1,
                       sizeof(ngx_http_charset_tables_t)) == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&mcf->recodes, cf->pool, 2,
                       sizeof(ngx_http_charset_recode_t)) == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    return mcf;
}


static void *
ngx_http_charset_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_charset_loc_conf_t  *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_charset_loc_conf_t));
    if (lcf == NULL) {
        return NGX_CONF_ERROR;
    }

    lcf->charset = NGX_CONF_UNSET;
    lcf->source_charset = NGX_CONF_UNSET;
    lcf->override_charset = NGX_CONF_UNSET;

    return lcf;
}


static char *
ngx_http_charset_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_charset_loc_conf_t *prev = parent;
    ngx_http_charset_loc_conf_t *conf = child;

    ngx_uint_t                     i;
    ngx_http_charset_recode_t     *recode;
    ngx_http_charset_main_conf_t  *mcf;

    ngx_conf_merge_value(conf->override_charset, prev->override_charset, 0);
    ngx_conf_merge_value(conf->charset, prev->charset, NGX_HTTP_NO_CHARSET);

    if (conf->source_charset == NGX_CONF_UNSET) {
        conf->source_charset = prev->source_charset;
    }

    if (conf->charset == NGX_HTTP_NO_CHARSET
        || conf->source_charset == NGX_CONF_UNSET
        || conf->charset == conf->source_charset)
    {
        return NGX_CONF_OK;
    }

    mcf = ngx_http_conf_get_module_main_conf(cf,
                                             ngx_http_charset_filter_module);
    recode = mcf->recodes.elts;
    for (i = 0; i < mcf->recodes.nelts; i++) {
        if (conf->source_charset == recode[i].src
            && conf->charset == recode[i].dst)
        {
            return NGX_CONF_OK;
        }
    }

    recode = ngx_array_push(&mcf->recodes);
    if (recode == NULL) {
        return NGX_CONF_ERROR;
    }

    recode->src = conf->source_charset;
    recode->dst = conf->charset;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_charset_postconfiguration(ngx_conf_t *cf)
{
    u_char                       **src, **dst;
    ngx_int_t                      c;
    ngx_uint_t                     i, t;
    ngx_http_charset_t            *charset;
    ngx_http_charset_recode_t     *recode;
    ngx_http_charset_tables_t     *tables;
    ngx_http_charset_main_conf_t  *mcf;

    mcf = ngx_http_conf_get_module_main_conf(cf,
                                             ngx_http_charset_filter_module);

    recode = mcf->recodes.elts;
    tables = mcf->tables.elts;
    charset = mcf->charsets.elts;

    for (i = 0; i < mcf->recodes.nelts; i++) {

        c = recode[i].src;

        for (t = 0; t < mcf->tables.nelts; t++) {

            if (c == tables[t].src && recode[i].dst == tables[t].dst) {
                goto next;
            }

            if (c == tables[t].dst && recode[i].dst == tables[t].src) {
                goto next;
            }
        }

        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      " no \"charset_map\" between the charsets "
                      "\"%V\" and \"%V\"",
                      &charset[c].name, &charset[recode[i].dst].name);
        return NGX_ERROR;

    next:
        continue;
    }


    for (t = 0; t < mcf->tables.nelts; t++) {

        src = charset[tables[t].src].tables;

        if (src == NULL) {
            src = ngx_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
            if (src == NULL) {
                return NGX_ERROR;
            }

            charset[tables[t].src].tables = src;
        }

        dst = charset[tables[t].dst].tables;

        if (dst == NULL) {
            dst = ngx_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
            if (dst == NULL) {
                return NGX_ERROR;
            }

            charset[tables[t].dst].tables = dst;
        }

        src[tables[t].dst] = tables[t].src2dst;
        dst[tables[t].src] = tables[t].dst2src;
    }

    return NGX_OK;
}
