
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_bufs_t  bufs;
} ngx_http_output_filter_conf_t;


static void *ngx_http_output_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_output_filter_merge_conf(ngx_conf_t *cf,
                                               void *parent, void *child);


static ngx_command_t  ngx_http_output_filter_commands[] = {

    {ngx_string("output_buffers"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
     ngx_conf_set_bufs_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_output_filter_conf_t, bufs),
     NULL},

    ngx_null_command
};


static ngx_http_module_t  ngx_http_output_filter_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_output_filter_create_conf,    /* create location configuration */
    ngx_http_output_filter_merge_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_output_filter_module = {
    NGX_MODULE,
    &ngx_http_output_filter_module_ctx,    /* module context */
    ngx_http_output_filter_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};



ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                       rc;
    ngx_output_chain_ctx_t         *ctx;
    ngx_http_output_filter_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r->main ? r->main : r,
                                            ngx_http_output_filter_module);

    if (ctx == NULL) {
        conf = ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                            ngx_http_output_filter_module);

        ngx_http_create_ctx(r, ctx, ngx_http_output_filter_module,
                            sizeof(ngx_output_chain_ctx_t), NGX_ERROR);

        ctx->sendfile = r->sendfile;
        ctx->need_in_memory = r->filter & NGX_HTTP_FILTER_NEED_IN_MEMORY;
        ctx->need_in_temp = r->filter & NGX_HTTP_FILTER_NEED_TEMP;

        ctx->pool = r->pool;
        ctx->bufs = conf->bufs;
        ctx->tag = (ngx_hunk_tag_t) &ngx_http_output_filter_module;

        ctx->output_filter = (ngx_output_chain_filter_pt)
                                                      ngx_http_top_body_filter;
        ctx->filter_ctx = r;

    }

    rc = ngx_output_chain(ctx, in);

    if (rc == NGX_ERROR) {

        /* NGX_ERROR could be returned by any filter */

        r->connection->write->error = 1;
    }

    return rc;
}


static void *ngx_http_output_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_output_filter_conf_t *conf;

    ngx_test_null(conf,
                  ngx_palloc(cf->pool, sizeof(ngx_http_output_filter_conf_t)),
                  NULL);

    conf->bufs.num = 0;

    return conf;
}


static char *ngx_http_output_filter_merge_conf(ngx_conf_t *cf,
                                               void *parent, void *child)
{
    ngx_http_output_filter_conf_t *prev = parent;
    ngx_http_output_filter_conf_t *conf = child;

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 1, 32768);

    return NULL;
}
