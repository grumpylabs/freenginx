
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


typedef struct {
    size_t  postpone_output;
} ngx_http_write_filter_conf_t;


typedef struct {
    ngx_chain_t  *out;
} ngx_http_write_filter_ctx_t;


static void *ngx_http_write_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_write_filter_merge_conf(ngx_conf_t *cf,
                                              void *parent, void *child);
static int ngx_http_write_filter_init(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_write_filter_commands[] = {

    /* STUB */
    { ngx_string("buffer_output"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_write_filter_conf_t, postpone_output),
      NULL },

    { ngx_string("postpone_output"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_write_filter_conf_t, postpone_output),
      NULL },

      ngx_null_command
};


ngx_http_module_t  ngx_http_write_filter_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_write_filter_create_conf,     /* create location configuration */
    ngx_http_write_filter_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_write_filter_module = {
    NGX_MODULE,
    &ngx_http_write_filter_module_ctx,     /* module context */
    ngx_http_write_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_write_filter_init,            /* init module */
    NULL                                   /* init child */
};


int ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                            last;
    off_t                          size, flush;
    ngx_chain_t                   *cl, **ll, *chain;
    ngx_http_write_filter_ctx_t   *ctx;
    ngx_http_write_filter_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r->main ? r->main : r,
                                  ngx_http_write_filter_module);

    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx, ngx_http_write_filter_module,
                            sizeof(ngx_http_write_filter_ctx_t), NGX_ERROR);
    }

    size = flush = 0;
    last = 0;
    ll = &ctx->out;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = ctx->out; cl; cl = cl->next) {
        ll = &cl->next;

        size += ngx_hunk_size(cl->hunk);

        if (cl->hunk->type & (NGX_HUNK_FLUSH|NGX_HUNK_RECYCLED)) {
            flush = size;
        }

        if (cl->hunk->type & NGX_HUNK_LAST) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (/* void */; in; in = in->next) {
        ngx_alloc_link_and_set_hunk(cl, in->hunk, r->pool, NGX_ERROR);
        *ll = cl;
        ll = &cl->next;

        size += ngx_hunk_size(cl->hunk);

        if (cl->hunk->type & (NGX_HUNK_FLUSH|NGX_HUNK_RECYCLED)) {
            flush = size;
        }

        if (cl->hunk->type & NGX_HUNK_LAST) {
            last = 1;
        }
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http write filter: l:%d f:" OFF_T_FMT " s:" OFF_T_FMT,
                   last, flush, size);

    conf = ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                        ngx_http_write_filter_module);

    /*
     * avoid the output if there is no last hunk, no flush point and
     * the size of the hunks is smaller than "postpone_output" directive
     */

    if (!last && flush == 0 && size < conf->postpone_output) {
        return NGX_OK;
    }

    if (r->connection->write->delayed) {
        return NGX_AGAIN;
    }

    if (size == 0) {
        return NGX_OK;
    }

    chain = ngx_write_chain(r->connection, ctx->out);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http write filter %X", chain);

    if (chain == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    ctx->out = chain;

    if (chain == NULL) {
        return NGX_OK;
    }

    return NGX_AGAIN;
}


static void *ngx_http_write_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_write_filter_conf_t *conf;

    ngx_test_null(conf,
                  ngx_palloc(cf->pool, sizeof(ngx_http_write_filter_conf_t)),
                  NULL);

    conf->postpone_output = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *ngx_http_write_filter_merge_conf(ngx_conf_t *cf,
                                              void *parent, void *child)
{
    ngx_http_write_filter_conf_t *prev = parent;
    ngx_http_write_filter_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->postpone_output, prev->postpone_output,
                              1460);

    return NULL;
}


static int ngx_http_write_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_top_body_filter = ngx_http_write_filter;

    return NGX_OK;
}
