
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hunk.h>
#include <ngx_event_write.h>
#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_write_filter.h>


static void *ngx_http_write_filter_create_conf(ngx_pool_t *pool);


static ngx_command_t ngx_http_write_filter_commands[] = {

    {ngx_string("write_buffer"),
     NGX_CONF_TAKE1, 
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF,
     offsetof(ngx_http_write_filter_conf_t, buffer_output)},

    {ngx_string(""), 0, NULL, 0, 0}
};


ngx_http_module_t  ngx_http_write_filter_module_ctx = {
    NGX_HTTP_MODULE,

    NULL,                                  /* create server config */
    ngx_http_write_filter_create_conf,     /* create location config */

    NULL,                                  /* translate handler */

    NULL,                                  /* output header filter */
    NULL,                                  /* next output header filter */
    ngx_http_write_filter,                 /* output body filter */
    NULL,                                  /* next output body filter */
};


ngx_module_t  ngx_http_write_filter_module = {
    &ngx_http_write_filter_module_ctx,     /* module context */
    ngx_http_write_filter_commands,        /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    NULL                                   /* init module */
};


int ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int    last;
    off_t  size, flush;
    ngx_chain_t  *ch, **prev, *chain;
    ngx_http_write_filter_ctx_t  *ctx;
    ngx_http_write_filter_conf_t *conf;


    ctx = (ngx_http_write_filter_ctx_t *)
                     ngx_http_get_module_ctx(r->main ? r->main : r,
                                             ngx_http_write_filter_module_ctx);
    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx,
                            ngx_http_write_filter_module_ctx,
                            sizeof(ngx_http_write_filter_ctx_t));
    }

    size = flush = 0;
    last = 0;
    prev = &ctx->out;

    /* find size, flush point and last link of saved chain */
    for (ch = ctx->out; ch; ch = ch->next) {
        prev = &ch->next;
        size += ch->hunk->last.file - ch->hunk->pos.file;

        ngx_log_debug(r->connection->log, "old chunk: %x " QX_FMT " " QD_FMT _
                      ch->hunk->type _ ch->hunk->pos.file _
                      ch->hunk->last.file - ch->hunk->pos.file);

        if (ch->hunk->type & (NGX_HUNK_FLUSH|NGX_HUNK_RECYCLED)) {
            flush = size;
        }

        if (ch->hunk->type & NGX_HUNK_LAST) {
            last = 1;
        }
    }

    /* add new chain to existent one */
    for (/* void */; in; in = in->next) {
        ngx_test_null(ch, ngx_palloc(r->pool, sizeof(ngx_chain_t)), NGX_ERROR);

        ch->hunk = in->hunk;
        ch->next = NULL;
        *prev = ch;
        prev = &ch->next;
        size += ch->hunk->last.file - ch->hunk->pos.file;

        ngx_log_debug(r->connection->log, "new chunk: %x " QX_FMT " " QD_FMT _
                      ch->hunk->type _ ch->hunk->pos.file _
                      ch->hunk->last.file - ch->hunk->pos.file);

        if (ch->hunk->type & (NGX_HUNK_FLUSH|NGX_HUNK_RECYCLED)) {
            flush = size;
        }

        if (ch->hunk->type & NGX_HUNK_LAST) {
            last = 1;
        }
    }

    conf = (ngx_http_write_filter_conf_t *)
                ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                             ngx_http_write_filter_module_ctx);

    ngx_log_debug(r->connection->log, "l:%d f:%d" _ last _ flush);

    if (!last && flush == 0 && size < conf->buffer_output) {
        return NGX_OK;
    }

    chain = ngx_event_write(r->connection, ctx->out, flush);
    if (chain == (ngx_chain_t *) -1) {
        return NGX_ERROR;
    }

    ctx->out = chain;

    ngx_log_debug(r->connection->log, "write filter %x" _ chain);

    return (chain ? NGX_AGAIN : NGX_OK);
}


static void *ngx_http_write_filter_create_conf(ngx_pool_t *pool)
{
    ngx_http_write_filter_conf_t *conf;

    ngx_test_null(conf,
                  ngx_palloc(pool, sizeof(ngx_http_write_filter_conf_t)),
                  NULL);

    conf->buffer_output = NGX_CONF_UNSET;

    return conf;
}
