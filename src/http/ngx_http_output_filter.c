
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_files.h>
#include <ngx_string.h>
#include <ngx_hunk.h>
#include <ngx_conf_file.h>

#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_output_filter.h>


static int ngx_http_output_filter_copy_hunk(ngx_hunk_t *dst, ngx_hunk_t *src);
static void *ngx_http_output_filter_create_conf(ngx_pool_t *pool);
static char *ngx_http_output_filter_merge_conf(ngx_pool_t *pool,
                                               void *parent, void *child);
static void ngx_http_output_filter_init(ngx_pool_t *pool,
                                        ngx_http_conf_filter_t *cf);


static ngx_command_t  ngx_http_output_filter_commands[] = {

    {ngx_string("output_buffer"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_output_filter_conf_t, hunk_size),
     NULL},

    {ngx_null_string, 0, NULL, 0, 0, NULL}
};


static ngx_http_module_t  ngx_http_output_filter_module_ctx = {
    NGX_HTTP_MODULE,

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_output_filter_create_conf,    /* create location configuration */
    ngx_http_output_filter_merge_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_output_filter_module = {
    &ngx_http_output_filter_module_ctx,    /* module context */
    0,                                     /* module index */
    ngx_http_output_filter_commands,       /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    NULL                                   /* init module */
};


#define next_filter  (*ngx_http_top_body_filter)

#if 0
static int (*next_filter) (ngx_http_request_t *r, ngx_chain_t *ch);
#endif


#if 0
#define next_filter  ngx_http_output_filter_module_ctx.next_output_body_filter
#endif

#define need_to_copy(r, hunk)                                             \
            (((r->filter & NGX_HTTP_FILTER_NEED_IN_MEMORY)                \
               && (hunk->type & NGX_HUNK_IN_MEMORY) == 0)                 \
             || ((r->filter & NGX_HTTP_FILTER_NEED_TEMP)                  \
                  && (hunk->type & (NGX_HUNK_MEMORY|NGX_HUNK_MMAP))))


int ngx_http_output_filter(ngx_http_request_t *r, ngx_hunk_t *hunk)
{
    int                             rc;
    size_t                          size;
    ngx_chain_t                    *ce, *le;
    ngx_http_output_filter_ctx_t   *ctx;
    ngx_http_output_filter_conf_t  *conf;

    ctx = (ngx_http_output_filter_ctx_t *)
                    ngx_http_get_module_ctx(r->main ? r->main : r,
                                            ngx_http_output_filter_module_ctx);

    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx, ngx_http_output_filter_module_ctx,
                            sizeof(ngx_http_output_filter_ctx_t), NGX_ERROR);
    }

    /* the short path for the case when the chain ctx->incoming is empty
       and there is no hunk or the hunk does not require the copy */
    if (ctx->incoming == NULL) {

        if (hunk == NULL) {
            return next_filter(r, NULL);
        }

        /* we do not need to copy the incoming hunk to our hunk */
        if (!need_to_copy(r, hunk)) {
            ctx->out.hunk = hunk;
            ctx->out.next = NULL;
            return next_filter(r, &ctx->out);
        }
    }

    /* add the incoming hunk to the chain ctx->incoming */
    if (hunk) {

        /* the output of the only hunk is common case so we have
           the special chain entry ctx->in for it */
        if (ctx->incoming == NULL) {
            ctx->in.hunk = hunk;
            ctx->in.next = NULL;
            ctx->incoming = &ctx->in;

        } else {
            for (ce = ctx->incoming; ce->next; ce = ce->next) { /* void */ ; }
            ngx_add_hunk_to_chain(ce->next, hunk, r->pool, NGX_ERROR);
        }
    }

    /* allocate our hunk if it's needed */
    if (ctx->hunk == NULL) {

        conf = (ngx_http_output_filter_conf_t *)
               ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                            ngx_http_output_filter_module_ctx);

        if (hunk->type & NGX_HUNK_LAST) {
            if (hunk->type & NGX_HUNK_IN_MEMORY) {
                size = hunk->last - hunk->pos;
            } else {
                size = hunk->file_last - hunk->file_pos;
            }

            if (size > conf->hunk_size) {
                size = conf->hunk_size;
            }

        } else {
            size = conf->hunk_size;
        }

        ngx_test_null(ctx->hunk,
                      ngx_create_temp_hunk(r->pool, size, 50, 50),
                      NGX_ERROR);
        ctx->hunk->type |= NGX_HUNK_RECYCLED;


    /* our hunk is still busy */
    } else if (ctx->hunk->pos < ctx->hunk->last) {
        rc = next_filter(r, NULL);

        if (rc == NGX_ERROR || rc == NGX_AGAIN) {
            return rc;
        }

        /* NGX_OK */
        /* set our hunk free */
        ctx->hunk->pos = ctx->hunk->last = ctx->hunk->start;
    }

#if (NGX_SUPPRESS_WARN)
    le = NULL;
#endif

    /* process the chain ctx->incoming */
    do {
        /* find the hunks that do not need to be copied ... */
        for (ce = ctx->incoming; ce; ce = ce->next) {
            if (need_to_copy(r, ce->hunk)) {
                break;
            }
            le = ce;
        }

        /* ... and pass them to the next filter */
        if (ctx->incoming != ce) {

            ctx->out.hunk = ctx->incoming->hunk;
            ctx->out.next = ctx->incoming->next;
            ctx->incoming = ce;
            le->next = NULL;

            rc = next_filter(r, &ctx->out);
            if (rc == NGX_ERROR || rc == NGX_AGAIN) {
                return rc;
            }

            /* NGX_OK */
            if (ctx->incoming == NULL) {
                return rc;
            }
        }

        /* copy the first hunk or its part from the chain ctx->incoming
           to our hunk and pass it to the next filter */
        do {
            rc = ngx_http_output_filter_copy_hunk(ctx->hunk,
                                                  ctx->incoming->hunk);
            if (rc == NGX_ERROR) {
                return rc;
            }

#if (NGX_FILE_AIO_READ)
            if (rc == NGX_AGAIN) {
                return rc;
            }
#endif
            ctx->out.hunk = ctx->hunk;
            ctx->out.next = NULL;

            rc = next_filter(r, &ctx->out);
            if (rc == NGX_ERROR || rc == NGX_AGAIN) {
                return rc;
            }

            /* NGX_OK */
            /* set our hunk free */
            ctx->hunk->pos = ctx->hunk->last = ctx->hunk->start;

            /* repeat until we will have copied the whole first hunk from
               the chain ctx->incoming */

            if (ctx->incoming->hunk->type & NGX_HUNK_IN_MEMORY) {
                size = ctx->incoming->hunk->last - ctx->incoming->hunk->pos;

            } else {
                size = ctx->incoming->hunk->file_last
                                               - ctx->incoming->hunk->file_pos;
            }

        } while (size);

    /* delete the completed hunk from the incoming chain */
    ctx->incoming = ctx->incoming->next;

    /* repeat until we will have processed the whole chain ctx->incoming */
    } while (ctx->incoming);

    return NGX_OK;
}


static int ngx_http_output_filter_copy_hunk(ngx_hunk_t *dst, ngx_hunk_t *src)
{
    ssize_t  n, size;

    if (src->type & NGX_HUNK_IN_MEMORY) {
        size = src->last - src->pos;
    } else {
        size = src->file_last - src->file_pos;
    }

    if (size > (dst->end - dst->pos)) {
        size = dst->end - dst->pos;
    }

    if (src->type & NGX_HUNK_IN_MEMORY) {
        ngx_memcpy(dst->pos, src->pos, size);
        src->pos += size;
        dst->last += size;

        if (src->type & NGX_HUNK_FILE) {
            src->file_pos += size;
        }

        if ((src->type & NGX_HUNK_LAST) && src->pos == src->last) {
            dst->type |= NGX_HUNK_LAST;
        }

    } else {
        n = ngx_read_file(src->file, dst->pos, size, src->file_pos);

        if (n == NGX_ERROR) {
            return n;
        }

#if (NGX_FILE_AIO_READ)
        if (n == NGX_AGAIN) {
            return n;
        }
#endif

        if (n != size) {
            ngx_log_error(NGX_LOG_ALERT, src->file->log, 0,
                          ngx_read_file_n " reads only %d of %d from file",
                          n, size);
            if (n == 0) {
                return NGX_ERROR;
            }
        }

        src->file_pos += n;
        dst->last += n;

        if ((src->type & NGX_HUNK_LAST) && src->file_pos == src->file_last) {
            dst->type |= NGX_HUNK_LAST;
        }
    }

    return NGX_OK;
}


static void ngx_http_output_filter_init(ngx_pool_t *pool,
                                        ngx_http_conf_filter_t *cf)
{
#if 0
    next_filter = cf->output_body_filter;
    cf->output_body_filter = NULL;
#endif
}


static void *ngx_http_output_filter_create_conf(ngx_pool_t *pool)
{
    ngx_http_output_filter_conf_t *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(pool, sizeof(ngx_http_output_filter_conf_t)),
                  NULL);

    conf->hunk_size = NGX_CONF_UNSET;

    return conf;
}


static char *ngx_http_output_filter_merge_conf(ngx_pool_t *pool,
                                               void *parent, void *child)
{
    ngx_http_output_filter_conf_t *prev =
                                      (ngx_http_output_filter_conf_t *) parent;
    ngx_http_output_filter_conf_t *conf =
                                       (ngx_http_output_filter_conf_t *) child;

    ngx_conf_merge_size_value(conf->hunk_size, prev->hunk_size, 32768);

    return NULL;
}
