
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t
    ngx_http_postpone_filter_output_postponed_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_postpone_filter_init(ngx_cycle_t *cycle);


static ngx_http_module_t  ngx_http_postpone_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_postpone_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_postpone_filter_module_ctx,  /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_http_postpone_filter_init,         /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_body_filter_pt    ngx_http_next_filter;


static ngx_int_t
ngx_http_postpone_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                      rc;
    ngx_chain_t                   *out;
    ngx_http_postponed_request_t  *pr, **ppr;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http postpone filter \"%V?%V\" %p", &r->uri, &r->args, in);

    if (r != r->connection->data || (r->postponed && in)) {

        if (r->postponed) {
            for (pr = r->postponed; pr->next; pr = pr->next) { /* void */ }

            ppr = pr->request ? &pr->next : NULL;

        } else {
            ppr = &r->postponed;
#if (NGX_SUPPRESS_WARN)
            pr = NULL;
#endif
        }

        if (ppr) {
            pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
            if (pr == NULL) {
                return NGX_ERROR;
            }

            *ppr = pr;

            pr->request = NULL;
            pr->out = NULL;
            pr->next = NULL;
        }

        if (ngx_chain_add_copy(r->pool, &pr->out, in) == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (r != r->connection->data || r->postponed->request) {
            return NGX_AGAIN;
        }
    }

    if (r->postponed) {
        out = r->postponed->out;
        r->postponed = r->postponed->next;

    } else {
        out = in;
    }

    if (out == NULL && r->main->out == NULL && !r->main->connection->buffered) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http postpone filter out \"%V?%V\"", &r->uri, &r->args);

    rc = ngx_http_next_filter(r->main, out);

    if (rc == NGX_ERROR) {
        /* NGX_ERROR may be returned by any filter */
        r->connection->error = 1;
    }

    if (r->postponed == NULL) {
        return rc;
    }

    rc = ngx_http_postpone_filter_output_postponed_request(r);

    if (rc == NGX_ERROR) {
        /* NGX_ERROR may be returned by any filter */
        r->connection->error = 1;
    }

    return rc;
}


static ngx_int_t
ngx_http_postpone_filter_output_postponed_request(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_http_postponed_request_t  *pr;

    for ( ;; ) {
        pr = r->postponed;

        if (pr == NULL) {
            return NGX_OK;
        }

        if (pr->request) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http postpone filter handle \"%V?%V\"",
                           &pr->request->uri, &pr->request->args);

            if (!pr->request->done) {
                r->connection->data = pr->request;
                return NGX_AGAIN;
            }

            rc = ngx_http_postpone_filter_output_postponed_request(pr->request);

            if (rc == NGX_AGAIN || rc == NGX_ERROR) {
                return rc;
            }

            r->postponed = r->postponed->next;
            pr = r->postponed;
        }

        if (pr->out) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http postpone filter out postponed \"%V?%V\"",
                           &r->uri, &r->args);

            if (ngx_http_next_filter(r->main, pr->out) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        r->postponed = r->postponed->next;
    }
}


static ngx_int_t
ngx_http_postpone_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_postpone_filter;

    return NGX_OK;
}
