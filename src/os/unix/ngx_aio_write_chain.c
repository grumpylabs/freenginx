
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_aio.h>


ngx_chain_t *ngx_aio_write_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    int           n;
    u_char       *buf, *prev;
    off_t         sent;
    size_t        size;
    ngx_err_t     err;
    ngx_chain_t  *cl;

    sent = 0;
    cl = in;

    while (cl) {

        if (cl->hunk->last - cl->hunk->pos == 0) {
            cl = cl->next;
            continue;
        }

        /* we can post the single aio operation only */

        if (!c->write->ready) {
            return cl;
        }

        buf = cl->hunk->pos;
        prev = buf;
        size = 0;

        /* coalesce the neighbouring hunks */

        while (cl && prev == cl->hunk->pos) {
            size += cl->hunk->last - cl->hunk->pos;
            prev = cl->hunk->last;
            cl = cl->next;
        }

        n = ngx_aio_write(c, buf, size);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "aio_write: %d", n);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n > 0) {
            sent += n;
            c->sent += n;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "aio_write sent: " OFF_T_FMT, c->sent);

        for (cl = in; cl; cl = cl->next) {

            if (sent >= cl->hunk->last - cl->hunk->pos) {
                sent -= cl->hunk->last - cl->hunk->pos;
                cl->hunk->pos = cl->hunk->last;

                continue;
            }

            cl->hunk->pos += sent;

            break;
        }
    }

    return cl;
}
