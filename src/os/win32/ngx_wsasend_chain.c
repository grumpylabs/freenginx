
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_chain_t *ngx_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    int               rc;
    char             *prev;
    size_t            size, sent;
    LPWSABUF          wsabuf;
    ngx_err_t         err;
    ngx_event_t      *wev;
    ngx_array_t       wsabufs;
    ngx_chain_t      *ce;
    LPWSAOVERLAPPED   ovlp;

#if 0

iocp:
    if ready
       get result
       update chain
       return if done;
    wsasend

non-block
    for ( ;; ) {
       wsasend
       if no again
          update chain
          return if done;
    }


    for ( ;; ) {

        make buffers and limit data for both ovlp and nonblocked,
                     configured in events module

        if (iocp && ready) {
            get result

        } else {
            if (file)
                transmitfile
            else
                wsasend

            if (iocp)
                return chain
            return chain if again
            here is result
        }

        if (result)
            update chain;
            return chain if done
        }
    }


#endif

    wev = c->write;

    if (((ngx_event_flags & NGX_HAVE_AIO_EVENT) && !wev->ready)
        || ((ngx_event_flags & NGX_HAVE_AIO_EVENT) == 0))
    {
        /*
         * WSABUFs must be 4-byte aligned otherwise
         * WSASend() will return undocumented WSAEINVAL error.
         */

        ngx_init_array(wsabufs, c->pool, 10, sizeof(WSABUF), NGX_CHAIN_ERROR);

        prev = NULL;
        wsabuf = NULL;

        /* create the WSABUF and coalesce the neighbouring chain entries */
        for (ce = in; ce; ce = ce->next) {

            if (prev == ce->hunk->pos) {
                wsabuf->len += ce->hunk->last - ce->hunk->pos;
                prev = ce->hunk->last;

            } else {
                ngx_test_null(wsabuf, ngx_push_array(&wsabufs),
                              NGX_CHAIN_ERROR);
                wsabuf->buf = ce->hunk->pos;
                wsabuf->len = ce->hunk->last - ce->hunk->pos;
                prev = ce->hunk->last;
            }
        }

        if (ngx_event_flags & NGX_HAVE_AIO_EVENT) {
            ovlp = (LPWSAOVERLAPPED) &c->write->ovlp;
            ngx_memzero(ovlp, sizeof(WSAOVERLAPPED));

        } else {
            ovlp = NULL;
        }

        rc = WSASend(c->fd, wsabufs.elts, wsabufs.nelts, &sent, 0, ovlp, NULL);

        if (rc == -1) {
            err = ngx_errno;
            if (err == WSA_IO_PENDING) {
                sent = 0;

            } else if (err == WSAEWOULDBLOCK) {
                sent = 0;
                ngx_log_error(NGX_LOG_INFO, c->log, err, "WSASend() EAGAIN");

            } else {
                ngx_log_error(NGX_LOG_CRIT, c->log, err, "WSASend() failed");
                return NGX_CHAIN_ERROR;
            }

        } else {

            if (ngx_event_flags & NGX_HAVE_IOCP_EVENT) {

                /*
                 * If a socket was bound with I/O completion port then
                 * GetQueuedCompletionStatus() would anyway return its status
                 * despite that WSASend() was already completed.
                 */

                sent = 0;
            }
        }

    } else {
        if (ngx_event_flags & NGX_HAVE_IOCP_EVENT) {
            wev->ready = 0;

            /* the overlapped WSASend() completed */

            if (wev->ovlp.error) {
                ngx_log_error(NGX_LOG_ERR, c->log, wev->ovlp.error,
                              "WSASend() failed");
                return NGX_CHAIN_ERROR;
            }

            sent = wev->available;
        }
    }

#if (NGX_DEBUG_WRITE_CHAIN)
    ngx_log_debug(c->log, "WSASend(): %d" _ sent);
#endif

    c->sent += sent;

    for (ce = in; ce && sent > 0; ce = ce->next) {

        size = ce->hunk->last - ce->hunk->pos;

        if (sent >= size) {
            sent -= size;

            if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
                ce->hunk->pos = ce->hunk->last;
            }

            continue;
        }

        if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
            ce->hunk->pos += sent;
        }

        break;
    }

    ngx_destroy_array(&wsabufs);

    return ce;
}
