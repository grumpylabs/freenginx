
#include <nginx.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_event_close.h>
#include <ngx_event_accept.h>


/* This function should always return NGX_OK even there are some failures
   because if we return NGX_ERROR then listening socket would be closed */

int ngx_event_accept(ngx_event_t *ev)
{
    socklen_t          len;
    struct sockaddr   *sa;
    ngx_err_t          err;
    ngx_pool_t        *pool;
    ngx_socket_t       s;
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c, *ls;

    ls = (ngx_connection_t *) ev->data;

    ngx_log_debug(ev->log, "ngx_event_accept: accept ready: %d" _
                  ev->available);

    ev->ready = 0;

#if 0
/* DEBUG */ ev->available++;
#endif

    do {
        ngx_test_null(pool, ngx_create_pool(ls->pool_size, ev->log), NGX_OK);

        ngx_test_null(sa, ngx_palloc(pool, ls->socklen), NGX_OK);
        len = ls->socklen;

        s = accept(ls->fd, sa, &len);
        if (s == -1) {
            err = ngx_socket_errno;
            ngx_destroy_pool(pool);

            if (err == NGX_EAGAIN) {
                ngx_log_error(NGX_LOG_NOTICE, ev->log, err,
                              "EAGAIN while accept %s", ls->addr_text.data);
                return NGX_OK;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err,
                          "accept %s failed", ls->addr_text.data);
            return NGX_OK;
        }


#if (HAVE_INHERITED_NONBLOCK)

#if (HAVE_AIO_EVENT)
        if ((ngx_event_flags & NGX_HAVE_AIO_EVENT)) {
            if (ngx_blocking(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                              ngx_blocking_n " %s failed", ls->addr_text.data);
                return NGX_OK;
            }
        }
#endif

#else /* !HAVE_INHERITED_NONBLOCK */

#if (HAVE_AIO_EVENT)
        if (!(ngx_event_flags & NGX_HAVE_AIO_EVENT)) {
            if (ngx_nonblocking(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                           ngx_nonblocking_n " %s failed", ls->addr_text.data);
                return NGX_OK;
            }
        }
#else
        if (ngx_nonblocking(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                          ngx_nonblocking_n " %s failed", ls->addr_text.data);
            return NGX_OK;
        }
#endif

#endif /* HAVE_INHERITED_NONBLOCK */


        rev = &ngx_read_events[s];
        wev = &ngx_write_events[s];
        c = &ngx_connections[s];

        ngx_memzero(rev, sizeof(ngx_event_t));
        ngx_memzero(wev, sizeof(ngx_event_t));
        ngx_memzero(c, sizeof(ngx_connection_t));

        c->pool = pool;

        c->sockaddr = sa;
        c->family = ls->family;
        c->socklen = len;
        c->addr = ls->addr;
        c->addr_text_max_len = ls->addr_text_max_len;
        c->post_accept_timeout = ls->post_accept_timeout;

        rev->index = wev->index = NGX_INVALID_INDEX;

        rev->data = wev->data = c;
        c->read = rev;
        c->write = wev;

        c->fd = s;
        c->unexpected_eof = 1;
        wev->write = 1;
        rev->first = wev->first = 1;

#if (HAVE_AIO_EVENT)
        if (!(ngx_event_flags & NGX_HAVE_AIO_EVENT)) {
            wev->ready = 1;
        }
#endif

        /* STUB ? */ wev->timer = rev->timer = 10000;

        wev->timer_handler = rev->timer_handler = ngx_event_close_connection;
        wev->close_handler = rev->close_handler = ngx_event_close_connection;

        c->ctx = ls->ctx;
        c->servers = ls->servers;

        ngx_test_null(c->log, ngx_palloc(c->pool, sizeof(ngx_log_t)), NGX_OK);
        ngx_memcpy(c->log, ev->log, sizeof(ngx_log_t));
        rev->log = wev->log = c->log;

        /* STUB: x86: SP: xadd ?, MT: lock xadd, MP: lock xadd, shared */
        c->number = ngx_connection_counter++;

        ngx_log_debug(ev->log, "ngx_event_accept: accept: %d, %d" _
                      s _ c->number);

#if (HAVE_DEFERRED_ACCEPT)
        if (ev->accept_filter) {
            rev->ready = 1;
        }
#endif

#if (HAVE_EDGE_EVENT) /* epoll */

        if (ngx_event_flags & NGX_HAVE_EDGE_EVENT) {
            if (ngx_edge_add_event(ev) == NGX_ERROR) {
                return NGX_OK;
            }
        }

#endif

        ls->handler(c);

#if (USE_KQUEUE)

        ev->available--;

#elif (HAVE_KQUEUE)

/*
        if (ngx_event_type == NGX_HAVE_AIO_EVENT  or NGX_HAVE_KQUEUE_EVENT) {
*/
        if (ngx_event_type == NGX_HAVE_KQUEUE_EVENT) {
            ev->available--;
        }

#endif
    } while (ev->available);
  
    return NGX_OK;
}
