
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>


void ngx_event_accept(ngx_event_t *ev)
{
    int                instance;
    socklen_t          len;
    struct sockaddr   *sa;
    ngx_err_t          err;
    ngx_pool_t        *pool;
    ngx_socket_t       s;
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c, *ls;
    ngx_event_conf_t  *ecf;

    ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    ls = ev->data;

    ngx_log_debug(ev->log, "ngx_event_accept: accept ready: %d" _
                  ev->available);

    ev->ready = 0;

    do {

        /*
         * Create the pool before accept() to avoid copy the sockaddr.
         * Although accept() can fail it's an uncommon case
         * and the pool can be got from the free pool list
         */

        pool = ngx_create_pool(ls->listening->pool_size, ev->log);
        if (pool == NULL) {
            return;
        }

        sa = ngx_palloc(pool, ls->listening->socklen);
        if (sa == NULL) {
            return;
        }

        len = ls->listening->socklen;

ngx_log_debug(ev->log, "ADDR %s" _ ls->listening->addr_text.data);

        s = accept(ls->fd, sa, &len);
        if (s == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                ngx_log_error(NGX_LOG_NOTICE, ev->log, err,
                              "EAGAIN while accept() %s",
                              ls->listening->addr_text.data);
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err,
                          "accept() %s failed", ls->listening->addr_text.data);

            ngx_destroy_pool(pool);
            return;
        }

        /* disable warnings: Win32 SOCKET is u_int while UNIX socket is int */
        if ((unsigned) s >= (unsigned) ecf->connections) {

            ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                          "accept() %s returned socket #%d while "
                          "only %d connections was configured, "
                          "sleeping for 1 second",
                          ls->listening->addr_text.data, s, ecf->connections);

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                              ngx_close_socket_n " %s failed",
                              ls->listening->addr_text.data);
            }

            ngx_msleep(1000);

            ngx_destroy_pool(pool);
            return;
        }

        /* set a blocking mode for aio and non-blocking mode for others */

        if (ngx_inherited_nonblocking) {
            if ((ngx_event_flags & NGX_USE_AIO_EVENT)) {
                if (ngx_blocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  ngx_blocking_n " %s failed",
                                  ls->listening->addr_text.data);

                    if (ngx_close_socket(s) == -1) {
                        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                      ngx_close_socket_n " %s failed",
                                      ls->listening->addr_text.data);
                    }

                    ngx_destroy_pool(pool);
                    return;
                }
            }

        } else {
            if ((ngx_event_flags & NGX_USE_AIO_EVENT) == 0) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  ngx_nonblocking_n " %s failed",
                                  ls->listening->addr_text.data);

                    if (ngx_close_socket(s) == -1) {
                        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                      ngx_close_socket_n " %s failed",
                                      ls->listening->addr_text.data);
                    }

                    ngx_destroy_pool(pool);
                    return;
                }
            }
        }

#if (WIN32)
        /*
         * Winsock assignes a socket number divisible by 4
         * so to find a connection we divide a socket number by 4.
         */

        if (s % 4) {
            ngx_log_error(NGX_LOG_EMERG, ls->log, 0,
                          ngx_socket_n
                          " created socket %d, not divisible by 4", s);
            exit(1);
        }

        c = &ngx_cycle->connections[s / 4];
        rev = &ngx_cycle->read_events[s / 4];
        wev = &ngx_cycle->write_events[s / 4];
#else
        c = &ngx_cycle->connections[s];
        rev = &ngx_cycle->read_events[s];
        wev = &ngx_cycle->write_events[s];
#endif

        instance = rev->instance;

        ngx_memzero(rev, sizeof(ngx_event_t));
        ngx_memzero(wev, sizeof(ngx_event_t));
        ngx_memzero(c, sizeof(ngx_connection_t));

        c->pool = pool;

        c->listening = ls->listening;
        c->sockaddr = sa;
        c->socklen = len;

        rev->instance = wev->instance = !instance;

        rev->index = wev->index = NGX_INVALID_INDEX;

        rev->data = wev->data = c;
        c->read = rev;
        c->write = wev;

        c->fd = s;
        c->unexpected_eof = 1;
        wev->write = 1;

        if ((ngx_event_flags & NGX_USE_AIO_EVENT) == 0) {
            wev->ready = 1;
        }

        c->ctx = ls->ctx;
        c->servers = ls->servers;

#if 0
        c->log = ngx_palloc(c->pool, sizeof(ngx_log_t));
        if (c->log == NULL) {
            return;
        }
        ngx_memcpy(c->log, ev->log, sizeof(ngx_log_t));
#endif
        rev->log = wev->log = c->log = ev->log;

        /* TODO: x86: MT: lock xadd, MP: lock xadd, shared */
        c->number = ngx_connection_counter++;

        ngx_log_debug(ev->log, "accept: %d, %d" _ s _ c->number);

        if (ev->deferred_accept) {
            rev->ready = 1;
        }

        if (ngx_add_conn) {
            if (ngx_add_conn(c) == NGX_ERROR) {
                if (ngx_close_socket(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  ngx_close_socket_n " %s failed",
                                  ls->listening->addr_text.data);
                }

                ngx_destroy_pool(pool);
                return;
            }
        }

        ls->listening->handler(c);

        if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
            ev->available--;
        }

    } while (ev->available);

    return;
}
