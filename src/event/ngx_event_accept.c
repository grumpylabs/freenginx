
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>


typedef struct {
    int      flag;
    u_char  *name;
} ngx_accept_log_ctx_t;


static size_t ngx_accept_log_error(void *data, char *buf, size_t len);


ngx_atomic_t  *ngx_accept_mutex_ptr;
ngx_atomic_t  *ngx_accept_mutex;
ngx_uint_t     ngx_accept_mutex_held;


void ngx_event_accept(ngx_event_t *ev)
{
    ngx_uint_t             instance, rinstance, winstance, accepted;
    socklen_t              len;
    struct sockaddr       *sa;
    ngx_err_t              err;
    ngx_log_t             *log;
    ngx_pool_t            *pool;
    ngx_socket_t           s;
    ngx_event_t           *rev, *wev;
    ngx_connection_t      *c, *ls;
    ngx_event_conf_t      *ecf;
    ngx_accept_log_ctx_t  *ctx;

    ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    if (ngx_event_flags & (NGX_USE_EDGE_EVENT|NGX_USE_SIGIO_EVENT)) {
        ev->available = 1;

    } else if (!(ngx_event_flags & NGX_HAVE_KQUEUE_EVENT)) {
        ev->available = ecf->multi_accept;
    }

    ls = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "accept on %s, ready: %d",
                   ls->listening->addr_text.data, ev->available);

    ev->ready = 0;
    accepted = 0;
    pool = NULL;

    do {

        if (pool == NULL) {

            /*
             * Create the pool before accept() to avoid copy the sockaddr.
             * Although accept() can fail it's an uncommon case
             * and besides the pool can be got from the free pool list
             */

            if (!(pool = ngx_create_pool(ls->listening->pool_size, ev->log))) {
                return;
            }
        }

        if (!(sa = ngx_palloc(pool, ls->listening->socklen))) {
            ngx_destroy_pool(pool);
            return;
        }

        if (!(log = ngx_palloc(pool, sizeof(ngx_log_t)))) {
            ngx_destroy_pool(pool);
            return;
        }

        ngx_memcpy(log, ls->log, sizeof(ngx_log_t));
        pool->log = log;

        if (!(ctx = ngx_palloc(pool, sizeof(ngx_accept_log_ctx_t)))) {
            ngx_destroy_pool(pool);
            return;
        }

        /* -1 disable logging the connection number */
        ctx->flag = -1;
        ctx->name = ls->listening->addr_text.data;

        log->data = ctx;
        log->handler = ngx_accept_log_error;

        len = ls->listening->socklen;

        s = accept(ls->fd, sa, &len);
        if (s == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                if (!(ngx_event_flags
                      & (NGX_USE_EDGE_EVENT|NGX_USE_SIGIO_EVENT)))
                {
                    ngx_log_error(NGX_LOG_NOTICE, log, err,
                                  "EAGAIN after %d accepted connection(s)",
                                  accepted);
                }

                ngx_destroy_pool(pool);
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err,
                          "accept() on %s failed",
                          ls->listening->addr_text.data);

            if (err == NGX_ECONNABORTED) {
                if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
                    ev->available--;
                }

                if (ev->available) {
                    /* reuse the previously allocated pool */
                    continue;
                }
            }

            ngx_destroy_pool(pool);
            return;
        }

        /* disable warning: Win32 SOCKET is u_int while UNIX socket is int */

        if ((unsigned) s >= (unsigned) ecf->connections) {

            ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                          "accept() on %s returned socket #%d while "
                          "only %d connections was configured, "
                          "closing the connection",
                          ls->listening->addr_text.data, s, ecf->connections);

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                              ngx_close_socket_n "failed");
            }

            /* TODO: disable temporary accept() event */

            ngx_destroy_pool(pool);
            return;
        }

        /* set a blocking mode for aio and non-blocking mode for the others */

        if (ngx_inherited_nonblocking) {
            if ((ngx_event_flags & NGX_USE_AIO_EVENT)) {
                if (ngx_blocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                                  ngx_blocking_n " failed");

                    if (ngx_close_socket(s) == -1) {
                        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                                      ngx_close_socket_n " failed");
                    }

                    ngx_destroy_pool(pool);
                    return;
                }
            }

        } else {
            if (!(ngx_event_flags & NGX_USE_AIO_EVENT)) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                                  ngx_nonblocking_n " failed");

                    if (ngx_close_socket(s) == -1) {
                        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                                      ngx_close_socket_n " failed");
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
            ngx_log_error(NGX_LOG_EMERG, ev->log, 0,
                          "accept() on %s returned socket #%d, "
                          "not divisible by 4",
                          ls->listening->addr_text.data, s);
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
        rinstance = rev->returned_instance;
        winstance = wev->returned_instance;

        ngx_memzero(rev, sizeof(ngx_event_t));
        ngx_memzero(wev, sizeof(ngx_event_t));
        ngx_memzero(c, sizeof(ngx_connection_t));

        c->pool = pool;

        c->listening = ls->listening;
        c->sockaddr = sa;
        c->socklen = len;

        rev->instance = (u_char) !instance;
        rev->returned_instance = (u_char) rinstance;

        wev->instance = (u_char) !instance;
        wev->returned_instance = (u_char) winstance;

        rev->index = NGX_INVALID_INDEX;
        wev->index = NGX_INVALID_INDEX;

        rev->data = c;
        wev->data = c;

        c->read = rev;
        c->write = wev;

        c->fd = s;
        c->unexpected_eof = 1;

        wev->write = 1;
        wev->ready = 1;

        if (ngx_event_flags
            & (NGX_USE_AIO_EVENT|NGX_USE_EDGE_EVENT|NGX_USE_SIGIO_EVENT))
        {
            /* aio, iocp, sigio, epoll */
            rev->ready = 1;
        }

        if (ev->deferred_accept) {
            rev->ready = 1;
        }

        c->ctx = ls->ctx;
        c->servers = ls->servers;

        c->log = log;
        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - atomic increment (x86: lock xadd)
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - atomic increment (x86: lock xadd)
         *             or protection by critical section or light mutex
         */

        c->number = ngx_atomic_inc(&ngx_connection_counter);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "accept: fd:%d c:%d", s, c->number);

        if (ngx_add_conn) {
            if (ngx_add_conn(c) == NGX_ERROR) {
                if (ngx_close_socket(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  ngx_close_socket_n " failed");
                }

                ngx_destroy_pool(pool);
                return;
            }
        }

        pool = NULL;

        log->data = NULL;
        log->handler = NULL;

        ls->listening->handler(c);

        if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
            ev->available--;
        }

        accepted++;

    } while (ev->available);
}


ngx_int_t ngx_trylock_accept_mutex(ngx_cycle_t *cycle)
{
    if (*ngx_accept_mutex == 0 && ngx_atomic_cmp_set(ngx_accept_mutex, 0, 1)) {

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "accept mutex locked");

        if (!ngx_accept_mutex_held) {
            if (ngx_enable_accept_events(cycle) == NGX_ERROR) {
                *ngx_accept_mutex = 0;
                return NGX_ERROR;
            }

            ngx_accept_mutex_held = 1;
        }

        return NGX_OK;
    }

    if (ngx_accept_mutex_held) {
        if (ngx_disable_accept_events(cycle) == NGX_ERROR) {
            return NGX_ERROR;
        }

        ngx_accept_mutex_held = 0;
    }

    return NGX_OK;
}


ngx_int_t ngx_enable_accept_events(ngx_cycle_t *cycle)
{
    ngx_uint_t        i;
    ngx_listening_t  *s;

    s = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        /*
         * we do not need to handle the Winsock sockets here (divde a socket
         * number by 4) because this function would never called
         * in the Winsock environment
         */

        if (ngx_event_flags & NGX_USE_SIGIO_EVENT) {
            if (ngx_add_conn(&cycle->connections[s[i].fd]) == NGX_ERROR) {
                return NGX_ERROR;
            }

        } else {
            if (ngx_add_event(&cycle->read_events[s[i].fd], NGX_READ_EVENT, 0)
                                                                  == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


ngx_int_t ngx_disable_accept_events(ngx_cycle_t *cycle)
{
    ngx_uint_t        i;
    ngx_listening_t  *s;

    s = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        /*
         * we do not need to handle the Winsock sockets here (divde a socket
         * number by 4) because this function would never called
         * in the Winsock environment
         */

        if (ngx_event_flags & NGX_USE_SIGIO_EVENT) {
            if (ngx_del_conn(&cycle->connections[s[i].fd], NGX_DISABLE_EVENT)
                                                                  == NGX_ERROR)
            {
                return NGX_ERROR;
            }

        } else {
            if (ngx_del_event(&cycle->read_events[s[i].fd], NGX_READ_EVENT,
                                               NGX_DISABLE_EVENT) == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static size_t ngx_accept_log_error(void *data, char *buf, size_t len)
{
    ngx_accept_log_ctx_t  *ctx = data;

    return ngx_snprintf(buf, len, " while accept() on %s", ctx->name);
}
