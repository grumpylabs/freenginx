
/*
 * Copyright (C) 2002-2004 Igor Sysoev, http://sysoev.ru/en/
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_kqueue_module.h>


typedef struct {
    int  changes;
    int  events;
} ngx_kqueue_conf_t;


static int ngx_kqueue_init(ngx_cycle_t *cycle);
static void ngx_kqueue_done(ngx_cycle_t *cycle);
static int ngx_kqueue_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_kqueue_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_kqueue_set_event(ngx_event_t *ev, int filter, u_int flags);
static int ngx_kqueue_process_events(ngx_log_t *log);

static void *ngx_kqueue_create_conf(ngx_cycle_t *cycle);
static char *ngx_kqueue_init_conf(ngx_cycle_t *cycle, void *conf);


int                    ngx_kqueue = -1;

static struct kevent  *change_list, *event_list;
static int             max_changes, nchanges, nevents;


static ngx_str_t      kqueue_name = ngx_string("kqueue");

static ngx_command_t  ngx_kqueue_commands[] = {

    {ngx_string("kqueue_changes"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_kqueue_conf_t, changes),
     NULL},

    {ngx_string("kqueue_events"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_kqueue_conf_t, events),
     NULL},

    ngx_null_command
};


ngx_event_module_t  ngx_kqueue_module_ctx = {
    &kqueue_name,
    ngx_kqueue_create_conf,                /* create configuration */
    ngx_kqueue_init_conf,                  /* init configuration */

    {
        ngx_kqueue_add_event,              /* add an event */
        ngx_kqueue_del_event,              /* delete an event */
        ngx_kqueue_add_event,              /* enable an event */
        ngx_kqueue_del_event,              /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        ngx_kqueue_process_events,         /* process the events */
        ngx_kqueue_init,                   /* init the events */
        ngx_kqueue_done                    /* done the events */
    }

};

ngx_module_t  ngx_kqueue_module = {
    NGX_MODULE,
    &ngx_kqueue_module_ctx,                /* module context */
    ngx_kqueue_commands,                   /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};



static int ngx_kqueue_init(ngx_cycle_t *cycle)
{
    struct timespec     ts;
    ngx_kqueue_conf_t  *kcf;

    kcf = ngx_event_get_conf(cycle->conf_ctx, ngx_kqueue_module);

    if (ngx_kqueue == -1) {
        ngx_kqueue = kqueue();

        if (ngx_kqueue == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "kqueue() failed");
            return NGX_ERROR;
        }
    }

    if (max_changes < kcf->changes) {
        if (nchanges) {
            ts.tv_sec = 0;
            ts.tv_nsec = 0;

            if (kevent(ngx_kqueue, change_list, nchanges, NULL, 0, &ts) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "kevent() failed");
                return NGX_ERROR;
            }
            nchanges = 0;
        }

        if (change_list) {
            ngx_free(change_list);
        }

        change_list = ngx_alloc(kcf->changes * sizeof(struct kevent),
                                cycle->log);
        if (change_list == NULL) {
            return NGX_ERROR;
        }
    }

    max_changes = kcf->changes;

    if (nevents < kcf->events) {
        if (event_list) {
            ngx_free(event_list);
        }

        event_list = ngx_alloc(kcf->events * sizeof(struct kevent),
                                cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    nevents = kcf->events;

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_kqueue_module_ctx.actions;

    ngx_event_flags = NGX_USE_ONESHOT_EVENT
#if (HAVE_CLEAR_EVENT)
                     |NGX_USE_CLEAR_EVENT
#else
                     |NGX_USE_LEVEL_EVENT
#endif
#if (HAVE_LOWAT_EVENT)
                     |NGX_HAVE_LOWAT_EVENT
#endif
                     |NGX_HAVE_KQUEUE_EVENT;

    return NGX_OK;
}


static void ngx_kqueue_done(ngx_cycle_t *cycle)
{
    if (close(ngx_kqueue) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "kqueue close() failed");
    }

    ngx_kqueue = -1;

    ngx_free(change_list);
    ngx_free(event_list);

    change_list = NULL;
    event_list = NULL;
    max_changes = 0;
    nchanges = 0;
    nevents = 0;
}


static int ngx_kqueue_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t       *e;
    ngx_connection_t  *c;

    ev->active = 1;
    ev->disabled = 0;
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;

    if (nchanges > 0
        && ev->index < (u_int) nchanges
        && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
                                                             == (uintptr_t) ev)
    {
        if (change_list[ev->index].flags == EV_DISABLE) {

            /*
             * if the EV_DISABLE is still not passed to a kernel
             * we will not pass it
             */

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                           "kevent activated: %d: ft:%d",
                           ngx_event_ident(ev->data), event);

            if (ev->index < (u_int) --nchanges) {
                e = (ngx_event_t *) change_list[nchanges].udata;
                change_list[ev->index] = change_list[nchanges];
                e->index = ev->index;
            }

            return NGX_OK;
        }

        c = ev->data;
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "previous event on #%d were not passed in kernel", c->fd);

        return NGX_ERROR;
    }

    return ngx_kqueue_set_event(ev, event, EV_ADD|EV_ENABLE|flags);
}


static int ngx_kqueue_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t  *e;

    ev->active = 0;
    ev->disabled = 0;

    if (nchanges > 0
        && ev->index < (u_int) nchanges
        && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
                                                             == (uintptr_t) ev)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "kevent deleted: %d: ft:%d",
                       ngx_event_ident(ev->data), event);

        /* if the event is still not passed to a kernel we will not pass it */

        if (ev->index < (u_int) --nchanges) {
            e = (ngx_event_t *) change_list[nchanges].udata;
            change_list[ev->index] = change_list[nchanges];
            e->index = ev->index;
        }

        return NGX_OK;
    }

    /*
     * when the file descriptor is closed a kqueue automatically deletes
     * its filters so we do not need to delete explicity the event
     * before the closing the file descriptor.
     */

    if (flags & NGX_CLOSE_EVENT) {
        return NGX_OK;
    }

    if (flags & NGX_DISABLE_EVENT) {
        ev->disabled = 1;
    }

    return ngx_kqueue_set_event(ev, event,
                           flags & NGX_DISABLE_EVENT ? EV_DISABLE : EV_DELETE);
}


static int ngx_kqueue_set_event(ngx_event_t *ev, int filter, u_int flags)
{
    struct timespec    ts;
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "kevent set event: %d: ft:%d fl:%04X",
                   c->fd, filter, flags);

    if (nchanges >= max_changes) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "kqueue change list is filled up");

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(ngx_kqueue, change_list, nchanges, NULL, 0, &ts) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "kevent() failed");
            return NGX_ERROR;
        }

        nchanges = 0;
    }

    change_list[nchanges].ident = c->fd;
    change_list[nchanges].filter = filter;
    change_list[nchanges].flags = flags;
    change_list[nchanges].udata = (void *) ((uintptr_t) ev | ev->instance);

    if (filter == EVFILT_VNODE) {
        change_list[nchanges].fflags = NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND
                                       |NOTE_ATTRIB|NOTE_RENAME
#if (__FreeBSD__ == 4 && __FreeBSD_version >= 430000) \
    || __FreeBSD_version >= 500018
                                       |NOTE_REVOKE
#endif
                                       ;
        change_list[nchanges].data = 0;

    } else {
#if (HAVE_LOWAT_EVENT)
        if (flags & NGX_LOWAT_EVENT) {
            change_list[nchanges].fflags = NOTE_LOWAT;
            change_list[nchanges].data = ev->available;

        } else {
            change_list[nchanges].fflags = 0;
            change_list[nchanges].data = 0;
        }
#else
        change_list[nchanges].fflags = 0;
        change_list[nchanges].data = 0;
#endif
    }

    ev->index = nchanges;

    nchanges++;

    return NGX_OK;
}


static int ngx_kqueue_process_events(ngx_log_t *log)
{
    int                events;
    ngx_int_t          instance, i;
    ngx_err_t          err;
    ngx_msec_t         timer;
    ngx_event_t       *ev;
    ngx_epoch_msec_t   delta;
    struct timeval     tv;
    struct timespec    ts, *tp;

    timer = ngx_event_find_timer();
    ngx_old_elapsed_msec = ngx_elapsed_msec;

    if (timer) {
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
        tp = &ts;

    } else {
        tp = NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "kevent timer: %d", timer);

    events = kevent(ngx_kqueue, change_list, nchanges, event_list, nevents, tp);

    if (events == -1) {
        err = ngx_errno;
    } else {
        err = 0;
    }

    nchanges = 0;

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    delta = ngx_elapsed_msec;
    ngx_elapsed_msec = tv.tv_sec * 1000 + tv.tv_usec / 1000 - ngx_start_msec;

    if (err) {
        ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                      log, err, "kevent() failed");
        return NGX_ERROR;
    }

    if (timer) {
        delta = ngx_elapsed_msec - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                       "kevent timer: %d, delta: %d", timer, (int) delta);

    } else {
        if (events == 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "kevent() returned no events without timeout");
            return NGX_ERROR;
        }
    }

    for (i = 0; i < events; i++) {

        ngx_log_debug6(NGX_LOG_DEBUG_EVENT, log, 0,

                       (event_list[i].ident > 0x8000000
                        && event_list[i].ident != (unsigned) -1) ?
                        "kevent: " PTR_FMT ": ft:%d fl:%04X ff:%08X d:%d ud:"
                                                                     PTR_FMT:
                        "kevent: %d: ft:%d fl:%04X ff:%08X d:%d ud:" PTR_FMT,

                        event_list[i].ident, event_list[i].filter,
                        event_list[i].flags, event_list[i].fflags,
                        event_list[i].data, event_list[i].udata);

        if (event_list[i].flags & EV_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, event_list[i].data,
                          "kevent() error on %d", event_list[i].ident);
            continue;
        }

        ev = (ngx_event_t *) event_list[i].udata;

        switch (event_list[i].filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:

            instance = (uintptr_t) ev & 1;
            ev = (ngx_event_t *) ((uintptr_t) ev & (uintptr_t) ~1);

            if (ev->active == 0 || ev->instance != instance) {

                /*
                 * it's a stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                               "kevent: stale event " PTR_FMT, ev);
                continue;
            }

            ev->available = event_list[i].data;

            if (event_list[i].flags & EV_EOF) {
                ev->kq_eof = 1;
                ev->kq_errno = event_list[i].fflags;
            }

            if (ev->oneshot && ev->timer_set) {
                ngx_del_timer(ev);
            }

            ev->ready = 1;

            ev->event_handler(ev);

            break;

        case EVFILT_VNODE:
            ev->kq_vnode = 1;

            ev->event_handler(ev);

            break;

        case EVFILT_AIO:
            ev->complete = 1;
            ev->ready = 1;

            ev->event_handler(ev);

            break;


        default:
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "unexpected kevent() filter %d",
                          event_list[i].filter);
        }
    }

    if (timer && delta) {
        ngx_event_expire_timers((ngx_msec_t) delta);
    }

    return NGX_OK;
}


static void *ngx_kqueue_create_conf(ngx_cycle_t *cycle)
{
    ngx_kqueue_conf_t  *kcf;

    ngx_test_null(kcf, ngx_palloc(cycle->pool, sizeof(ngx_kqueue_conf_t)),
                  NGX_CONF_ERROR);

    kcf->changes = NGX_CONF_UNSET;
    kcf->events = NGX_CONF_UNSET;

    return kcf;
}


static char *ngx_kqueue_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_kqueue_conf_t *kcf = conf;

    ngx_conf_init_value(kcf->changes, 512);
    ngx_conf_init_value(kcf->events, 512);

    return NGX_CONF_OK;
}
