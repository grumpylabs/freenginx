
/*
 * Copyright (C) 2002-2003 Igor Sysoev, http://sysoev.ru
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_kqueue_module.h>


static int ngx_kqueue_init(ngx_log_t *log);
static void ngx_kqueue_done(ngx_log_t *log);
static int ngx_kqueue_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_kqueue_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_kqueue_set_event(ngx_event_t *ev, int filter, u_int flags);
static int ngx_kqueue_process_events(ngx_log_t *log);

static void *ngx_kqueue_create_conf(ngx_pool_t *pool);
static char *ngx_kqueue_init_conf(ngx_pool_t *pool, void *conf);


int                    ngx_kqueue;

static struct kevent  *change_list, *event_list;
static u_int           max_changes, nchanges;
static int             nevents;


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

    {ngx_string(""), 0, NULL, 0, 0, NULL}
};


ngx_event_module_t  ngx_kqueue_module_ctx = {
    NGX_EVENT_MODULE,
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
    &ngx_kqueue_module_ctx,                /* module context */
    0,                                     /* module index */
    ngx_kqueue_commands,                   /* module directives */
    NGX_EVENT_MODULE_TYPE,                 /* module type */
    NULL                                   /* init module */
};


static int ngx_kqueue_init(ngx_log_t *log)
{
    ngx_kqueue_conf_t  *kcf;

    kcf = ngx_event_get_conf(ngx_kqueue_module_ctx);

ngx_log_debug(log, "CH: %d" _ kcf->changes);
ngx_log_debug(log, "EV: %d" _ kcf->events);

    max_changes = kcf->changes;
    nevents = kcf->events;
    nchanges = 0;

    ngx_kqueue = kqueue();

    if (ngx_kqueue == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "kqueue() failed");
        return NGX_ERROR;
    }

    ngx_test_null(change_list,
                  ngx_alloc(kcf->changes * sizeof(struct kevent), log),
                  NGX_ERROR);
    ngx_test_null(event_list,
                  ngx_alloc(kcf->events * sizeof(struct kevent), log),
                  NGX_ERROR);

    if (ngx_event_timer_init(log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_event_actions = ngx_kqueue_module_ctx.actions;

    ngx_event_flags = NGX_HAVE_LEVEL_EVENT
                     |NGX_HAVE_ONESHOT_EVENT
#if (HAVE_CLEAR_EVENT)
                     |NGX_HAVE_CLEAR_EVENT
#else
                     |NGX_USE_LEVEL_EVENT
#endif
#if (HAVE_LOWAT_EVENT)
                     |NGX_HAVE_LOWAT_EVENT
#endif
                     |NGX_HAVE_KQUEUE_EVENT;

    return NGX_OK;
}


static void ngx_kqueue_done(ngx_log_t *log)
{
    if (close(ngx_kqueue) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "kqueue close() failed");
    }

    ngx_event_timer_done(log);

    ngx_free(change_list);
    ngx_free(event_list);
}


static int ngx_kqueue_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_connection_t  *c;

    ev->active = 1;
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;

    if (nchanges > 0
        && ev->index < nchanges
        && (void *) ((uintptr_t) change_list[ev->index].udata & ~1) == ev)
    {
        c = ev->data;
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "previous event were not passed in kernel", c->fd);

        return NGX_ERROR;
    }

    return ngx_kqueue_set_event(ev, event, EV_ADD | flags);
}


static int ngx_kqueue_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_event_t  *e;

    ev->active = 0;

    if (nchanges > 0
        && ev->index < nchanges
        && (void *) ((uintptr_t) change_list[ev->index].udata & ~1) == ev)
    {
#if (NGX_DEBUG_EVENT)
        ngx_connection_t *c = (ngx_connection_t *) ev->data;
        ngx_log_debug(ev->log, "kqueue event deleted: %d: ft:%d" _
                      c->fd _ event);
#endif

        /* if the event is still not passed to a kernel we will not pass it */

        if (ev->index < --nchanges) {
            e = (ngx_event_t *) change_list[nchanges].udata;
            change_list[ev->index] = change_list[nchanges];
            e->index = ev->index;
        }

        return NGX_OK;
    }

    /* when the file descriptor is closed a kqueue automatically deletes
       its filters so we do not need to delete explicity the event
       before the closing the file descriptor */

    if (flags & NGX_CLOSE_EVENT) {
        return NGX_OK;
    }

    return ngx_kqueue_set_event(ev, event, EV_DELETE);
}


static int ngx_kqueue_set_event(ngx_event_t *ev, int filter, u_int flags)
{
    struct timespec     ts;
    ngx_connection_t   *c;

    c = ev->data;

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(ev->log, "kqueue set event: %d: ft:%d f:%08x" _
                  c->fd _ filter _ flags);
#endif

    if (nchanges >= max_changes) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "kqueue change list is filled up");

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(ngx_kqueue, change_list, nchanges, NULL, 0, &ts) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "kevent failed");
            return NGX_ERROR;
        }

        nchanges = 0;
    }

    change_list[nchanges].ident = c->fd;
    change_list[nchanges].filter = filter;
    change_list[nchanges].flags = flags;
    change_list[nchanges].udata = (void *) ((uintptr_t) ev | ev->instance);

#if (HAVE_LOWAT_EVENT)

    if ((flags & EV_ADD) && ev->lowat > 0) {
        change_list[nchanges].fflags = NOTE_LOWAT;
        change_list[nchanges].data = ev->lowat;

    } else {
        change_list[nchanges].fflags = 0;
        change_list[nchanges].data = 0;
    }

#else

    change_list[nchanges].fflags = 0;
    change_list[nchanges].data = 0;

#endif

    ev->index = nchanges;

    nchanges++;

    return NGX_OK;
}


static int ngx_kqueue_process_events(ngx_log_t *log)
{
    int              events, instance, i;
    ngx_msec_t       timer, delta;
    ngx_event_t      *ev;
    struct timeval   tv;
    struct timespec  ts, *tp;

    timer = ngx_event_find_timer();

    if (timer) {
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
        tp = &ts;
        gettimeofday(&tv, NULL);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    } else {
        timer = 0;
        delta = 0;
        tp = NULL;
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(log, "kevent timer: %d" _ timer);
#endif

    events = kevent(ngx_kqueue, change_list, nchanges, event_list, nevents, tp);

    if (events == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "kevent failed");
        return NGX_ERROR;
    }

    nchanges = 0;

    if (timer) {
        gettimeofday(&tv, NULL);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000 - delta;

        /* The expired timers must be handled before a processing of the events
           because the new timers can be added during a processing */

        ngx_event_expire_timers(delta);

    } else {
        if (events == 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "kevent returns no events without timeout");
            return NGX_ERROR;
        }
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(log, "kevent timer: %d, delta: %d" _ timer _ delta);
#endif

    for (i = 0; i < events; i++) {

#if (NGX_DEBUG_EVENT)
        if (event_list[i].ident > 0x8000000) {
            ngx_log_debug(log,
                          "kevent: %08x: ft:%d f:%08x ff:%08x d:%d ud:%08x" _
                          event_list[i].ident _ event_list[i].filter _
                          event_list[i].flags _ event_list[i].fflags _
                          event_list[i].data _ event_list[i].udata);
        } else {
            ngx_log_debug(log,
                          "kevent: %d: ft:%d f:%08x ff:%08x d:%d ud:%08x" _
                          event_list[i].ident _ event_list[i].filter _
                          event_list[i].flags _ event_list[i].fflags _
                          event_list[i].data _ event_list[i].udata);
        }
#endif

        if (event_list[i].flags & EV_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, event_list[i].data,
                          "kevent error on %d", event_list[i].ident);
            continue;
        }

        ev = (ngx_event_t *) event_list[i].udata;

        switch (event_list[i].filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:

            instance = (uintptr_t) ev & 1;
            ev = (void *) ((uintptr_t) ev & ~1);

            /* It's a stale event from a file descriptor
               that was just closed in this iteration */

            if (ev->active == 0 || ev->instance != instance) {
                ngx_log_debug(log, "stale kevent");
                continue;
            }

            ev->available = event_list[i].data;

            if (event_list[i].flags & EV_EOF) {
                ev->eof = 1;
                ev->error = event_list[i].fflags;
            }

            if (ev->oneshot && ev->timer_set) {
                ngx_del_timer(ev);
                ev->timer_set = 0;
            }

            /* fall through */

        case EVFILT_AIO:
            ev->ready = 1;

            ev->event_handler(ev);

            break;


        default:
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "unknown kevent filter %d" _ event_list[i].filter);
        }
    }

    return NGX_OK;
}


static void *ngx_kqueue_create_conf(ngx_pool_t *pool)
{
    ngx_kqueue_conf_t  *kcf;

    ngx_test_null(kcf, ngx_palloc(pool, sizeof(ngx_kqueue_conf_t)),
                  NGX_CONF_ERROR);

    kcf->changes = NGX_CONF_UNSET;
    kcf->events = NGX_CONF_UNSET;

    return kcf;
}


static char *ngx_kqueue_init_conf(ngx_pool_t *pool, void *conf)
{
    ngx_kqueue_conf_t *kcf = conf;

    ngx_conf_init_value(kcf->changes, 512);
    ngx_conf_init_value(kcf->events, 512);

    return NGX_CONF_OK;
}
