#ifndef _NGX_EVENT_H_INCLUDED_
#define _NGX_EVENT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_time.h>
#include <ngx_socket.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_array.h>

typedef struct ngx_event_s       ngx_event_t;

struct ngx_event_s {
    void            *data;

    int            (*event_handler)(ngx_event_t *ev);
    int            (*close_handler)(ngx_event_t *ev);
    void            *context;
    char            *action;

    ngx_event_t     *prev;     /* queue in select(), poll(), mutex(),        */
    ngx_event_t     *next;     /*   aio_read(), aio_write()                  */

    int            (*timer_handler)(ngx_event_t *ev);
    ngx_event_t     *timer_prev;
    ngx_event_t     *timer_next;

    u_int            timer_delta;
    u_int            timer;

    ngx_log_t       *log;

    int              available; /* kqueue only:                              */
                                /*   accept: number of sockets that wait     */
                                /*           to be accepted                  */
                                /*   read:   bytes to read                   */
                                /*   write:  available space in buffer       */
                                /* otherwise:                                */
                                /*   accept: 1 if accept many, 0 otherwise   */

    /* flags - int are probably faster on write then bits ??? */
#if !(USE_KQUEUE)
    unsigned         oneshot:1;
#endif
    unsigned         listening:1;
    unsigned         write:1;

    unsigned         ready:1;
    unsigned         timedout:1;
    unsigned         blocked:1;

    unsigned         process:1;
    unsigned         read_discarded:1;

    unsigned         unexpected_eof:1;

#if (HAVE_DEFERRED_ACCEPT)
    unsigned         deferred_accept:1;
#endif
#if (HAVE_KQUEUE)
    unsigned         eof:1;
    int              error;
#endif
};

typedef enum {
    NGX_SELECT_EVENT = 0,
#if (HAVE_POLL)
    NGX_POLL_EVENT,
#endif
#if (HAVE_KQUEUE)
    NGX_KQUEUE_EVENT,
#endif
} ngx_event_type_e ;

typedef struct {
    int  (*add)(ngx_event_t *ev, int event, u_int flags);
    int  (*del)(ngx_event_t *ev, int event);
    void (*timer)(ngx_event_t *ev, ngx_msec_t timer);
    int  (*process)(ngx_log_t *log);
    int  (*read)(ngx_event_t *ev, char *buf, size_t size);
/*
    int  (*write)(ngx_event_t *ev, char *buf, size_t size);
*/
} ngx_event_actions_t;


/*
NGX_LEVEL_EVENT (default)  select, poll, /dev/poll, kqueue
                                requires to read whole data
NGX_ONESHOT_EVENT          select, poll, kqueue
NGX_CLEAR_EVENT            kqueue
NGX_AIO_EVENT              overlapped, aio_read, aioread
                                no need to add or delete events
*/

#if (HAVE_KQUEUE)

#define NGX_READ_EVENT     EVFILT_READ
#define NGX_WRITE_EVENT    EVFILT_WRITE

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  EV_ONESHOT

#ifndef HAVE_CLEAR_EVENT
#define HAVE_CLEAR_EVENT   1
#endif

#if (HAVE_CLEAR_EVENT)
#define NGX_CLEAR_EVENT    EV_CLEAR
#endif

#else

#define NGX_READ_EVENT     0
#define NGX_WRITE_EVENT    1

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1

#endif


#if (USE_KQUEUE)

#define ngx_init_events      ngx_kqueue_init
#define ngx_process_events   ngx_kqueue_process_events
#define ngx_kqueue_add_event(ev, event)                                       \
            ngx_kqueue_set_event(ev, event, EV_ADD | flags)
#define ngx_kqueue_del_event(ev, event)                                       \
            ngx_kqueue_set_event(ev, event, EV_DELETE)
#define ngx_add_timer        ngx_kqueue_add_timer
#define ngx_event_recv       ngx_event_recv_core

#else

#define ngx_init_events     (ngx_event_init[ngx_event_type])
#define ngx_process_events   ngx_event_actions.process
#define ngx_add_event        ngx_event_actions.add
#define ngx_del_event        ngx_event_actions.del
#define ngx_add_timer        ngx_event_actions.timer
#define ngx_event_recv       ngx_event_recv_core

#endif


static void ngx_inline ngx_del_timer(ngx_event_t *ev)
{
    if (ev->timer_prev)
        ev->timer_prev->timer_next = ev->timer_next;

    if (ev->timer_next) {
        ev->timer_next->timer_prev = ev->timer_prev;
        ev->timer_next = NULL;
    }

    if (ev->timer_prev)
        ev->timer_prev = NULL;
}




extern ngx_event_t          *ngx_read_events;
extern ngx_event_t          *ngx_write_events;
extern ngx_connection_t     *ngx_connections;

#if !(USE_KQUEUE)
extern ngx_event_actions_t   ngx_event_actions;
extern ngx_event_type_e      ngx_event_type;
#endif


void ngx_pre_thread(ngx_array_t *ls, ngx_pool_t *pool, ngx_log_t *log);
void ngx_worker(ngx_log_t *log);


#endif /* _NGX_EVENT_H_INCLUDED_ */
