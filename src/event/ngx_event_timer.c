
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*
 * TODO: in multithreaded enviroment all timer operations must be
 * protected by the single mutex
 */


ngx_rbtree_t  *ngx_event_timer_rbtree;
ngx_rbtree_t   ngx_event_timer_sentinel;


int ngx_event_timer_init(ngx_cycle_t *cycle)
{
    if (ngx_event_timer_rbtree) {
        return NGX_OK;
    }

    ngx_event_timer_rbtree = &ngx_event_timer_sentinel;

#if 0
    ngx_event_timer_sentinel.left = &ngx_event_timer_sentinel;
    ngx_event_timer_sentinel.right = &ngx_event_timer_sentinel;
    ngx_event_timer_sentinel.parent = &ngx_event_timer_sentinel;
#endif

    return NGX_OK;
}


void ngx_event_timer_done(ngx_cycle_t *cycle)
{
}


ngx_msec_t ngx_event_find_timer(void)
{
    ngx_rbtree_t  *node;

    if (ngx_event_timer_rbtree == &ngx_event_timer_sentinel) {
        return 0;
    }

    node = ngx_rbtree_min(ngx_event_timer_rbtree, &ngx_event_timer_sentinel);

    return (ngx_msec_t)
         (node->key * NGX_TIMER_RESOLUTION -
               ngx_elapsed_msec / NGX_TIMER_RESOLUTION * NGX_TIMER_RESOLUTION);
#if 0
                         (node->key * NGX_TIMER_RESOLUTION - ngx_elapsed_msec);
#endif
}


void ngx_event_expire_timers(ngx_msec_t timer)
{
    ngx_event_t   *ev;
    ngx_rbtree_t  *node;

    for ( ;; ) {

        if (ngx_event_timer_rbtree == &ngx_event_timer_sentinel) {
            break;
        }

        node = ngx_rbtree_min(ngx_event_timer_rbtree,
                              &ngx_event_timer_sentinel);

        if ((ngx_msec_t) node->key <= (ngx_msec_t)
                         (ngx_old_elapsed_msec + timer) / NGX_TIMER_RESOLUTION)
        {
            ev = (ngx_event_t *)
                           ((char *) node - offsetof(ngx_event_t, rbtree_key));

            ngx_del_timer(ev);

            if (ev->delayed) {
                ev->delayed = 0;
                if (ev->ready == 0) {
                    continue;
                }

            } else {
                ev->timedout = 1;
            }

            ev->event_handler(ev);
            continue;
        }

        break;
    }
}
