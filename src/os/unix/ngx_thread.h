#ifndef _NGX_THREAD_H_INCLUDED_
#define _NGX_THREAD_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_THREADS)

#define NGX_MAX_THREADS      128

#if (NGX_USE_RFORK)
#include <ngx_freebsd_rfork_thread.h>


#else /* use pthreads */

#include <pthread.h>
#include <pthread_np.h>

typedef pthread_t  ngx_tid_t;

#define ngx_thread_self()   pthread_self()
#define ngx_log_tid         (int) ngx_thread_self()

#define TID_T_FMT           PTR_FMT


#define ngx_thread_create_tls()  pthread_key_create(0, NULL)
#define ngx_thread_create_tls_n  "pthread_key_create(0, NULL)"
#define ngx_thread_get_tls()     pthread_getspecific(0)
#define ngx_thread_set_tls(v)    pthread_setspecific(0, v)


#define NGX_MUTEX_LIGHT     0

typedef struct {
    pthread_mutex_t   mutex;
    ngx_log_t        *log;
} ngx_mutex_t;

typedef struct {
    pthread_cond_t    cond;
    ngx_tid_t         tid;
    ngx_log_t        *log;
} ngx_cond_t;

#define ngx_thread_sigmask     pthread_sigmask
#define ngx_thread_sigmask_n  "pthread_sigmask()"

#define ngx_thread_join(t, p)  pthread_join(t, p)

#define ngx_setthrtitle(n)



ngx_int_t ngx_mutex_trylock(ngx_mutex_t *m);
ngx_int_t ngx_mutex_lock(ngx_mutex_t *m);
ngx_int_t ngx_mutex_unlock(ngx_mutex_t *m);

#endif


#define ngx_thread_volatile   volatile


typedef struct {
    ngx_tid_t    tid;
    ngx_cond_t  *cv;
    ngx_uint_t   state;
} ngx_thread_t;

#define NGX_THREAD_FREE   1
#define NGX_THREAD_BUSY   2
#define NGX_THREAD_EXIT   3
#define NGX_THREAD_DONE   4

extern ngx_int_t              ngx_threads_n;
extern volatile ngx_thread_t  ngx_threads[NGX_MAX_THREADS];


ngx_int_t ngx_init_threads(int n, size_t size, ngx_cycle_t *cycle);
int ngx_create_thread(ngx_tid_t *tid, void* (*func)(void *arg), void *arg,
                      ngx_log_t *log);


ngx_mutex_t *ngx_mutex_init(ngx_log_t *log, uint flags);
void ngx_mutex_destroy(ngx_mutex_t *m);


ngx_cond_t *ngx_cond_init(ngx_log_t *log);
void ngx_cond_destroy(ngx_cond_t *cv);
ngx_int_t ngx_cond_wait(ngx_cond_t *cv, ngx_mutex_t *m);
ngx_int_t ngx_cond_signal(ngx_cond_t *cv);


#else /* !NGX_THREADS */

#define ngx_thread_volatile

#define ngx_log_tid  0
#define TID_T_FMT    "%d"

#define ngx_mutex_lock(m)     NGX_OK
#define ngx_mutex_unlock(m)

#define ngx_cond_signal(cv)

#define ngx_thread_main()     1

#endif


typedef struct {
    ngx_event_t  *event;
} ngx_tls_t;



#endif /* _NGX_THREAD_H_INCLUDED_ */
