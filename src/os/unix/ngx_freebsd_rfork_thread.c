
/*
 * Copyright (C) 2002-2004 Igor Sysoev, http://sysoev.ru/en/
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
 * The threads implementation uses the rfork(RFPROC|RFTHREAD|RFMEM)
 * to create threads.  All threads use the stacks of the same size mmap()ed
 * below the main stack.  Thus the stack pointer is used to determine
 * the current thread id.
 *
 * The mutex implementation uses the ngx_atomic_cmp_set() operation
 * to acquire mutex and the SysV semaphore to wait on a mutex or to wake up
 * the waiting threads.
 *
 * The condition variable implementation uses the SysV semaphore set of two
 * semaphores. The first is used by the CV mutex, and the second is used
 * by CV itself.
 *
 * This threads implementation currently works on i486 and amd64
 * platforms only.
 */


char       *ngx_freebsd_kern_usrstack;
size_t      ngx_thread_stack_size;


static size_t       rz_size = /* STUB: PAGE_SIZE */ 4096;
static size_t       usable_stack_size;
static char        *last_stack;

static ngx_uint_t   nthreads;
static ngx_uint_t   max_threads;
static ngx_tid_t   *tids;  /* the threads tids array */


/* the thread-safe libc errno */

static int   errno0;   /* the main thread's errno */
static int  *errnos;   /* the threads errno's array */

int *__error()
{
    int  tid;

    tid = ngx_gettid();

    return tid ? &errnos[tid - 1] : &errno0;
}


/*
 * __isthreaded enables the spinlocks in some libc functions, i.e. in malloc()
 * and some other places.  Nevertheless we protect our malloc()/free() calls
 * by own mutex that is more efficient than the spinlock.
 *
 * _spinlock() is a weak referenced stub in src/lib/libc/gen/_spinlock_stub.c
 * that does nothing.
 */

extern int  __isthreaded;

void _spinlock(ngx_atomic_t *lock)
{
    ngx_int_t  tries;

    tries = 0;

    for ( ;; ) {

        if (*lock) {
            if (ngx_freebsd_hw_ncpu > 1 && tries++ < 1000) {
                continue;
            }

            sched_yield();
            tries = 0;

        } else {
            if (ngx_atomic_cmp_set(lock, 0, 1)) {
                return;
            }
        }
    }
}


/*
 * Before FreeBSD 5.1 _spinunlock() is a simple #define in
 * src/lib/libc/include/spinlock.h that zeroes lock.
 *
 * Since FreeBSD 5.1 _spinunlock() is a weak referenced stub in
 * src/lib/libc/gen/_spinlock_stub.c that does nothing.
 */

#ifndef _spinunlock

void _spinunlock(ngx_atomic_t *lock)
{
    *lock = 0;
}

#endif


int ngx_create_thread(ngx_tid_t *tid, int (*func)(void *arg), void *arg,
                      ngx_log_t *log)
{
    int    id, err;
    char  *stack, *stack_top;

    if (nthreads >= max_threads) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "no more than %d threads can be created", max_threads);
        return NGX_ERROR;
    }

    last_stack -= ngx_thread_stack_size;

    stack = mmap(last_stack, usable_stack_size, PROT_READ|PROT_WRITE,
                 MAP_STACK, -1, 0);

    if (stack == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "mmap(" PTR_FMT ":" SIZE_T_FMT
                      ", MAP_STACK) thread stack failed",
                      last_stack, usable_stack_size);
        return NGX_ERROR;
    }

    if (stack != last_stack) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "stack address was changed");
    }

    stack_top = stack + usable_stack_size;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, log, 0,
                   "thread stack: " PTR_FMT "-" PTR_FMT, stack, stack_top);

#if 1
    id = rfork_thread(RFPROC|RFTHREAD|RFMEM, stack_top, func, arg);
#elif 1
    id = rfork_thread(RFPROC|RFMEM, stack_top, func, arg);
#elif 1
    id = rfork_thread(RFFDG|RFCFDG, stack_top, func, arg);
#else
    id = rfork(RFFDG|RFCFDG);
#endif

    err = ngx_errno;

    if (id == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, err, "rfork() failed");

    } else {
        *tid = id;
        nthreads = (ngx_freebsd_kern_usrstack - stack_top)
                                                       / ngx_thread_stack_size;
        tids[nthreads] = id;

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0, "rfork()ed thread: %d", id);
    }

    return err;
}


ngx_int_t ngx_init_threads(int n, size_t size, ngx_cycle_t *cycle)
{
    size_t   len;
    char    *red_zone, *zone;

    max_threads = n;

    len = sizeof(ngx_freebsd_kern_usrstack);
    if (sysctlbyname("kern.usrstack", &ngx_freebsd_kern_usrstack, &len,
                                                                NULL, 0) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sysctlbyname(kern.usrstack) failed");
        return NGX_ERROR;
    }

    /* the main thread stack red zone */
    red_zone = ngx_freebsd_kern_usrstack - (size + rz_size);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "usrstack: " PTR_FMT " red zone: " PTR_FMT,
                   ngx_freebsd_kern_usrstack, red_zone);

    zone = mmap(red_zone, rz_size, PROT_NONE, MAP_ANON, -1, 0);
    if (zone == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "mmap(" PTR_FMT ":" SIZE_T_FMT
                      ", PROT_NONE, MAP_ANON) red zone failed",
                      red_zone, rz_size);
        return NGX_ERROR;
    }

    if (zone != red_zone) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "red zone address was changed");
    }

    /* create the threads errno array */

    if (!(errnos = ngx_calloc(n * sizeof(int), cycle->log))) {
        return NGX_ERROR;
    }

    /* create the threads tid array */

    if (!(tids = ngx_calloc((n + 1) * sizeof(ngx_tid_t), cycle->log))) {
        return NGX_ERROR;
    }

    tids[0] = ngx_pid;
    nthreads = 1;

    last_stack = zone + rz_size;
    usable_stack_size = size;
    ngx_thread_stack_size = size + rz_size;

    /* allow the spinlock in libc malloc() */
    __isthreaded = 1;

    ngx_threaded = 1;

    return NGX_OK;
}


ngx_tid_t ngx_thread_self()
{
    int        tid;
    ngx_tid_t  pid;

    tid = ngx_gettid();

    if (tids == NULL) {
        return ngx_pid;
    }

#if 0
    if (tids[tid] == 0) {
        pid = ngx_pid;
        tids[tid] = pid;
        return pid;
    }
#endif

    return tids[tid];
}


ngx_mutex_t *ngx_mutex_init(ngx_log_t *log, uint flags)
{
    int           nsem, i;
    ngx_mutex_t  *m;
    union semun   op;

    if (!(m = ngx_alloc(sizeof(ngx_mutex_t), log))) {
        return NULL;
    }

    m->lock = 0;
    m->log = log;

    if (flags & NGX_MUTEX_LIGHT) {
        m->semid = -1;
        return m;
    }

    nsem = flags & NGX_MUTEX_CV ? 2 : 1;

    m->semid = semget(IPC_PRIVATE, nsem, SEM_R|SEM_A);
    if (m->semid == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "semget() failed");
        return NULL;
    }

    op.val = 0;
    for (i = 0; i < nsem; i++) {
        if (semctl(m->semid, i, SETVAL, op) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          "semctl(SETVAL) failed");

            if (semctl(m->semid, 0, IPC_RMID) == -1) {
                ngx_log_error(NGX_LOG_ALERT, m->log, ngx_errno,
                              "semctl(IPC_RMID) failed");
            }

            return NULL;
        }
    }

    return m;
}


void ngx_mutex_done(ngx_mutex_t *m)
{
    if (semctl(m->semid, 0, IPC_RMID) == -1) {
        ngx_log_error(NGX_LOG_ALERT, m->log, ngx_errno,
                      "semctl(IPC_RMID) failed");
    }

    ngx_free((void *) m);
}


ngx_int_t ngx_mutex_dolock(ngx_mutex_t *m, ngx_int_t try)
{
    uint32_t       lock, new, old;
    ngx_uint_t     tries;
    struct sembuf  op;

    if (!ngx_threaded) {
        return NGX_OK;
    }

#if (NGX_DEBUG)
    if (try) {
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, m->log, 0,
                       "try lock mutex " PTR_FMT " lock:%X", m, m->lock);
    } else {
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, m->log, 0,
                       "lock mutex " PTR_FMT " lock:%X", m, m->lock);
    }
#endif

    old = m->lock;
    tries = 0;

    for ( ;; ) {
        if (old & NGX_MUTEX_LOCK_BUSY) {

            if (try) {
                return NGX_AGAIN;
            }

            if (ngx_freebsd_hw_ncpu > 1 && tries++ < 1000) {

                /* the spinlock is used only on the SMP system */

                old = m->lock;
                continue;
            }

            if (m->semid == -1) {
                sched_yield();

                tries = 0;
                old = m->lock;
                continue;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_CORE, m->log, 0,
                           "mutex " PTR_FMT " lock:%X", m, m->lock);

            /*
             * The mutex is locked so we increase a number
             * of the threads that are waiting on the mutex
             */

            lock = old + 1;

            if ((lock & ~NGX_MUTEX_LOCK_BUSY) > nthreads) {
                ngx_log_error(NGX_LOG_ALERT, m->log, ngx_errno,
                              "%d threads wait for mutex " PTR_FMT
                              ", while only %d threads are available",
                              lock & ~NGX_MUTEX_LOCK_BUSY, m, nthreads);
                return NGX_ERROR;
            }

            if (ngx_atomic_cmp_set(&m->lock, old, lock)) {

                ngx_log_debug2(NGX_LOG_DEBUG_CORE, m->log, 0,
                               "wait mutex " PTR_FMT " lock:%X", m, m->lock);

                /*
                 * The number of the waiting threads has been increased
                 * and we would wait on the SysV semaphore.
                 * A semaphore should wake up us more efficiently than
                 * a simple usleep().
                 */

                op.sem_num = 0;
                op.sem_op = -1;
                op.sem_flg = SEM_UNDO;

                if (semop(m->semid, &op, 1) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, m->log, ngx_errno,
                                  "semop() failed while waiting "
                                  "on mutex " PTR_FMT, m);
                    return NGX_ERROR;
                }

                tries = 0;
                old = m->lock;
                continue;
            }

            old = m->lock;

        } else {
            lock = old | NGX_MUTEX_LOCK_BUSY;

            if (ngx_atomic_cmp_set(&m->lock, old, lock)) {

                /* we locked the mutex */

                break;
            }

            old = m->lock;
        }

        if (tries++ > 1000) {

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, m->log, 0,
                           "mutex " PTR_FMT " is contested", m);

            /* the mutex is probably contested so we are giving up now */

            sched_yield();

            tries = 0;
            old = m->lock;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, m->log, 0,
                   "mutex " PTR_FMT " is locked, lock:%X", m, m->lock);

    return NGX_OK;
}


ngx_int_t ngx_mutex_unlock(ngx_mutex_t *m)
{
    uint32_t       lock, new, old;
    struct sembuf  op;

    if (!ngx_threaded) {
        return NGX_OK;
    }

    old = m->lock;

    if (!(old & NGX_MUTEX_LOCK_BUSY)) {
        ngx_log_error(NGX_LOG_ALERT, m->log, 0,
                      "tring to unlock the free mutex " PTR_FMT, m);
        return NGX_ERROR;
    }

    /* free the mutex */

    for ( ;; ) {
        lock = old & ~NGX_MUTEX_LOCK_BUSY;

        if (ngx_atomic_cmp_set(&m->lock, old, lock)) {
            break;
        }

        old = m->lock;
    }

    if (m->semid == -1) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, m->log, 0,
                       "mutex " PTR_FMT " is unlocked", m);

        return NGX_OK;
    }

    /* check weather we need to wake up a waiting thread */

    old = m->lock;

    for ( ;; ) {
        if (old & NGX_MUTEX_LOCK_BUSY) {

            /* the mutex is just locked by another thread */

            break;
        }

        if (old == 0) {
            break;
        }

        /* there are the waiting threads */

        lock = old - 1;

        if (ngx_atomic_cmp_set(&m->lock, old, lock)) {

            /* wake up the thread that waits on semaphore */

            op.sem_num = 0;
            op.sem_op = 1;
            op.sem_flg = SEM_UNDO;

            if (semop(m->semid, &op, 1) == -1) {
                ngx_log_error(NGX_LOG_ALERT, m->log, ngx_errno,
                              "semop() failed while waking up on mutex "
                              PTR_FMT, m);
                return NGX_ERROR;
            }

            break;
        }

        old = m->lock;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, m->log, 0,
                   "mutex " PTR_FMT " is unlocked", m);

    return NGX_OK;
}
