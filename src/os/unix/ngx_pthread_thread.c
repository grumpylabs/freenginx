
/*
 * Copyright (C) 2002-2004 Igor Sysoev, http://sysoev.ru/en/
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_uint_t   nthreads;
static ngx_uint_t   max_threads;


static pthread_attr_t  thr_attr;


int ngx_create_thread(ngx_tid_t *tid, void* (*func)(void *arg), void *arg,
                      ngx_log_t *log)
{
    int  err;

    if (nthreads >= max_threads) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "no more than %d threads can be created", max_threads);
        return NGX_ERROR;
    }

    err = pthread_create(tid, &thr_attr, func, arg);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, log, err, "pthread_create() failed");
        return err;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
                   "thread is created: " TID_T_FMT, *tid);

    nthreads++;

    return err;
}


ngx_int_t ngx_init_threads(int n, size_t size, ngx_cycle_t *cycle)
{   
    int  err;

    max_threads = n;

    err = pthread_attr_init(&thr_attr);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      "pthread_attr_init() failed");
        return NGX_ERROR;
    }

    err = pthread_attr_setstacksize(&thr_attr, size);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      "pthread_attr_setstacksize() failed");
        return NGX_ERROR;
    }

    ngx_threaded = 1;

    return NGX_OK;
}


ngx_mutex_t *ngx_mutex_init(ngx_log_t *log, uint flags)
{
    int           err;
    ngx_mutex_t  *m;

    if (!(m = ngx_alloc(sizeof(ngx_mutex_t), log))) {
        return NULL;
    }
    
    m->log = log;

    err = pthread_mutex_init(&m->mutex, NULL);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, m->log, err,
                      "pthread_mutex_init() failed");
        return NULL;
    }

    return m;
}


void ngx_mutex_destroy(ngx_mutex_t *m)
{
    int  err;

    err = pthread_mutex_destroy(&m->mutex);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, m->log, err,
                      "pthread_mutex_destroy(" PTR_FMT ") failed", m);
    }

    ngx_free(m);
}


ngx_int_t ngx_mutex_lock(ngx_mutex_t *m)
{
    int  err;

    if (!ngx_threaded) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, m->log, 0, "lock mutex " PTR_FMT, m);

    err = pthread_mutex_lock(&m->mutex);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, m->log, err,
                      "pthread_mutex_lock(" PTR_FMT ") failed", m);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, m->log, 0,
                   "mutex " PTR_FMT " is locked", m);

    return NGX_OK;
}


ngx_int_t ngx_mutex_trylock(ngx_mutex_t *m)
{
    int  err;

    if (!ngx_threaded) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, m->log, 0, "try lock mutex " PTR_FMT, m);

    err = pthread_mutex_trylock(&m->mutex);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, m->log, err,
                      "pthread_mutex_trylock(" PTR_FMT ") failed", m);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, m->log, 0,
                   "mutex " PTR_FMT " is locked", m);

    return NGX_OK;
}


ngx_int_t ngx_mutex_unlock(ngx_mutex_t *m)
{
    int  err;

    if (!ngx_threaded) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, m->log, 0, "unlock mutex " PTR_FMT, m);

    err = pthread_mutex_unlock(&m->mutex);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, m->log, err,
                      "pthread_mutex_unlock(" PTR_FMT ") failed", m);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, m->log, 0,
                   "mutex " PTR_FMT " is unlocked", m);

    return NGX_OK;
}


ngx_cond_t *ngx_cond_init(ngx_log_t *log)
{
    int          err;
    ngx_cond_t  *cv;

    if (!(cv = ngx_alloc(sizeof(ngx_cond_t), log))) {
        return NULL;
    }
    
    cv->log = log;

    err = pthread_cond_init(&cv->cond, NULL);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cv->log, err,
                      "pthread_cond_init() failed");
        return NULL;
    }

    return cv;
}


void ngx_cond_destroy(ngx_cond_t *cv)
{
    int  err;

    err = pthread_cond_destroy(&cv->cond);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cv->log, err,
                      "pthread_cond_destroy(" PTR_FMT ") failed", cv);
    }

    ngx_free(cv);
}


ngx_int_t ngx_cond_wait(ngx_cond_t *cv, ngx_mutex_t *m)
{
    int  err;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0,
                   "cv " PTR_FMT " wait", cv);

    err = pthread_cond_wait(&cv->cond, &m->mutex);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cv->log, err,
                      "pthread_cond_wait(" PTR_FMT ") failed", cv);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0,
                   "cv " PTR_FMT " is waked up", cv);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, m->log, 0,
                   "mutex " PTR_FMT " is locked", m);

    return NGX_OK;
}


ngx_int_t ngx_cond_signal(ngx_cond_t *cv)
{
    int  err;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0,
                   "cv " PTR_FMT " to signal", cv);

    err = pthread_cond_signal(&cv->cond);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cv->log, err,
                      "pthread_cond_signal(" PTR_FMT ") failed", cv);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0,
                   "cv " PTR_FMT " is signaled", cv);

    return NGX_OK;
}
