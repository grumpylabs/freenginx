
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t      ngx_threads_n;


static size_t  stack_size;


ngx_err_t ngx_create_thread(ngx_tid_t *tid, void* (*func)(void *arg), void *arg,
                      ngx_log_t *log)
{
    ngx_err_t  err;

    *tid = CreateThread(NULL, stack_size,
                        (LPTHREAD_START_ROUTINE) func, arg, 0, NULL);

    if (*tid != NULL) {
        return 0;
    }

    err = ngx_errno;
    ngx_log_error(NGX_LOG_ALERT, log, err, "CreateThread() failed");
    return err;
}


ngx_int_t ngx_init_threads(int n, size_t size, ngx_cycle_t *cycle)
{
    stack_size = size;

    return NGX_OK;
}


ngx_err_t ngx_thread_key_create(ngx_tls_key_t *key)
{
    *key = TlsAlloc();

    if (*key == TLS_OUT_OF_INDEXES) {
        return ngx_errno;
    }

    return 0;
}


ngx_err_t ngx_thread_set_tls(ngx_tls_key_t *key, void *data)
{
    if (TlsSetValue(*key, data) == 0) {
        return ngx_errno;
    }

    return 0;
}


ngx_mutex_t *ngx_mutex_init(ngx_log_t *log, ngx_uint_t flags)
{
    return (ngx_mutex_t *) 1;
}


/* STUB */

ngx_int_t
ngx_mutex_lock(ngx_mutex_t *m) {
    return NGX_OK;
}


ngx_int_t
ngx_mutex_trylock(ngx_mutex_t *m) {
    return NGX_OK;
}

/**/
