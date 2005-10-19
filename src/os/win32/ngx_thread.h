
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_THREAD_H_INCLUDED_
#define _NGX_THREAD_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef HANDLE  ngx_tid_t;
typedef DWORD   ngx_tls_key_t;
typedef DWORD   ngx_thread_value_t;


typedef struct {
    HANDLE      mutex;
    ngx_log_t   *log;
} ngx_mutex_t;


ngx_err_t ngx_create_thread(ngx_tid_t *tid,
    ngx_thread_value_t (__stdcall *func)(void *arg), void *arg, ngx_log_t *log);
ngx_int_t ngx_init_threads(int n, size_t size, ngx_cycle_t *cycle);

ngx_err_t ngx_thread_key_create(ngx_tls_key_t *key);
#define ngx_thread_key_create_n     "TlsAlloc()"
ngx_err_t ngx_thread_set_tls(ngx_tls_key_t *key, void *data);
#define ngx_thread_set_tls_n         "TlsSetValue()"
#define ngx_thread_get_tls           TlsGetValue


#define ngx_thread_volatile  volatile

#define ngx_log_tid                 GetCurrentThreadId()
#define NGX_TID_T_FMT               "%ud"


ngx_mutex_t *ngx_mutex_init(ngx_log_t *log, ngx_uint_t flags);

void ngx_mutex_lock(ngx_mutex_t *m);
ngx_int_t ngx_mutex_trylock(ngx_mutex_t *m);
void ngx_mutex_unlock(ngx_mutex_t *m);


/* STUB */
#define NGX_MUTEX_LIGHT             0
/**/


extern ngx_int_t  ngx_threads_n;


#endif /* _NGX_THREAD_H_INCLUDED_ */
