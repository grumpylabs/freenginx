
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


typedef DWORD            ngx_pid_t;
#define NGX_INVALID_PID  0


#define ngx_getpid   GetCurrentProcessId
#define ngx_log_pid  ngx_pid


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


#define NGX_PROCESS_SINGLE   0
#define NGX_PROCESS_MASTER   1
#define NGX_PROCESS_WORKER   2


ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);

#define ngx_debug_point()
#define ngx_sched_yield()  Sleep(0)


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;


#endif /* _NGX_PROCESS_H_INCLUDED_ */
