
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <nginx.h>


static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n,
                                       ngx_int_t type);
static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo);
static void ngx_master_exit(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx);
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
#if (NGX_THREADS)
static int ngx_worker_thread_cycle(void *data);
#endif


ngx_uint_t    ngx_process;
ngx_pid_t     ngx_pid;
ngx_uint_t    ngx_threaded;

sig_atomic_t  ngx_reap;
sig_atomic_t  ngx_timer;
sig_atomic_t  ngx_terminate;
sig_atomic_t  ngx_quit;
ngx_uint_t    ngx_exiting;
sig_atomic_t  ngx_reconfigure;
sig_atomic_t  ngx_reopen;

sig_atomic_t  ngx_change_binary;
ngx_pid_t     ngx_new_binary;
ngx_uint_t    ngx_inherited;

sig_atomic_t  ngx_noaccept;
ngx_uint_t    ngx_noaccepting;
ngx_uint_t    ngx_restart;


u_char  master_process[] = "master process";


void ngx_master_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    char              *title;
    u_char            *p;
    size_t             size;
    ngx_int_t          n;
    ngx_uint_t         i;
    sigset_t           set;
    struct timeval     tv;
    struct itimerval   itv;
    ngx_uint_t         live;
    ngx_msec_t         delay;
    ngx_core_conf_t   *ccf;

    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGINT);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_NOACCEPT_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    sigemptyset(&set);


    size = sizeof(master_process);

    for (n = 0; n < ctx->argc; n++) {
        size += ngx_strlen(ctx->argv[n]) + 1;
    }

    title = ngx_palloc(cycle->pool, size);

    p = ngx_cpymem(title, master_process, sizeof(master_process) - 1);
    for (n = 0; n < ctx->argc; n++) {
        *p++ = ' ';
        p = ngx_cpystrn(p, (u_char *) ctx->argv[n], size);
    }

    ngx_setproctitle(title);


    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    ngx_start_worker_processes(cycle, ccf->worker_processes,
                               NGX_PROCESS_RESPAWN);

    ngx_new_binary = 0;
    delay = 0;
    live = 1;

    for ( ;; ) {
        if (delay) {
            delay *= 2;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "temination cycle: %d", delay);

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;

            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "setitimer() failed");
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");

        sigsuspend(&set);

        ngx_gettimeofday(&tv);
        ngx_time_update(tv.tv_sec);

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "wake up");

        if (ngx_reap) {
            ngx_reap = 0;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "reap childs");

            live = 0;
            for (i = 0; i < ngx_last_process; i++) {

                ngx_log_debug6(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "child: " PID_T_FMT " e:%d t:%d d:%d r:%d j:%d",
                               ngx_processes[i].pid,
                               ngx_processes[i].exiting,
                               ngx_processes[i].exited,
                               ngx_processes[i].detached,
                               ngx_processes[i].respawn,
                               ngx_processes[i].just_respawn);

                if (ngx_processes[i].exited) {

                    if (ngx_processes[i].respawn
                        && !ngx_processes[i].exiting
                        && !ngx_terminate
                        && !ngx_quit)
                    {
                         if (ngx_spawn_process(cycle, ngx_processes[i].proc,
                                               ngx_processes[i].data,
                                               ngx_processes[i].name, i)
                                                                  == NGX_ERROR)
                         {
                             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                                           "can not respawn %s",
                                           ngx_processes[i].name);
                             continue;
                         }

                         live = 1;

                         continue;
                    }

                    if (ngx_processes[i].pid == ngx_new_binary) {
                        ngx_new_binary = 0;
                        if (ngx_noaccepting) {
                            ngx_restart = 1;
                            ngx_noaccepting = 0;
                        }
                    }

                    if (i != --ngx_last_process) {
                        ngx_processes[i--] = ngx_processes[ngx_last_process];
                    }

                } else if (ngx_processes[i].exiting
                           || !ngx_processes[i].detached)
                {
                    live = 1;
                }
            }
        }

        if (!live && (ngx_terminate || ngx_quit)) {
            ngx_master_exit(cycle, ctx);
        }

        if (ngx_terminate) {
            if (delay == 0) {
                delay = 50;
            }

            if (delay > 1000) {
                ngx_signal_worker_processes(cycle, SIGKILL);
            } else {
                ngx_signal_worker_processes(cycle,
                                       ngx_signal_value(NGX_TERMINATE_SIGNAL));
            }

            continue;
        }

        if (ngx_quit) {
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
            continue;
        }

        if (ngx_timer) {
            ngx_timer = 0;
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_JUST_RESPAWN);
            live = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }

        if (ngx_reconfigure) {
            ngx_reconfigure = 0;

            if (ngx_new_binary) {
                ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "start new workers");

                ngx_start_worker_processes(cycle, ccf->worker_processes,
                                           NGX_PROCESS_JUST_RESPAWN);
                continue;
            }

            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reconfiguring");

            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;
            ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                   ngx_core_module);
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_JUST_RESPAWN);
            live = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }

        if (ngx_restart) {
            ngx_restart = 0;
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_RESPAWN);
            live = 1;
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, ccf->user);
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_REOPEN_SIGNAL));
        }

        if (ngx_change_binary) {
            ngx_change_binary = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "changing binary");
            ngx_new_binary = ngx_exec_new_binary(cycle, ctx->argv);
        }

        if (ngx_noaccept) {
            ngx_noaccept = 0;
            ngx_noaccepting = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }
    }
}


void ngx_single_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    ngx_uint_t  i;

#if 0
    ngx_setproctitle("single worker process");
#endif

    ngx_init_temp_number();

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events(cycle);

        if (ngx_terminate || ngx_quit) {
            ngx_master_exit(cycle, ctx);
        }

        if (ngx_reconfigure) {
            ngx_reconfigure = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reconfiguring");

            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, (ngx_uid_t) -1);
        }
    }
}


static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n,
                                       ngx_int_t type)
{
    struct itimerval  itv;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "start worker processes");

    while (n--) {
        ngx_spawn_process(cycle, ngx_worker_process_cycle, NULL,
                          "worker process", type);
    }

    /*
     * we have to limit the maximum life time of the worker processes
     * by 10 days because our millisecond event timer is limited
     * by 24 days on 32-bit platforms
     */

    itv.it_interval.tv_sec = 0;
    itv.it_interval.tv_usec = 0;
    itv.it_value.tv_sec = 10 * 24 * 60 * 60;
    itv.it_value.tv_usec = 0;

    if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "setitimer() failed");
    }
}

static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo)
{
    ngx_uint_t  i;
    ngx_err_t   err;

    for (i = 0; i < ngx_last_process; i++) {

        if (ngx_processes[i].detached) {
            continue;
        }

        if (ngx_processes[i].just_respawn) {
            ngx_processes[i].just_respawn = 0;
            continue;
        }

        if (ngx_processes[i].exiting
            && signo == ngx_signal_value(NGX_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (" PID_T_FMT ", %d)" ,
                       ngx_processes[i].pid, signo);

        if (kill(ngx_processes[i].pid, signo) == -1) {
            err = ngx_errno;
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "kill(%d, %d) failed",
                          ngx_processes[i].pid, signo);

            if (err == NGX_ESRCH) {
                ngx_processes[i].exited = 1;
                ngx_processes[i].exiting = 0;
                ngx_reap = 1;
            }

            continue;
        }

        if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
            ngx_processes[i].exiting = 1;
        }
    }
}


static void ngx_master_exit(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    ngx_delete_pidfile(cycle);

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exit");

    ngx_destroy_pool(cycle->pool);

    exit(0);
}


static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data)
{
    sigset_t          set;
    ngx_uint_t        i;
    ngx_listening_t  *ls;
    ngx_core_conf_t  *ccf;
#if (NGX_THREADS)
    ngx_tid_t         tid;
#endif

    ngx_process = NGX_PROCESS_WORKER;
    ngx_last_process = 0;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ccf->group != (gid_t) NGX_CONF_UNSET) {
        if (setuid(ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }
    }

    if (ccf->user != (uid_t) NGX_CONF_UNSET && geteuid() == 0) {
        if (setuid(ccf->user) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }
    }

#if (HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "prctl(PR_SET_DUMPABLE) failed");
    }

#endif

    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    ngx_init_temp_number();

    /*
     * disable deleting previous events for the listening sockets because
     * in the worker processes there are no events at all at this point
     */ 
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        ls[i].remain = 0;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    ngx_setproctitle("worker process");

#if (NGX_THREADS)

    if (ngx_init_threads(5, 128 * 1024 * 1024, cycle) == NGX_ERROR) {
        /* fatal */
        exit(2);
    }

    for (i = 0; i < 1; i++) {
        if (ngx_create_thread(&tid, ngx_worker_thread_cycle,
                              cycle, cycle->log) != 0)
        {
            /* fatal */
            exit(2);
        }
    }

#endif

    for ( ;; ) {
        if (ngx_exiting
            && ngx_event_timer_rbtree == &ngx_event_timer_sentinel)
        {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exiting");
            ngx_destroy_pool(cycle->pool);
            exit(0);
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events(cycle);

        if (ngx_terminate) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exiting");
            ngx_destroy_pool(cycle->pool);
            exit(0);
        }

        if (ngx_quit) {
            ngx_quit = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                          "gracefully shutting down");
            ngx_setproctitle("worker process is shutting down");

            if (!ngx_exiting) {
                ngx_close_listening_sockets(cycle);
                ngx_exiting = 1;
            }
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reopen logs");
            ngx_reopen_files(cycle, -1);
        }
    }
}


#if (NGX_THREADS)

int ngx_worker_thread_cycle(void *data)
{
    ngx_cycle_t *cycle = data;

    ngx_err_t       err;
    sigset_t        set;
    struct timeval  tv;

    sigfillset(&set);
    sigdelset(&set, SIGALRM);
    sigdelset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));
    sigdelset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));

    err = ngx_thread_sigmask(SIG_BLOCK, &set, NULL);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      ngx_thread_sigmask_n " failed");
        return 1;
    }


    /* STUB */

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, ngx_errno,
                   "thread %d started", ngx_thread_self());

    ngx_setproctitle("worker thread");

    sleep(5);

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, ngx_errno,
                   "thread %d done", ngx_thread_self());

    return 1;
}

#endif
