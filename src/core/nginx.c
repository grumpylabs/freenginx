
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>



static int ngx_open_listening_sockets(ngx_log_t *log);


void  ****ngx_conf_ctx;


ngx_os_io_t  ngx_io;


int     ngx_max_module;
void   *ctx_conf;

int ngx_connection_counter;

ngx_array_t  ngx_listening_sockets;


#if 0

int main(int argc, char *const *argv)
{
    int          i;
    ngx_str_t    conf_file;
    ngx_log_t   *log;
    ngx_pool_t  *pool;
    ngx_conf_t   conf;

    ngx_max_sockets = -1;

    log = ngx_log_init_errlog();

    if (ngx_os_init(log) == NGX_ERROR) {
        return 1;
    }

    ngx_max_module = 0;
    for (i = 0; ngx_modules[i]; i++) {
        ngx_modules[i]->index = ngx_max_module++;
    }

    ngx_test_null(pool, ngx_create_pool(16 * 1024, log), 1);
    ngx_test_null(cycle, ngx_pcalloc(pool, sizeof(ngx_cycle_t)), 1);
    cycle->pool = pool;

    if (ngx_init_conf(cycle) == NGX_ERROR) {
        return 1;
    }

    /* daemon */

    /* life cycle */

    for ( ;; ) {

        /* forks */

        ngx_init_temp_number();

        /* threads */

        for ( ;; ) {

            worker(cycle->log);

            pool = ngx_create_pool(16 * 1024, cycle->log);

            if (pool == NULL) {
                continue;
            }

            new_cycle = ngx_pcalloc(pool, sizeof(ngx_cycle_t));

            if (new_cycle == NULL) {
                ngx_destroy_pool(pool);
                continue;
            }

            new_cycle->pool = pool;

            if (ngx_init_conf(new_cycle, cycle->log) == NGX_ERROR) {
                ngx_destroy_pool(new_cycle->pool);
                continue;
            }

            nls = new_cycle->listening.elts;
            for (n = 0; n < new_cycle->listening.nelts; n++) {
                ls = cycle->listening.elts;
                for (i = 0; i < cycle->listening.nelts; i++) {
                    if (ngx_memcmp(nls[n].sockaddr,
                                   ls[i].sockaddr, ls[i].socklen) == 0)
                    {
                        nls[n].fd = ls[i].fd;
                        break;
                    }
                }

                if (nls[n].fd == -1) {
                    nls[n].new = 1;
                }
            }

            if (ngx_open_listening_sockets(new_cycle) == NGX_ERROR) {
                for (n = 0; n < new_cycle->listening.nelts; n++) {
                    if (nls[n].new && nls[n].fd != -1) {
                        if (ngx_close_socket(nls[n].fd) == -1)
                            ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                          ngx_close_socket_n " %s failed",
                                          nls[n].addr_text.data);
                        }
                    }
                }

                ngx_destroy_pool(new_cycle->pool);
                continue;
            }

            new_cycle->log = new log;

            ngx_destroy_pool(cycle->pool);

            cycle = new_cycle;
            break;
        }
    }

    return 0;
}


static int ngx_init_cycle(ngx_cycle_t *old_cycle, ngx_log_t *log)
{
    int           n;
    ngx_conf_t    conf;
    ngx_pool_t   *pool;
    ngx_cycle_t  *cycle;


    pool = ngx_create_pool(16 * 1024, log);
    if (pool == NULL) {
        return NULL;
    }

    cycle = ngx_pcalloc(pool, sizeof(ngx_cycle_t));
    if (cycle == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->pool = pool;

    n = old_cycle ? old_cycle->open_files.nelts : 20;
    cycle->open_files.elts = ngx_pcalloc(pool, n * sizeof(ngx_open_file_t));
    if (cycle->open_files.elts == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->open_files.nelts = 0;
    cycle->open_files.size = sizeof(ngx_open_file_t);
    cycle->open_files.nalloc = n;
    cycle->open_files.pool = pool;

    n = old_cycle ? old_cycle->listening.nelts : 10;
    cycle->listening.elts = ngx_pcalloc(pool, n * sizeof(ngx_listening_t));
    if (cycle->listening.elts == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->listening.nelts = 0;
    cycle->listening.size = sizeof(ngx_listening_t);
    cycle->listening.nalloc = n;
    cycle->listening.pool = pool;

    cycle->conf_ctx = ngx_pcalloc(pool, ngx_max_module * sizeof(void *));
    if (cycle->conf_ctx == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ngx_memzero(&conf, sizeof(ngx_conf_t));
    /* STUB: init array ? */
    conf.args = ngx_create_array(pool, 10, sizeof(ngx_str_t));
    if (conf.args == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    conf.ctx = cycle->conf_ctx;
    conf.cycle = cycle;
    /* STUB */ conf.pool = cycle->pool;
    conf.log = log;
    conf.module_type = NGX_CORE_MODULE;
    conf.cmd_type = NGX_MAIN_CONF;

    conf_file.len = sizeof(NGINX_CONF) - 1;
    conf_file.data = NGINX_CONF;

    if (ngx_conf_parse(&conf, &conf_file) != NGX_CONF_OK) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_module) {
            if (ngx_modules[i]->init_module(cycle, log) == NGX_ERROR)
            {
                failed = 1;
                break;
            }
        }
    }

    if (!failed) {
        file = cycle->open_files.elts;
        for (i = 0; i < cycle->open_files.nelts; i++) {
            if (file->name.data = NULL) {
                continue;
            }

            file->fd = ngx_open_file(file->name.data,
                                     NGX_FILE_RDWR,
                                     NGX_FILE_CREATE_OR_OPEN|NGX_FILE_APPEND);

            if (file->fd == NGX_INVALID_FILE) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                              ngx_open_file_n " \"%s\" failed",
                              file->name.data);
                failed = 1;
                break;
            }

            /* TODO: Win32 append */
        }
    }

    if (!failed) {
        if (ngx_open_listening_sockets(new_cycle) == NGX_ERROR) {
            failed = 1;
        }
    }

    if (failed) {

        /* rollback the new cycle configuration */

        for (i = 0; ngx_modules[i]; i++) {
            if (ngx_modules[i]->rollback_module) {
                ngx_modules[i]->rollback_module(cycle);
            }
        }

        file = cycle->open_files.elts;
        for (i = 0; i < cycle->open_files.nelts; i++) {
            if (file->fd != NGX_INVALID_FILE) {
                if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                                  ngx_close_file_n " \"%s\" failed",
                                  file->name.data);
                }
            }
        }

        ls[i] = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {
            if (ls[i].new && ls[i].fd != -1) {
                if (ngx_close_socket(ls[i].fd) == -1)
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_close_socket_n " %s failed",
                                  ls[i].addr_text.data);
                }
            }
        }

        ngx_destroy_pool(pool);
        return NULL;

    } else {

        /* commit the new cycle configuration */

        for (i = 0; ngx_modules[i]; i++) {
            if (ngx_modules[i]->commit_module) {
                ngx_modules[i]->commit_module(cycle);
            }
        }
    }

    new_cycle->log = ???;
    pool->log = ???;

    return cycle;






----------------

    ngx_init_array(cycle->listening, cycle->pool, 10, sizeof(ngx_listening_t),
                   NGX_ERROR);

    ngx_memzero(&conf, sizeof(ngx_conf_t));

    ngx_test_null(conf.args,
                  ngx_create_array(cycle->pool, 10, sizeof(ngx_str_t)),
                  NGX_ERROR);

    ngx_test_null(cycle->conf_ctx,
                  ngx_pcalloc(cycle->pool, ngx_max_module * sizeof(void *)),
                  NGX_ERROR);

    conf.ctx = cycle->conf_ctx;
    conf.cycle = cycle;
    /* STUB */ conf.pool = cycle->pool; conf.log = cycle->log;
    conf.module_type = NGX_CORE_MODULE;
    conf.cmd_type = NGX_MAIN_CONF;

    conf_file.len = sizeof(NGINX_CONF) - 1;
    conf_file.data = NGINX_CONF;

    if (ngx_conf_parse(&conf, &conf_file) == NGX_CONF_OK) {
        for (i = 0; ngx_modules[i]; i++) {
            if (ngx_modules[i]->init_module) {
                if (ngx_modules[i]->init_module(pool) == NGX_ERROR) {
                    failed = 1;
                    break;
                }
            }
        }

    } else {
        failed = 1;
    }

    if (failed) {
        for (i = 0; ngx_modules[i]; i++) {
            if (ngx_modules[i]->rollback_module) {
                ngx_modules[i]->rollback_module(pool);
            }
        }

        return NGX_ERROR;

    } else {
        for (i = 0; ngx_modules[i]; i++) {
            if (ngx_modules[i]->commit_module) {
                ngx_modules[i]->commit_module(pool);
            }
        }
    }

    return NGX_OK;
}


#endif


int main(int argc, char *const *argv)
{
    int          i;
    ngx_str_t    conf_file;
    ngx_log_t   *log;
    ngx_pool_t  *pool, *old_pool;
    ngx_conf_t   conf;

    ngx_max_sockets = -1;

    log = ngx_log_init_errlog();

    if (ngx_os_init(log) == NGX_ERROR) {
        return 1;
    }

    ngx_max_module = 0;
    for (i = 0; ngx_modules[i]; i++) {
        ngx_modules[i]->index = ngx_max_module++;
    }

    /* life cycle */

    {
        old_pool = pool;

        pool = ngx_create_pool(16 * 1024, log);

        ngx_init_array(ngx_listening_sockets,
                       pool, 10, sizeof(ngx_listening_t),
                       1);

        ngx_memzero(&conf, sizeof(ngx_conf_t));

        ngx_test_null(conf.args,
                      ngx_create_array(pool, 10, sizeof(ngx_str_t)),
                      1);

        ngx_test_null(ngx_conf_ctx,
                      ngx_pcalloc(pool, ngx_max_module * sizeof(void *)),
                      1);

        conf.ctx = ngx_conf_ctx;
        conf.pool = pool;
        conf.log = log;
        conf.module_type = NGX_CORE_MODULE;
        conf.cmd_type = NGX_MAIN_CONF;

        conf_file.len = sizeof(NGINX_CONF) - 1;
        conf_file.data = NGINX_CONF;

        if (ngx_conf_parse(&conf, &conf_file) != NGX_CONF_OK) {
            return 1;
        }

#if 0
        log = (ngx_log_t *) ngx_get_conf(ngx_errlog_module);
        /* STUB */ log->log_level = NGX_LOG_DEBUG;
#endif

        ngx_init_temp_number();

        ngx_io = ngx_os_io;

        for (i = 0; ngx_modules[i]; i++) {
            if (ngx_modules[i]->init_module) {
                if (ngx_modules[i]->init_module(pool) == NGX_ERROR) {
                    return 1;
                }
            }
        }

        if (ngx_open_listening_sockets(log) == NGX_ERROR) {
            return 1;
        }

        /* TODO: daemon, once only */

        /* TODO: fork */

        ngx_pre_thread(&ngx_listening_sockets, pool, log);

        /* TODO: threads */

        /* STUB */
        ngx_worker(log);
    }

    return 0;
}


static int ngx_open_listening_sockets(ngx_log_t *log)
{
    int              times, failed, reuseaddr, i;
    ngx_err_t        err;
    ngx_socket_t     s;
    ngx_listening_t *ls;

    reuseaddr = 1;

    for (times = 10; times; times--) {
         failed = 0;

        /* for each listening socket */

        ls = ngx_listening_sockets.elts;
        for (i = 0; i < ngx_listening_sockets.nelts; i++) {

            if (ls[i].bound)
                continue;

            if (ls[i].inherited) {

                /* TODO: close on exit */
                /* TODO: nonblocking */
                /* TODO: deferred accept */

                ls[i].bound = 1;
                continue;
            }

            s = ngx_socket(ls[i].family, ls[i].type, ls[i].protocol,
                           ls[i].flags);
            if (s == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              ngx_socket_n " %s falied", ls[i].addr_text.data);
                return NGX_ERROR;
            }

#if (WIN32)
            /*
             * Winsock assignes a socket number divisible by 4
             * so to find a connection we divide a socket number by 4.
             */

            if (s % 4) {
                ngx_log_error(NGX_LOG_EMERG, ls->log, 0,
                              ngx_socket_n " created socket %d", s);
                return NGX_ERROR;
            }
#endif

            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuseaddr, sizeof(int)) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              "setsockopt(SO_REUSEADDR) %s failed",
                              ls[i].addr_text.data);
                return NGX_ERROR;
            }

            /* TODO: close on exit */

            if (ls[i].nonblocking) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_nonblocking_n " %s failed",
                                  ls[i].addr_text.data);
                    return NGX_ERROR;
                }
            }

            if (bind(s, ls[i].sockaddr, ls[i].socklen) == -1) {
                err = ngx_socket_errno;
                ngx_log_error(NGX_LOG_EMERG, log, err,
                              "bind() to %s failed", ls[i].addr_text.data);

                if (err != NGX_EADDRINUSE)
                    return NGX_ERROR;

                if (ngx_close_socket(s) == -1)
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_close_socket_n " %s failed",
                                  ls[i].addr_text.data);

                failed = 1;
                continue;
            }

            if (listen(s, ls[i].backlog) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              "listen() to %s failed", ls[i].addr_text.data);
                return NGX_ERROR;
            }

            /* TODO: deferred accept */

            ls[i].fd = s;
            ls[i].bound = 1;
        }

        if (!failed)
            break;

        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "try again to bind() after 500ms");
        ngx_msleep(500);
    }

    if (failed) {

        /* TODO: configurable */

        ngx_log_error(NGX_LOG_EMERG, log, 0, "can not bind(), exiting");
        return NGX_ERROR;
    }

    return NGX_OK;
}
