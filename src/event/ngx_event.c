
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define DEFAULT_CONNECTIONS  512


extern ngx_module_t ngx_select_module;
extern ngx_event_module_t ngx_select_module_ctx;

#if (HAVE_KQUEUE)
#include <ngx_kqueue_module.h>
#endif

#if (HAVE_DEVPOLL)
extern ngx_module_t ngx_devpoll_module;
#endif

#if (HAVE_AIO)
#include <ngx_aio_module.h>
#endif

static int ngx_event_init(ngx_cycle_t *cycle);
static char *ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);
static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_event_create_conf(ngx_cycle_t *cycle);
static char *ngx_event_init_conf(ngx_cycle_t *cycle, void *conf);


int                  ngx_event_flags;
ngx_event_actions_t  ngx_event_actions;


static int           ngx_event_max_module;



static ngx_str_t  events_name = ngx_string("events");

static ngx_command_t  ngx_events_commands[] = {

    { ngx_string("events"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_events_block,
      0,
      0,
      NULL },

      ngx_null_command
};


ngx_module_t  ngx_events_module = {
    NGX_MODULE,
    &events_name,                          /* module context */
    ngx_events_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static ngx_str_t  event_core_name = ngx_string("event_core");

static ngx_command_t  ngx_event_core_commands[] = {

    { ngx_string("connections"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_connections,
      0,
      0,
      NULL },

    { ngx_string("use"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_use,
      0,
      0,
      NULL },

    { ngx_string("multi_accept"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_event_conf_t, multi_accept),
      NULL },

      ngx_null_command
};


ngx_event_module_t  ngx_event_core_module_ctx = {
    &event_core_name,
    ngx_event_create_conf,                 /* create configuration */
    ngx_event_init_conf,                   /* init configuration */

    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


ngx_module_t  ngx_event_core_module = {
    NGX_MODULE,
    &ngx_event_core_module_ctx,            /* module context */
    ngx_event_core_commands,               /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init module */
    ngx_event_init                         /* init child */
};


static int ngx_event_init(ngx_cycle_t *cycle)
{
    int                  m, i, fd;
    ngx_event_t         *rev, *wev;
    ngx_listening_t     *s;
    ngx_connection_t    *c;
    ngx_event_conf_t    *ecf;
    ngx_event_module_t  *module;
#if (WIN32)
    ngx_iocp_conf_t     *iocpcf;
#endif


    ngx_event_timer_init();

    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    cycle->connection_n = ecf->connections;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        if (ngx_modules[m]->ctx_index == ecf->use) {
            module = ngx_modules[m]->ctx;
            if (module->actions.init(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
            break;
        }
    }

    cycle->connections = ngx_alloc(sizeof(ngx_connection_t) * ecf->connections,
                                   cycle->log);
    if (cycle->connections == NULL) {
        return NGX_ERROR;
    }

    c = cycle->connections;
    for (i = 0; i < cycle->connection_n; i++) {
        c[i].fd = -1;
    }

    cycle->read_events = ngx_alloc(sizeof(ngx_event_t) * ecf->connections,
                                   cycle->log);
    if (cycle->read_events == NULL) {
        return NGX_ERROR;
    }

    cycle->write_events = ngx_alloc(sizeof(ngx_event_t) * ecf->connections,
                                   cycle->log);
    if (cycle->write_events == NULL) {
        return NGX_ERROR;
    }

    /* for each listening socket */

    s = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        fd = s[i].fd;

#if (WIN32)
        /*
         * Winsock assignes a socket number divisible by 4
         * so to find a connection we divide a socket number by 4.
         */

        fd /= 4;
#endif

        c = &cycle->connections[fd];
        rev = &cycle->read_events[fd];
        wev = &cycle->write_events[fd];

        ngx_memzero(c, sizeof(ngx_connection_t));
        ngx_memzero(rev, sizeof(ngx_event_t));

        c->fd = s[i].fd;
        c->listening = &s[i];

        c->ctx = s[i].ctx;
        c->servers = s[i].servers;
        c->log = s[i].log;
        c->read = rev;

        /* required by iocp in "c->write->active = 1" */
        c->write = wev;

        /* required by poll */
        wev->index = NGX_INVALID_INDEX;

        rev->log = c->log;
        rev->data = c;
        rev->index = NGX_INVALID_INDEX;

        rev->available = 0;

#if (HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = s[i].deferred_accept;
#endif

        if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)) {
            if (s[i].remain) {

                /*
                 * delete the old accept events that were bound to
                 * the old cycle read events array
                 */

                if (ngx_del_event(&cycle->old_cycle->read_events[fd],
                                 NGX_READ_EVENT, NGX_CLOSE_EVENT) == NGX_ERROR)
                {
                    return NGX_ERROR;
                }

                cycle->old_cycle->connections[fd].fd = -1;
            }
        }

#if (WIN32)

        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            rev->event_handler = &ngx_event_acceptex;

            if (ngx_add_event(rev, 0, NGX_IOCP_ACCEPT) == NGX_ERROR) {
                return NGX_ERROR;
            }

            iocpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);
            if (ngx_event_post_acceptex(&s[i], iocpcf->acceptex) == NGX_ERROR) {
                return NGX_ERROR;
            }

        } else {
            rev->event_handler = &ngx_event_accept;
            ngx_add_event(rev, NGX_READ_EVENT, 0);
        }

#else

        rev->event_handler = &ngx_event_accept;
        ngx_add_event(rev, NGX_READ_EVENT, 0);

#endif
    }

    return NGX_OK;
}


static char *ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    int                    m;
    char                  *rv;
    void               ***ctx;
    ngx_conf_t            pcf;
    ngx_event_module_t   *module;

    /* count the number of the event modules and set up their indices */

    ngx_event_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_event_max_module++;
    }

    ngx_test_null(ctx, ngx_pcalloc(cf->pool, sizeof(void *)), NGX_CONF_ERROR);

    ngx_test_null(*ctx,
                  ngx_pcalloc(cf->pool, ngx_event_max_module * sizeof(void *)),
                  NGX_CONF_ERROR);

    *(void **) conf = ctx;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_conf) {
            ngx_test_null((*ctx)[ngx_modules[m]->ctx_index],
                          module->create_conf(cf->cycle),
                          NGX_CONF_ERROR);
        }
    }

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NGX_EVENT_MODULE;
    cf->cmd_type = NGX_EVENT_CONF;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;

    if (rv != NGX_CONF_OK)
        return rv;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->init_conf) {
            rv = module->init_conf(cf->cycle,
                                   (*ctx)[ngx_modules[m]->ctx_index]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }
    }

    return NGX_CONF_OK;
}


static char *ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    ngx_str_t  *value;

    if (ecf->connections != NGX_CONF_UNSET) {
        return "is duplicate" ;
    }

    value = cf->args->elts;
    ecf->connections = ngx_atoi(value[1].data, value[1].len);
    if (ecf->connections == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number \"%s\"", value[1].data);

        return NGX_CONF_ERROR;
    }

    cf->cycle->connection_n = ecf->connections;

    return NGX_CONF_OK;
}


static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    int                   m;
    ngx_str_t            *value;
    ngx_event_conf_t     *old_ecf;
    ngx_event_module_t   *module;

    if (ecf->use != NGX_CONF_UNSET) {
        return "is duplicate" ;
    }

    value = cf->args->elts;

    if (cf->cycle->old_cycle->conf_ctx) {
        old_ecf = ngx_event_get_conf(cf->cycle->old_cycle->conf_ctx,
                                     ngx_event_core_module);
    } else {
        old_ecf = NULL;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        if (module->name->len == value[1].len) {
            if (ngx_strcmp(module->name->data, value[1].data) == 0) {
                ecf->use = ngx_modules[m]->ctx_index;
                ecf->name = module->name->data;

                if (old_ecf && old_ecf->use != ecf->use) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "the \"%s\" event type must be the same as "
                        "in previous configuration - \"%s\" "
                        "and it can not be changed on the fly, "
                        "to change it you need to stop server "
                        "and start it again",
                        value[1].data, old_ecf->name);
                    return NGX_CONF_ERROR;
                }

                return NGX_CONF_OK;
            }
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid event type \"%s\"", value[1].data);

    return NGX_CONF_ERROR;
}


static void *ngx_event_create_conf(ngx_cycle_t *cycle)
{
    ngx_event_conf_t  *ecf;

    ngx_test_null(ecf, ngx_palloc(cycle->pool, sizeof(ngx_event_conf_t)),
                  NGX_CONF_ERROR);

    ecf->connections = NGX_CONF_UNSET;
    ecf->use = NGX_CONF_UNSET;
    ecf->multi_accept = NGX_CONF_UNSET;
    ecf->name = (void *) NGX_CONF_UNSET;

    return ecf;
}


static char *ngx_event_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_conf_t *ecf = conf;

#if (HAVE_KQUEUE)

    ngx_conf_init_value(ecf->connections, DEFAULT_CONNECTIONS);
    ngx_conf_init_value(ecf->use, ngx_kqueue_module.ctx_index);
    ngx_conf_init_ptr_value(ecf->name, ngx_kqueue_module_ctx.name->data);

#elif (HAVE_DEVPOLL)

    ngx_conf_init_value(ecf->connections, DEFAULT_CONNECTIONS);
    ngx_conf_init_value(ecf->use, ngx_devpoll_module.ctx_index);
    ngx_conf_init_ptr_value(ecf->name, ngx_devpoll_module_ctx.name->data);

#else /* HAVE_SELECT */

    ngx_conf_init_value(ecf->connections,
          FD_SETSIZE < DEFAULT_CONNECTIONS ? FD_SETSIZE : DEFAULT_CONNECTIONS);

    ngx_conf_init_value(ecf->use, ngx_select_module.ctx_index);
    ngx_conf_init_ptr_value(ecf->name, ngx_select_module_ctx.name->data);

#endif

    cycle->connection_n = ecf->connections;

    ngx_conf_init_value(ecf->multi_accept, 1);

    return NGX_CONF_OK;
}
