
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


int  ngx_http_max_module;


int  (*ngx_http_top_header_filter) (ngx_http_request_t *r);
int  (*ngx_http_top_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);


static ngx_str_t  http_name = ngx_string("http");


static ngx_command_t  ngx_http_commands[] = {

    {ngx_string("http"),
     NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_http_block,
     0,
     0,
     NULL},

    ngx_null_command
};


ngx_module_t  ngx_http_module = {
    NGX_MODULE,
    &http_name,                            /* module context */
    ngx_http_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    int                          mi, m, s, l, p, a, n;
    int                          port_found, addr_found, virtual_names;
    char                        *rv;
    struct sockaddr_in          *addr_in;
    ngx_array_t                  in_ports;
    ngx_listening_t             *ls;
    ngx_http_module_t           *module;
    ngx_conf_t                   pcf;
    ngx_http_conf_ctx_t         *ctx;
    ngx_http_in_port_t          *in_port, *inport;
    ngx_http_in_addr_t          *in_addr, *inaddr;
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_core_srv_conf_t   **cscfp, *cscf;
    ngx_http_core_loc_conf_t   **clcfp, *clcf;
    ngx_http_listen_t           *lscf;
    ngx_http_server_name_t      *s_name, *name;
#if (WIN32)
    ngx_iocp_conf_t             *iocpcf;
#endif

    /* the main http context */
    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    *(ngx_http_conf_ctx_t **) conf = ctx;

    /* count the number of the http modules and set up their indices */

    ngx_http_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_http_max_module++;
    }

    /* the main http main_conf, it's the same in the all http contexts */
    ngx_test_null(ctx->main_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    /* the http null srv_conf, it's used to merge the server{}s' srv_conf's */
    ngx_test_null(ctx->srv_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    /* the http null loc_conf, it's used to merge the server{}s' loc_conf's */
    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);


    /* create the main_conf, srv_conf and loc_conf in all http modules */

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->create_main_conf) {
            ngx_test_null(ctx->main_conf[mi], module->create_main_conf(cf),
                          NGX_CONF_ERROR);
        }

        if (module->create_srv_conf) {
            ngx_test_null(ctx->srv_conf[mi], module->create_srv_conf(cf),
                          NGX_CONF_ERROR);
        }

        if (module->create_loc_conf) {
            ngx_test_null(ctx->loc_conf[mi], module->create_loc_conf(cf),
                          NGX_CONF_ERROR);
        }
    }

    /* parse inside the http{} block */

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NGX_HTTP_MODULE;
    cf->cmd_type = NGX_HTTP_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }

    /*
     * init http{} main_conf's, merge the server{}s' srv_conf's
     * and its location{}s' loc_conf's
     */

    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        /* init http{} main_conf's */

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                                            ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    return rv;
                }
            }

            if (module->merge_loc_conf) {

                /* merge the server{}'s loc_conf */

                rv = module->merge_loc_conf(cf,
                                            ctx->loc_conf[mi],
                                            cscfp[s]->ctx->loc_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    return rv;
                }

                /* merge the locations{}' loc_conf's */

                clcfp = (ngx_http_core_loc_conf_t **)cscfp[s]->locations.elts;

                for (l = 0; l < cscfp[s]->locations.nelts; l++) {
                    rv = module->merge_loc_conf(cf,
                                                cscfp[s]->ctx->loc_conf[mi],
                                                clcfp[l]->loc_conf[mi]);
                    if (rv != NGX_CONF_OK) {
                        return rv;
                    }
                }
            }
        }
    }


    /* init lists of the handlers */

    ngx_init_array(cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers,
                   cf->cycle->pool, 10, sizeof(ngx_http_handler_pt),
                   NGX_CONF_ERROR);

    cmcf->phases[NGX_HTTP_REWRITE_PHASE].type = NGX_OK;
    cmcf->phases[NGX_HTTP_REWRITE_PHASE].post_handler =
                                                 ngx_http_find_location_config;


    ngx_init_array(cmcf->phases[NGX_HTTP_TRANSLATE_PHASE].handlers,
                   cf->cycle->pool, 10, sizeof(ngx_http_handler_pt),
                   NGX_CONF_ERROR);

    cmcf->phases[NGX_HTTP_TRANSLATE_PHASE].type = NGX_OK;


    /* create the lists of the ports, the addresses and the server names
       to allow quickly find the server core module configuration at run-time */

    ngx_init_array(in_ports, cf->pool, 10, sizeof(ngx_http_in_port_t),
                   NGX_CONF_ERROR);

    /* "server" directives */
    cscfp = cmcf->servers.elts;
    for (s = 0; s < cmcf->servers.nelts; s++) {

        /* "listen" directives */
        lscf = cscfp[s]->listen.elts;
        for (l = 0; l < cscfp[s]->listen.nelts; l++) {

            port_found = 0;

            /* AF_INET only */

            in_port = in_ports.elts;
            for (p = 0; p < in_ports.nelts; p++) {

                if (lscf[l].port == in_port[p].port) {

                    /* the port is already in the port list */

                    port_found = 1;
                    addr_found = 0;

                    in_addr = in_port[p].addrs.elts;
                    for (a = 0; a < in_port[p].addrs.nelts; a++) {

                        if (lscf[l].addr == in_addr[a].addr) {

                            /* the address is already bound to this port */

                            /* "server_name" directives */
                            s_name = cscfp[s]->server_names.elts;
                            for (n = 0; n < cscfp[s]->server_names.nelts; n++) {

                                /* add the server name and server core module
                                   configuration to the address:port */

                                /* TODO: duplicate names can be checked here */

                                ngx_test_null(name,
                                              ngx_push_array(&in_addr[a].names),
                                              NGX_CONF_ERROR);

                                name->name = s_name[n].name;
                                name->core_srv_conf = s_name[n].core_srv_conf;
                            }

                            /* check duplicate "default" server that
                               serves this address:port */

                            if (lscf[l].flags & NGX_HTTP_DEFAULT_SERVER) {
                                if (in_addr[a].flags
                                                   & NGX_HTTP_DEFAULT_SERVER) {

                                    ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                                           "duplicate default server in %s:%d",
                                           lscf[l].file_name.data,
                                           lscf[l].line);

                                    return NGX_CONF_ERROR;
                                }

                                in_addr[a].flags |= NGX_HTTP_DEFAULT_SERVER;
                                in_addr[a].core_srv_conf = cscfp[s];
                            }

                            addr_found = 1;

                            break;

                        } else if (in_addr[a].addr == INADDR_ANY) {

                            /* "*:port" must be the last resort so move it
                               to the end of the address list and add
                               the new address at its place */

                            ngx_test_null(inaddr,
                                          ngx_push_array(&in_port[p].addrs),
                                          NGX_CONF_ERROR);

                            ngx_memcpy(inaddr, &in_addr[a],
                                       sizeof(ngx_http_in_addr_t));

                            in_addr[a].addr = lscf[l].addr;
                            in_addr[a].flags = lscf[l].flags;
                            in_addr[a].core_srv_conf = cscfp[s];

                            /* create the empty list of the server names that
                               can be served on this address:port */

                            ngx_init_array(inaddr->names, cf->pool, 10,
                                           sizeof(ngx_http_server_name_t),
                                           NGX_CONF_ERROR);

                            addr_found = 1;

                            break;
                        }
                    }

                    if (!addr_found) {

                        /* add the address to the addresses list that
                           bound to this port */

                        ngx_test_null(inaddr,
                                      ngx_push_array(&in_port[p].addrs),
                                      NGX_CONF_ERROR);

                        inaddr->addr = lscf[l].addr;
                        inaddr->flags = lscf[l].flags;
                        inaddr->core_srv_conf = cscfp[s];

                        /* create the empty list of the server names that
                           can be served on this address:port */

                        ngx_init_array(inaddr->names, cf->pool, 10,
                                       sizeof(ngx_http_server_name_t),
                                       NGX_CONF_ERROR);
                    }
                }
            }

            if (!port_found) {

                /* add the port to the in_port list */

                ngx_test_null(in_port,
                              ngx_push_array(&in_ports),
                              NGX_CONF_ERROR);

                in_port->port = lscf[l].port;

                ngx_test_null(in_port->port_name.data, ngx_palloc(cf->pool, 7),
                              NGX_CONF_ERROR);
                in_port->port_name.len = ngx_snprintf(in_port->port_name.data,
                                                      7, ":%d",
                                                      in_port->port);

                /* create list of the addresses that bound to this port ... */

                ngx_init_array(in_port->addrs, cf->pool, 10,
                               sizeof(ngx_http_in_addr_t),
                               NGX_CONF_ERROR);

                ngx_test_null(inaddr, ngx_push_array(&in_port->addrs),
                              NGX_CONF_ERROR);

                /* ... and add the address to this list */

                inaddr->addr = lscf[l].addr;
                inaddr->flags = lscf[l].flags;
                inaddr->core_srv_conf = cscfp[s];

                /* create the empty list of the server names that
                   can be served on this address:port */

                ngx_init_array(inaddr->names, cf->pool, 10,
                               sizeof(ngx_http_server_name_t),
                               NGX_CONF_ERROR);
            }
        }
    }

    /* optimize the lists of the ports, the addresses and the server names */

    /* AF_INET only */

    in_port = in_ports.elts;
    for (p = 0; p < in_ports.nelts; p++) {

        /* check whether the all server names point to the same server */

        in_addr = in_port[p].addrs.elts;
        for (a = 0; a < in_port[p].addrs.nelts; a++) {

            virtual_names = 0;

            name = in_addr[a].names.elts;
            for (n = 0; n < in_addr[a].names.nelts; n++) {
                if (in_addr[a].core_srv_conf != name[n].core_srv_conf) {
                    virtual_names = 1;
                    break;
                }
            }

            /* if the all server names point to the same server
               then we do not need to check them at run-time */

            if (!virtual_names) {
                in_addr[a].names.nelts = 0;
            }
        }

        /* if there's the binding to "*:port" then we need to bind()
           to "*:port" only and ignore the other bindings */

        if (in_addr[a - 1].addr == INADDR_ANY) {
            a--;

        } else {
            a = 0;
        }

        in_addr = in_port[p].addrs.elts;
        while (a < in_port[p].addrs.nelts) {

            ngx_test_null(ls, ngx_push_array(&cf->cycle->listening),
                          NGX_CONF_ERROR);
            ngx_memzero(ls, sizeof(ngx_listening_t));

            ngx_test_null(addr_in,
                          ngx_pcalloc(cf->pool, sizeof(struct sockaddr_in)),
                          NGX_CONF_ERROR);

            addr_in->sin_family = AF_INET;
            addr_in->sin_addr.s_addr = in_addr[a].addr;
            addr_in->sin_port = htons((u_short) in_port[p].port);

            ngx_test_null(ls->addr_text.data,
                          ngx_palloc(cf->pool, INET_ADDRSTRLEN + 6),
                          NGX_CONF_ERROR);

            ls->addr_text.len =
                        ngx_snprintf(ls->addr_text.data
                                     + ngx_inet_ntop(AF_INET,
                                                     (char *) &in_addr[a].addr,
                                                     ls->addr_text.data,
                                                     INET_ADDRSTRLEN),
                                     6, ":%d", in_port[p].port);

            ls->fd = -1;
            ls->family = AF_INET;
            ls->type = SOCK_STREAM;
            ls->protocol = IPPROTO_IP;
#if (WIN32)
            ls->flags = WSA_FLAG_OVERLAPPED;
#endif
            ls->sockaddr = (struct sockaddr *) addr_in;
            ls->socklen = sizeof(struct sockaddr_in);
            ls->addr = offsetof(struct sockaddr_in, sin_addr);
            ls->addr_text_max_len = INET_ADDRSTRLEN;
            ls->backlog = -1;
            ls->nonblocking = 1;

            ls->handler = ngx_http_init_connection;

#if 0
            ls->log = cf->cycle->log;
#endif

            cscf = in_addr[a].core_srv_conf;
            ls->pool_size = cscf->connection_pool_size;
            ls->post_accept_timeout = cscf->post_accept_timeout;

            clcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];
            ls->log = clcf->err_log;

#if (WIN32)
            iocpcf = ngx_event_get_conf(cf->cycle->conf_ctx, ngx_iocp_module);
            if (iocpcf->acceptex_read) {
                ls->post_accept_buffer_size = cscf->client_header_buffer_size;
            }
#endif

            ls->ctx = ctx;

            if (in_port[p].addrs.nelts > 1) {

                in_addr = in_port[p].addrs.elts;
                if (in_addr[in_port[p].addrs.nelts - 1].addr != INADDR_ANY) {

                    /* if this port has not the "*:port" binding then create
                       the separate ngx_http_in_port_t for the all bindings */

                    ngx_test_null(inport,
                                  ngx_palloc(cf->pool,
                                             sizeof(ngx_http_in_port_t)),
                                  NGX_CONF_ERROR);

                    inport->port = in_port[p].port;
                    inport->port_name = in_port[p].port_name;

                    /* init list of the addresses ... */

                    ngx_init_array(inport->addrs, cf->pool, 1,
                                   sizeof(ngx_http_in_addr_t),
                                   NGX_CONF_ERROR);

                    /* ... and set up it with the first address */

                    inport->addrs.nelts = 1;
                    inport->addrs.elts = in_port[p].addrs.elts;

                    ls->servers = inport;

                    /* prepare for the next cycle */

                    in_port[p].addrs.elts = (char *) in_port[p].addrs.elts
                                                       + in_port[p].addrs.size;
                    in_port[p].addrs.nelts--;

                    in_addr = (ngx_http_in_addr_t *) in_port[p].addrs.elts;
                    a = 0;

                    continue;
                }
            }

            ls->servers = &in_port[p];
            a++;
        }
    }

    /* DEBUG STUFF */
    in_port = in_ports.elts;
    for (p = 0; p < in_ports.nelts; p++) {
ngx_log_debug(cf->log, "port: %d %08x" _ in_port[p].port _ &in_port[p]);
        in_addr = in_port[p].addrs.elts;
        for (a = 0; a < in_port[p].addrs.nelts; a++) {
            char ip[20];
            ngx_inet_ntop(AF_INET, (char *) &in_addr[a].addr, ip, 20);
ngx_log_debug(cf->log, "%s %08x" _ ip _ in_addr[a].core_srv_conf);
            s_name = in_addr[a].names.elts;
            for (n = 0; n < in_addr[a].names.nelts; n++) {
ngx_log_debug(cf->log, "%s %08x" _ s_name[n].name.data _
              s_name[n].core_srv_conf);
            }
        }
    }
    /**/

    *cf = pcf;
    return NGX_CONF_OK;
}
