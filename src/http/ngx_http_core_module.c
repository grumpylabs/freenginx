
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_conf_file.h>

#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_core_module.h>

#if 0
#include <ngx_http_write_filter.h>
#include <ngx_http_output_filter.h>
#include <ngx_http_index_handler.h>
#endif

/* STUB */
#include <ngx_http_output_filter.h>
int ngx_http_static_handler(ngx_http_request_t *r);
int ngx_http_index_handler(ngx_http_request_t *r);
int ngx_http_proxy_handler(ngx_http_request_t *r);
/**/


static char *ngx_server_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy);
static char *ngx_location_block(ngx_conf_t *cf, ngx_command_t *cmd,
                                                                  char *dummy);
static void *ngx_http_core_create_srv_conf(ngx_pool_t *pool);
static char *ngx_http_core_init_srv_conf(ngx_pool_t *pool, void *conf);
static void *ngx_http_core_create_loc_conf(ngx_pool_t *pool);


static ngx_command_t  ngx_http_core_commands[] = {

    {ngx_string("server"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_server_block,
     0,
     0},

    {ngx_string("location"),
     NGX_HTTP_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
     ngx_location_block,
     0,
     0},

    {ngx_string("root"),
     NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, doc_root)},

    {ngx_string("send_timeout"),
     NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
     ngx_conf_set_time_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, send_timeout)},

    {ngx_string(""), 0, NULL, 0, 0}
};


ngx_http_module_t  ngx_http_core_module_ctx = {
    NGX_HTTP_MODULE,

    ngx_http_core_create_srv_conf,         /* create server config */
    ngx_http_core_init_srv_conf,           /* init server config */
    ngx_http_core_create_loc_conf,         /* create location config */
    NULL,                                  /* merge location config */

    ngx_http_core_translate_handler,       /* translate handler */

    NULL,                                  /* output header filter */
    NULL,                                  /* next output header filter */
    NULL,                                  /* output body filter */
    NULL                                   /* next output body filter */
};


ngx_module_t  ngx_http_core_module = {
    0,                                     /* module index */
    &ngx_http_core_module_ctx,             /* module context */
    ngx_http_core_commands,                /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    NULL                                   /* init module */
};


int ngx_http_handler(ngx_http_request_t *r)
{
    int  rc, i;
    ngx_http_module_t    *module;
    ngx_http_conf_ctx_t  *ctx;

    r->connection->unexpected_eof = 0;
    r->lingering_close = 1;
    r->keepalive = 0;

    ctx = (ngx_http_conf_ctx_t *) r->connection->ctx;
    r->srv_conf = ctx->srv_conf;
    r->loc_conf = ctx->loc_conf;

ngx_log_debug(r->connection->log, "srv_conf: %0x" _ r->srv_conf);
ngx_log_debug(r->connection->log, "loc_conf: %0x" _ r->loc_conf);
ngx_log_debug(r->connection->log, "servers: %0x" _ r->connection->servers);


#if 1
    r->filter = NGX_HTTP_FILTER_NEED_IN_MEMORY;
#endif

    /* run translation phase */
    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;

        if (module->translate_handler == NULL) {
            continue;
        }

        rc = module->translate_handler(r);
        if (rc == NGX_OK) {
            break;
        }

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return ngx_http_special_response(r, rc);
        }
    }

    rc = r->handler(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return ngx_http_special_response(r, rc);
    }

    return rc;
}


int ngx_http_core_translate_handler(ngx_http_request_t *r)
{
    int                         i, rc;
    char                       *location, *last;
    ngx_err_t                   err;
    ngx_table_elt_t            *h;
    ngx_http_core_srv_conf_t   *scf;
    ngx_http_core_loc_conf_t  **lcf, *loc_conf;

    scf = (ngx_http_core_srv_conf_t *)
                     ngx_http_get_module_srv_conf(r, ngx_http_core_module_ctx);

    /* find location config */
    lcf = (ngx_http_core_loc_conf_t **) scf->locations.elts;
    for (i = 0; i < scf->locations.nelts; i++) {
ngx_log_debug(r->connection->log, "trans: %s" _ lcf[i]->name.data);
         if (r->uri.len < lcf[i]->name.len) {
             continue;
         }

         rc = ngx_strncmp(r->uri.data, lcf[i]->name.data, lcf[i]->name.len);

         if (rc < 0) {
             break;
         }

         if (rc == 0) {
             r->loc_conf = lcf[i]->loc_conf;
         }
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        /* TODO: find index handler */
        /* STUB */ r->handler = ngx_http_index_handler;

        return NGX_OK;
    }

    loc_conf = (ngx_http_core_loc_conf_t *)
                     ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    r->file.name.len = loc_conf->doc_root.len + r->uri.len;

    ngx_test_null(r->file.name.data,
                  ngx_palloc(r->pool, r->file.name.len + 1),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    location = ngx_cpystrn(r->file.name.data, loc_conf->doc_root.data,
                           loc_conf->doc_root.len + 1);
    last = ngx_cpystrn(location, r->uri.data, r->uri.len + 1);

    ngx_log_debug(r->connection->log, "HTTP filename: '%s'" _
                  r->file.name.data);

#if (WIN9X)

    /* There is no way to open file or directory in Win9X with
       one syscall: Win9X has not FILE_FLAG_BACKUP_SEMANTICS flag.
       so we need to check its type before opening */

    r->file.info.dwFileAttributes = GetFileAttributes(r->file.name.data);
    if (r->file.info.dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      "ngx_http_core_translate_handler: "
                      ngx_file_type_n " %s failed", r->file.name.data);

        if (err == ERROR_FILE_NOT_FOUND) {
            return NGX_HTTP_NOT_FOUND;
        } else if (err == ERROR_PATH_NOT_FOUND) {
            return NGX_HTTP_NOT_FOUND;
        } else {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

#else

    if (r->file.fd == NGX_INVALID_FILE) {
        r->file.fd = ngx_open_file(r->file.name.data, NGX_FILE_RDONLY);
    }

    if (r->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "ngx_http_core_handler: "
                      ngx_open_file_n " %s failed", r->file.name.data);

        if (err == NGX_ENOENT) {
            return NGX_HTTP_NOT_FOUND;
#if (WIN32)
        } else if (err == ERROR_PATH_NOT_FOUND) {
            return NGX_HTTP_NOT_FOUND;
#endif
        } else {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (!r->file.info_valid) {
        if (ngx_stat_fd(r->file.fd, &r->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "ngx_http_core_handler: "
                          ngx_stat_fd_n " %s failed", r->file.name.data);

            if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                              "ngx_http_core_handler: "
                              ngx_close_file_n " %s failed", r->file.name.data);
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->file.info_valid = 1;
    }
#endif

    if (ngx_is_dir(r->file.info)) {
        ngx_log_debug(r->connection->log, "HTTP DIR: '%s'" _ r->file.name.data);

#if !(WIN9X)
        if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "ngx_http_core_handler: "
                          ngx_close_file_n " %s failed", r->file.name.data);
        }
#endif

        /* BROKEN: need to include server name */

        ngx_test_null(h, ngx_push_table(r->headers_out.headers),
                      NGX_HTTP_INTERNAL_SERVER_ERROR);

        *last++ = '/';
        *last = '\0';
        h->key.len = 8;
        h->key.data = "Location" ;
        h->value.len = last - location;
        h->value.data = location;
        r->headers_out.location = h;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

    /* TODO: r->handler = loc_conf->default_handler; */
    /* STUB */ r->handler = ngx_http_static_handler;

    return NGX_OK;
}


int ngx_http_send_header(ngx_http_request_t *r)
{
    return (*ngx_http_top_header_filter)(r);
}


int ngx_http_redirect(ngx_http_request_t *r, int redirect)
{
    /* STUB */

    /* log request */

    return ngx_http_close_request(r);
}


int ngx_http_error(ngx_http_request_t *r, int error) 
{
    /* STUB */
    ngx_log_debug(r->connection->log, "http error: %d" _ error);

    /* log request */

    ngx_http_special_response(r, error);
    return ngx_http_close_request(r);
}


int ngx_http_close_request(ngx_http_request_t *r)
{
    ngx_log_debug(r->connection->log, "CLOSE#: %d" _ r->file.fd);

    ngx_http_log_handler(r);

    ngx_assert((r->file.fd != NGX_INVALID_FILE), /* void */ ; ,
               r->connection->log, "file already closed");

    if (r->file.fd != NGX_INVALID_FILE) {
        if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          ngx_close_file_n " failed");
        }
    }

/*
    if (r->logging)
        ngx_http_log_request(r);
*/

    ngx_destroy_pool(r->pool);

    ngx_log_debug(r->connection->log, "http close");

    ngx_del_timer(r->connection->read);
    ngx_del_timer(r->connection->write);

    return NGX_DONE;
}


int ngx_http_internal_redirect(ngx_http_request_t *r, ngx_str_t uri)
{
    ngx_log_debug(r->connection->log, "internal redirect: '%s'" _ uri.data);

    r->uri.len = uri.len;
    r->uri.data = uri.data;

    /* NEEDED ? */
    r->uri_start = uri.data;
    r->uri_end = uri.data + uri.len;
    /**/

    return ngx_http_handler(r);
}


#if 0
void *ngx_http_find_server_conf(ngx_http_request_t *r)
{
    int  i;
    ngx_http_listen_t       *fs, *ls;
    ngx_http_server_name_t  *n;

    fs = NULL;
    ls = (ngx_http_listen_t *) http->ports.elts;

    for (i = 0; i < http->ports.nelts; i++) {
        if (s->family != ls[i].family || s->port != ls[i].port) {
            continue;
        }

        if (s->family == AF_INET) {

            if (ls[i].addr == INADDR_ANY || ls[i].addr == s->addr) {
                fs = &ls[i];
                break;
            }

        } else {
            /* STUB: AF_INET only */
        }
    }

    if (fs == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "unknown local socket %s:%d",
                      s->addr_text.data, s->port);
        return NULL;
    }

    if (r->headers_in.host && fs->server_names.nelts) {

        n = (ngx_http_server_name_t *) fs->server_names.elts;
        for (i = 0; i < fs->server_names.nelts; i++) {
            if (r->headers_in.host->value.len != n[i].name.len) {
                continue;
            }

            if (ngx_strcmp(r->headers_in.host->value.data, n[i].name.data) == 0)            {
                return n[i].srv_conf;
            }
        }
    }

    return fs->srv_conf;
}
#endif


static char *ngx_server_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy)
{
    int                        i, j;
    char                      *rv;
    ngx_http_module_t         *module;
    ngx_http_conf_ctx_t       *ctx, *prev;
    ngx_http_core_srv_conf_t  *scf;
    ngx_http_core_loc_conf_t **lcf;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    /* server config */
    ngx_test_null(ctx->srv_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    /* server location config */
    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;

        if (module->create_srv_conf) {
            ngx_test_null(ctx->srv_conf[module->index],
                          module->create_srv_conf(cf->pool),
                          NGX_CONF_ERROR);
ngx_log_debug(cf->log, "srv_conf: %d:%0x" _
              module->index _ ctx->loc_conf[module->index]);
        }

        if (module->create_loc_conf) {
            ngx_test_null(ctx->loc_conf[module->index],
                          module->create_loc_conf(cf->pool),
                          NGX_CONF_ERROR);
ngx_log_debug(cf->log, "srv loc_conf: %d:%0x" _
              module->index _ ctx->loc_conf[module->index]);
        }
    }

    prev = cf->ctx;
    cf->ctx = ctx;
    rv = ngx_conf_parse(cf, NULL);
    cf->ctx = prev;

    if (rv != NGX_CONF_OK)
        return rv;


    scf = ctx->srv_conf[ngx_http_core_module_ctx.index];
    scf->ctx = ctx;

    lcf = (ngx_http_core_loc_conf_t **)scf->locations.elts;

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;

        if (module->init_srv_conf) {
            if (module->init_srv_conf(cf->pool,
                                      ctx->srv_conf[module->index])
                                                           == NGX_CONF_ERROR) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->merge_loc_conf) {
            if (module->merge_loc_conf(cf->pool,
                                       prev->loc_conf[module->index],
                                       ctx->loc_conf[module->index])
                                                           == NGX_CONF_ERROR) {
                return NGX_CONF_ERROR;
            }

            for (j = 0; j < scf->locations.nelts; j++) {
ngx_log_debug(cf->log, "%d:%0x" _ j _ lcf[j]);
ngx_log_debug(cf->log, "%d:'%s'" _ lcf[j]->name.len _ lcf[j]->name.data);
                if (module->merge_loc_conf(cf->pool,
                                           ctx->loc_conf[module->index],
                                           lcf[j]->loc_conf[module->index])
                                                           == NGX_CONF_ERROR) {
                    return NGX_CONF_ERROR;
                }
            }
        }
    }

    return NGX_CONF_OK;
}


static char *ngx_location_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy)
{
    int                        i;
    char                      *rv;
    void                     **loc;
    ngx_str_t                 *location;
    ngx_http_module_t         *module;
    ngx_http_conf_ctx_t       *ctx, *prev;
    ngx_http_core_srv_conf_t  *scf;
    ngx_http_core_loc_conf_t  *lcf;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    prev = (ngx_http_conf_ctx_t *) cf->ctx;
    ctx->srv_conf = prev->srv_conf;

    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;

        if (module->create_loc_conf) {
            ngx_test_null(ctx->loc_conf[module->index],
                          module->create_loc_conf(cf->pool),
                          NGX_CONF_ERROR);
ngx_log_debug(cf->log, "loc_conf: %d:%0x" _
              module->index _ ctx->loc_conf[module->index]);
        }
    }

    lcf = (ngx_http_core_loc_conf_t *)
                                 ctx->loc_conf[ngx_http_core_module_ctx.index];
    location = (ngx_str_t *) cf->args->elts;
    lcf->name.len = location[1].len;
    lcf->name.data = location[1].data;
    lcf->loc_conf = ctx->loc_conf;

    scf = (ngx_http_core_srv_conf_t *)
                                 ctx->srv_conf[ngx_http_core_module_ctx.index];
    ngx_test_null(loc, ngx_push_array(&scf->locations), NGX_CONF_ERROR);
    *loc = lcf;

ngx_log_debug(cf->log, "%0x:%s" _ lcf _ lcf->name.data);

    cf->ctx = ctx;
    rv = ngx_conf_parse(cf, NULL);
    cf->ctx = prev;

    return rv;
}


int ngx_http_config_modules(ngx_pool_t *pool, ngx_module_t **modules)
{
    int i;
    ngx_http_module_t  *module;

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) modules[i]->ctx;
        module->index = i;
    }

    ngx_http_max_module = i;

#if 0
    ngx_test_null(ngx_srv_conf,
                  ngx_pcalloc(pool, sizeof(void *) * ngx_http_max_module),
                  NGX_ERROR);
    ngx_test_null(ngx_loc_conf,
                  ngx_pcalloc(pool, sizeof(void *) * ngx_http_max_module),
                  NGX_ERROR);

    for (i = 0; modules[i]; i++) {
        if (modules[i]->create_srv_conf)
            ngx_srv_conf[i] = modules[i]->create_srv_conf(pool);

        if (modules[i]->create_loc_conf)
            ngx_loc_conf[i] = modules[i]->create_loc_conf(pool);
    }
#endif
}


void ngx_http_init_filters(ngx_pool_t *pool, ngx_module_t **modules)
{
    int  i;
    ngx_http_module_t  *module;
    int (*ohf)(ngx_http_request_t *r);
    int (*obf)(ngx_http_request_t *r, ngx_chain_t *ch);

    ohf = NULL;
    obf = NULL;

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) modules[i]->ctx;

        if (module->output_header_filter) {
            module->next_output_header_filter = ohf;
            ohf = module->output_header_filter;
        }

        if (module->output_body_filter) {
            module->next_output_body_filter = obf;
            obf = module->output_body_filter;
        }
    }

    ngx_http_top_header_filter = ohf;
}


static void *ngx_http_core_create_srv_conf(ngx_pool_t *pool)
{
    ngx_http_core_srv_conf_t *scf, **cf;

    ngx_test_null(scf,
                  ngx_pcalloc(pool, sizeof(ngx_http_core_srv_conf_t)), 
                  NGX_CONF_ERROR);

    ngx_init_array(scf->locations, pool, 5, sizeof(void *), NGX_CONF_ERROR);
    ngx_init_array(scf->listen, pool, 5, sizeof(ngx_http_listen_t),
                   NGX_CONF_ERROR);

    ngx_test_null(cf, ngx_push_array(&ngx_http_servers), NGX_CONF_ERROR);
    *cf = scf;

    return scf;
}


static char *ngx_http_core_init_srv_conf(ngx_pool_t *pool, void *conf)
{
    ngx_http_core_srv_conf_t *scf = (ngx_http_core_srv_conf_t *) conf;

    ngx_http_listen_t        *l;

    if (scf->listen.nelts == 0) {
        ngx_test_null(l, ngx_push_array(&scf->listen), NGX_CONF_ERROR);
        l->addr = INADDR_ANY;
        l->port = 8000;
        l->family = AF_INET;
    }

    return NGX_CONF_OK;
}


static void *ngx_http_core_create_loc_conf(ngx_pool_t *pool)
{
    ngx_http_core_loc_conf_t *lcf;

    ngx_test_null(lcf,
                  ngx_pcalloc(pool, sizeof(ngx_http_core_loc_conf_t)), 
                  NGX_CONF_ERROR);

    lcf->doc_root.len = 4;
    lcf->doc_root.data = "html";

    lcf->send_timeout = 10;
    lcf->discarded_buffer_size = 1500;
    lcf->lingering_time = 30;
    lcf->lingering_timeout = 5000;

/*
    lcf->send_timeout = NGX_CONF_UNSET;
*/

    return lcf;
}
