
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_errno.h>
#include <ngx_string.h>
#include <ngx_files.h>
#include <ngx_config_command.h>
#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_index_handler.h>


static void *ngx_http_index_create_conf(ngx_pool_t *pool);
static void *ngx_http_index_merge_conf(ngx_pool_t *p,
                                       void *parent, void *child);
static char *ngx_http_index_set_index(ngx_pool_t *p, void *conf,
                                      ngx_str_t *value);

static ngx_command_t ngx_http_index_commands[];


ngx_http_module_t  ngx_http_index_module = {
    NGX_HTTP_MODULE,

    NULL,                                  /* create server config */
    ngx_http_index_create_conf,            /* create location config */
    ngx_http_index_commands,               /* module directives */

    NULL,                                  /* init module */
    NULL,                                  /* translate handler */

    NULL,                                  /* init output body filter */
};


static ngx_command_t ngx_http_index_commands[] = {

    {"index", ngx_http_index_set_index, NULL,
     NGX_HTTP_LOC_CONF, NGX_CONF_ITERATE,
     "set index files"},

    {NULL}

};


int ngx_http_index_handler(ngx_http_request_t *r)
{
    int          i;
    char        *name, *file;
    ngx_str_t    loc, *index;
    ngx_err_t    err;
    ngx_fd_t     fd;

    ngx_http_index_conf_t  *cf;

    cf = (ngx_http_index_conf_t *)
                            ngx_get_module_loc_conf(r, ngx_http_index_module);

    ngx_test_null(name,
                  ngx_palloc(r->pool,
                             r->server->doc_root_len + r->uri.len
                             + cf->max_index_len),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    loc.data = ngx_cpystrn(name, r->server->doc_root, r->server->doc_root_len);
    file = ngx_cpystrn(loc.data, r->uri.data, r->uri.len + 1);

    index = (ngx_str_t *) cf->indices->elts;
    for (i = 0; i < cf->indices->nelts; i++) {
        ngx_memcpy(file, index[i].data, index[i].len + 1);

        fd = ngx_open_file(name, NGX_FILE_RDONLY);
        if (fd == -1) {
            err = ngx_errno;
            if (err == NGX_ENOENT)
                continue;

            ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                          ngx_open_file_n " %s failed", name);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->filename.len = r->server->doc_root_len + r->uri.len + index[i].len;
        r->filename.data = name; 
        r->fd = fd; 

        loc.len = r->uri.len + index[i].len;
        return ngx_http_internal_redirect(r, loc);
    }

    return NGX_DECLINED;
}


static void *ngx_http_index_create_conf(ngx_pool_t *pool)
{
    ngx_http_index_conf_t  *conf;

    ngx_test_null(conf, ngx_pcalloc(pool, sizeof(ngx_http_index_conf_t)), NULL);

    ngx_test_null(conf->indices,
                  ngx_create_array(pool, sizeof(ngx_str_t), 3),
                  NULL);

    return conf;
}


static void *ngx_http_index_merge_conf(ngx_pool_t *p, void *parent, void *child)
{
    ngx_http_index_conf_t *prev = (ngx_http_index_conf_t *) parent;
    ngx_http_index_conf_t *conf = (ngx_http_index_conf_t *) child;
    ngx_str_t  *index;

    if (conf->max_index_len == 0) {
        if (prev->max_index_len != 0)
            return prev;

        ngx_test_null(index, ngx_push_array(conf->indices), NULL);
        index->len = sizeof(NGX_HTTP_INDEX) - 1;
        index->data = NGX_HTTP_INDEX;
        conf->max_index_len = sizeof(NGX_HTTP_INDEX);
    }

    return conf;
}


static char *ngx_http_index_set_index(ngx_pool_t *p, void *conf,
                                      ngx_str_t *value)
{
    ngx_http_index_conf_t *cf = (ngx_http_index_conf_t *) conf;
    ngx_str_t  *index;

    ngx_test_null(index, ngx_push_array(cf->indices), NULL);
    index->len = value->len;
    index->data = value->data;

    if (cf->max_index_len < index->len)
        cf->max_index_len = index->len;

    return NULL;
}
