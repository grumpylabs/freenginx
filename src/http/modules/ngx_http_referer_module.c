
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_hash_t               hash;
    ngx_hash_wildcard_t     *dns_wildcards;

    ngx_flag_t               no_referer;
    ngx_flag_t               blocked_referer;

    ngx_hash_keys_arrays_t  *keys;
} ngx_http_referer_conf_t;


static void * ngx_http_referer_create_conf(ngx_conf_t *cf);
static char * ngx_http_referer_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_valid_referers(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_add_referer(ngx_conf_t *cf, ngx_hash_keys_arrays_t *keys,
    ngx_str_t *value);
static int ngx_libc_cdecl ngx_http_cmp_referer_wildcards(const void *one,
    const void *two);


static ngx_command_t  ngx_http_referer_commands[] = {

    { ngx_string("valid_referers"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_valid_referers,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_referer_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_referer_create_conf,          /* create location configuration */
    ngx_http_referer_merge_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_referer_module = {
    NGX_MODULE_V1,
    &ngx_http_referer_module_ctx,          /* module context */
    ngx_http_referer_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_referer_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
     uintptr_t data)
{
    u_char                   *p, *ref;
    size_t                    len;
    ngx_http_referer_conf_t  *rlcf;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_referer_module);

    if (rlcf->hash.buckets == NULL
        && rlcf->dns_wildcards == NULL
        && rlcf->dns_wildcards->hash.buckets == NULL)
    {
        *v = ngx_http_variable_null_value;
        return NGX_OK;
    }

    if (r->headers_in.referer == NULL) {
        if (rlcf->no_referer) {
            *v = ngx_http_variable_null_value;
            return NGX_OK;

        } else {
            *v = ngx_http_variable_true_value;
            return NGX_OK;
        }
    }

    len = r->headers_in.referer->value.len;
    ref = r->headers_in.referer->value.data;

    if (len < sizeof("http://i.ru") - 1
        || (ngx_strncasecmp(ref, "http://", 7) != 0))
    {
        if (rlcf->blocked_referer) {
            *v = ngx_http_variable_null_value;
            return NGX_OK;

        } else {
            *v = ngx_http_variable_true_value;
            return NGX_OK;
        }
    }

    len -= 7;
    ref += 7;

    for (p = ref; p < ref + len; p++) {
        if (*p == '/' || *p == ':') {
            break;
        }
    }

    len = p - ref;

    if (rlcf->hash.buckets) {
        if (ngx_hash_find(&rlcf->hash, ngx_hash_key_lc(ref, len), ref, len)) {
            *v = ngx_http_variable_null_value;
            return NGX_OK;
        }
    }

    if (rlcf->dns_wildcards && rlcf->dns_wildcards->hash.buckets) {
        if (ngx_hash_find_wildcard(rlcf->dns_wildcards, ref, len)) {
            *v = ngx_http_variable_null_value;
            return NGX_OK;
        }
    }

    *v = ngx_http_variable_true_value;

    return NGX_OK;
}


static void *
ngx_http_referer_create_conf(ngx_conf_t *cf)
{
    ngx_http_referer_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_referer_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->no_referer = NGX_CONF_UNSET;
    conf->blocked_referer = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_referer_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_referer_conf_t *prev = parent;
    ngx_http_referer_conf_t *conf = child;

    ngx_hash_init_t  hash;

    if (conf->keys == NULL) {
        conf->hash = prev->hash;
        conf->dns_wildcards = prev->dns_wildcards;

        ngx_conf_merge_value(conf->no_referer, prev->no_referer, 0);
        ngx_conf_merge_value(conf->blocked_referer, prev->blocked_referer, 0);

        return NGX_CONF_OK;
    }

    hash.key = ngx_hash_key_lc;
    hash.max_size = 2048; /* TODO: referer_hash_max_size; */
    hash.bucket_size = 64; /* TODO: referer_hash_bucket_size; */
    hash.name = "referers_hash";
    hash.pool = cf->pool;

    if (conf->keys->keys.nelts) {
        hash.hash = &conf->hash;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, conf->keys->keys.elts, conf->keys->keys.nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (conf->keys->dns_wildcards.nelts) {

        ngx_qsort(conf->keys->dns_wildcards.elts,
                  (size_t) conf->keys->dns_wildcards.nelts,
                  sizeof(ngx_hash_key_t),
                  ngx_http_cmp_referer_wildcards);

        hash.hash = NULL;
        hash.temp_pool = cf->temp_pool;

        if (ngx_hash_wildcard_init(&hash, conf->keys->dns_wildcards.elts,
                                   conf->keys->dns_wildcards.nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        conf->dns_wildcards = (ngx_hash_wildcard_t *) hash.hash;
    }

    if (conf->no_referer == NGX_CONF_UNSET) {
        conf->no_referer = 0;
    }

    if (conf->blocked_referer == NGX_CONF_UNSET) {
        conf->blocked_referer = 0;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_valid_referers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_referer_conf_t  *rlcf = conf;

    u_char                    *p;
    ngx_str_t                 *value, name;
    ngx_uint_t                 i, n;
    ngx_http_variable_t       *var;
    ngx_http_server_name_t    *sn;
    ngx_http_core_srv_conf_t  *cscf;

    name.len = sizeof("invalid_referer") - 1;
    name.data = (u_char *) "invalid_referer";

    var = ngx_http_add_variable(cf, &name,
                                NGX_HTTP_VAR_CHANGABLE|NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->handler = ngx_http_referer_variable;

    if (rlcf->keys == NULL) {
        rlcf->keys = ngx_pcalloc(cf->temp_pool, sizeof(ngx_hash_keys_arrays_t));
        if (rlcf->keys == NULL) {
            return NGX_CONF_ERROR;
        }

        rlcf->keys->pool = cf->pool;
        rlcf->keys->temp_pool = cf->pool;

        if (ngx_hash_keys_array_init(rlcf->keys, NGX_HASH_SMALL) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid referer \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(value[i].data, "none") == 0) {
            rlcf->no_referer = 1;
            continue;
        }

        if (ngx_strcmp(value[i].data, "blocked") == 0) {
            rlcf->blocked_referer = 1;
            continue;
        }

        if (ngx_strcmp(value[i].data, "server_names") == 0) {

            cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

            sn = cscf->server_names.elts;
            for (n = 0; n < cscf->server_names.nelts; n++) {
                if (ngx_http_add_referer(cf, rlcf->keys, &sn[n].name) != NGX_OK)                {
                    return NGX_CONF_ERROR;
                }
            }

            continue;
        }

        p = (u_char *) ngx_strstr(value[i].data, "/");

        if (p) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "URI part \"%s\" is deprecated, ignored", p);

            value[i].len = p - value[i].data;
        }

        if (ngx_http_add_referer(cf, rlcf->keys, &value[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_add_referer(ngx_conf_t *cf, ngx_hash_keys_arrays_t *keys,
    ngx_str_t *value)
{
    u_char      ch;
    ngx_int_t   rc;
    ngx_uint_t  flags;

    ch = value->data[0];

    if ((ch == '*' && (value->len < 3 || value->data[1] != '.'))
        || (ch == '.' && value->len < 2))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid DNS wildcard \"%V\"", value);

        return NGX_CONF_ERROR;
    }

    flags = (ch == '*' || ch == '.') ? NGX_HASH_WILDCARD_KEY : 0;

    rc = ngx_hash_add_key(keys, value, (void *) 4, flags);

    if (rc == NGX_OK) {
        return NGX_CONF_OK;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "conflicting parameter \"%V\"", value);
    }

    return NGX_CONF_ERROR;
}


static int ngx_libc_cdecl
ngx_http_cmp_referer_wildcards(const void *one, const void *two)
{
    ngx_hash_key_t  *first, *second;

    first = (ngx_hash_key_t *) one;
    second = (ngx_hash_key_t *) two;

    return ngx_strcmp(first->key.data, second->key.data);
}
