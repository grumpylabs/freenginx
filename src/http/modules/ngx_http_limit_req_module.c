
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    u_char              color;
    u_char              dummy;
    u_short             len;
    ngx_queue_t         queue;
    ngx_msec_t          last;
    float               rate;
    u_char              data[1];
} ngx_http_limit_req_node_t;


typedef struct {
    ngx_rbtree_t       *rbtree;
    ngx_queue_t        *queue;
    ngx_slab_pool_t    *shpool;
    float               rate;
    ngx_int_t           index;
    ngx_str_t           var;
} ngx_http_limit_req_ctx_t;


typedef struct {
    ngx_shm_zone_t     *shm_zone;
    float               burst;
    ngx_uint_t          nodelay;     /* unsigned  nodelay:1 */
} ngx_http_limit_req_conf_t;


static void ngx_http_limit_req_delay(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_req_lookup(ngx_http_limit_req_conf_t *lzcf,
    ngx_uint_t hash, u_char *data, size_t len, ngx_http_limit_req_node_t **lzp);
static void ngx_http_limit_req_expire(ngx_http_limit_req_ctx_t *ctx,
    ngx_uint_t n);

static void *ngx_http_limit_req_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_req_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_limit_req_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_limit_req(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_limit_req_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_limit_req_commands[] = {

    { ngx_string("limit_req_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_limit_req_zone,
      0,
      0,
      NULL },

    { ngx_string("limit_req"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_limit_req,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_req_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_limit_req_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_limit_req_create_conf,        /* create location configration */
    ngx_http_limit_req_merge_conf          /* merge location configration */
};


ngx_module_t  ngx_http_limit_req_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_req_module_ctx,        /* module context */
    ngx_http_limit_req_commands,           /* module directives */
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
ngx_http_limit_req_handler(ngx_http_request_t *r)
{
    float                       rate;
    size_t                      len, n;
    uint32_t                    hash;
    ngx_int_t                   rc;
    ngx_time_t                 *tp;
    ngx_rbtree_node_t          *node;
    ngx_http_variable_value_t  *vv;
    ngx_http_limit_req_ctx_t   *ctx;
    ngx_http_limit_req_node_t  *lz;
    ngx_http_limit_req_conf_t  *lzcf;

    if (r->main->limit_req_set) {
        return NGX_DECLINED;
    }

    lzcf = ngx_http_get_module_loc_conf(r, ngx_http_limit_req_module);

    if (lzcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    ctx = lzcf->shm_zone->data;

    vv = ngx_http_get_indexed_variable(r, ctx->index);

    if (vv == NULL || vv->not_found) {
        return NGX_DECLINED;
    }

    len = vv->len;

    if (len == 0) {
        return NGX_DECLINED;
    }

    if (len > 65535) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "the value of the \"%V\" variable "
                      "is more than 65535 bytes: \"%v\"",
                      &ctx->var, vv);
        return NGX_DECLINED;
    }

    r->main->limit_req_set = 1;

    hash = ngx_crc32_short(vv->data, len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_http_limit_req_expire(ctx, 1);

    rc = ngx_http_limit_req_lookup(lzcf, hash, vv->data, len, &lz);

    if (lz) {
        ngx_queue_remove(&lz->queue);

        ngx_queue_insert_head(ctx->queue, &lz->queue);

        rate = lz->rate;

    } else {
        rate = 0.0;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "limit_req: %i %.3f", rc, rate);

    if (rc == NGX_BUSY) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "limiting requests, excess: %.3f", rate);

        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    if (rc == NGX_AGAIN) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        if (lzcf->nodelay) {
            return NGX_DECLINED;
        }

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "delaying request, excess: %.3f", rate);

        if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->read_event_handler = ngx_http_test_reading;
        r->write_event_handler = ngx_http_limit_req_delay;
        ngx_add_timer(r->connection->write, (ngx_msec_t) (rate * 1000));

        return NGX_AGAIN;
    }

    if (rc == NGX_OK) {
        goto done;
    }

    /* rc == NGX_DECLINED */

    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_limit_req_node_t, data)
        + len;

    node = ngx_slab_alloc_locked(ctx->shpool, n);
    if (node == NULL) {

        ngx_http_limit_req_expire(ctx, 0);

        node = ngx_slab_alloc_locked(ctx->shpool, n);
        if (node == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_HTTP_SERVICE_UNAVAILABLE;
        }
    }

    lz = (ngx_http_limit_req_node_t *) &node->color;

    node->key = hash;
    lz->len = (u_char) len;

    tp = ngx_timeofday();
    lz->last = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    lz->rate = 0.0;
    ngx_memcpy(lz->data, vv->data, len);

    ngx_rbtree_insert(ctx->rbtree, node);

    ngx_queue_insert_head(ctx->queue, &lz->queue);

done:

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_DECLINED;
}


static void
ngx_http_limit_req_delay(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "limit_req delay");

    if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    r->read_event_handler = ngx_http_block_reading;
    r->write_event_handler = ngx_http_core_run_phases;

    ngx_http_core_run_phases(r);
}


static void
ngx_http_limit_req_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t          **p;
    ngx_http_limit_req_node_t   *lzn, *lznt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lzn = (ngx_http_limit_req_node_t *) &node->color;
            lznt = (ngx_http_limit_req_node_t *) &temp->color;

            p = (ngx_memn2cmp(lzn->data, lznt->data, lzn->len, lznt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_http_limit_req_lookup(ngx_http_limit_req_conf_t *lzcf, ngx_uint_t hash,
    u_char *data, size_t len, ngx_http_limit_req_node_t **lzp)
{
    ngx_int_t                   rc;
    ngx_time_t                 *tp;
    ngx_msec_t                  now;
    ngx_msec_int_t              ms;
    ngx_rbtree_node_t          *node, *sentinel;
    ngx_http_limit_req_ctx_t   *ctx;
    ngx_http_limit_req_node_t  *lz;

    ctx = lzcf->shm_zone->data;

    node = ctx->rbtree->root;
    sentinel = ctx->rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        do {
            lz = (ngx_http_limit_req_node_t *) &node->color;

            rc = ngx_memn2cmp(data, lz->data, len, (size_t) lz->len);

            if (rc == 0) {

                tp = ngx_timeofday();

                now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);
                ms = (ngx_msec_int_t) (now - lz->last);

                lz->rate = lz->rate - ctx->rate * ngx_abs(ms) / 1000 + 1;

                if (lz->rate < 0.0) {
                    lz->rate = 0.0;
                }

                lz->last = now;

                *lzp = lz;

                if (lz->rate > lzcf->burst) {
                    return NGX_BUSY;
                }

                if (lz->rate > 0.0) {
                    return NGX_AGAIN;
                }

                return NGX_OK;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && hash == node->key);

        break;
    }

    *lzp = NULL;

    return NGX_DECLINED;
}


static void
ngx_http_limit_req_expire(ngx_http_limit_req_ctx_t *ctx, ngx_uint_t n)
{
    float                       rate;
    ngx_time_t                 *tp;
    ngx_msec_t                  now;
    ngx_queue_t                *q;
    ngx_msec_int_t              ms;
    ngx_rbtree_node_t          *node;
    ngx_http_limit_req_node_t  *lz;

    tp = ngx_timeofday();

    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    /*
     * n == 1 deletes one or two zero rate entries
     * n == 0 deletes oldest entry by force
     *        and one or two zero rate entries
     */

    while (n < 3) {

        if (ngx_queue_empty(ctx->queue)) {
            return;
        }

        q = ngx_queue_last(ctx->queue);

        lz = ngx_queue_data(q, ngx_http_limit_req_node_t, queue);

        if (n++ != 0) {

            ms = (ngx_msec_int_t) (now - lz->last);
            ms = ngx_abs(ms);

            if (ms < 60000) {
                return;
            }

            rate = lz->rate - ctx->rate * ms / 1000;

            if (rate > 0.0) {
                return;
            }
        }

        ngx_queue_remove(q);

        node = (ngx_rbtree_node_t *)
                   ((u_char *) lz - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(ctx->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);
    }
}


static ngx_int_t
ngx_http_limit_req_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_req_ctx_t  *octx = data;

    ngx_rbtree_node_t         *sentinel;
    ngx_http_limit_req_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ngx_strcmp(ctx->var.data, octx->var.data) != 0) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_req \"%V\" uses the \"%V\" variable "
                          "while previously it used the \"%V\" variable",
                          &shm_zone->name, &ctx->var, &octx->var);
            return NGX_ERROR;
        }

        ctx->rbtree = octx->rbtree;
        ctx->queue = octx->queue;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ctx->rbtree = ngx_slab_alloc(ctx->shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    sentinel = ngx_slab_alloc(ctx->shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, sentinel,
                    ngx_http_limit_req_rbtree_insert_value);

    ctx->queue = ngx_slab_alloc(ctx->shpool, sizeof(ngx_queue_t));
    if (ctx->queue == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_init(ctx->queue);

    return NGX_OK;
}


static void *
ngx_http_limit_req_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_req_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->shm_zone = NULL;
     *     conf->burst = 0.0;
     *     conf->nodelay = 0;
     */

    return conf;
}


static char *
ngx_http_limit_req_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_req_conf_t *prev = parent;
    ngx_http_limit_req_conf_t *conf = child;

    if (conf->shm_zone == NULL) {
        *conf = *prev;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_req_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                    *p;
    size_t                     size, len;
    ngx_str_t                 *value, name, s;
    ngx_int_t                  rate, scale;
    ngx_uint_t                 i;
    ngx_shm_zone_t            *shm_zone;
    ngx_http_limit_req_ctx_t  *ctx;

    value = cf->args->elts;

    ctx = NULL;
    size = 0;
    rate = 1;
    scale = 1;
    name.len = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p) {
                name.len = p - name.data;

                p++;

                s.len = value[i].data + value[i].len - p;
                s.data = p;

                size = ngx_parse_size(&s);
                if (size > 8191) {
                    continue;
                }
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {

            len = value[i].len;
            p = value[i].data + len - 3;

            if (ngx_strncmp(p, "r/s", 3) == 0) {
                scale = 1;
                len -= 3;

            } else if (ngx_strncmp(p, "r/m", 3) == 0) {
                scale = 60;
                len -= 3;
            }

            rate = ngx_atoi(value[i].data + 5, len - 5);
            if (rate <= NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rate \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (value[i].data[0] == '$') {

            value[i].len--;
            value[i].data++;

            ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_ctx_t));
            if (ctx == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->index = ngx_http_get_variable_index(cf, &value[i]);
            if (ctx->index == NGX_ERROR) {
                return NGX_CONF_ERROR;
            }

            ctx->var = value[i];

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0 || size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (ctx == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no variable is defined for limit_req_zone \"%V\"",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    ctx->rate = (float) rate / scale;

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_limit_req_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                   "limit_req_zone \"%V\" is already bound to variable \"%V\"",
                   &value[1], &ctx->var);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_limit_req_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_req(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_limit_req_conf_t  *lzcf = conf;

    ngx_int_t    burst;
    ngx_str_t   *value, s;
    ngx_uint_t   i;

    if (lzcf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    burst = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            lzcf->shm_zone = ngx_shared_memory_add(cf, &s, 0,
                                                   &ngx_http_limit_req_module);
            if (lzcf->shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "burst=", 6) == 0) {

            burst = ngx_atoi(value[i].data + 6, value[i].len - 6);
            if (burst <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid burst rate \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "nodelay", 7) == 0) {
            lzcf->nodelay = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (lzcf->shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (lzcf->shm_zone->data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown limit_req_zone \"%V\"",
                           &lzcf->shm_zone->name);
        return NGX_CONF_ERROR;
    }

    lzcf->burst = (float) burst;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_limit_req_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_limit_req_handler;

    return NGX_OK;
}
