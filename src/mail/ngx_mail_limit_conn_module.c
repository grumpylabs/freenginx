
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mail.h>


#define NGX_MAIL_LIMIT_CONN_REMOTE_USER  1
#define NGX_MAIL_LIMIT_CONN_REMOTE_ADDR  2
#define NGX_MAIL_LIMIT_CONN_AUTH_HTTP    3


typedef struct {
    u_char                        color;
    u_char                        len;
    u_short                       conn;
    u_char                        data[1];
} ngx_mail_limit_conn_node_t;


typedef struct {
    ngx_shm_zone_t               *shm_zone;
    ngx_rbtree_node_t            *node;
} ngx_mail_limit_conn_cleanup_t;


typedef struct {
    ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
} ngx_mail_limit_conn_shctx_t;


typedef struct {
    ngx_mail_limit_conn_shctx_t  *sh;
    ngx_slab_pool_t              *shpool;
    ngx_str_t                     key;
    ngx_uint_t                    key_type;
} ngx_mail_limit_conn_ctx_t;


typedef struct {
    ngx_shm_zone_t               *shm_zone;
    ngx_uint_t                    conn;
} ngx_mail_limit_conn_limit_t;


typedef struct {
    ngx_array_t                   limits;
    ngx_uint_t                    log_level;
    ngx_flag_t                    dry_run;
} ngx_mail_limit_conn_conf_t;


static ngx_int_t ngx_mail_limit_conn_key(ngx_mail_session_t *s,
    ngx_mail_limit_conn_ctx_t *ctx, ngx_str_t *key);
static void ngx_mail_limit_conn_send_error(ngx_mail_session_t *s);
static ngx_rbtree_node_t *ngx_mail_limit_conn_lookup(ngx_rbtree_t *rbtree,
    ngx_str_t *key, uint32_t hash);
static void ngx_mail_limit_conn_cleanup(void *data);
static ngx_inline void ngx_mail_limit_conn_cleanup_all(ngx_pool_t *pool);
static void ngx_mail_limit_conn_cleanup_node(ngx_shm_zone_t *shm_zone,
    ngx_rbtree_node_t *node);

static void *ngx_mail_limit_conn_create_conf(ngx_conf_t *cf);
static char *ngx_mail_limit_conn_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_mail_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_mail_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_enum_t  ngx_mail_limit_conn_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_mail_limit_conn_commands[] = {

    { ngx_string("limit_conn_zone"),
      NGX_MAIL_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_mail_limit_conn_zone,
      0,
      0,
      NULL },

    { ngx_string("limit_conn"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE2,
      ngx_mail_limit_conn,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_conn_log_level"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_limit_conn_conf_t, log_level),
      &ngx_mail_limit_conn_log_levels },

    { ngx_string("limit_conn_dry_run"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_limit_conn_conf_t, dry_run),
      NULL },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_limit_conn_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_limit_conn_create_conf,       /* create server configuration */
    ngx_mail_limit_conn_merge_conf         /* merge server configuration */
};


ngx_module_t  ngx_mail_limit_conn_module = {
    NGX_MODULE_V1,
    &ngx_mail_limit_conn_module_ctx,       /* module context */
    ngx_mail_limit_conn_commands,          /* module directives */
    NGX_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char  pop3_error[] = "-ERR [SYS/TEMP] Too many connections" CRLF;
static u_char  imap_error[] = "NO [UNAVAILABLE] Too many connections" CRLF;
static u_char  smtp_error[] = "454 4.7.0 Too many connections" CRLF;


ngx_int_t
ngx_mail_limit_conn_handler(ngx_mail_session_t *s)
{
    size_t                          n;
    uint32_t                        hash;
    ngx_str_t                       key;
    ngx_uint_t                      i;
    ngx_rbtree_node_t              *node;
    ngx_pool_cleanup_t             *cln;
    ngx_mail_limit_conn_ctx_t      *ctx;
    ngx_mail_limit_conn_node_t     *lc;
    ngx_mail_limit_conn_conf_t     *lccf;
    ngx_mail_limit_conn_limit_t    *limits;
    ngx_mail_limit_conn_cleanup_t  *lccln;

    s->connection->log->action = NULL;

    lccf = ngx_mail_get_module_srv_conf(s, ngx_mail_limit_conn_module);
    limits = lccf->limits.elts;

    for (i = 0; i < lccf->limits.nelts; i++) {
        ctx = limits[i].shm_zone->data;

        if (ngx_mail_limit_conn_key(s, ctx, &key) != NGX_OK) {
            ngx_mail_session_internal_server_error(s);
            return NGX_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 255) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 255 bytes: \"%V\"",
                          &ctx->key, &key);
            continue;
        }

        hash = ngx_crc32_short(key.data, key.len);

        ngx_shmtx_lock(&ctx->shpool->mutex);

        node = ngx_mail_limit_conn_lookup(&ctx->sh->rbtree, &key, hash);

        if (node == NULL) {

            n = offsetof(ngx_rbtree_node_t, color)
                + offsetof(ngx_mail_limit_conn_node_t, data)
                + key.len;

            node = ngx_slab_alloc_locked(ctx->shpool, n);

            if (node == NULL) {
                ngx_shmtx_unlock(&ctx->shpool->mutex);
                ngx_mail_limit_conn_cleanup_all(s->connection->pool);

                if (lccf->dry_run) {
                    return NGX_OK;
                }

                ngx_mail_session_internal_server_error(s);
                return NGX_ERROR;
            }

            lc = (ngx_mail_limit_conn_node_t *) &node->color;

            node->key = hash;
            lc->len = (u_char) key.len;
            lc->conn = 1;
            ngx_memcpy(lc->data, key.data, key.len);

            ngx_rbtree_insert(&ctx->sh->rbtree, node);

        } else {

            lc = (ngx_mail_limit_conn_node_t *) &node->color;

            if ((ngx_uint_t) lc->conn >= limits[i].conn) {

                ngx_shmtx_unlock(&ctx->shpool->mutex);

                ngx_log_error(lccf->log_level, s->connection->log, 0,
                              "limiting connections%s by zone \"%V\"",
                              lccf->dry_run ? ", dry run," : "",
                              &limits[i].shm_zone->shm.name);

                ngx_mail_limit_conn_cleanup_all(s->connection->pool);

                if (lccf->dry_run) {
                    return NGX_OK;
                }

                ngx_mail_limit_conn_send_error(s);
                return NGX_BUSY;
            }

            lc->conn++;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "limit conn: %08Xi %d", node->key, lc->conn);

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        cln = ngx_pool_cleanup_add(s->connection->pool,
                                   sizeof(ngx_mail_limit_conn_cleanup_t));
        if (cln == NULL) {
            ngx_mail_limit_conn_cleanup_node(limits[i].shm_zone, node);
            ngx_mail_session_internal_server_error(s);
            return NGX_ERROR;
        }

        cln->handler = ngx_mail_limit_conn_cleanup;
        lccln = cln->data;

        lccln->shm_zone = limits[i].shm_zone;
        lccln->node = node;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_mail_limit_conn_key(ngx_mail_session_t *s, ngx_mail_limit_conn_ctx_t *ctx,
    ngx_str_t *key)
{
    ngx_str_t  name;

    switch (ctx->key_type) {

    case NGX_MAIL_LIMIT_CONN_REMOTE_USER:
        *key = s->login;
        break;

    case NGX_MAIL_LIMIT_CONN_REMOTE_ADDR:
        *key = s->connection->addr_text;
        break;

    case NGX_MAIL_LIMIT_CONN_AUTH_HTTP:

        name.len = ctx->key.len - (sizeof("$auth_http_") - 1);
        name.data = ctx->key.data + (sizeof("$auth_http_") - 1);

        if (ngx_mail_auth_http_header_value(s, &name, key) != NGX_OK) {
            return NGX_ERROR;
        }

        break;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "limit conn key: \"%V\"", key);

    return NGX_OK;
}


static void
ngx_mail_limit_conn_send_error(ngx_mail_session_t *s)
{
    u_char  *p, *err;
    size_t   len;

    switch (s->protocol) {

    case NGX_MAIL_POP3_PROTOCOL:
        ngx_str_set(&s->out, pop3_error);
        break;

    case NGX_MAIL_IMAP_PROTOCOL:
        len = s->tag.len + sizeof(imap_error) - 1;

        err = ngx_pnalloc(s->connection->pool, len);
        if (err == NULL) {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(err, s->tag.data, s->tag.len);
        ngx_memcpy(p, imap_error, sizeof(imap_error) - 1);

        s->out.len = len;
        s->out.data = err;

        break;

    default: /* NGX_MAIL_SMTP_PROTOCOL */
        ngx_str_set(&s->out, smtp_error);
        break;
    }

    s->quit = 1;

    ngx_mail_send(s->connection->write);
}


static void
ngx_mail_limit_conn_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_mail_limit_conn_node_t   *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (ngx_mail_limit_conn_node_t *) &node->color;
            lcnt = (ngx_mail_limit_conn_node_t *) &temp->color;

            p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
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


static ngx_rbtree_node_t *
ngx_mail_limit_conn_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash)
{
    ngx_int_t                    rc;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_mail_limit_conn_node_t  *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

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

        lcn = (ngx_mail_limit_conn_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
ngx_mail_limit_conn_cleanup(void *data)
{
    ngx_mail_limit_conn_cleanup_t  *lccln = data;

    ngx_rbtree_node_t           *node;
    ngx_mail_limit_conn_ctx_t   *ctx;
    ngx_mail_limit_conn_node_t  *lc;

    ctx = lccln->shm_zone->data;
    node = lccln->node;
    lc = (ngx_mail_limit_conn_node_t *) &node->color;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_MAIL, lccln->shm_zone->shm.log, 0,
                   "limit conn cleanup: %08Xi %d", node->key, lc->conn);

    lc->conn--;

    if (lc->conn == 0) {
        ngx_rbtree_delete(&ctx->sh->rbtree, node);
        ngx_slab_free_locked(ctx->shpool, node);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);
}


static ngx_inline void
ngx_mail_limit_conn_cleanup_all(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t  *cln;

    cln = pool->cleanup;

    while (cln && cln->handler == ngx_mail_limit_conn_cleanup) {
        ngx_mail_limit_conn_cleanup(cln->data);
        cln = cln->next;
    }

    pool->cleanup = cln;
}


static void
ngx_mail_limit_conn_cleanup_node(ngx_shm_zone_t *shm_zone,
    ngx_rbtree_node_t *node)
{
    ngx_mail_limit_conn_cleanup_t  lccln;

    lccln.shm_zone = shm_zone;
    lccln.node = node;

    ngx_mail_limit_conn_cleanup(&lccln);
}


static ngx_int_t
ngx_mail_limit_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_mail_limit_conn_ctx_t  *octx = data;

    size_t                      len;
    ngx_mail_limit_conn_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.len != octx->key.len
            || ngx_strncmp(ctx->key.data, octx->key.data,
                           ctx->key.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_conn_zone \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key,
                          &octx->key);
            return NGX_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_mail_limit_conn_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_mail_limit_conn_rbtree_insert_value);

    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in limit_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static void *
ngx_mail_limit_conn_create_conf(ngx_conf_t *cf)
{
    ngx_mail_limit_conn_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_limit_conn_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->log_level = NGX_CONF_UNSET_UINT;
    conf->dry_run = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_mail_limit_conn_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_limit_conn_conf_t *prev = parent;
    ngx_mail_limit_conn_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);
    ngx_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    return NGX_CONF_OK;
}


static char *
ngx_mail_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                     *p;
    ssize_t                     size;
    ngx_str_t                  *value, name, s;
    ngx_uint_t                  i;
    ngx_shm_zone_t             *shm_zone;
    ngx_mail_limit_conn_ctx_t  *ctx;

    value = cf->args->elts;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_mail_limit_conn_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_strcmp(value[1].data, "$remote_user") == 0) {
        ctx->key = value[1];
        ctx->key_type = NGX_MAIL_LIMIT_CONN_REMOTE_USER;

    } else if (ngx_strcmp(value[1].data, "$remote_addr") == 0) {
        ctx->key = value[1];
        ctx->key_type = NGX_MAIL_LIMIT_CONN_REMOTE_ADDR;

    } else if (ngx_strncmp(value[1].data, "$auth_http_", 11) == 0) {
        ctx->key = value[1];
        ctx->key_type = NGX_MAIL_LIMIT_CONN_AUTH_HTTP;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    size = 0;
    name.len = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_mail_limit_conn_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_mail_limit_conn_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_mail_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_shm_zone_t               *shm_zone;
    ngx_mail_limit_conn_conf_t   *lccf = conf;
    ngx_mail_limit_conn_limit_t  *limit, *limits;

    ngx_str_t  *value;
    ngx_int_t   n;
    ngx_uint_t  i;

    value = cf->args->elts;

    shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                     &ngx_mail_limit_conn_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    limits = lccf->limits.elts;

    if (limits == NULL) {
        if (ngx_array_init(&lccf->limits, cf->pool, 1,
                           sizeof(ngx_mail_limit_conn_limit_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 0; i < lccf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    n = ngx_atoi(value[2].data, value[2].len);
    if (n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of connections \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (n > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "connection limit must be less 65536");
        return NGX_CONF_ERROR;
    }

    limit = ngx_array_push(&lccf->limits);
    if (limit == NULL) {
        return NGX_CONF_ERROR;
    }

    limit->conn = n;
    limit->shm_zone = shm_zone;

    return NGX_CONF_OK;
}
