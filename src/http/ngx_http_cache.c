
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#include <md5.h>

#if (HAVE_OPENSSL_MD5)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif


static ngx_http_module_t  ngx_http_cache_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_cache_module = {
    NGX_MODULE,
    &ngx_http_cache_module_ctx,            /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


ngx_http_cache_t *ngx_http_cache_get(ngx_http_cache_hash_t *hash,
                                     ngx_http_cleanup_t *cleanup,
                                     ngx_str_t *key, uint32_t *crc)
{
    ngx_uint_t         i;
    ngx_http_cache_t  *c;

    *crc = ngx_crc(key->data, key->len);

    c = hash->elts + *crc % hash->hash * hash->nelts;

    ngx_mutex_lock(&hash->mutex);

    for (i = 0; i < hash->nelts; i++) {
        if (c[i].crc == *crc
            && c[i].key.len == key->len
            && ngx_rstrncmp(c[i].key.data, key->data, key->len) == 0)
        {
            c[i].refs++;
            ngx_mutex_unlock(&hash->mutex);

            if (c[i].notify) {
                if (!(ngx_event_flags & NGX_HAVE_KQUEUE_EVENT)) {
                    c[i].valid = 0;
                }

            } else if (ngx_cached_time - c[i].updated >= hash->update) {
                c[i].valid = 0;
            }

            if (cleanup) {
                cleanup->data.cache.hash = hash;
                cleanup->data.cache.cache = &c[i];
                cleanup->valid = 1;
                cleanup->cache = 1;
            }

            return &c[i];
        }
    }

    ngx_mutex_unlock(&hash->mutex);

    return NULL;
}


ngx_http_cache_t *ngx_http_cache_alloc(ngx_http_cache_hash_t *hash,
                                       ngx_http_cache_t *cache,
                                       ngx_http_cleanup_t *cleanup,
                                       ngx_str_t *key, uint32_t crc,
                                       ngx_str_t *value, ngx_log_t *log)
{
    time_t             old;
    ngx_uint_t         i;
    ngx_http_cache_t  *c;

    old = ngx_cached_time + 1;

    c = hash->elts + crc % hash->hash * hash->nelts;

    ngx_mutex_lock(&hash->mutex);

    if (cache == NULL) {

        /* allocate a new entry */

        for (i = 0; i < hash->nelts; i++) {
            if (c[i].refs > 0) {
                /* a busy entry */
                continue;
            }

            if (c[i].key.len == 0) {
                /* a free entry is found */
                cache = &c[i];
                break;
            }

            /* looking for the oldest cache entry */

            if (old > c[i].accessed) {

                old = c[i].accessed;
                cache = &c[i];
            }
        }

        if (cache == NULL) {
            ngx_mutex_unlock(&hash->mutex);
            return NULL;
        }

        ngx_http_cache_free(cache, key, value, log);

        if (cache->key.data == NULL) {
            cache->key.data = ngx_alloc(key->len, log);
            if (cache->key.data == NULL) {
                ngx_http_cache_free(cache, NULL, NULL, log);
                ngx_mutex_unlock(&hash->mutex);
                return NULL;
            }
        }

        cache->key.len = key->len;
        ngx_memcpy(cache->key.data, key->data, key->len);

    } else if (value) {
        ngx_http_cache_free(cache, key, value, log);
    }

    if (value) {
        if (cache->data.value.data == NULL) {
            cache->data.value.data = ngx_alloc(value->len, log);
            if (cache->data.value.data == NULL) {
                ngx_http_cache_free(cache, NULL, NULL, log);
                ngx_mutex_unlock(&hash->mutex);
                return NULL;
            }
        }

        cache->data.value.len = value->len;
        ngx_memcpy(cache->data.value.data, value->data, value->len);
    }

    cache->crc = crc;
    cache->key.len = key->len;

    cache->refs = 1;
    cache->count = 0;

    cache->valid = 1;
    cache->deleted = 0;
    cache->memory = 0;
    cache->mmap = 0;
    cache->notify = 0;

    if (cleanup) {
        cleanup->data.cache.hash = hash;
        cleanup->data.cache.cache = cache;
        cleanup->valid = 1;
        cleanup->cache = 1;
    }

    ngx_mutex_unlock(&hash->mutex);

    return cache;
}


void ngx_http_cache_free(ngx_http_cache_t *cache,
                         ngx_str_t *key, ngx_str_t *value, ngx_log_t *log)
{
    if (cache->memory) {
        if (cache->data.value.data
            && (value == NULL || value->len > cache->data.value.len))
        {
            ngx_free(cache->data.value.data);
            cache->data.value.data = NULL;
        }
    }

    /* TODO: mmap */

    cache->data.value.len = 0;

    if (cache->fd != NGX_INVALID_FILE) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http cache close fd: %d", cache->fd);

        if (ngx_close_file(cache->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          cache->key.data);
        }

        cache->fd = NGX_INVALID_FILE;
    }

    if (cache->key.data && (key == NULL || key->len > cache->key.len)) {
        ngx_free(cache->key.data);
        cache->key.data = NULL;
    }

    cache->key.len = 0;

    cache->refs = 0;
}


void ngx_http_cache_unlock(ngx_http_cache_hash_t *hash,
                           ngx_http_cache_t *cache, ngx_log_t *log)
{
    ngx_mutex_lock(&hash->mutex);

    cache->refs--;

    if (cache->refs == 0 && cache->deleted) {
        ngx_http_cache_free(cache, NULL, NULL, log);
    }

    ngx_mutex_unlock(&hash->mutex);
}


#if 0

ngx_add_file_event(ngx_fd_t, ngx_event_handler_pt *handler, void *data)
{
    ngx_event_t  *ev;

    ev = &ngx_cycle->read_events[fd];
    ngx_memzero(ev, sizeof(ngx_event_t);

    ev->data = data;
    ev->event_handler = handler;

    return ngx_add_event(ev, NGX_VNODE_EVENT, 0);
}


void ngx_http_cache_invalidate(ngx_event_t *ev)
{
    ngx_http_cache_ctx_t  *ctx;

    ctx = ev->data;

    ngx_http_cache_lock(&ctx->hash->mutex);

    if (ctx->cache->refs == 0)
        ngx_http_cache_free(ctx->cache, NULL, NULL, ctx->log);

    } else {
        ctx->cache->deleted = 1;
    }

    ngx_http_cache_unlock(&ctx->hash->mutex);
}

#endif


int ngx_http_cache_get_file(ngx_http_request_t *r, ngx_http_cache_ctx_t *ctx)
{
    MD5_CTX  md5;

    /* we use offsetof() because sizeof() pads struct size to int size */
    ctx->header_size = offsetof(ngx_http_cache_header_t, key)
                                                            + ctx->key.len + 1;

    ctx->file.name.len = ctx->path->name.len + 1 + ctx->path->len + 32;
    if (!(ctx->file.name.data = ngx_palloc(r->pool, ctx->file.name.len + 1))) {
        return NGX_ERROR;
    }

    ngx_memcpy(ctx->file.name.data, ctx->path->name.data, ctx->path->name.len);

    MD5Init(&md5);
    MD5Update(&md5, (u_char *) ctx->key.data, ctx->key.len);
    MD5Final(ctx->md5, &md5);

    ngx_md5_text(ctx->file.name.data + ctx->path->name.len + 1 + ctx->path->len,
                 ctx->md5);

ngx_log_debug(r->connection->log, "URL: %s, md5: %s" _ ctx->key.data _
              ctx->file.name.data + ctx->path->name.len + 1 + ctx->path->len);

    ngx_create_hashed_filename(&ctx->file, ctx->path);

ngx_log_debug(r->connection->log, "FILE: %s" _ ctx->file.name.data);

    /* TODO: look open files cache */

    return ngx_http_cache_open_file(ctx, 0);
}


int ngx_http_cache_open_file(ngx_http_cache_ctx_t *ctx, ngx_file_uniq_t uniq)
{
    ssize_t                   n;
    ngx_err_t                 err;
    ngx_http_cache_header_t  *h;

    ctx->file.fd = ngx_open_file(ctx->file.name.data,
                                 NGX_FILE_RDONLY, NGX_FILE_OPEN);

    if (ctx->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
            return NGX_DECLINED;
        }

        ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", ctx->file.name.data);
        return NGX_ERROR;
    }

    if (uniq) {
        if (ngx_fd_info(ctx->file.fd, &ctx->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                          ngx_fd_info_n " \"%s\" failed", ctx->file.name.data);

            return NGX_ERROR;
        }

        if (ngx_file_uniq(&ctx->file.info) == uniq) {
            if (ngx_close_file(ctx->file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              ctx->file.name.data);
            }

            return NGX_HTTP_CACHE_THE_SAME;
        }
    }

    n = ngx_read_file(&ctx->file, ctx->buf->pos,
                      ctx->buf->end - ctx->buf->last, 0);

    if (n == NGX_ERROR || n == NGX_AGAIN) {
        return n;
    }

    if (n <= ctx->header_size) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, 0,
                      "cache file \"%s\" is too small", ctx->file.name.data);
        return NGX_ERROR;
    }

    h = (ngx_http_cache_header_t *) ctx->buf->pos;
    ctx->expires = h->expires;
    ctx->last_modified= h->last_modified;
    ctx->date = h->date;
    ctx->length = h->length;

    if (h->key_len > (size_t) (ctx->buf->end - ctx->buf->pos)) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                      "cache file \"%s\" is probably invalid",
                      ctx->file.name.data);
        return NGX_DECLINED;
    }

    if (ctx->key.len
        && (h->key_len != ctx->key.len
            || ngx_strncmp(h->key, ctx->key.data, h->key_len) != 0))
    {
        h->key[h->key_len] = '\0';
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                          "md5 collision: \"%s\" and \"%s\"",
                          h->key, ctx->key.data);
        return NGX_DECLINED;
    }

    ctx->buf->last += n;

    if (ctx->expires < ngx_time()) {
ngx_log_debug(ctx->log, "EXPIRED");
        return NGX_HTTP_CACHE_STALE;
    }

    /* TODO: NGX_HTTP_CACHE_AGED */

    return NGX_OK;
}


int ngx_http_cache_update_file(ngx_http_request_t *r, ngx_http_cache_ctx_t *ctx,
                               ngx_str_t *temp_file)
{
    int        retry;
    ngx_err_t  err;

    retry = 0;

    for ( ;; ) {
        if (ngx_rename_file(temp_file->data, ctx->file.name.data) == NGX_OK) {
            return NGX_OK;
        }

        err = ngx_errno;

#if (WIN32)
        if (err == NGX_EEXIST) {
            if (ngx_win32_rename_file(temp_file, &ctx->file.name, r->pool)
                                                                  == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }
#endif

        if (retry || (err != NGX_ENOENT && err != NGX_ENOTDIR)) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_rename_file_n "(\"%s\", \"%s\") failed",
                          temp_file->data, ctx->file.name.data);

            return NGX_ERROR;
        }

        if (ngx_create_path(&ctx->file, ctx->path) == NGX_ERROR) {
            return NGX_ERROR;
        }

        retry = 1;
    }
}


/* TODO: currently fd only */

ngx_int_t ngx_http_send_cached(ngx_http_request_t *r)
{
    ngx_int_t            rc;
    ngx_hunk_t          *h;
    ngx_chain_t          out;
    ngx_http_log_ctx_t  *ctx;

    ctx = r->connection->log->data;
    ctx->action = "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = r->cache->data.size;
    r->headers_out.last_modified_time = r->cache->last_modified;

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* we need to allocate all before the header would be sent */

    if (!(h = ngx_pcalloc(r->pool, sizeof(ngx_hunk_t)))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!(h->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t)))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    h->type = r->main ? NGX_HUNK_FILE : NGX_HUNK_FILE|NGX_HUNK_LAST;

    h->file_pos = 0;
    h->file_last = ngx_file_size(&r->file.info);

    h->file->fd = r->cache->fd;
    h->file->log = r->connection->log;

    out.hunk = h;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


int ngx_garbage_collector_http_cache_handler(ngx_gc_t *gc, ngx_str_t *name,
                                             ngx_dir_t *dir)
{
    int                   rc;
    char                  data[sizeof(ngx_http_cache_header_t)];
    ngx_hunk_t            buf;
    ngx_http_cache_ctx_t  ctx;

    ctx.file.fd = NGX_INVALID_FILE;
    ctx.file.name = *name;
    ctx.file.log = gc->log;

    ctx.header_size = sizeof(ngx_http_cache_header_t);
    ctx.buf = &buf;
    ctx.log = gc->log;
    ctx.key.len = 0;

    buf.type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
    buf.pos = data;
    buf.last = data;
    buf.start = data;
    buf.end = data + sizeof(ngx_http_cache_header_t);

    rc = ngx_http_cache_open_file(&ctx, 0);

    /* TODO: NGX_AGAIN */

    if (rc != NGX_ERROR && rc != NGX_DECLINED && rc != NGX_HTTP_CACHE_STALE) {
        return NGX_OK;
    }

    if (ngx_delete_file(name->data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, gc->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name->data);
        return NGX_ERROR;
    }

    gc->deleted++;
    gc->freed += ngx_de_size(dir);

    return NGX_OK;
}


char *ngx_http_set_cache_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_int_t              i, j, dup, invalid;
    ngx_str_t              *value, line;
    ngx_http_cache_t       *c;
    ngx_http_cache_hash_t  *ch, **chp;

    chp = (ngx_http_cache_hash_t **) (p + cmd->offset);
    if (*chp) {
        return "is duplicate";
    }

    if (!(ch = ngx_pcalloc(cf->pool, sizeof(ngx_http_cache_hash_t)))) {
        return NGX_CONF_ERROR;
    }
    *chp = ch;

    dup = 0;
    invalid = 0;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].data[1] != '=') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }

        switch (value[i].data[0]) {

        case 'h':
            if (ch->hash) {
                dup = 1;
                break;
            }

            ch->hash = ngx_atoi(value[i].data + 2, value[i].len - 2);
            if (ch->hash == (size_t)  NGX_ERROR || ch->hash == 0) {
                invalid = 1;
                break;
            }

            continue;

        case 'n':
            if (ch->nelts) {
                dup = 1;
                break;
            }

            ch->nelts = ngx_atoi(value[i].data + 2, value[i].len - 2);
            if (ch->nelts == (size_t) NGX_ERROR || ch->nelts == 0) {
                invalid = 1;
                break;
            }

            continue;

        case 'l':
            if (ch->life) {
                dup = 1;
                break;
            }

            line.len = value[i].len - 2;
            line.data = value[i].data + 2;

            ch->life = ngx_parse_time(&line, 1);
            if (ch->life == NGX_ERROR || ch->life == 0) {
                invalid = 1;
                break;
            }

            continue;

        case 'u':
            if (ch->update) {
                dup = 1;
                break;
            }

            line.len = value[i].len - 2;
            line.data = value[i].data + 2;

            ch->update = ngx_parse_time(&line, 1);
            if (ch->update == NGX_ERROR || ch->update == 0) {
                invalid = 1;
                break;
            }

            continue;

        default:
            invalid = 1;
        }

        if (dup) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate value \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }

        if (invalid) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }
    }

    ch->elts = ngx_pcalloc(cf->pool,
                           ch->hash * ch->nelts * sizeof(ngx_http_cache_t));
    if (ch->elts == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; i < (ngx_int_t) ch->hash; i++) {
        c = ch->elts + i * ch->nelts;

        for (j = 0; j < (ngx_int_t) ch->nelts; j++) {
            c[j].fd = NGX_INVALID_FILE;
        }
    }

    return NGX_CONF_OK;
}
