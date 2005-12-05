
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t
ngx_hash_init(ngx_hash_t *hash, ngx_pool_t *pool, void *names, ngx_uint_t nelts)
{
    u_char      *p;
    ngx_str_t   *name, *bucket;
    ngx_uint_t   i, n, key, size, best, *test, buckets, min_buckets;

    if (nelts == 0) {
        for (name = (ngx_str_t *) names;
             name->len;
             name = (ngx_str_t *) ((char *) name + hash->bucket_size))
        {
            nelts++;
        }
    }

    test = ngx_alloc(hash->max_size * sizeof(ngx_uint_t), pool->log);
    if (test == NULL) {
        return NGX_ERROR;
    }

    min_buckets = hash->bucket_limit + 1;

#if (NGX_SUPPRESS_WARN)
    best = 0;
#endif

    for (size = 1; size < hash->max_size; size++) {

        buckets = 0;

        for (i = 0; i < size; i++) {
            test[i] = 0;
        }

        for (n = 0, name = (ngx_str_t *) names;
             n < nelts;
             n++, name = (ngx_str_t *) ((char *) name + hash->bucket_size))
        {
            if (name->data == NULL) {
                continue;
            }

            key = 0;

            for (i = 0; i < name->len; i++) {
                key += ngx_tolower(name->data[i]);
            }

            key %= size;

            if (test[key] == hash->bucket_limit) {
                break;
            }

            test[key]++;

            if (buckets < test[key]) {
                buckets = test[key];
            }
        }

        if (n == nelts) {
            if (min_buckets > buckets) {
                min_buckets = buckets;
                best = size;
            }

            if (hash->bucket_limit == 1) {
                break;
            }
        }
    }

    if (min_buckets == hash->bucket_limit + 1) {
        ngx_log_error(NGX_LOG_EMERG, pool->log, 0,
                      "could not build the %s hash, you should increase "
                      "either %s_size: %i or %s_bucket_limit: %i",
                      hash->name, hash->name, hash->max_size,
                      hash->name, hash->bucket_limit);
        ngx_free(test);
        return NGX_ERROR;
    }

    hash->buckets = ngx_pcalloc(pool, best * hash->bucket_size);
    if (hash->buckets == NULL) {
        ngx_free(test);
        return NGX_ERROR;
    }

    if (hash->bucket_limit != 1) {

        for (i = 0; i < best; i++) {
            test[i] = 0;
        }

        for (n = 0, name = (ngx_str_t *) names;
             n < nelts;
             n++, name = (ngx_str_t *) ((char *) name + hash->bucket_size))
        {
            if (name->data == NULL) {
                continue;
            }

            key = 0;

            for (i = 0; i < name->len; i++) {
                key += ngx_tolower(name->data[i]);
            }

            key %= best;

            test[key]++;
        }

        for (i = 0; i < best; i++) {
            if (test[i] == 0) {
                continue;
            }

            bucket = ngx_palloc(pool, test[i] * hash->bucket_size);
            if (bucket == NULL) {
                ngx_free(test);
                return NGX_ERROR;
            }

            hash->buckets[i] = bucket;
            bucket->len = 0;
        }
    }

    for (n = 0, name = (ngx_str_t *) names;
         n < nelts;
         n++, name = (ngx_str_t *) ((char *) name + hash->bucket_size))
    {
        if (name->data == NULL) {
            continue;
        }

        key = 0;

        for (i = 0; i < name->len; i++) {
            key += ngx_tolower(name->data[i]);
        }

        key %= best;

        if (hash->bucket_limit == 1) {
            p = (u_char *) hash->buckets + key * hash->bucket_size;
            ngx_memcpy(p, name, hash->bucket_size);
            continue;
        }

        for (bucket = hash->buckets[key];
             bucket->len;
             bucket = (ngx_str_t *) ((char *) bucket + hash->bucket_size))
        {
            bucket->len &= 0x7fffffff;
        }

        ngx_memcpy(bucket, name, hash->bucket_size);
        bucket->len |= 0x80000000;
    }

    ngx_free(test);

    hash->hash_size = best;
    hash->min_buckets = min_buckets;

    return NGX_OK;
}
