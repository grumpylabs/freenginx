
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


void *
ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len)
{
    ngx_uint_t       i;
    ngx_hash_elt_t  *elt;

#if 0
    ngx_str_t  line;

    line.len = len;
    line.data = name;
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "hf:\"%V\"", &line);
#endif

    elt = hash->buckets[key % hash->size];

    if (elt == NULL) {
        return NULL;
    }

    while (elt->value) {
        if (len != (size_t) elt->len) {
            goto next;
        }

        for (i = 0; i < len; i++) {
            if (name[i] != elt->name[i]) {
                goto next;
            }
        }

        return elt->value;

    next:

        elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
                                               sizeof(void *));
        continue;
    }

    return NULL;
}


void *
ngx_hash_find_wildcard(ngx_hash_wildcard_t *hwc, u_char *name, size_t len)
{
    void        *value;
    ngx_uint_t   i, n, key;

#if 0
    ngx_str_t  line;

    line.len = len;
    line.data = name;
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "wc:\"%V\"", &line);
#endif

    n = len;

    while (n) {
        if (name[n - 1] == '.') {
            break;
        }

        n--;
    }

    key = 0;

    for (i = n; i < len; i++) {
        key = ngx_hash(key, name[i]);
    }

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "key:\"%ui\"", key);
#endif

    value = ngx_hash_find(&hwc->hash, key, &name[n], len - n);

    if (value) {

        /*
         * the 2 low bits of value have the special meaning:
         *     00 - value is data pointer,
         *     01 - value is pointer to wildcard hash allowing
         *          "*.example.com" only,
         *     11 - value is pointer to wildcard hash allowing
         *          both "example.com" and "*.example.com".
         */

        if ((uintptr_t) value & 1) {

            hwc = (ngx_hash_wildcard_t *) ((uintptr_t) value & (uintptr_t) ~3);

            if (n == 0) {
                if ((uintptr_t) value & 2) {
                    return hwc->value;

                } else {
                    return NULL;
                }
            }

            value = ngx_hash_find_wildcard(hwc, name, n - 1);

            if (value) {
                return value;
            }

            return hwc->value;
        }

        return value;
    }

    return hwc->value;
}


#define NGX_HASH_ELT_SIZE(name)                                               \
            sizeof(void *) + ngx_align((name)->key.len + 1, sizeof(void *))

ngx_int_t
ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names, ngx_uint_t nelts)
{
    u_char          *elts;
    size_t          *test, len;
    ngx_uint_t       i, n, key, size, start, bucket_size;
    ngx_hash_elt_t  *elt, **buckets;

    for (n = 0; n < nelts; n++) {
        if (names[n].key.len >= 255) {
            ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                          "the \"%V\" value to hash is to long: %uz bytes, "
                          "the maximum length can be 255 bytes only",
                          &names[n].key, names[n].key.len);
            return NGX_ERROR;
        }

        if (hinit->bucket_size < NGX_HASH_ELT_SIZE(&names[n]) + sizeof(void *))
        {
            ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                          "could not build the %s hash, you should "
                          "increase %s_bucket_size: %i",
                          hinit->name, hinit->name, hinit->bucket_size);
            return NGX_ERROR;
        }
    }

    test = ngx_alloc(hinit->max_size * sizeof(ngx_uint_t), hinit->pool->log);
    if (test == NULL) {
        return NGX_ERROR;
    }

    start = nelts / (ngx_cacheline_size / (2 * sizeof(void *)) - 1);
    start = start ? start : 1;

    bucket_size = hinit->bucket_size - sizeof(void *);

    for (size = start; size < hinit->max_size; size++) {

        ngx_memzero(test, size * sizeof(ngx_uint_t));

        for (n = 0; n < nelts; n++) {
            if (names[n].key.data == NULL) {
                continue;
            }

            key = names[n].key_hash % size;
            test[key] += NGX_HASH_ELT_SIZE(&names[n]);

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: %ui %ui \"%V\"",
                          size, key, test[key], &names[n].key);
#endif

            if (test[key] > bucket_size) {
                goto next;
            }
        }

        goto found;

    next:

        continue;
    }

    ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                  "could not build the %s hash, you should increase "
                  "either %s_max_size: %i or %s_bucket_size: %i",
                  hinit->name, hinit->name, hinit->max_size,
                  hinit->name, hinit->bucket_size);

    ngx_free(test);

    return NGX_ERROR;

found:

    for (i = 0; i < size; i++) {
        test[i] = sizeof(void *);
    }

    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {
            continue;
        }

        key = names[n].key_hash % size;
        test[key] += NGX_HASH_ELT_SIZE(&names[n]);
    }

    len = 0;

    for (i = 0; i < size; i++) {
        if (test[i] == sizeof(void *)) {
            continue;
        }

        test[i] = ngx_align(test[i], ngx_cacheline_size);

        len += test[i];
    }

    if (hinit->hash == NULL) {
        hinit->hash = ngx_pcalloc(hinit->pool, sizeof(ngx_hash_wildcard_t)
                                             + size * sizeof(ngx_hash_elt_t *));
        if (hinit->hash == NULL) {
            ngx_free(test);
            return NGX_ERROR;
        }

        buckets = (ngx_hash_elt_t **)
                      ((u_char *) hinit->hash + sizeof(ngx_hash_wildcard_t));

    } else {
        buckets = ngx_pcalloc(hinit->pool, size * sizeof(ngx_hash_elt_t *));
        if (buckets == NULL) {
            ngx_free(test);
            return NGX_ERROR;
        }
    }

    elts = ngx_palloc(hinit->pool, len + ngx_cacheline_size);
    if (elts == NULL) {
        ngx_free(test);
        return NGX_ERROR;
    }

    elts = ngx_align_ptr(elts, ngx_cacheline_size);

    for (i = 0; i < size; i++) {
        if (test[i] == sizeof(void *)) {
            continue;
        }

        buckets[i] = (ngx_hash_elt_t *) elts;
        elts += test[i];

    }

    for (i = 0; i < size; i++) {
        test[i] = 0;
    }

    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {
            continue;
        }

        key = names[n].key_hash % size;
        elt = (ngx_hash_elt_t *) ((u_char *) buckets[key] + test[key]);

        elt->value = names[n].value;
        elt->len = (u_char) names[n].key.len;

        for (i = 0; i < names[n].key.len; i++) {
            elt->name[i] = ngx_tolower(names[n].key.data[i]);
        }

        test[key] += NGX_HASH_ELT_SIZE(&names[n]);
    }

    for (i = 0; i < size; i++) {
        if (buckets[i] == NULL) {
            continue;
        }

        elt = (ngx_hash_elt_t *) ((u_char *) buckets[i] + test[i]);

        elt->value = NULL;
    }

    ngx_free(test);

    hinit->hash->buckets = buckets;
    hinit->hash->size = size;

#if 0

    for (i = 0; i < size; i++) {
        ngx_str_t   val;
        ngx_uint_t  key;

        elt = buckets[i];

        if (elt == NULL) {
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: NULL", i);
            continue;
        }

        while (elt->value) {
            val.len = elt->len;
            val.data = &elt->name[0];

            key = hinit->key(val.data, val.len);

            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: %p \"%V\" %ui", i, elt, &val, key);

            elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
                                                   sizeof(void *));
        }
    }

#endif

    return NGX_OK;
}


ngx_int_t
ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts)
{
    size_t                len;
    ngx_uint_t            i, n, dot;
    ngx_array_t           curr_names, next_names;
    ngx_hash_key_t       *name, *next_name;
    ngx_hash_init_t       h;
    ngx_hash_wildcard_t  *wdc;

    if (ngx_array_init(&curr_names, hinit->temp_pool, nelts,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&next_names, hinit->temp_pool, nelts,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (n = 0; n < nelts; n = i) {

#if 0
        ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                      "wc0: \"%V\"", &names[n].key);
#endif

        dot = 0;

        for (len = 0; len < names[n].key.len; len++) {
            if (names[n].key.data[len] == '.') {
                dot = 1;
                break;
            }
        }

        name = ngx_array_push(&curr_names);
        if (name == NULL) {
            return NGX_ERROR;
        }

        name->key.len = len;
        name->key.data = names[n].key.data;
        name->key_hash = hinit->key(name->key.data, name->key.len);
        name->value = names[n].value;

#if 0
        ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                      "wc1: \"%V\"", &name->key);
#endif

        if (dot) {
            len++;
        }

        next_names.nelts = 0;

        if (names[n].key.len != len) {
            next_name = ngx_array_push(&next_names);
            if (next_name == NULL) {
                return NGX_ERROR;
            }

            next_name->key.len = names[n].key.len - len;
            next_name->key.data = names[n].key.data + len;
            next_name->key_hash= 0;
            next_name->value = names[n].value;

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "wc2: \"%V\"", &next_name->key);
#endif
        }

        for (i = n + 1; i < nelts; i++) {
            if (ngx_strncmp(names[n].key.data, names[i].key.data, len) != 0) {
                break;
            }

            next_name = ngx_array_push(&next_names);
            if (next_name == NULL) {
                return NGX_ERROR;
            }

            next_name->key.len = names[i].key.len - len;
            next_name->key.data = names[i].key.data + len;
            next_name->key_hash= 0;
            next_name->value = names[i].value;

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "wc3: \"%V\"", &next_name->key);
#endif
        }

        if (next_names.nelts) {
            h = *hinit;
            h.hash = NULL;

            if (ngx_hash_wildcard_init(&h, (ngx_hash_key_t *) next_names.elts,
                                       next_names.nelts)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            wdc = (ngx_hash_wildcard_t *) h.hash;

            if (names[n].key.len == len) {
                wdc->value = names[n].value;
#if 0
                 ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                               "wdc: \"%V\"", wdc->value);
#endif
            }

            name->value = (void *) ((uintptr_t) wdc | (dot ? 1 : 3));
        }
    }

    if (ngx_hash_init(hinit, (ngx_hash_key_t *) curr_names.elts,
                      curr_names.nelts)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_uint_t
ngx_hash_key(u_char *data, size_t len)
{
    ngx_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = ngx_hash(key, data[i]);
    }

    return key;
}


ngx_uint_t
ngx_hash_key_lc(u_char *data, size_t len)
{
    ngx_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = ngx_hash(key, ngx_tolower(data[i]));
    }

    return key;
}


ngx_int_t
ngx_hash0_init(ngx_hash0_t *hash, ngx_pool_t *pool, void *names,
    ngx_uint_t nelts)
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
