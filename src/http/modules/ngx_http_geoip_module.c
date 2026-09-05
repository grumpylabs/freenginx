
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if (NGX_HAVE_GEOIP_LEGACY)

#include <GeoIP.h>
#include <GeoIPCity.h>

#endif

#if (NGX_HAVE_GEOIP_MMDB)

#include <maxminddb.h>

#endif


#define NGX_GEOIP_COUNTRY_CODE    0
#define NGX_GEOIP_COUNTRY_CODE3   1
#define NGX_GEOIP_COUNTRY_NAME    2
#define NGX_GEOIP_CONTINENT_CODE  3
#define NGX_GEOIP_REGION          4
#define NGX_GEOIP_REGION_NAME     5
#define NGX_GEOIP_CITY            6
#define NGX_GEOIP_POSTAL_CODE     7
#define NGX_GEOIP_LATITUDE        8
#define NGX_GEOIP_LONGITUDE       9
#define NGX_GEOIP_DMA_CODE        10
#define NGX_GEOIP_AREA_CODE       11


typedef struct {
    void         *country;
    void         *org;
    void         *city;
    ngx_array_t  *proxies;    /* array of ngx_cidr_t */
    ngx_array_t  *mmdb;       /* array of MMDB_s */
    ngx_flag_t    proxy_recursive;
    unsigned      country_v6:1;
    unsigned      country_mmdb:1;
    unsigned      org_v6:1;
    unsigned      org_mmdb:1;
    unsigned      city_v6:1;
    unsigned      city_mmdb:1;
} ngx_http_geoip_conf_t;


#if (NGX_HAVE_GEOIP_MMDB)

typedef struct {
    MMDB_s       *mmdb;
    const char  **path;
} ngx_http_geoip_variable_t;

#endif


static ngx_int_t ngx_http_geoip_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip_org_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip_city_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip_region_name_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip_city_float_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip_city_int_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#if (NGX_HAVE_GEOIP_LEGACY)
static GeoIPRecord *ngx_http_geoip_get_city_record(ngx_http_request_t *r);
#endif

#if (NGX_HAVE_GEOIP_MMDB)
static ngx_int_t ngx_http_geoip_mmdb_city_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip_mmdb_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#endif

#if (NGX_HAVE_GEOIP_LEGACY)
static u_long ngx_http_geoip_addr(ngx_http_request_t *r,
    ngx_http_geoip_conf_t *gcf);
#if (NGX_HAVE_GEOIP_V6)
static geoipv6_t ngx_http_geoip_addr_v6(ngx_http_request_t *r,
    ngx_http_geoip_conf_t *gcf);
#endif
#endif
static struct sockaddr *ngx_http_geoip_sockaddr(ngx_http_request_t *r,
    ngx_http_geoip_conf_t *gcf);

static ngx_int_t ngx_http_geoip_add_variables(ngx_conf_t *cf);
static void *ngx_http_geoip_create_conf(ngx_conf_t *cf);
static char *ngx_http_geoip_init_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_geoip_country(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip_org(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip_city(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#if (NGX_HAVE_GEOIP_MMDB)
static MMDB_s *ngx_http_geoip_mmdb_open(ngx_conf_t *cf,
    ngx_http_geoip_conf_t *gcf, ngx_str_t *file);
#endif
#if (NGX_HAVE_GEOIP_LEGACY)
static ngx_int_t ngx_http_geoip_mmdb_file(ngx_str_t *file);
#endif
static char *ngx_http_geoip_proxy(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_geoip_cidr_value(ngx_conf_t *cf, ngx_str_t *net,
    ngx_cidr_t *cidr);
static void ngx_http_geoip_cleanup(void *data);


static ngx_command_t  ngx_http_geoip_commands[] = {

    { ngx_string("geoip_country"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_geoip_country,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip_org"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_geoip_org,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip_city"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_geoip_city,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip_set"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_geoip_set,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip_proxy"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_geoip_proxy,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip_proxy_recursive"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_geoip_conf_t, proxy_recursive),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_geoip_module_ctx = {
    ngx_http_geoip_add_variables,          /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_geoip_create_conf,            /* create main configuration */
    ngx_http_geoip_init_conf,              /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_geoip_module = {
    NGX_MODULE_V1,
    &ngx_http_geoip_module_ctx,            /* module context */
    ngx_http_geoip_commands,               /* module directives */
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


static ngx_http_variable_t  ngx_http_geoip_vars[] = {

    { ngx_string("geoip_country_code"), NULL,
      ngx_http_geoip_country_variable,
      NGX_GEOIP_COUNTRY_CODE, 0, 0 },

    { ngx_string("geoip_country_code3"), NULL,
      ngx_http_geoip_country_variable,
      NGX_GEOIP_COUNTRY_CODE3, 0, 0 },

    { ngx_string("geoip_country_name"), NULL,
      ngx_http_geoip_country_variable,
      NGX_GEOIP_COUNTRY_NAME, 0, 0 },

    { ngx_string("geoip_org"), NULL,
      ngx_http_geoip_org_variable,
      0, 0, 0 },

    { ngx_string("geoip_city_continent_code"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_CONTINENT_CODE, 0, 0 },

    { ngx_string("geoip_city_country_code"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_COUNTRY_CODE, 0, 0 },

    { ngx_string("geoip_city_country_code3"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_COUNTRY_CODE3, 0, 0 },

    { ngx_string("geoip_city_country_name"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_COUNTRY_NAME, 0, 0 },

    { ngx_string("geoip_region"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_REGION, 0, 0 },

    { ngx_string("geoip_region_name"), NULL,
      ngx_http_geoip_region_name_variable,
      NGX_GEOIP_REGION_NAME, 0, 0 },

    { ngx_string("geoip_city"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_CITY, 0, 0 },

    { ngx_string("geoip_postal_code"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_POSTAL_CODE, 0, 0 },

    { ngx_string("geoip_latitude"), NULL,
      ngx_http_geoip_city_float_variable,
      NGX_GEOIP_LATITUDE, 0, 0 },

    { ngx_string("geoip_longitude"), NULL,
      ngx_http_geoip_city_float_variable,
      NGX_GEOIP_LONGITUDE, 0, 0 },

    { ngx_string("geoip_dma_code"), NULL,
      ngx_http_geoip_city_int_variable,
      NGX_GEOIP_DMA_CODE, 0, 0 },

    { ngx_string("geoip_area_code"), NULL,
      ngx_http_geoip_city_int_variable,
      NGX_GEOIP_AREA_CODE, 0, 0 },

      ngx_http_null_variable
};


#if (NGX_HAVE_GEOIP_LEGACY)

static uintptr_t  ngx_http_geoip_city_offsets[] = {
    offsetof(GeoIPRecord, country_code),
    offsetof(GeoIPRecord, country_code3),
    offsetof(GeoIPRecord, country_name),
    offsetof(GeoIPRecord, continent_code),
    offsetof(GeoIPRecord, region),
    0,                                                /* region name */
    offsetof(GeoIPRecord, city),
    offsetof(GeoIPRecord, postal_code),
    offsetof(GeoIPRecord, latitude),
    offsetof(GeoIPRecord, longitude),
    offsetof(GeoIPRecord, dma_code),
    offsetof(GeoIPRecord, area_code)
};

#endif


#if (NGX_HAVE_GEOIP_MMDB)

static const char  *ngx_http_geoip_mmdb_paths[][5] = {
    { "country", "iso_code", NULL, NULL, NULL },
    { NULL, NULL, NULL, NULL, NULL },                 /* country code3 */
    { "country", "names", "en", NULL, NULL },
    { "continent", "code", NULL, NULL, NULL },
    { "subdivisions", "0", "iso_code", NULL, NULL },
    { "subdivisions", "0", "names", "en", NULL },
    { "city", "names", "en", NULL, NULL },
    { "postal", "code", NULL, NULL, NULL },
    { "location", "latitude", NULL, NULL, NULL },
    { "location", "longitude", NULL, NULL, NULL },
    { "location", "metro_code", NULL, NULL, NULL },
    { NULL, NULL, NULL, NULL, NULL }                  /* area code */
};

#endif


static ngx_int_t
ngx_http_geoip_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_GEOIP_LEGACY)
    const char             *val;
#endif
    ngx_http_geoip_conf_t  *gcf;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

    if (gcf->country == NULL) {
        goto not_found;
    }

#if (NGX_HAVE_GEOIP_MMDB)

    if (gcf->country_mmdb) {
        ngx_http_geoip_variable_t  gv;

        gv.mmdb = gcf->country;
        gv.path = ngx_http_geoip_mmdb_paths[data];

        return ngx_http_geoip_mmdb_variable(r, v, (uintptr_t) &gv);
    }

#endif

#if (NGX_HAVE_GEOIP_LEGACY)

#if (NGX_HAVE_GEOIP_V6)
    if (gcf->country_v6) {
        if (data == NGX_GEOIP_COUNTRY_CODE) {
            val = GeoIP_country_code_by_ipnum_v6(gcf->country,
                                               ngx_http_geoip_addr_v6(r, gcf));

        } else if (data == NGX_GEOIP_COUNTRY_CODE3) {
            val = GeoIP_country_code3_by_ipnum_v6(gcf->country,
                                               ngx_http_geoip_addr_v6(r, gcf));

        } else { /* NGX_GEOIP_COUNTRY_NAME */
            val = GeoIP_country_name_by_ipnum_v6(gcf->country,
                                               ngx_http_geoip_addr_v6(r, gcf));
        }
    } else
#endif
    {
        if (data == NGX_GEOIP_COUNTRY_CODE) {
            val = GeoIP_country_code_by_ipnum(gcf->country,
                                              ngx_http_geoip_addr(r, gcf));

        } else if (data == NGX_GEOIP_COUNTRY_CODE3) {
            val = GeoIP_country_code3_by_ipnum(gcf->country,
                                               ngx_http_geoip_addr(r, gcf));

        } else { /* NGX_GEOIP_COUNTRY_NAME */
            val = GeoIP_country_name_by_ipnum(gcf->country,
                                              ngx_http_geoip_addr(r, gcf));
        }
    }

    if (val == NULL) {
        goto not_found;
    }

    v->len = ngx_strlen(val);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) val;

    return NGX_OK;

#endif

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_org_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_GEOIP_LEGACY)
    size_t                  len;
    char                   *val;
#endif
    ngx_http_geoip_conf_t  *gcf;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

    if (gcf->org == NULL) {
        goto not_found;
    }

#if (NGX_HAVE_GEOIP_MMDB)

    if (gcf->org_mmdb) {
        ngx_int_t                  rc;
        ngx_http_geoip_variable_t  gv;

        static const char *org[] = { "organization", NULL };
        static const char *asorg[] = { "autonomous_system_organization", NULL };

        gv.mmdb = gcf->org;
        gv.path = org;

        rc = ngx_http_geoip_mmdb_variable(r, v, (uintptr_t) &gv);

        if (rc == NGX_OK && v->not_found) {
            gv.path = asorg;
            rc = ngx_http_geoip_mmdb_variable(r, v, (uintptr_t) &gv);
        }

        return rc;
    }

#endif

#if (NGX_HAVE_GEOIP_LEGACY)

#if (NGX_HAVE_GEOIP_V6)
    if (gcf->org_v6) {
        val = GeoIP_name_by_ipnum_v6(gcf->org, ngx_http_geoip_addr_v6(r, gcf));

    } else
#endif
    {
        val = GeoIP_name_by_ipnum(gcf->org, ngx_http_geoip_addr(r, gcf));
    }

    if (val == NULL) {
        goto not_found;
    }

    len = ngx_strlen(val);
    v->data = ngx_pnalloc(r->pool, len);
    if (v->data == NULL) {
        ngx_free(val);
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_free(val);

    return NGX_OK;

#endif

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_city_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_GEOIP_LEGACY)
    char         *val;
    size_t        len;
    GeoIPRecord  *gr;
#endif

#if (NGX_HAVE_GEOIP_MMDB)

    ngx_int_t  rc;

    rc = ngx_http_geoip_mmdb_city_variable(r, v, data);

    if (rc != NGX_DECLINED) {
        return rc;
    }

#endif

#if (NGX_HAVE_GEOIP_LEGACY)

    gr = ngx_http_geoip_get_city_record(r);
    if (gr == NULL) {
        goto not_found;
    }

    val = *(char **) ((char *) gr + ngx_http_geoip_city_offsets[data]);
    if (val == NULL) {
        goto no_value;
    }

    len = ngx_strlen(val);
    v->data = ngx_pnalloc(r->pool, len);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return NGX_OK;

no_value:

    GeoIPRecord_delete(gr);

not_found:

#endif

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_region_name_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_GEOIP_LEGACY)
    size_t        len;
    const char   *val;
    GeoIPRecord  *gr;
#endif

#if (NGX_HAVE_GEOIP_MMDB)

    ngx_int_t  rc;

    rc = ngx_http_geoip_mmdb_city_variable(r, v, data);

    if (rc != NGX_DECLINED) {
        return rc;
    }

#endif

#if (NGX_HAVE_GEOIP_LEGACY)

    gr = ngx_http_geoip_get_city_record(r);
    if (gr == NULL) {
        goto not_found;
    }

    val = GeoIP_region_name_by_code(gr->country_code, gr->region);

    GeoIPRecord_delete(gr);

    if (val == NULL) {
        goto not_found;
    }

    len = ngx_strlen(val);
    v->data = ngx_pnalloc(r->pool, len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

#endif

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_city_float_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_GEOIP_LEGACY)
    float         val;
    GeoIPRecord  *gr;
#endif

#if (NGX_HAVE_GEOIP_MMDB)

    ngx_int_t  rc;

    rc = ngx_http_geoip_mmdb_city_variable(r, v, data);

    if (rc != NGX_DECLINED) {
        return rc;
    }

#endif

#if (NGX_HAVE_GEOIP_LEGACY)

    gr = ngx_http_geoip_get_city_record(r);
    if (gr == NULL) {
        goto not_found;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN + 5);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return NGX_ERROR;
    }

    val = *(float *) ((char *) gr + ngx_http_geoip_city_offsets[data]);

    v->len = ngx_sprintf(v->data, "%.4f", val) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return NGX_OK;

not_found:

#endif

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_city_int_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_GEOIP_LEGACY)
    int           val;
    GeoIPRecord  *gr;
#endif

#if (NGX_HAVE_GEOIP_MMDB)

    ngx_int_t  rc;

    rc = ngx_http_geoip_mmdb_city_variable(r, v, data);

    if (rc != NGX_DECLINED) {
        return rc;
    }

#endif

#if (NGX_HAVE_GEOIP_LEGACY)

    gr = ngx_http_geoip_get_city_record(r);
    if (gr == NULL) {
        goto not_found;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return NGX_ERROR;
    }

    val = *(int *) ((char *) gr + ngx_http_geoip_city_offsets[data]);

    v->len = ngx_sprintf(v->data, "%d", val) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return NGX_OK;

not_found:

#endif

    v->not_found = 1;

    return NGX_OK;
}


#if (NGX_HAVE_GEOIP_LEGACY)

static GeoIPRecord *
ngx_http_geoip_get_city_record(ngx_http_request_t *r)
{
    ngx_http_geoip_conf_t  *gcf;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

    if (gcf->city) {
#if (NGX_HAVE_GEOIP_V6)
        if (gcf->city_v6) {
            return GeoIP_record_by_ipnum_v6(gcf->city,
                                            ngx_http_geoip_addr_v6(r, gcf));
        }
#endif
        return GeoIP_record_by_ipnum(gcf->city, ngx_http_geoip_addr(r, gcf));
    }

    return NULL;
}

#endif


#if (NGX_HAVE_GEOIP_MMDB)

static ngx_int_t
ngx_http_geoip_mmdb_city_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_geoip_conf_t      *gcf;
    ngx_http_geoip_variable_t   gv;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

    if (!gcf->city_mmdb) {
        return NGX_DECLINED;
    }

    gv.mmdb = gcf->city;
    gv.path = ngx_http_geoip_mmdb_paths[data];

    return ngx_http_geoip_mmdb_variable(r, v, (uintptr_t) &gv);
}


static ngx_int_t
ngx_http_geoip_mmdb_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_geoip_variable_t *gv = (ngx_http_geoip_variable_t *) data;

    int                     status;
    struct sockaddr        *sockaddr;
    MMDB_entry_data_s       entry;
    MMDB_lookup_result_s    result;
    ngx_http_geoip_conf_t  *gcf;

    if (gv->path[0] == NULL) {
        goto not_found;
    }

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

    sockaddr = ngx_http_geoip_sockaddr(r, gcf);

    if (sockaddr->sa_family != AF_INET
#if (NGX_HAVE_INET6)
        && sockaddr->sa_family != AF_INET6
#endif
        )
    {
        goto not_found;
    }

    result = MMDB_lookup_sockaddr(gv->mmdb, sockaddr, &status);

    if (status != MMDB_SUCCESS) {
        if (status == MMDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR) {
            goto not_found;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "MMDB_lookup_sockaddr() failed: %s",
                      MMDB_strerror(status));
        return NGX_ERROR;
    }

    if (!result.found_entry) {
        goto not_found;
    }

    status = MMDB_aget_value(&result.entry, &entry, gv->path);

    if (status != MMDB_SUCCESS) {
        if (status == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
            goto not_found;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "MMDB_aget_value() failed: %s",
                      MMDB_strerror(status));
        return NGX_ERROR;
    }

    if (!entry.has_data) {
        goto not_found;
    }

    if (entry.type == MMDB_DATA_TYPE_UTF8_STRING) {
        v->len = entry.data_size;
        v->data = (u_char *) entry.utf8_string;

    } else if (entry.type == MMDB_DATA_TYPE_BYTES) {
        v->len = entry.data_size;
        v->data = (u_char *) entry.bytes;

    } else if (entry.type == MMDB_DATA_TYPE_DOUBLE
               || entry.type == MMDB_DATA_TYPE_FLOAT)
    {
        v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN + 5);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        if (entry.type == MMDB_DATA_TYPE_DOUBLE) {
            v->len = ngx_sprintf(v->data, "%.4f", entry.double_value)
                     - v->data;

        } else { /* MMDB_DATA_TYPE_FLOAT */
            v->len = ngx_sprintf(v->data, "%.4f", (double) entry.float_value)
                     - v->data;
        }

    } else if (entry.type == MMDB_DATA_TYPE_INT32
               || entry.type == MMDB_DATA_TYPE_UINT16
               || entry.type == MMDB_DATA_TYPE_UINT32
               || entry.type == MMDB_DATA_TYPE_UINT64
               || entry.type == MMDB_DATA_TYPE_BOOLEAN)
    {
        v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        if (entry.type == MMDB_DATA_TYPE_INT32) {
            v->len = ngx_sprintf(v->data, "%D", entry.int32) - v->data;

        } else if (entry.type == MMDB_DATA_TYPE_UINT16) {
            v->len = ngx_sprintf(v->data, "%uD", (uint32_t) entry.uint16)
                     - v->data;

        } else if (entry.type == MMDB_DATA_TYPE_UINT32) {
            v->len = ngx_sprintf(v->data, "%uD", entry.uint32) - v->data;

        } else if (entry.type == MMDB_DATA_TYPE_UINT64) {
            v->len = ngx_sprintf(v->data, "%uL", entry.uint64) - v->data;

        } else { /* MMDB_DATA_TYPE_BOOLEAN */
            v->len = ngx_sprintf(v->data, "%uD", (uint32_t) entry.boolean)
                     - v->data;
        }

    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "MMDB_aget_value(): unexpected entry type, %d",
                       entry.type);
        goto not_found;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}

#endif


#if (NGX_HAVE_GEOIP_LEGACY)

static u_long
ngx_http_geoip_addr(ngx_http_request_t *r, ngx_http_geoip_conf_t *gcf)
{
    struct sockaddr     *sockaddr;
    struct sockaddr_in  *sin;

    sockaddr = ngx_http_geoip_sockaddr(r, gcf);

#if (NGX_HAVE_INET6)

    if (sockaddr->sa_family == AF_INET6) {
        u_char           *p;
        in_addr_t         inaddr;
        struct in6_addr  *inaddr6;

        inaddr6 = &((struct sockaddr_in6 *) sockaddr)->sin6_addr;

        if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
            p = inaddr6->s6_addr;

            inaddr = (in_addr_t) p[12] << 24;
            inaddr += p[13] << 16;
            inaddr += p[14] << 8;
            inaddr += p[15];

            return inaddr;
        }
    }

#endif

    if (sockaddr->sa_family != AF_INET) {
        return INADDR_NONE;
    }

    sin = (struct sockaddr_in *) sockaddr;
    return ntohl(sin->sin_addr.s_addr);
}


#if (NGX_HAVE_GEOIP_V6)

static geoipv6_t
ngx_http_geoip_addr_v6(ngx_http_request_t *r, ngx_http_geoip_conf_t *gcf)
{
    in_addr_t             addr4;
    struct in6_addr       addr6;
    struct sockaddr      *sockaddr;
    struct sockaddr_in   *sin;
    struct sockaddr_in6  *sin6;

    sockaddr = ngx_http_geoip_sockaddr(r, gcf);

    switch (sockaddr->sa_family) {

    case AF_INET:
        /* Produce IPv4-mapped IPv6 address. */
        sin = (struct sockaddr_in *) sockaddr;
        addr4 = ntohl(sin->sin_addr.s_addr);

        ngx_memzero(&addr6, sizeof(struct in6_addr));
        addr6.s6_addr[10] = 0xff;
        addr6.s6_addr[11] = 0xff;
        addr6.s6_addr[12] = addr4 >> 24;
        addr6.s6_addr[13] = addr4 >> 16;
        addr6.s6_addr[14] = addr4 >> 8;
        addr6.s6_addr[15] = addr4;
        return addr6;

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sockaddr;
        return sin6->sin6_addr;

    default:
        return in6addr_any;
    }
}

#endif
#endif


static struct sockaddr *
ngx_http_geoip_sockaddr(ngx_http_request_t *r, ngx_http_geoip_conf_t *gcf)
{
    ngx_addr_t        addr;
    ngx_table_elt_t  *xfwd;

    addr.sockaddr = r->connection->sockaddr;
    addr.socklen = r->connection->socklen;
    /* addr.name = r->connection->addr_text; */

    xfwd = r->headers_in.x_forwarded_for;

    if (xfwd != NULL && gcf->proxies != NULL) {
        (void) ngx_http_get_forwarded_addr(r, &addr, xfwd, NULL,
                                           gcf->proxies, gcf->proxy_recursive);
    }

    return addr.sockaddr;
}


static ngx_int_t
ngx_http_geoip_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_geoip_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_geoip_create_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t     *cln;
    ngx_http_geoip_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_geoip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->proxy_recursive = NGX_CONF_UNSET;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_geoip_cleanup;
    cln->data = conf;

    return conf;
}


static char *
ngx_http_geoip_init_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_geoip_conf_t  *gcf = conf;

    ngx_conf_init_value(gcf->proxy_recursive, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_geoip_country(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip_conf_t  *gcf = conf;

    ngx_str_t  *value;

    if (gcf->country) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_GEOIP_MMDB)

#if (NGX_HAVE_GEOIP_LEGACY)

    if (ngx_http_geoip_mmdb_file(&value[1]) != NGX_OK) {
        goto legacy;
    }

#endif

    gcf->country = ngx_http_geoip_mmdb_open(cf, gcf, &value[1]);

    if (gcf->country == NULL) {
        return NGX_CONF_ERROR;
    }

    gcf->country_mmdb = 1;

    if (cf->args->nelts == 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

#endif

#if (NGX_HAVE_GEOIP_LEGACY)

#if (NGX_HAVE_GEOIP_MMDB)

legacy:

#else

    if (ngx_http_geoip_mmdb_file(&value[1]) == NGX_OK) {
        return "does not support mmdb databases on this platform";
    }

#endif

    gcf->country = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->country == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->country, GEOIP_CHARSET_UTF8);

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    switch (((GeoIP *) gcf->country)->databaseType) {

    case GEOIP_COUNTRY_EDITION:

        return NGX_CONF_OK;

#if (NGX_HAVE_GEOIP_V6)
    case GEOIP_COUNTRY_EDITION_V6:

        gcf->country_v6 = 1;
        return NGX_CONF_OK;
#endif

    default:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid GeoIP database \"%V\" type:%d",
                           &value[1], ((GeoIP *) gcf->country)->databaseType);
        return NGX_CONF_ERROR;
    }

#endif
}


static char *
ngx_http_geoip_org(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip_conf_t  *gcf = conf;

    ngx_str_t  *value;

    if (gcf->org) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_GEOIP_MMDB)

#if (NGX_HAVE_GEOIP_LEGACY)

    if (ngx_http_geoip_mmdb_file(&value[1]) != NGX_OK) {
        goto legacy;
    }

#endif

    gcf->org = ngx_http_geoip_mmdb_open(cf, gcf, &value[1]);

    if (gcf->org == NULL) {
        return NGX_CONF_ERROR;
    }

    gcf->org_mmdb = 1;

    if (cf->args->nelts == 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

#endif

#if (NGX_HAVE_GEOIP_LEGACY)

#if (NGX_HAVE_GEOIP_MMDB)

legacy:

#else

    if (ngx_http_geoip_mmdb_file(&value[1]) == NGX_OK) {
        return "does not support mmdb databases on this platform";
    }

#endif

    gcf->org = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->org == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->org, GEOIP_CHARSET_UTF8);

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    switch (((GeoIP *) gcf->org)->databaseType) {

    case GEOIP_ISP_EDITION:
    case GEOIP_ORG_EDITION:
    case GEOIP_DOMAIN_EDITION:
    case GEOIP_ASNUM_EDITION:

        return NGX_CONF_OK;

#if (NGX_HAVE_GEOIP_V6)
    case GEOIP_ISP_EDITION_V6:
    case GEOIP_ORG_EDITION_V6:
    case GEOIP_DOMAIN_EDITION_V6:
    case GEOIP_ASNUM_EDITION_V6:

        gcf->org_v6 = 1;
        return NGX_CONF_OK;
#endif

    default:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid GeoIP database \"%V\" type:%d",
                           &value[1], ((GeoIP *) gcf->org)->databaseType);
        return NGX_CONF_ERROR;
    }

#endif
}


static char *
ngx_http_geoip_city(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip_conf_t  *gcf = conf;

    ngx_str_t  *value;

    if (gcf->city) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_GEOIP_MMDB)

#if (NGX_HAVE_GEOIP_LEGACY)

    if (ngx_http_geoip_mmdb_file(&value[1]) != NGX_OK) {
        goto legacy;
    }

#endif

    gcf->city = ngx_http_geoip_mmdb_open(cf, gcf, &value[1]);

    if (gcf->city == NULL) {
        return NGX_CONF_ERROR;
    }

    gcf->city_mmdb = 1;

    if (cf->args->nelts == 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

#endif

#if (NGX_HAVE_GEOIP_LEGACY)

#if (NGX_HAVE_GEOIP_MMDB)

legacy:

#else

    if (ngx_http_geoip_mmdb_file(&value[1]) == NGX_OK) {
        return "does not support mmdb databases on this platform";
    }

#endif

    gcf->city = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->city == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->city, GEOIP_CHARSET_UTF8);

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    switch (((GeoIP *) gcf->city)->databaseType) {

    case GEOIP_CITY_EDITION_REV0:
    case GEOIP_CITY_EDITION_REV1:

        return NGX_CONF_OK;

#if (NGX_HAVE_GEOIP_V6)
    case GEOIP_CITY_EDITION_REV0_V6:
    case GEOIP_CITY_EDITION_REV1_V6:

        gcf->city_v6 = 1;
        return NGX_CONF_OK;
#endif

    default:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid GeoIP City database \"%V\" type:%d",
                           &value[1], ((GeoIP *) gcf->city)->databaseType);
        return NGX_CONF_ERROR;
    }

#endif
}


static char *
ngx_http_geoip_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (NGX_HAVE_GEOIP_MMDB)

    ngx_http_geoip_conf_t  *gcf = conf;

    u_char                     *key;
    ngx_str_t                  *value;
    ngx_uint_t                  i, n;
    ngx_http_variable_t        *v;
    ngx_http_geoip_variable_t  *gv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    gv = ngx_palloc(cf->pool, sizeof(ngx_http_geoip_variable_t));
    if (gv == NULL) {
        return NGX_CONF_ERROR;
    }

    v->get_handler = ngx_http_geoip_mmdb_variable;
    v->data = (uintptr_t) gv;

    /* database file name */

    if (ngx_conf_full_name(cf->cycle, &value[2], 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    gv->mmdb = ngx_http_geoip_mmdb_open(cf, gcf, &value[2]);

    if (gv->mmdb == NULL) {
        return NGX_CONF_ERROR;
    }

    /* data path specification */

    n = 0;
    for (i = 0; i < value[3].len; i++) {
        if (value[3].data[i] == '.') {
            n++;
        }
    }

    gv->path = ngx_pcalloc(cf->pool, (n + 2) * sizeof(char *));
    if (gv->path == NULL) {
        return NGX_CONF_ERROR;
    }

    n = 0;
    key = &value[3].data[0];

    for (i = 0; i < value[3].len; i++) {
        if (value[3].data[i] != '.') {
            continue;
        }

        value[3].data[i] = '\0';
        gv->path[n++] = (char *) key;
        key = &value[3].data[i + 1];
    }

    gv->path[n++] = (char *) key;
    gv->path[n] = NULL;

    return NGX_CONF_OK;

#else
    return "is not supported on this platform";
#endif
}


#if (NGX_HAVE_GEOIP_MMDB)

static MMDB_s *
ngx_http_geoip_mmdb_open(ngx_conf_t *cf, ngx_http_geoip_conf_t *gcf,
    ngx_str_t *file)
{
    int          status;
    MMDB_s      *mmdb;
    ngx_uint_t   i;

    if (gcf->mmdb == NULL) {
        gcf->mmdb = ngx_array_create(cf->pool, 1, sizeof(MMDB_s));
        if (gcf->mmdb == NULL) {
            return NULL;
        }
    }

    mmdb = gcf->mmdb->elts;
    for (i = 0; i < gcf->mmdb->nelts; i++) {
        if (ngx_strcmp(mmdb[i].filename, file->data) == 0) {
            return &mmdb[i];
        }
    }

    mmdb = ngx_array_push(gcf->mmdb);
    if (mmdb == NULL) {
        return NULL;
    }

    status = MMDB_open((char *) file->data, 0, mmdb);

    if (status != MMDB_SUCCESS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf,
                           (status == MMDB_IO_ERROR) ? ngx_errno : 0,
                           "MMDB_open(\"%V\") failed: %s",
                           file, MMDB_strerror(status));

        gcf->mmdb->nelts--;

        return NULL;
    }

    return mmdb;
}

#endif


#if (NGX_HAVE_GEOIP_LEGACY)

static ngx_int_t
ngx_http_geoip_mmdb_file(ngx_str_t *file)
{
    if (file->len < sizeof(".mmdb") - 1
        || ngx_strncasecmp(file->data + file->len - (sizeof(".mmdb") - 1),
                           (u_char *) ".mmdb", sizeof(".mmdb") - 1)
           != 0)
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

#endif


static char *
ngx_http_geoip_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip_conf_t  *gcf = conf;

    ngx_str_t   *value;
    ngx_cidr_t  cidr, *c;

    value = cf->args->elts;

    if (ngx_http_geoip_cidr_value(cf, &value[1], &cidr) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (gcf->proxies == NULL) {
        gcf->proxies = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
        if (gcf->proxies == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    c = ngx_array_push(gcf->proxies);
    if (c == NULL) {
        return NGX_CONF_ERROR;
    }

    *c = cidr;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_geoip_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr)
{
    ngx_int_t  rc;

    if (ngx_strcmp(net->data, "255.255.255.255") == 0) {
        cidr->family = AF_INET;
        cidr->u.in.addr = 0xffffffff;
        cidr->u.in.mask = 0xffffffff;

        return NGX_OK;
    }

    rc = ngx_ptocidr(net, cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid network \"%V\"", net);
        return NGX_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", net);
    }

    return NGX_OK;
}


static void
ngx_http_geoip_cleanup(void *data)
{
    ngx_http_geoip_conf_t  *gcf = data;

#if (NGX_HAVE_GEOIP_LEGACY)

    if (gcf->country && !gcf->country_mmdb) {
        GeoIP_delete(gcf->country);
    }

    if (gcf->org && !gcf->org_mmdb) {
        GeoIP_delete(gcf->org);
    }

    if (gcf->city && !gcf->city_mmdb) {
        GeoIP_delete(gcf->city);
    }

#endif

#if (NGX_HAVE_GEOIP_MMDB)

    if (gcf->mmdb) {
        MMDB_s      *mmdb;
        ngx_uint_t   i;

        mmdb = gcf->mmdb->elts;
        for (i = 0; i < gcf->mmdb->nelts; i++) {
            MMDB_close(&mmdb[i]);
        }
    }

#endif
}
