#ifndef _NGX_HTTP_CONFIG_H_INCLUDED_
#define _NGX_HTTP_CONFIG_H_INCLUDED_


#include <ngx_alloc.h>
#include <ngx_http.h>


typedef struct {
    void   **main_conf;
    void   **srv_conf;
    void   **loc_conf;
} ngx_http_conf_ctx_t;


typedef struct {
    int    (*output_header_filter) (ngx_http_request_t *r);
    int    (*output_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);
} ngx_http_conf_filter_t;


typedef struct {
    int    (*pre_conf)(ngx_conf_t *cf);

    void  *(*create_main_conf)(ngx_conf_t *cf);
    char  *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void  *(*create_srv_conf)(ngx_conf_t *cf);
    char  *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);

    void  *(*create_loc_conf)(ngx_conf_t *cf);
    char  *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_http_module_t;


#define NGX_HTTP_MODULE           0x50545448   /* "HTTP" */

#define NGX_HTTP_MAIN_CONF        0x2000000
#define NGX_HTTP_SRV_CONF         0x4000000
#define NGX_HTTP_LOC_CONF         0x8000000


#define NGX_HTTP_MAIN_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, main_conf)
#define NGX_HTTP_SRV_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, srv_conf)
#define NGX_HTTP_LOC_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, loc_conf)


#define ngx_http_get_module_main_conf(r, module) r->main_conf[module.ctx_index]
#define ngx_http_get_module_srv_conf(r, module)  r->srv_conf[module.ctx_index]
#define ngx_http_get_module_loc_conf(r, module)  r->loc_conf[module.ctx_index]

#define ngx_http_conf_module_main_conf(cf, module)                            \
            ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]


extern int (*ngx_http_top_header_filter) (ngx_http_request_t *r);


#endif /* _NGX_HTTP_CONFIG_H_INCLUDED_ */
