#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_string.h>
#include <ngx_array.h>
#include <ngx_http.h>


typedef struct {
    in_addr_t  addr;
    int        port;
    int        family;
    ngx_str_t  file_name;
    int        line;

    unsigned   default_server:1;
} ngx_http_listen_t;


typedef enum {
    NGX_HTTP_REWRITE_PHASE = 0,
    NGX_HTTP_FIND_CONFIG_PHASE,
    NGX_HTTP_CONTENT_PHASE,
    NGX_HTTP_LAST_PHASE
} ngx_http_phases;


typedef struct {
    ngx_array_t          handlers;
    ngx_int_t            type;                /* NGX_OK, NGX_DECLINED */
} ngx_http_phase_t;


typedef struct {
    ngx_array_t       servers;         /* array of ngx_http_core_srv_conf_t */

    ngx_http_phase_t  phases[NGX_HTTP_LAST_PHASE];
    ngx_array_t       index_handlers;
} ngx_http_core_main_conf_t;


typedef struct {
    ngx_array_t  locations;    /* array of ngx_http_core_loc_conf_t,
                                  used in the translation handler
                                  and in the merge phase */

    ngx_array_t  listen;       /* 'listen', array of ngx_http_listen_t */
    ngx_array_t  server_names; /* 'server_name',
                                  array of ngx_http_server_name_t */

    ngx_http_conf_ctx_t *ctx;  /* server ctx */

    size_t       connection_pool_size;
    size_t       request_pool_size;
    size_t       client_header_buffer_size;

    ngx_msec_t   post_accept_timeout;
    ngx_msec_t   client_header_timeout;

    ngx_flag_t   large_client_header;
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */

typedef struct {
    int           port;
    ngx_str_t     port_name;
    ngx_array_t   addrs;       /* array of ngx_http_in_addr_t */
} ngx_http_in_port_t;


typedef struct {
    in_addr_t                  addr;
    ngx_array_t                names;     /* array of ngx_http_server_name_t */
    ngx_http_core_srv_conf_t  *core_srv_conf;  /* default server conf
                                                  for this address:port */

    unsigned                   default_server:1;
} ngx_http_in_addr_t;


typedef struct {
    ngx_str_t                  name;
    ngx_http_core_srv_conf_t  *core_srv_conf; /* virtual name server conf */
} ngx_http_server_name_t;


#define NGX_HTTP_TYPES_HASH_PRIME  13

#define ngx_http_types_hash_key(key, ext)                                   \
        {                                                                   \
            u_int n;                                                        \
            for (key = 0, n = 0; n < ext.len; n++) {                        \
                key += ext.data[n];                                         \
            }                                                               \
            key %= NGX_HTTP_TYPES_HASH_PRIME;                               \
        }

typedef struct {
    ngx_str_t  exten;
    ngx_str_t  type;
} ngx_http_type_t;


typedef struct {
    ngx_int_t  status;
    ngx_int_t  overwrite;
    ngx_str_t  uri;
} ngx_http_err_page_t;


typedef struct {
    ngx_str_t     name;          /* location name */
    void        **loc_conf ;     /* pointer to the modules' loc_conf */

    int         (*handler) (ngx_http_request_t *r);

    ngx_str_t     root;                    /* root, alias */

    ngx_array_t  *types;
    ngx_str_t     default_type;

    size_t        client_max_body_size;    /* client_max_body_size */
    size_t        send_lowat;              /* send_lowat */
    size_t        discarded_buffer_size;   /* discarded_buffer_size */
    size_t        client_body_buffer_size; /* client_body_buffer_size */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */

    ngx_flag_t    sendfile;                /* sendfile */
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    msie_padding;            /* msie_padding */

    ngx_array_t  *error_pages;             /* error_page */

    ngx_http_cache_hash_t  *open_files;

#if (HAVE_PCRE)
    ngx_regex_t  *regex;
#endif

    unsigned      exact_match:1;
    unsigned      auto_redirect:1;
    unsigned      alias:1;

    ngx_log_t    *err_log;
} ngx_http_core_loc_conf_t;


extern ngx_http_module_t  ngx_http_core_module_ctx;
extern ngx_module_t  ngx_http_core_module;

extern int ngx_http_max_module;



int ngx_http_find_location_config(ngx_http_request_t *r);
int ngx_http_core_translate_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
ngx_int_t ngx_http_set_exten(ngx_http_request_t *r);

int ngx_http_internal_redirect(ngx_http_request_t *r,
                               ngx_str_t *uri, ngx_str_t *args);


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
