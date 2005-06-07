
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_string.h>
#include <ngx_array.h>
#include <ngx_http.h>


typedef struct {
    in_addr_t                  addr;
    in_port_t                  port;
    int                        family;
    ngx_str_t                  file_name;
    ngx_int_t                  line;

    ngx_uint_t                 default_server; /* unsigned  default_server:1; */
} ngx_http_listen_t;


typedef enum {
    NGX_HTTP_FIND_CONFIG_PHASE = 0,

    NGX_HTTP_REWRITE_PHASE,

    NGX_HTTP_ACCESS_PHASE,
    NGX_HTTP_CONTENT_PHASE,

    NGX_HTTP_LAST_PHASE
} ngx_http_phases;


typedef struct {
    ngx_array_t                handlers;
    ngx_int_t                  type;                /* NGX_OK, NGX_DECLINED */
} ngx_http_phase_t;


typedef struct {
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */

    ngx_http_phase_t           phases[NGX_HTTP_LAST_PHASE];
    ngx_array_t                index_handlers;

    ngx_hash_t                 headers_in_hash;
    ngx_hash_t                 variables_hash;

    ngx_uint_t                 server_names_hash;
    ngx_uint_t                 server_names_hash_threshold;

    size_t                     max_server_name_len;

    ngx_array_t                variables;        /* ngx_http_variable_t */
    ngx_array_t                all_variables;    /* ngx_http_variable_t */
} ngx_http_core_main_conf_t;


typedef struct {
    /*
     * array of the ngx_http_core_loc_conf_t,
     * used in the translation handler and in the merge phase
     */
    ngx_array_t                locations;

    /* array of the ngx_http_listen_t, "listen" directive */
    ngx_array_t                listen;

    /* array of the ngx_http_server_name_t, "server_name" directive */
    ngx_array_t                server_names;

    /* server ctx */
    ngx_http_conf_ctx_t       *ctx;

    size_t                     connection_pool_size;
    size_t                     request_pool_size;
    size_t                     client_header_buffer_size;

    ngx_bufs_t                 large_client_header_buffers;

    ngx_msec_t                 post_accept_timeout;
    ngx_msec_t                 client_header_timeout;

    ngx_uint_t                 restrict_host_names;

    ngx_flag_t                 ignore_invalid_headers;
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */

typedef struct {
    in_port_t                  port;
    ngx_str_t                  port_text;
    ngx_array_t                addrs;       /* array of ngx_http_in_addr_t */
} ngx_http_in_port_t;


struct ngx_http_in_addr_s {
    in_addr_t                  addr;

    ngx_array_t                names;     /* array of ngx_http_server_name_t */
    ngx_array_t               *hash;      /* hash of ngx_http_server_name_t */
    ngx_array_t                wildcards;  /* array of ngx_http_server_name_t */

    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *core_srv_conf;

    ngx_uint_t                 default_server; /* unsigned  default_server:1; */
};


typedef struct {
    ngx_str_t                  name;
    ngx_http_core_srv_conf_t  *core_srv_conf; /* virtual name server conf */

    ngx_uint_t                 wildcard;  /* unsigned  wildcard:1 */
} ngx_http_server_name_t;


#define ngx_http_server_names_hash_key(key, name, len, prime)               \
        {                                                                   \
            ngx_uint_t  n;                                                  \
            for (key = 0, n = 0; n < len; n++) {                            \
                key += name[n];                                             \
            }                                                               \
            key %= prime;                                                   \
        }


#define NGX_HTTP_TYPES_HASH_PRIME  13

#define ngx_http_types_hash_key(key, ext)                                   \
        {                                                                   \
            ngx_uint_t  n;                                                  \
            for (key = 0, n = 0; n < ext.len; n++) {                        \
                key += ext.data[n];                                         \
            }                                                               \
            key %= NGX_HTTP_TYPES_HASH_PRIME;                               \
        }

typedef struct {
    ngx_str_t     exten;
    ngx_str_t     type;
} ngx_http_type_t;


typedef struct {
    ngx_int_t     status;
    ngx_int_t     overwrite;
    ngx_str_t     uri;
} ngx_http_err_page_t;


typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;

struct ngx_http_core_loc_conf_s {
    ngx_str_t     name;          /* location name */

#if (NGX_PCRE)
    ngx_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block */

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
    unsigned      alias:1;

    /* array of inclusive ngx_http_core_loc_conf_t */
    ngx_array_t   locations;

    /* pointer to the modules' loc_conf */
    void        **loc_conf ;

    ngx_http_handler_pt  handler;

    ngx_str_t     root;                    /* root, alias */

    ngx_array_t  *types;
    ngx_str_t     default_type;

    size_t        client_max_body_size;    /* client_max_body_size */
    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        limit_rate;              /* limit_rate */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */

    time_t        keepalive_header;        /* keepalive_timeout */

    ngx_flag_t    internal;                /* internal */
    ngx_flag_t    sendfile;                /* sendfile */
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */

    ngx_array_t  *error_pages;             /* error_page */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */

    ngx_http_cache_hash_t  *open_files;

    ngx_log_t    *err_log;

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};



extern ngx_http_module_t  ngx_http_core_module_ctx;
extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;



ngx_int_t ngx_http_find_location_config(ngx_http_request_t *r);

ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
ngx_int_t ngx_http_set_exten(ngx_http_request_t *r);

ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);


typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);
typedef ngx_int_t (*ngx_http_output_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
