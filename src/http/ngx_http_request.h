
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#define NGX_HTTP_MAX_REWRITE_CYCLES        10


#define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
#define NGX_HTTP_LINGERING_BUFFER_SIZE     4096


#define NGX_HTTP_VERSION_9                 9
#define NGX_HTTP_VERSION_10                1000
#define NGX_HTTP_VERSION_11                1001

#define NGX_HTTP_GET                       1
#define NGX_HTTP_HEAD                      2
#define NGX_HTTP_POST                      3

#define NGX_HTTP_CONNECTION_CLOSE          1
#define NGX_HTTP_CONNECTION_KEEP_ALIVE     2


#define NGX_NONE                           1


#define NGX_HTTP_PARSE_HEADER_DONE         1

#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARSE_INVALID_09_METHOD   12

#define NGX_HTTP_PARSE_HEADER_ERROR        13
#define NGX_HTTP_PARSE_INVALID_HEADER      13


#define NGX_HTTP_OK                        200
#define NGX_HTTP_NO_CONTENT                204
#define NGX_HTTP_PARTIAL_CONTENT           206

#define NGX_HTTP_SPECIAL_RESPONSE          300
#define NGX_HTTP_MOVED_PERMANENTLY         301
#define NGX_HTTP_MOVED_TEMPORARILY         302
#define NGX_HTTP_NOT_MODIFIED              304

#define NGX_HTTP_BAD_REQUEST               400
#define NGX_HTTP_UNAUTHORIZED              401
#define NGX_HTTP_FORBIDDEN                 403
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_NOT_ALLOWED               405
#define NGX_HTTP_REQUEST_TIME_OUT          408
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
#define NGX_HTTP_RANGE_NOT_SATISFIABLE     416


/* Our own HTTP codes */

#define NGX_HTTP_NGX_CODES                 NGX_HTTP_TO_HTTPS

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection 
 */
#define NGX_HTTP_TO_HTTPS                  497

/*
 * We use the special code for the requests with invalid host name
 * to distinguish it from 4XX in an error page redirection 
 */
#define NGX_HTTP_INVALID_HOST              498

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NGX_HTTP_CLIENT_CLOSED_REQUEST     499


#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_NOT_IMPLEMENTED           501
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_SERVICE_UNAVAILABLE       503
#define NGX_HTTP_GATEWAY_TIME_OUT          504


typedef enum {
    NGX_HTTP_RESTRICT_HOST_OFF = 0,
    NGX_HTTP_RESTRICT_HOST_ON,
    NGX_HTTP_RESTRICT_HOST_CLOSE
} ngx_http_restrict_host_e;


typedef enum {
    NGX_HTTP_INITING_REQUEST_STATE = 0,
    NGX_HTTP_READING_REQUEST_STATE,
    NGX_HTTP_PROCESS_REQUEST_STATE,

    NGX_HTTP_CONNECT_UPSTREAM_STATE,
    NGX_HTTP_WRITING_UPSTREAM_STATE,
    NGX_HTTP_READING_UPSTREAM_STATE,

    NGX_HTTP_WRITING_REQUEST_STATE,
    NGX_HTTP_LINGERING_CLOSE_STATE,
    NGX_HTTP_KEEPALIVE_STATE
} ngx_http_state_e;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
    ngx_http_header_handler_pt        handler;
} ngx_http_header_t;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
} ngx_http_header0_t;


typedef struct {
    ngx_list_t                        headers;

    ngx_table_elt_t                  *host;
    ngx_table_elt_t                  *connection;
    ngx_table_elt_t                  *if_modified_since;
    ngx_table_elt_t                  *user_agent;
    ngx_table_elt_t                  *referer;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_type;

    ngx_table_elt_t                  *range;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                  *accept_encoding;
    ngx_table_elt_t                  *via;
#endif

    ngx_table_elt_t                  *authorization;

    ngx_table_elt_t                  *keep_alive;

#if (NGX_HTTP_PROXY)
    ngx_table_elt_t                  *x_forwarded_for;
    ngx_table_elt_t                  *x_real_ip;
    ngx_table_elt_t                  *x_url;
#endif

#if (NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept;
    ngx_table_elt_t                  *accept_language;
#endif

    ngx_str_t                         user;
    ngx_str_t                         passwd;

    ngx_array_t                       cookies;

    size_t                            host_name_len;
    ssize_t                           content_length_n;
    time_t                            keep_alive_n;

    unsigned                          connection_type:2;
    unsigned                          msie:1;
    unsigned                          msie4:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          konqueror:1;
} ngx_http_headers_in_t;


typedef struct {
    off_t                             start;
    off_t                             end;
    ngx_str_t                         content_range;
} ngx_http_range_t;


typedef struct {
    ngx_list_t                        headers;

    ngx_uint_t                        status;
    ngx_str_t                         status_line;

    ngx_table_elt_t                  *server;
    ngx_table_elt_t                  *date;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_encoding;
    ngx_table_elt_t                  *location;
    ngx_table_elt_t                  *last_modified;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *accept_ranges;
    ngx_table_elt_t                  *www_authenticate;
    ngx_table_elt_t                  *expires;
    ngx_table_elt_t                  *etag;

    ngx_str_t                         content_type;
    ngx_str_t                         charset;
    ngx_array_t                       ranges;

    ngx_array_t                       cache_control;

    off_t                             content_length_n;
    time_t                            date_time;
    time_t                            last_modified_time;
} ngx_http_headers_out_t;


typedef void (*ngx_http_client_body_handler_pt)(ngx_http_request_t *r);

typedef struct {
    ngx_temp_file_t                  *temp_file;
    ngx_chain_t                      *bufs;
    ngx_buf_t                        *buf;
    size_t                            rest;
    ngx_http_client_body_handler_pt   post_handler;
} ngx_http_request_body_t;


typedef struct {
    ngx_http_request_t               *request;

    ngx_buf_t                       **busy;
    ngx_int_t                         nbusy;

    ngx_buf_t                       **free;
    ngx_int_t                         nfree;

    ngx_uint_t                        pipeline;    /* unsigned  pipeline:1; */
} ngx_http_connection_t;


typedef struct ngx_http_postponed_request_s  ngx_http_postponed_request_t;

struct ngx_http_postponed_request_s {
    ngx_http_request_t            *request;
    ngx_chain_t                   *out;
    ngx_http_postponed_request_t  *next;
};


typedef ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);
typedef void (*ngx_http_event_handler_pt)(ngx_http_request_t *r);


struct ngx_http_request_s {
    uint32_t                          signature;         /* "HTTP" */

    ngx_connection_t                 *connection;

    void                            **ctx;
    void                            **main_conf;
    void                            **srv_conf;
    void                            **loc_conf;

    ngx_http_event_handler_pt         read_event_handler;
    ngx_http_event_handler_pt         write_event_handler;

    ngx_http_cache_t                 *cache;

    ngx_http_upstream_t              *upstream;

    ngx_pool_t                       *pool;
    ngx_buf_t                        *header_in;

    ngx_http_headers_in_t             headers_in;
    ngx_http_headers_out_t            headers_out;

    ngx_http_request_body_t          *request_body;

    time_t                            lingering_time;
    time_t                            start_time;

    ngx_uint_t                        method;
    ngx_uint_t                        http_version;
    ngx_uint_t                        http_major;
    ngx_uint_t                        http_minor;
 
    ngx_str_t                         request_line;
    ngx_str_t                         uri;
    ngx_str_t                         args;
    ngx_str_t                         exten;
    ngx_str_t                         unparsed_uri;

    ngx_str_t                         method_name;
    ngx_str_t                         http_protocol;
 
    ngx_chain_t                      *out;
    ngx_http_request_t               *main;
    ngx_http_request_t               *parent;
    ngx_http_postponed_request_t     *postponed;

    uint32_t                          in_addr;
    ngx_uint_t                        port;
    ngx_str_t                        *port_text;    /* ":80" */
    ngx_str_t                         server_name;
    ngx_http_in_addr_t               *virtual_names;

    ngx_uint_t                        phase;
    ngx_int_t                         phase_handler;
    ngx_http_handler_pt               content_handler;

    ngx_http_variable_value_t       **variables;

    /* used to learn the Apache compatible response length without a header */
    size_t                            header_size;

    size_t                            request_length;

    void                            **err_ctx;
    ngx_uint_t                        err_status;

    ngx_http_connection_t            *http_connection;

    ngx_http_log_handler_pt           log_handler;

    unsigned                          http_state:4;

    /* URI with "/." and on Win32 with "//" */
    unsigned                          complex_uri:1;

    /* URI with "%" */
    unsigned                          quoted_uri:1;

    /* URI with "+" */
    unsigned                          plus_in_uri:1;

    /* URI with "\0" or "%00" */
    unsigned                          zero_in_uri:1;

    unsigned                          invalid_header:1;

    unsigned                          valid_location:1;
    unsigned                          valid_unparsed_uri:1;
    unsigned                          uri_changed:1;
    unsigned                          uri_changes:4;

    unsigned                          low_case_exten:1;
    unsigned                          header_timeout_set:1;

    unsigned                          proxy:1;
    unsigned                          bypass_cache:1;
    unsigned                          no_cache:1;

#if 0
    unsigned                          cachable:1;
#endif

    unsigned                          pipeline:1;
    unsigned                          plain_http:1;
    unsigned                          chunked:1;
    unsigned                          header_only:1;
    unsigned                          keepalive:1;
    unsigned                          lingering_close:1;
    unsigned                          internal:1;
    unsigned                          closed:1;
    unsigned                          done:1;

    unsigned                          main_filter_need_in_memory:1;
    unsigned                          filter_need_in_memory:1;
    unsigned                          filter_need_temporary:1;
    unsigned                          filter_allow_ranges:1;

#if (NGX_STAT_STUB)
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
#endif

    /* used to parse HTTP headers */
    ngx_uint_t                        state;
    u_char                           *uri_start;
    u_char                           *uri_end;
    u_char                           *uri_ext;
    u_char                           *args_start;
    u_char                           *request_start;
    u_char                           *request_end;
    u_char                           *method_end;
    u_char                           *schema_start;
    u_char                           *schema_end;
    u_char                           *host_start;
    u_char                           *host_end;
    u_char                           *port_start;
    u_char                           *port_end;
    u_char                           *header_name_start;
    u_char                           *header_name_end;
    u_char                           *header_start;
    u_char                           *header_end;
    ngx_uint_t                        header_hash;
};


extern ngx_http_header_t   ngx_http_headers_in[];
extern ngx_http_header0_t   ngx_http_headers_out[];


#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */
