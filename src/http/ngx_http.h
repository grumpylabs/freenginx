#ifndef _NGX_HTTP_H_INCLUDED_
#define _NGX_HTTP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_hunk.h>
#include <ngx_files.h>
#include <ngx_connection.h>


#define NGX_HTTP_GET   1
#define NGX_HTTP_HEAD  2
#define NGX_HTTP_POST  3

#define NGX_HTTP_CONN_CLOSE       0
#define NGX_HTTP_CONN_KEEP_ALIVE  1


#define NGX_HTTP_HEADER_DONE            1
#define NGX_HTTP_INVALID_METHOD         10
#define NGX_HTTP_INVALID_REQUEST        11
#define NGX_HTTP_INVALID_HEAD           12
#define NGX_HTTP_INVALID_HEADER         13


#define NGX_HTTP_OK                     200
#define NGX_HTTP_SPECIAL_RESPONSE       300
#define NGX_HTTP_MOVED_PERMANENTLY      302
#define NGX_HTTP_BAD_REQUEST            400
#define NGX_HTTP_NOT_FOUND              404
#define NGX_HTTP_INTERNAL_SERVER_ERROR  503


#define NGX_HTTP_STATIC_HANDLER     0
#define NGX_HTTP_DIRECTORY_HANDLER  1



typedef struct {
    char          *doc_root;
    size_t         doc_root_len;

    size_t         request_pool_size;

    size_t         header_buffer_size;
    size_t         discarded_buffer_size;

    unsigned int   header_timeout;
} ngx_http_server_t;

typedef struct {
    char *buff;
    char *pos;
    char *last;
    char *end;
} ngx_buff_t;

typedef struct {
    int     status;
    int     connection;
    off_t   content_length;
    char   *location;
    char   *content_type;
    char   *charset;
    char   *etag;
    char   *server;
    time_t  date;
    time_t  last_modified;
} ngx_http_headers_out_t;

typedef struct ngx_http_request_s ngx_http_request_t;

struct ngx_http_request_s {
    char  *filename;
    char  *location;
    ngx_fd_t  fd;

    void  **ctx;
    void  **loc_conf;
    void  **srv_conf;

    ngx_pool_t  *pool;
    ngx_hunk_t  *header_in;

/*
    ngx_http_headers_in_t *headers_in;
*/
    ngx_http_headers_out_t *headers_out;

    int    filename_len;
    int  (*handler)(ngx_http_request_t *r);

    ngx_file_info_t fileinfo;

    int    method;

    int    http_version;
    int    http_major;
    int    http_minor;

    char  *uri;
    ngx_http_request_t *main;

    ngx_connection_t  *connection;
    ngx_http_server_t *server;

    int       filter;

    ssize_t   client_content_length;
    char     *discarded_buffer;

    unsigned  header_timeout:1;
    unsigned  process_header:1;

    unsigned  header_only:1;
    unsigned  unusual_uri:1;
    unsigned  complex_uri:1;

    int    state;
    char  *uri_start;
    char  *uri_end;
    char  *uri_ext;
    char  *args_start;
    char  *header_name_start;
    char  *header_name_end;
    char  *header_start;
    char  *header_end;
#ifdef NGX_EVENT
    int  (*state_handler)(ngx_http_request_t *r);
#endif
};

typedef struct {
    char  *action;
    char  *client;
    char  *url;
} ngx_http_log_ctx_t;


typedef struct {
    int    index;
} ngx_http_module_t;

#define NGX_HTTP_MODULE  0

#define ngx_get_module_loc_conf(r, module)  r->loc_conf[module.index]
#define ngx_get_module_ctx(r, module)  r->ctx[module.index]



/* STUB */
#define NGX_INDEX "index.html"


/* STUB */
int ngx_http_init(ngx_pool_t *pool, ngx_log_t *log);

int ngx_http_init_connection(ngx_connection_t *c);


#endif /* _NGX_HTTP_H_INCLUDED_ */
