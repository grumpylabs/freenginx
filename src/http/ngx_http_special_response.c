
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static u_char error_tail[] =
"<hr><center>" NGINX_VER "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char ngx_http_msie_stub[] =
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
"<!-- The padding to disable MSIE's friendly error page -->" CRLF
;


static char error_301_page[] =
"<html>" CRLF
"<head><title>301 Moved Permanently</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>301 Moved Permanently</h1></center>" CRLF
;


static char error_302_page[] =
"<html>" CRLF
"<head><title>302 Found</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>302 Found</h1></center>" CRLF
;


static char error_400_page[] =
"<html>" CRLF
"<head><title>400 Bad Request</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
;


static char error_401_page[] =
"<html>" CRLF
"<head><title>401 Authorization Required</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>401 Authorization Required</h1></center>" CRLF
;


static char error_402_page[] =
"<html>" CRLF
"<head><title>402 Payment Required</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>402 Payment Required</h1></center>" CRLF
;


static char error_403_page[] =
"<html>" CRLF
"<head><title>403 Forbidden</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>403 Forbidden</h1></center>" CRLF
;


static char error_404_page[] =
"<html>" CRLF
"<head><title>404 Not Found</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>404 Not Found</h1></center>" CRLF
;


static char error_405_page[] =
"<html>" CRLF
"<head><title>405 Not Allowed</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>405 Not Allowed</h1></center>" CRLF
;


static char error_406_page[] =
"<html>" CRLF
"<head><title>406 Not Acceptable</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>406 Not Acceptable</h1></center>" CRLF
;


static char error_408_page[] =
"<html>" CRLF
"<head><title>408 Request Time-out</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>408 Request Time-out</h1></center>" CRLF
;


static char error_410_page[] =
"<html>" CRLF
"<head><title>410 Gone</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>410 Gone</h1></center>" CRLF
;


static char error_411_page[] =
"<html>" CRLF
"<head><title>411 Length Required</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>411 Length Required</h1></center>" CRLF
;


static char error_413_page[] =
"<html>" CRLF
"<head><title>413 Request Entity Too Large</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>413 Request Entity Too Large</h1></center>" CRLF
;


static char error_414_page[] =
"<html>" CRLF
"<head><title>414 Request-URI Too Large</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>414 Request-URI Too Large</h1></center>" CRLF
;


static char error_416_page[] =
"<html>" CRLF
"<head><title>416 Requested Range Not Satisfiable</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>416 Requested Range Not Satisfiable</h1></center>" CRLF
;


static char error_497_page[] =
"<html>" CRLF
"<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>"
CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The plain HTTP request was sent to HTTPS port</center>" CRLF
;


static char error_500_page[] =
"<html>" CRLF
"<head><title>500 Internal Server Error</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>500 Internal Server Error</h1></center>" CRLF
;


static char error_501_page[] =
"<html>" CRLF
"<head><title>501 Method Not Implemented</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>501 Method Not Implemented</h1></center>" CRLF
;


static char error_502_page[] =
"<html>" CRLF
"<head><title>502 Bad Gateway</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>502 Bad Gateway</h1></center>" CRLF
;


static char error_503_page[] =
"<html>" CRLF
"<head><title>503 Service Temporarily Unavailable</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>503 Service Temporarily Unavailable</h1></center>" CRLF
;


static char error_504_page[] =
"<html>" CRLF
"<head><title>504 Gateway Time-out</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>504 Gateway Time-out</h1></center>" CRLF
;


static ngx_str_t error_pages[] = {

    ngx_null_string,             /* 201, 204 */

#define NGX_HTTP_LEVEL_200  1

    /* ngx_null_string, */       /* 300 */
    ngx_string(error_301_page),
    ngx_string(error_302_page),
    ngx_null_string,             /* 303 */

#define NGX_HTTP_LEVEL_300  3

    ngx_string(error_400_page),
    ngx_string(error_401_page),
    ngx_string(error_402_page),
    ngx_string(error_403_page),
    ngx_string(error_404_page),
    ngx_string(error_405_page),
    ngx_string(error_406_page),
    ngx_null_string,             /* 407 */
    ngx_string(error_408_page),
    ngx_null_string,             /* 409 */
    ngx_string(error_410_page),
    ngx_string(error_411_page),
    ngx_null_string,             /* 412 */
    ngx_string(error_413_page),
    ngx_string(error_414_page),
    ngx_null_string,             /* 415 */
    ngx_string(error_416_page),

#define NGX_HTTP_LEVEL_400  17

    ngx_string(error_497_page),  /* 497, http to https */
    ngx_string(error_404_page),  /* 498, invalid host name */
    ngx_null_string,             /* 499, client had closed connection */

    ngx_string(error_500_page),
    ngx_string(error_501_page),
    ngx_string(error_502_page),
    ngx_string(error_503_page),
    ngx_string(error_504_page)
};


ngx_int_t
ngx_http_special_response_handler(ngx_http_request_t *r, ngx_int_t error)
{
    ngx_int_t                  rc;
    ngx_uint_t                 i, err, msie_padding;
    ngx_buf_t                 *b;
    ngx_chain_t               *out, *cl;
    ngx_http_err_page_t       *err_page;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http special response: %d, \"%V\"", error, &r->uri);

    rc = ngx_http_discard_body(r);

    if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        error = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = error;

    if (r->keepalive != 0) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_REQUEST_ENTITY_TOO_LARGE:
            case NGX_HTTP_REQUEST_URI_TOO_LARGE:
            case NGX_HTTP_TO_HTTPS:
            case NGX_HTTP_INTERNAL_SERVER_ERROR:
                r->keepalive = 0;
        }
    }

    if (r->lingering_close == 1) {
        switch (error) {
            case NGX_HTTP_BAD_REQUEST:
            case NGX_HTTP_TO_HTTPS:
                r->lingering_close = 0;
        }
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->err_ctx == NULL && clcf->error_pages) {

        err_page = clcf->error_pages->elts;

        for (i = 0; i < clcf->error_pages->nelts; i++) {

            if (err_page[i].status == error) {
                r->err_status = err_page[i].overwrite;
                r->err_ctx = r->ctx;

                r->method = NGX_HTTP_GET;

                if (err_page[i].uri.data[0] == '/') {
                    return ngx_http_internal_redirect(r, &err_page[i].uri,
                                                      NULL);
                }

                r->headers_out.location =
                                        ngx_list_push(&r->headers_out.headers);

                if (r->headers_out.location) {
                    r->err_status = NGX_HTTP_MOVED_TEMPORARILY;
                    error = NGX_HTTP_MOVED_TEMPORARILY;

                    r->headers_out.location->hash = 1;
                    r->headers_out.location->key.len = sizeof("Location") - 1;
                    r->headers_out.location->key.data = (u_char *) "Location";
                    r->headers_out.location->value = err_page[i].uri;

                } else {
                    error = NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }
        }
    }

    if (error == NGX_HTTP_CREATED) {
        /* 201 */
        err = 0;

    } else if (error == NGX_HTTP_NO_CONTENT) {
        /* 204 */
        err = 0;

    } else if (error < NGX_HTTP_BAD_REQUEST) {
        /* 3XX */
        err = error - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_LEVEL_200;

    } else if (error < NGX_HTTP_OWN_CODES) {
        /* 4XX */
        err = error - NGX_HTTP_BAD_REQUEST + NGX_HTTP_LEVEL_200
                                           + NGX_HTTP_LEVEL_300;

    } else {
        /* 49X, 5XX */
        err = error - NGX_HTTP_OWN_CODES + NGX_HTTP_LEVEL_200
                                         + NGX_HTTP_LEVEL_300
                                         + NGX_HTTP_LEVEL_400;
        switch (error) {
            case NGX_HTTP_TO_HTTPS:
                r->headers_out.status = NGX_HTTP_BAD_REQUEST;
                error = NGX_HTTP_BAD_REQUEST;
                break;
        }
    }

    msie_padding = 0;

    if (error_pages[err].len) {
        r->headers_out.content_length_n = error_pages[err].len
                                          + sizeof(error_tail) - 1;

        if (clcf->msie_padding
            && r->headers_in.msie
            && r->http_version >= NGX_HTTP_VERSION_10
            && error >= NGX_HTTP_BAD_REQUEST
            && error != NGX_HTTP_REQUEST_URI_TOO_LARGE)
        {
            r->headers_out.content_length_n += sizeof(ngx_http_msie_stub) - 1;
            msie_padding = 1;
        }

        r->headers_out.content_type.len = sizeof("text/html") - 1;
        r->headers_out.content_type.data = (u_char *) "text/html";

    } else {
        r->headers_out.content_length_n = -1;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_last_modified(r);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    if (error_pages[err].len == 0) {
        return NGX_OK;
    }


    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->memory = 1;
    b->pos = error_pages[err].data;
    b->last = error_pages[err].data + error_pages[err].len;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    out = cl;


    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->memory = 1;
    b->pos = error_tail;
    b->last = error_tail + sizeof(error_tail) - 1;

    cl->next = ngx_alloc_chain_link(r->pool);
    if (cl->next == NULL) {
        return NGX_ERROR;
    }

    cl = cl->next;
    cl->buf = b;

    if (msie_padding) {
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->memory = 1;
        b->pos = ngx_http_msie_stub;
        b->last = ngx_http_msie_stub + sizeof(ngx_http_msie_stub) - 1;

        cl->next = ngx_alloc_chain_link(r->pool);
        if (cl->next == NULL) {
            return NGX_ERROR;
        }

        cl = cl->next;
        cl->buf = b;
    }

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    cl->next = NULL;

    return ngx_http_output_filter(r, out);
}
