
#include <nginx.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_table.h>
#include <ngx_hunk.h>
#include <ngx_http.h>


#if 0

ngx_http_module_t  ngx_http_header_filter_module = {
    NGX_HTTP_MODULE,

    NULL,                                  /* create server config */
    NULL,                                  /* create location config */
    NULL,                                  /* module directives */

    NULL,                                  /* init module */
    NULL,                                  /* translate handler */

    ngx_http_header_filter_init            /* init output header filter */
    NULL                                   /* init output body filter */
};

#endif


static char server_string[] = "Server: " NGINX_VER CRLF;


static ngx_str_t http_codes[] = {
    { 6,  "200 OK" },

    { 21, "301 Moved Permanently" },

    { 15, "400 Bad Request" },
    { 0,  NULL },
    { 0,  NULL },
    { 13, "403 Forbidden" },
    { 13, "404 Not Found" }
};



int ngx_http_header_filter(ngx_http_request_t *r)
{
    int  len, status, i;
    ngx_hunk_t       *h;
    ngx_chain_t      *ch;
    ngx_table_elt_t  *header;

    if (r->http_version < NGX_HTTP_VERSION_10)
        return NGX_OK;

    /* 9 is for "HTTP/1.1 ", 2 is for trailing "\r\n"
       and 2 is for end of header */
    len = 9 + 2 + 2;

    /* status line */
    if (r->headers_out.status_line.len) {
        len += r->headers_out.status_line.len;
    } else {
        if (r->headers_out.status < NGX_HTTP_MOVED_PERMANENTLY)
            status = r->headers_out.status - NGX_HTTP_OK;

        else if (r->headers_out.status < NGX_HTTP_BAD_REQUEST)
            status = r->headers_out.status - NGX_HTTP_MOVED_PERMANENTLY + 1;

        else
            status = r->headers_out.status - NGX_HTTP_BAD_REQUEST + 1 + 1;

        len += http_codes[status].len;
    }

    if (r->headers_out.server && r->headers_out.server->key.len) {
        len += r->headers_out.server->key.len
               + r->headers_out.server->value.len + 2;
    } else {
        len += sizeof(server_string) - 1;
    }

    if (r->headers_out.date && r->headers_out.date->key.len) {
        len += r->headers_out.date->key.len
               + r->headers_out.date->value.len + 2;
    } else {
        /* "Date: ... \r\n"; */
        len += 37;
    }

    /* 2^64 is 20 characters */
    if (r->headers_out.content_length >= 0)
        len += 48;

#if 0
    if (r->headers_out.content_type.len)
        len += r->headers_out.content_type.len + 16;
#endif

    if (r->keepalive)
        len += 24;
    else
        len += 19;

    header = (ngx_table_elt_t *) r->headers_out.headers->elts;
    for (i = 0; i < r->headers_out.headers->nelts; i++) {
        if (header[i].key.len == 0)
            continue;

        len += header[i].key.len + 2 + header[i].value.len + 2;
    }

    ngx_test_null(h, ngx_create_temp_hunk(r->pool, len, 0, 64), NGX_ERROR);

    /* "HTTP/1.1 " */
    ngx_memcpy(h->last.mem, "HTTP/1.1 ", 9);
    h->last.mem += 9;

    /* status line */
    if (r->headers_out.status_line.len) {
        ngx_memcpy(h->last.mem, r->headers_out.status_line.data,
                   r->headers_out.status_line.len);
        h->last.mem += r->headers_out.status_line.len;

    } else {
        ngx_memcpy(h->last.mem, http_codes[status].data,
                   http_codes[status].len);
        h->last.mem += http_codes[status].len;
    }
    *(h->last.mem++) = CR; *(h->last.mem++) = LF;

    if (!(r->headers_out.server && r->headers_out.server->key.len)) {
        ngx_memcpy(h->last.mem, server_string, sizeof(server_string) - 1);
        h->last.mem += sizeof(server_string) - 1;
    }

    if (!(r->headers_out.date && r->headers_out.date->key.len)) {
        ngx_memcpy(h->last.mem, "Date: ", 6);
        h->last.mem += 6;
        h->last.mem += ngx_http_get_time(h->last.mem, time(NULL));
        *(h->last.mem++) = CR; *(h->last.mem++) = LF;
    }

    /* 2^64 is 20 characters  */
    if (r->headers_out.content_length >= 0)
        h->last.mem += ngx_snprintf(h->last.mem, 49, "Content-Length: %u" CRLF,
                                    r->headers_out.content_length);

#if 0
    if (r->headers_out.content_type.len) {
        ngx_memcpy(h->last.mem, "Content-Type: ", 14);
        h->last.mem += 14;
        ngx_memcpy(h->last.mem, r->headers_out.content_type.data,
                   r->headers_out.content_type.len);
        h->last.mem += r->headers_out.content_type.len;
        *(h->last.mem++) = CR; *(h->last.mem++) = LF;
    }
#endif

    if (r->keepalive) {
        ngx_memcpy(h->last.mem, "Connection: keep-alive" CRLF, 24);
        h->last.mem += 24;

    } else {
        ngx_memcpy(h->last.mem, "Connection: close" CRLF, 19);
        h->last.mem += 19;
    }

    for (i = 0; i < r->headers_out.headers->nelts; i++) {
        if (header[i].key.len == 0)
            continue;

        ngx_memcpy(h->last.mem, header[i].key.data, header[i].key.len);
        h->last.mem += header[i].key.len;
        *(h->last.mem++) = ':' ; *(h->last.mem++) = ' ' ;

        ngx_memcpy(h->last.mem, header[i].value.data, header[i].value.len);
        h->last.mem += header[i].value.len;
        *(h->last.mem++) = CR; *(h->last.mem++) = LF;
    }

    /* end of HTTP header */
    *(h->last.mem++) = CR; *(h->last.mem++) = LF;

    ngx_test_null(ch, ngx_palloc(r->pool, sizeof(ngx_chain_t)), NGX_ERROR);

    ch->hunk = h;
    ch->next = NULL;

    return ngx_http_write_filter(r, ch);
}
