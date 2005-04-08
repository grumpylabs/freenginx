
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b)
{
    u_char  c, ch, *p, *m;
    enum {
        sw_start = 0,
        sw_method,
        sw_space_after_method,
        sw_spaces_before_uri,
        sw_schema,
        sw_schema_slash,
        sw_schema_slash_slash,
        sw_host,
        sw_port,
        sw_after_slash_in_uri,
        sw_check_uri,
        sw_uri,
        sw_http_09,
        sw_http_H,
        sw_http_HT,
        sw_http_HTT,
        sw_http_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_almost_done
    } state;

    state = r->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        /* gcc 2.95.2 and msvc 6.0 compile this switch as an jump table */

        switch (state) {

        /* HTTP methods: GET, HEAD, POST */
        case sw_start:
            r->request_start = p;

            if (ch == CR || ch == LF) {
                break;
            }

            if (ch < 'A' || ch > 'Z') {
                return NGX_HTTP_PARSE_INVALID_METHOD;
            }

            state = sw_method;
            break;

        case sw_method:
            if (ch == ' ') {
                r->method_end = p;
                m = r->request_start;

                if (p - m == 3) {

                    if (m[0] == 'G' && m[1] == 'E' && m[2] == 'T') {
                        r->method = NGX_HTTP_GET;
                    }

                } else if (p - m == 4) {

                    if (m[0] == 'P' && m[1] == 'O'
                        && m[2] == 'S' && m[3] == 'T')
                    {
                        r->method = NGX_HTTP_POST;

                    } else if (m[0] == 'H' && m[1] == 'E'
                               && m[2] == 'A' && m[3] == 'D')
                    {
                        r->method = NGX_HTTP_HEAD;
                    }
                }

                state = sw_spaces_before_uri;
                break;
            }

            if (ch < 'A' || ch > 'Z') {
                return NGX_HTTP_PARSE_INVALID_METHOD;
            }

            break;

        /* single space after method */
        case sw_space_after_method:
            switch (ch) {
            case ' ':
                state = sw_spaces_before_uri;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_METHOD;
            }
            break;

        /* space* before URI */
        case sw_spaces_before_uri:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                r->schema_start = p;
                state = sw_schema;
                break;
            }

            switch (ch) {
            case '/':
                r->uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            case ' ':
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                break;
            }

            switch (ch) {
            case ':':
                r->schema_end = p;
                state = sw_schema_slash;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema_slash:
            switch (ch) {
            case '/':
                state = sw_schema_slash_slash;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema_slash_slash:
            switch (ch) {
            case '/':
                r->host_start = p;
                state = sw_host;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_host:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                break;
            }

            if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-')
            {
                break;
            }

            switch (ch) {
            case ':':
                r->host_end = p;
                state = sw_port;
                break;
            case '/':
                r->host_end = p;
                r->uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_port:
            if (ch >= '0' && ch <= '9') {
                break;
            }

            switch (ch) {
            case '/':
                r->port_end = p;
                r->uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* check "/.", "//", "%", and "\" (Win32) in URI */
        case sw_after_slash_in_uri:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                state = sw_check_uri;
                break;
            }

            if (ch >= '0' && ch <= '9') {
                state = sw_check_uri;
                break;
            }

            switch (ch) {
            case ' ':
                r->uri_end = p;
                state = sw_http_09;
                break;
            case CR:
                r->uri_end = p;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p;
                r->http_minor = 9;
                goto done;
            case '.':
                r->complex_uri = 1;
                state = sw_uri;
                break;
            case '%':
                r->quoted_uri = 1;
                state = sw_uri;
                break;
            case '/':
                r->complex_uri = 1;
                state = sw_uri;
                break;
#if (NGX_WIN32)
            case '\\':
                r->complex_uri = 1;
                state = sw_uri;
                break;
#endif
            case '?':
                r->args_start = p + 1;
                state = sw_uri;
                break;
            case '+':
                r->plus_in_uri = 1;
                break;
            case '\0':
                r->zero_in_uri = 1;
                break;
            default:
                state = sw_check_uri;
                break;
            }
            break;

        /* check "/", "%" and "\" (Win32) in URI */
        case sw_check_uri:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                break;
            }

            if (ch >= '0' && ch <= '9') {
                break;
            }

            switch (ch) {
            case '/':
                r->uri_ext = NULL;
                state = sw_after_slash_in_uri;
                break;
            case '.':
                r->uri_ext = p + 1;
                break;
            case ' ':
                r->uri_end = p;
                state = sw_http_09;
                break;
            case CR:
                r->uri_end = p;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p;
                r->http_minor = 9;
                goto done;
#if (NGX_WIN32)
            case '\\':
                r->complex_uri = 1;
                state = sw_after_slash_in_uri;
                break;
#endif
            case '%':
                r->quoted_uri = 1;
                state = sw_uri;
                break;
            case '+':
                r->plus_in_uri = 1;
                break;
            case '?':
                r->args_start = p + 1;
                state = sw_uri;
                break;
            case '\0':
                r->zero_in_uri = 1;
                break;
            }
            break;

        /* URI */
        case sw_uri:
            switch (ch) {
            case ' ':
                r->uri_end = p;
                state = sw_http_09;
                break;
            case CR:
                r->uri_end = p;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p;
                r->http_minor = 9;
                goto done;
            case '+':
                r->plus_in_uri = 1;
                break;
            case '\0':
                r->zero_in_uri = 1;
                break;
            }
            break;

        /* space+ after URI */
        case sw_http_09:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->http_minor = 9;
                goto done;
            case 'H':
                r->http_protocol.data = p;
                state = sw_http_H;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_H:
            switch (ch) {
            case 'T':
                state = sw_http_HT;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HT:
            switch (ch) {
            case 'T':
                state = sw_http_HTT;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HTT:
            switch (ch) {
            case 'P':
                state = sw_http_HTTP;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_major = ch - '0';
            state = sw_major_digit;
            break;

        /* major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_major = r->http_major * 10 + ch - '0';
            break;

        /* first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_minor = ch - '0';
            state = sw_minor_digit;
            break;

        /* minor HTTP version or end of request line */
        case sw_minor_digit:
            if (ch == CR) {
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                goto done;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_minor = r->http_minor * 10 + ch - '0';
            break;

        /* end of request line */
        case sw_almost_done:
            r->request_end = p - 1;
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
        }
    }

    b->pos = p;
    r->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;

    if (r->request_end == NULL) {
        r->request_end = p;
    }

    r->http_version = r->http_major * 1000 + r->http_minor;
    r->state = sw_start;

    if (r->http_version == 9 && r->method != NGX_HTTP_GET) {
        return NGX_HTTP_PARSE_INVALID_09_METHOD;
    }

    return NGX_OK;
}


ngx_int_t ngx_http_parse_header_line(ngx_http_request_t *r, ngx_buf_t *b)
{
    u_char      c, ch, *p;
    ngx_uint_t  hash;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_ignore_line,
        sw_skip_line,
        sw_almost_done,
        sw_header_almost_done
    } state;

    state = r->state;
    hash = r->header_hash;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:
            r->invalid_header = 0;

            switch (ch) {
            case CR:
                r->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                r->header_end = p;
                goto header_done;
            default:
                state = sw_name;
                r->header_name_start = p;

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    hash = c;
                    break;
                }

                if (ch == '-') {
                    hash = ch;
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    hash = ch;
                    break;
                }

                r->invalid_header = 1;
                state = sw_skip_line;
                break;

            }
            break;

        /* header name */
        case sw_name:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                hash += c;
                break;
            }

            if (ch == ':') {
                r->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                hash += ch;
                break;
            }

            if (ch >= '0' && ch <= '9') {
                hash += ch;
                break;
            }

            /* IIS may send the duplicate "HTTP/1.1 ..." lines */
            if (ch == '/'
                && r->proxy
                && p - r->header_start == 4
                && ngx_strncmp(r->header_start, "HTTP", 4) == 0)
            {
                state = sw_ignore_line;
                break;
            }

            r->invalid_header = 1;
            state = sw_skip_line;
            break;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->header_start = r->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                r->header_start = r->header_end = p;
                goto done;
            default:
                r->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                r->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                r->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                r->header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* ignore header line */
        case sw_ignore_line:
            switch (ch) {
            case LF:
                state = sw_start;
                break;
            default:
                break;
            }
            break;

        /* skip header line */
        case sw_skip_line:
            switch (ch) {
            case CR:
                r->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                r->header_end = p;
                goto done;
            default:
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
        }
    }

    b->pos = p;
    r->state = state;
    r->header_hash = hash;

    return NGX_AGAIN;

done:

    b->pos = p + 1;
    r->state = sw_start;
    r->header_hash = hash;

    return NGX_OK;

header_done:

    b->pos = p + 1;
    r->state = sw_start;

    return NGX_HTTP_PARSE_HEADER_DONE;
}


ngx_int_t ngx_http_parse_complex_uri(ngx_http_request_t *r)
{
    u_char  c, ch, decoded, *p, *u;
    enum {
        sw_usual = 0,
        sw_slash,
        sw_dot,
        sw_dot_dot,
#if (NGX_WIN32)
        sw_dot_dot_dot,
#endif
        sw_quoted,
        sw_quoted_second
    } state, quoted_state;

#if (NGX_SUPPRESS_WARN)
    decoded = '\0';
    quoted_state = sw_usual;
#endif

    state = sw_usual;
    p = r->uri_start;
    u = r->uri.data;
    r->uri_ext = NULL;
    r->args_start = NULL;

    ch = *p++;

    while (p <= r->uri_end) {

        /*
         * we use "ch = *p++" inside the cycle, but this operation is safe,
         * because after the URI there is always at least one charcter:
         * the line feed
         */

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "s:%d in:'%Xd:%c', out:'%c'", state, ch, ch, *u);

        switch (state) {
        case sw_usual:
            switch(ch) {
#if (NGX_WIN32)
            case '\\':
                r->uri_ext = NULL;

                if (p == r->uri_start + r->uri.len) {

                    /*
                     * we omit the last "\" to cause redirect because
                     * the browsers do not treat "\" as "/" in relative URL path
                     */

                    break;
                }

                state = sw_slash;
                *u++ = '/';
                break;
#endif
            case '/':
                r->uri_ext = NULL;
                state = sw_slash;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->args_start = p;
                goto done;
            case '.':
                r->uri_ext = u + 1;
                *u++ = ch;
                break;
            default:
                *u++ = ch;
                break;
            }
            ch = *p++;
            break;

        case sw_slash:
            switch(ch) {
#if (NGX_WIN32)
            case '\\':
                break;
#endif
            case '/':
                break;
            case '.':
                state = sw_dot;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->args_start = p;
                goto done;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }
            ch = *p++;
            break;

        case sw_dot:
            switch(ch) {
#if (NGX_WIN32)
            case '\\':
                /* fall through */
#endif
            case '/':
                state = sw_slash;
                u--;
                break;
            case '.':
                state = sw_dot_dot;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->args_start = p;
                goto done;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }
            ch = *p++;
            break;

        case sw_dot_dot:
            switch(ch) {
#if (NGX_WIN32)
            case '\\':
                /* fall through */
#endif
            case '/':
                state = sw_slash;
                u -= 4;
                if (u < r->uri.data) {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
                while (*(u - 1) != '/') {
                    u--;
                }
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->args_start = p;
                goto done;
#if (NGX_WIN32)
            case '.':
                state = sw_dot_dot_dot;
                *u++ = ch;
                break;
#endif
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }
            ch = *p++;
            break;

#if (NGX_WIN32)
        case sw_dot_dot_dot:
            switch(ch) {
            case '\\':
            case '/':
                state = sw_slash;
                u -= 5;
                if (u < r->uri.data) {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
                while (*u != '/') {
                    u--;
                }
                if (u < r->uri.data) {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
                while (*(u - 1) != '/') {
                    u--;
                }
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }
            ch = *p++;
            break;
#endif

        case sw_quoted:
            if (ch >= '0' && ch <= '9') {
                decoded = (u_char) (ch - '0');
                state = sw_quoted_second;
                ch = *p++;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                decoded = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                ch = *p++;
                break;
            }

            return NGX_HTTP_PARSE_INVALID_REQUEST;

        case sw_quoted_second:
            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((decoded << 4) + ch - '0');

                if (ch == '%') {
                    state = sw_usual;
                    *u++ = ch;
                    ch = *p++;
                    break;
                }

                if (ch == '\0') {
                    r->zero_in_uri = 1;
                    *u++ = ch;
                    ch = *p++;
                }

                state = quoted_state;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((decoded << 4) + c - 'a' + 10);
                if (ch == '?') {
                    *u++ = ch;
                    ch = *p++;
                }
                state = quoted_state;
                break;
            }

            return NGX_HTTP_PARSE_INVALID_REQUEST;
        }
    }

done:

    r->uri.len = u - r->uri.data;
    r->uri.data[r->uri.len] = '\0';

    if (r->uri_ext) {
        r->exten.len = u - r->uri_ext;
        r->exten.data = r->uri_ext;
    }

    r->uri_ext = NULL;

    return NGX_OK;
}
