
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


u_char *
ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }

    for ( /* void */ ; --n; dst++, src++) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }
    }

    *dst = '\0';

    return dst;
}


u_char *
ngx_pstrdup(ngx_pool_t *pool, ngx_str_t *src)
{
    u_char  *dst;

    dst = ngx_palloc(pool, src->len);
    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, src->data, src->len);

    return dst;
}


/*
 * supported formats:
 *    %[0][width][x][X]O        off_t
 *    %[0][width]T              time_t
 *    %[0][width][u][x|X]z      ssize_t/size_t
 *    %[0][width][u][x|X]d      int/u_int
 *    %[0][width][u][x|X]l      long
 *    %[0][width|m][u][x|X]i    ngx_int_t/ngx_uint_t
 *    %[0][width][u][x|X]D      int32_t/uint32_t
 *    %[0][width][u][x|X]L      int64_t/uint64_t
 *    %[0][width|m][u][x|X]A    ngx_atomic_int_t/ngx_atomic_uint_t
 *    %P                        ngx_pid_t
 *    %r                        rlim_t
 *    %p                        pointer
 *    %V                        pointer to ngx_str_t
 *    %s                        null-terminated string
 *    %Z                        '\0'
 *    %N                        '\n'
 *    %c                        char
 *    %%                        %
 *
 *  TODO:
 *    %M                        ngx_msec_t
 *
 *  reserved:
 *    %t                        ptrdiff_t
 *    %S                        null-teminated wchar string
 *    %C                        wchar
 */


u_char * ngx_cdecl
ngx_sprintf(u_char *buf, const char *fmt, ...)
{
    u_char   *p;
    va_list   args;

    va_start(args, fmt);
    p = ngx_vsnprintf(buf, /* STUB */ 65536, fmt, args);
    va_end(args);

    return p;
}


u_char * ngx_cdecl
ngx_snprintf(u_char *buf, size_t max, const char *fmt, ...)
{
    u_char   *p;
    va_list   args;

    va_start(args, fmt);
    p = ngx_vsnprintf(buf, max, fmt, args);
    va_end(args);

    return p;
}


u_char *
ngx_vsnprintf(u_char *buf, size_t max, const char *fmt, va_list args)
{
    u_char         *p, zero, *last, temp[NGX_INT64_LEN + 1];
                                    /*
                                     * really we need temp[NGX_INT64_LEN] only,
                                     * but icc issues the warning
                                     */
    int             d;
    size_t          len;
    uint32_t        ui32;
    int64_t         i64;
    uint64_t        ui64;
    ngx_str_t      *s;
    ngx_uint_t      width, sign, hexadecimal, max_width;
    static u_char   hex[] = "0123456789abcdef";
    static u_char   HEX[] = "0123456789ABCDEF";

    if (max == 0) {
        return buf;
    }

    last = buf + max;

    while (*fmt && buf < last) {

        /*
         * "buf < last" means that we could copy at least one character:
         * the plain character, "%%", "%c", and minus without the checking
         */

        if (*fmt == '%') {

            i64 = 0;
            ui64 = 0;

            zero = (u_char) ((*++fmt == '0') ? '0' : ' ');
            width = 0;
            sign = 1;
            hexadecimal = 0;
            max_width = 0;

            p = temp + NGX_INT64_LEN;

            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + *fmt++ - '0';
            }


            for ( ;; ) {
                switch (*fmt) {

                case 'u':
                    sign = 0;
                    fmt++;
                    continue;

                case 'm':
                    max_width = 1;
                    fmt++;
                    continue;

                case 'X':
                    hexadecimal = 2;
                    sign = 0;
                    fmt++;
                    continue;

                case 'x':
                    hexadecimal = 1;
                    sign = 0;
                    fmt++;
                    continue;

                default:
                    break;
                }

                break;
            }


            switch (*fmt) {

            case 'V':
                s = va_arg(args, ngx_str_t *);

                len = (buf + s->len < last) ? s->len : (size_t) (last - buf);
                buf = ngx_cpymem(buf, s->data, len);
                fmt++;

                continue;

            case 's':
                p = va_arg(args, u_char *);

                while (*p && buf < last) {
                    *buf++ = *p++;
                }
                fmt++;

                continue;

            case 'O':
                i64 = (int64_t) va_arg(args, off_t);
                sign = 1;
                break;

            case 'P':
                i64 = (int64_t) va_arg(args, ngx_pid_t);
                sign = 1;
                break;

            case 'T':
                i64 = (int64_t) va_arg(args, time_t);
                sign = 1;
                break;

            case 'z':
                if (sign) {
                    i64 = (int64_t) va_arg(args, ssize_t);
                } else {
                    ui64 = (uint64_t) va_arg(args, size_t);
                }
                break;

            case 'i':
                if (sign) {
                    i64 = (int64_t) va_arg(args, ngx_int_t);
                } else {
                    ui64 = (uint64_t) va_arg(args, ngx_uint_t);
                }

                if (max_width) {
                    width = NGX_INT_T_LEN;
                }

                break;

            case 'd':
                if (sign) {
                    i64 = (int64_t) va_arg(args, int);
                } else {
                    ui64 = (uint64_t) va_arg(args, u_int);
                }
                break;

            case 'l':
                if (sign) {
                    i64 = (int64_t) va_arg(args, long);
                } else {
                    ui64 = (uint64_t) va_arg(args, u_long);
                }
                break;

            case 'D':
                if (sign) {
                    i64 = (int64_t) va_arg(args, int32_t);
                } else {
                    ui64 = (uint64_t) va_arg(args, uint32_t);
                }
                break;

            case 'L':
                if (sign) {
                    i64 = va_arg(args, int64_t);
                } else {
                    ui64 = va_arg(args, uint64_t);
                }
                break;

            case 'A':
                if (sign) {
                    i64 = (int64_t) va_arg(args, ngx_atomic_int_t);
                } else {
                    ui64 = (uint64_t) va_arg(args, ngx_atomic_uint_t);
                }

                if (max_width) {
                    width = NGX_ATOMIC_T_LEN;
                }

                break;

#if !(NGX_WIN32)
            case 'r':
                i64 = (int64_t) va_arg(args, rlim_t);
                sign = 1;
                break;
#endif

            case 'p':
                ui64 = (uintptr_t) va_arg(args, void *);
                hexadecimal = 2;
                sign = 0;
                zero = '0';
                width = 8;
                break;

            case 'c':
                d = va_arg(args, int);
                *buf++ = (u_char) (d & 0xff);
                fmt++;

                continue;

            case 'Z':
                *buf++ = '\0';
                fmt++;

                continue;

            case 'N':
#if (NGX_WIN32)
                *buf++ = CR;
#endif
                *buf++ = LF;
                fmt++;

                continue;

            case '%':
                *buf++ = '%';
                fmt++;

                continue;

            default:
                *buf++ = *fmt++;

                continue;
            }

            if (sign) {
                if (i64 < 0) {
                    *buf++ = '-';
                    ui64 = (uint64_t) -i64;

                } else {
                    ui64 = (uint64_t) i64;
                }
            }

            if (hexadecimal == 1) {
                do {

                    /* the "(uint32_t)" cast disables the BCC's warning */
                    *--p = hex[(uint32_t) (ui64 & 0xf)];

                } while (ui64 >>= 4);

            } else if (hexadecimal == 2) {
                do {

                    /* the "(uint32_t)" cast disables the BCC's warning */
                    *--p = HEX[(uint32_t) (ui64 & 0xf)];

                } while (ui64 >>= 4);

            } else if (ui64 <= NGX_MAX_UINT32_VALUE) {

                /*
                 * To divide 64-bit number and to find the remainder
                 * on the x86 platform gcc and icc call the libc functions
                 * [u]divdi3() and [u]moddi3(), they call another function
                 * in its turn.  On FreeBSD it is the qdivrem() function,
                 * its source code is about 170 lines of the code.
                 * The glibc counterpart is about 150 lines of the code.
                 *
                 * For 32-bit numbers and some divisors gcc and icc use
                 * the inlined multiplication and shifts.  For example,
                 * unsigned "i32 / 10" is compiled to
                 *
                 *     (i32 * 0xCCCCCCCD) >> 35
                 */

                ui32 = (uint32_t) ui64;

                do {
                    *--p = (u_char) (ui32 % 10 + '0');
                } while (ui32 /= 10);

            } else {
                do {
                    *--p = (u_char) (ui64 % 10 + '0');
                } while (ui64 /= 10);
            }

            len = (temp + NGX_INT64_LEN) - p;

            while (len++ < width && buf < last) {
                *buf++ = zero;
            }

            len = (temp + NGX_INT64_LEN) - p;
            if (buf + len > last) {
                len = last - buf;
            }

            buf = ngx_cpymem(buf, p, len);

            fmt++;

        } else {
            *buf++ = *fmt++;
        }
    }

    return buf;
}


ngx_int_t
ngx_rstrncmp(u_char *s1, u_char *s2, size_t n)
{
    if (n == 0) {
        return 0;
    }

    n--;

    for ( ;; ) {
        if (s1[n] != s2[n]) {
            return s1[n] - s2[n];
        }

        if (n == 0) {
            return 0;
        }

        n--;
    }
}


ngx_int_t
ngx_rstrncasecmp(u_char *s1, u_char *s2, size_t n)
{
    u_char  c1, c2;

    if (n == 0) {
        return 0;
    }

    n--;

    for ( ;; ) {
        c1 = s1[n];
        if (c1 >= 'a' && c1 <= 'z') {
            c1 -= 'a' - 'A';
        }

        c2 = s2[n];
        if (c2 >= 'a' && c2 <= 'z') {
            c2 -= 'a' - 'A';
        }

        if (c1 != c2) {
            return c1 - c2;
        }

        if (n == 0) {
            return 0;
        }

        n--;
    }
}


ngx_int_t
ngx_atoi(u_char *line, size_t n)
{
    ngx_int_t  value;

    if (n == 0) {
        return NGX_ERROR;
    }

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }

        value = value * 10 + (*line - '0');
    }

    if (value < 0) {
        return NGX_ERROR;

    } else {
        return value;
    }
}


ssize_t
ngx_atosz(u_char *line, size_t n)
{
    ssize_t  value;

    if (n == 0) {
        return NGX_ERROR;
    }

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }

        value = value * 10 + (*line - '0');
    }

    if (value < 0) {
        return NGX_ERROR;

    } else {
        return value;
    }
}


off_t
ngx_atoof(u_char *line, size_t n)
{
    off_t  value;

    if (n == 0) {
        return NGX_ERROR;
    }

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }

        value = value * 10 + (*line - '0');
    }

    if (value < 0) {
        return NGX_ERROR;

    } else {
        return value;
    }
}


time_t
ngx_atotm(u_char *line, size_t n)
{
    time_t  value;

    if (n == 0) {
        return NGX_ERROR;
    }

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }

        value = value * 10 + (*line - '0');
    }

    if (value < 0) {
        return NGX_ERROR;

    } else {
        return value;
    }
}


ngx_int_t
ngx_hextoi(u_char *line, size_t n)
{
    u_char     ch;
    ngx_int_t  value;

    if (n == 0) {
        return NGX_ERROR;
    }

    for (value = 0; n--; line++) {
        ch = *line;

        if (ch >= '0' && ch <= '9') {
            value = value * 16 + (ch - '0');
            continue;
        }

        if (ch >= 'A' && ch <= 'F') {
            value = value * 16 + (ch - 'A' + 10);
            continue;
        }

        if (ch >= 'a' && ch <= 'f') {
            value = value * 16 + (ch - 'a' + 10);
            continue;
        }

        return NGX_ERROR;
    }

    if (value < 0) {
        return NGX_ERROR;

    } else {
        return value;
    }
}


void
ngx_md5_text(u_char *text, u_char *md5)
{
    int            i;
    static u_char  hex[] = "0123456789abcdef";

    for (i = 0; i < 16; i++) {
        *text++ = hex[md5[i] >> 4];
        *text++ = hex[md5[i] & 0xf];
    }

    *text = '\0';
}


void
ngx_encode_base64(ngx_str_t *dst, ngx_str_t *src)
{
    u_char         *d, *s;
    size_t          len;
    static u_char   basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    len = src->len;
    s = src->data;
    d = dst->data;

    while (len > 2) {
        *d++ = basis64[(s[0] >> 2) & 0x3f];
        *d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis64[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis64[s[2] & 0x3f];

        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = basis64[(s[0] >> 2) & 0x3f];

        if (len == 1) {
            *d++ = basis64[(s[0] & 3) << 4];
            *d++ = '=';

        } else {
            *d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis64[(s[1] & 0x0f) << 2];
        }

        *d++ = '=';
    }

    dst->len = d - dst->data;
}


ngx_int_t
ngx_decode_base64(ngx_str_t *dst, ngx_str_t *src)
{
    size_t          len;
    u_char         *d, *s;
    static u_char   basis64[] =
        { 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
          52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
          77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
          15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
          77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
          41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
          77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77 };

    for (len = 0; len < src->len; len++) {
        if (src->data[len] == '=') {
            break;
        }

        if (basis64[src->data[len]] == 77) {
            return NGX_ERROR;
        }
    }

    if (len % 4 == 1) {
        return NGX_ERROR;
    }

    s = src->data;
    d = dst->data;

    while (len > 3) {
        *d++ = (u_char) (basis64[s[0]] << 2 | basis64[s[1]] >> 4);
        *d++ = (u_char) (basis64[s[1]] << 4 | basis64[s[2]] >> 2);
        *d++ = (u_char) (basis64[s[2]] << 6 | basis64[s[3]]);

        s += 4;
        len -= 4;
    }

    if (len > 1) {
        *d++ = (u_char) (basis64[s[0]] << 2 | basis64[s[1]] >> 4);
    }

    if (len > 2) {
        *d++ = (u_char) (basis64[s[1]] << 4 | basis64[s[2]] >> 2);
    }

    dst->len = d - dst->data;

    return NGX_OK;
}


size_t
ngx_utf_length(ngx_str_t *utf)
{
    u_char      c;
    size_t      len;
    ngx_uint_t  i;

    for (len = 0, i = 0; i < utf->len; len++, i++) {

        c = utf->data[i];

        if (c < 0x80) {
            continue;
        }

        if (c < 0xC0) {
            /* invalid utf */
            return utf->len;
        }

        for (c <<= 1; c & 0x80; c <<= 1) {
            i++;
        }
    }

    return len;
}


uintptr_t
ngx_escape_uri(u_char *dst, u_char *src, size_t size, ngx_uint_t type)
{
    ngx_uint_t        i, n;
    uint32_t         *escape;
    static u_char     hex[] = "0123456789abcdef";

                      /* " ", "#", "%", "?", %00-%1F, %7F-%FF */

    static uint32_t   uri[] =
        { 0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                      /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
          0x80000029, /* 1000 0000 0000 0000  0000 0000 0010 1001 */

                      /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
          0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                      /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
          0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */ };

                      /* " ", "#", "%", "+", "?", %00-%1F, %7F-%FF */

    static uint32_t   args[] =
        { 0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                      /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
          0x80000829, /* 1000 0000 0000 0000  0000 1000 0010 1001 */

                      /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
          0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                      /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
          0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */ };

                      /* " ", """, "%", "'", %00-%1F, %7F-%FF */

    static uint32_t   html[] =
        { 0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                      /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
          0x800000ad, /* 0000 0000 0000 0000  0000 0000 1010 1101 */

                      /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
          0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                      /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
          0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
          0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */ };


    switch (type) {
    case NGX_ESCAPE_HTML:
        escape = html;
        break;
    case NGX_ESCAPE_ARGS:
        escape = args;
        break;
    default:
        escape = uri;
        break;
    }

    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n  = 0;

        for (i = 0; i < size; i++) {
            if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
                n++;
            }
            src++;
        }

        return (uintptr_t) n;
    }

    for (i = 0; i < size; i++) {
        if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
            *dst++ = '%';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }
    }

    return (uintptr_t) dst;
}
