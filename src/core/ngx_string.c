
#include <ngx_config.h>
#include <ngx_core.h>


char *ngx_cpystrn(char *dst, char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }

    for (/* void */; --n; dst++, src++) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }
    }

    *dst = '\0';

    return dst;
}


int ngx_rstrncmp(char *s1, char *s2, size_t n)
{
    if (n == 0) {
        return 0;
    }

    n--;

    for ( ;; ) {
        if (s1[n] != s2[n]) {
            return (u_char) s1[n] - (u_char) s2[n];
        }

        if (n == 0) {
            return 0;
        }

        n--;
    }
}


int ngx_atoi(char *line, size_t n)
{
    int  value;

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


void ngx_md5_text(char *text, u_char *md5)
{
    int          i;
    static char  hex[] = "0123456789abcdef";

    for (i = 0; i < 16; i++) {
        *text++ = hex[md5[i] >> 4];
        *text++ = hex[md5[i] & 0xf];
    }

    *text = '\0';
}


#if 0
char *ngx_psprintf(ngx_pool_t *p, const char *fmt, ...)
{
    va_list    args;

    va_start(args, fmt);

    while (*fmt) {
         switch(*fmt++) {
         case '%':
             switch(*fmt++) {
             case 's':
                 s = va_arg(args, char *);
                 n += ngx_strlen(s);
                 break;

             default:
                 n++;
         }
         default:
             n++;
         }
    }

    str = ngx_palloc(p, n);

    va_start(args, fmt);

    for (i = 0; i < n; i++) {
         switch(*fmt++) {
         case '%':
             switch(*fmt++) {
             case 's':
                 s = va_arg(args, char *);
                 while (str[i++] = s);
                 break;

             default:
                 n++;
         }
         default:
             str[i] = *fmt;
         }
    }

    len += ngx_vsnprintf(errstr + len, sizeof(errstr) - len - 1, fmt, args);

    va_end(args);

}
#endif
