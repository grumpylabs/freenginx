
#include <time.h>

#define NGX_ERROR  -1

static int mday[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

time_t ngx_http_parse_time(char *value, size_t len)
{
    char  *p, *end;
    int    day, month, year, hour, min, sec;
    enum {
        no = 0,
        rfc822,   /* Tue 10 Nov 2002 23:50:13    */
        rfc850,   /* Tuesday, 10-Dec-02 23:50:13 */
        isoc      /* Tue Dec 10 23:50:13 2002    */
    } fmt;

    end = value + len;

    for (p = value; p < end; p++) {
        if (*p == ',')
            break;

        if (*p == ' ') {
            fmt = isoc;
            break;
        }
    }

    for (p++; p < end; p++)
        if (*p != ' ')
            break;

    if (end - p < 18)
        return NGX_ERROR;

    if (fmt != isoc) {
        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9')
            return NGX_ERROR;

        day = (*p - '0') * 10 + *(p + 1) - '0';
        p += 2;

        if (*p == ' ') {
            if (end - p < 18)
                return NGX_ERROR;
            fmt = rfc822;

        } else if (*p == '-') {
            fmt = rfc850;

        } else {
            return NGX_ERROR;
        }

        p++;
    }

    switch (*p) {

    case 'J':
        month = *(p + 1) == 'a' ? 0 : *(p + 2) == 'n' ? 5 : 6;
        break;

    case 'F':
        month = 1;
        break;

    case 'M':
        month = *(p + 2) == 'r' ? 2 : 4;
        break;

    case 'A':
        month = *(p + 1) == 'p' ? 3 : 7;
        break;

    case 'S':
        month = 8;
        break;

    case 'O':
        month = 9;
        break;

    case 'N':
        month = 10;
        break;

    case 'D':
        month = 11;
        break;

    default:
        return NGX_ERROR;
    }

    p += 3;

    if ((fmt == rfc822 && *p != ' ') || (fmt == rfc850 && *p != '-'))
        return NGX_ERROR;

    p++;

    if (fmt == rfc822) {
        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
            || *(p + 2) < '0' || *(p + 2) > '9'
            || *(p + 3) < '0' || *(p + 3) > '9')
            return NGX_ERROR;

        year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
               + (*(p + 2) - '0') * 10 + *(p + 3) - '0';
        p += 4;

    } else if (fmt == rfc850) {
        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9')
            return NGX_ERROR;

        year = (*p - '0') * 10 + *(p + 1) - '0';
        year += (year < 70) ? 2000 : 1900;
        p += 2;
    }

    if (fmt == isoc) {
        if (*p == ' ')
            p++;

        if (*p < '0' || *p > '9')
            return NGX_ERROR;

        day = *p++ - '0';

        if (*p != ' ') {
            if (*p < '0' || *p > '9')
                return NGX_ERROR;

            day = day * 10 + *p++ - '0';
        }

        if (end - p < 14)
            return NGX_ERROR;
    }

    if (*p++ != ' ')
        return NGX_ERROR;

    if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9')
        return NGX_ERROR;

    hour = (*p - '0') * 10 + *(p + 1) - '0';
    p += 2;

    if (*p++ != ':')
        return NGX_ERROR;

    if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9')
        return NGX_ERROR;

    min = (*p - '0') * 10 + *(p + 1) - '0';
    p += 2;

    if (*p++ != ':')
        return NGX_ERROR;

    if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9')
        return NGX_ERROR;

    sec = (*p - '0') * 10 + *(p + 1) - '0';

    if (fmt == isoc) {
        p += 2;

        if (*p++ != ' ')
            return NGX_ERROR;

        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
            || *(p + 2) < '0' || *(p + 2) > '9'
            || *(p + 3) < '0' || *(p + 3) > '9')
            return NGX_ERROR;

        year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
               + (*(p + 2) - '0') * 10 + *(p + 3) - '0';
    }

    printf("%d.%d.%d %d:%d:%d\n", day, month + 1, year, hour, min, sec);

    if (hour > 23 || min > 60 || sec > 60)
         return NGX_ERROR;

    if (day == 29 && month == 1) {
        if ((year & 3) || ((year % 100 == 0) && (year % 400) != 0))
            return NGX_ERROR;

    } else if (day > mday[month])
        return NGX_ERROR;
    }

    if (sizeof(time_t) <= 4 && year >= 2038)
        return NGX_ERROR;

    if (--month <= 0) {
       month += 12;
       year -= 1;
    }

    return year / 4 - year / 100 + year / 400
           + 367 * month / 12 + day + year * 365 - 719499;
}

char zero[] = "Sun, 01 Jan 1970 08:49:30";
char one[]  = "Sunday, 11-Dec-02 08:49:30";
char two[]  = "Sun Mar 1 08:49:37 2000";
char thr[]  = "Sun Dec 11 08:49:37 2002";

main()
{
    int rc;

    rc = ngx_http_parse_time(zero, sizeof(zero) - 1);
    printf("rc: %d\n", rc);

    rc = ngx_http_parse_time(one, sizeof(one) - 1);
    printf("rc: %d\n", rc);

    rc = ngx_http_parse_time(two, sizeof(two) - 1);
    printf("rc: %d\n", rc);

    rc = ngx_http_parse_time(thr, sizeof(thr) - 1);
    printf("rc: %d\n", rc);
}
