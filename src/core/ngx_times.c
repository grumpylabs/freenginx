
#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_THREADS)
static ngx_mutex_t  *ngx_time_mutex;
#endif


ngx_epoch_msec_t    ngx_elapsed_msec;
ngx_epoch_msec_t    ngx_old_elapsed_msec;
ngx_epoch_msec_t    ngx_start_msec;

volatile time_t     ngx_cached_time;

volatile ngx_str_t  ngx_cached_err_log_time;
volatile ngx_str_t  ngx_cached_http_time;
volatile ngx_str_t  ngx_cached_http_log_time;

static ngx_tm_t     ngx_cached_gmtime;
static ngx_int_t    ngx_gmtoff;

static u_char       cached_err_log_time0[] = "1970/09/28 12:00:00";
static u_char       cached_err_log_time1[] = "1970/09/28 12:00:00";

static u_char       cached_http_time0[] = "Mon, 28 Sep 1970 06:00:00 GMT";
static u_char       cached_http_time1[] = "Mon, 28 Sep 1970 06:00:00 GMT";

static u_char       cached_http_log_time0[] = "28/Sep/1970:12:00:00 +0600";
static u_char       cached_http_log_time1[] = "28/Sep/1970:12:00:00 +0600";


static char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fir", "Sat" };
static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };


void ngx_time_init()
{
    struct timeval  tv;

    ngx_memzero(&ngx_cached_gmtime, sizeof(ngx_tm_t));
#ifdef ngx_tm_zone
    ngx_cached_gmtime.ngx_tm_zone = "GMT";
#endif

    ngx_cached_err_log_time.len = sizeof(cached_err_log_time0) - 1;
    ngx_cached_err_log_time.data = cached_err_log_time0;

    ngx_cached_http_time.len = sizeof(cached_http_time0) - 1;
    ngx_cached_http_time.data = cached_http_time0;

    ngx_cached_http_log_time.len = sizeof(cached_http_log_time0) - 1;
    ngx_cached_http_log_time.data = cached_http_log_time0;

    ngx_cached_time = 0;

    ngx_gettimeofday(&tv);

    ngx_start_msec = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    ngx_old_elapsed_msec = 0;
    ngx_elapsed_msec = 0;

#if !(WIN32)
    tzset();
#endif

    ngx_time_update(tv.tv_sec);
}


#if (NGX_THREADS)

ngx_int_t ngx_time_mutex_init(ngx_log_t *log)
{
    if (!(ngx_time_mutex = ngx_mutex_init(log, NGX_MUTEX_LIGHT))) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif


void ngx_time_update(time_t s)
{
    u_char    *p;
    ngx_tm_t   tm;

    if (ngx_cached_time == s) {
        return;
    }

#if (NGX_THREADS)
    if (ngx_mutex_trylock(ngx_time_mutex) != NGX_OK) {
        return;
    }
#endif

    ngx_cached_time = s;

    ngx_gmtime(ngx_cached_time, &ngx_cached_gmtime);


    if (ngx_cached_http_time.data == cached_http_time0) {
        p = cached_http_time1;
    } else {
        p = cached_http_time0;
    }

    ngx_snprintf((char *) p, sizeof("Mon, 28 Sep 1970 06:00:00 GMT"),
                 "%s, %02d %s %4d %02d:%02d:%02d GMT",
                 week[ngx_cached_gmtime.ngx_tm_wday],
                 ngx_cached_gmtime.ngx_tm_mday,
                 months[ngx_cached_gmtime.ngx_tm_mon - 1],
                 ngx_cached_gmtime.ngx_tm_year,
                 ngx_cached_gmtime.ngx_tm_hour,
                 ngx_cached_gmtime.ngx_tm_min,
                 ngx_cached_gmtime.ngx_tm_sec);

    ngx_cached_http_time.data = p;


#if (HAVE_TIMEZONE)

    ngx_gmtoff = ngx_timezone();
    ngx_gmtime(ngx_cached_time + ngx_gmtoff * 60, &tm);

#else

    ngx_localtime(&tm);
    ngx_gmtoff = tm.ngx_tm_gmtoff / 60;

#endif


    if (ngx_cached_err_log_time.data == cached_err_log_time0) {
        p = cached_err_log_time1;
    } else {
        p = cached_err_log_time0;
    }

    ngx_snprintf((char *) p, sizeof("1970/09/28 12:00:00"),
                 "%4d/%02d/%02d %02d:%02d:%02d",
                 tm.ngx_tm_year, tm.ngx_tm_mon,
                 tm.ngx_tm_mday, tm.ngx_tm_hour,
                 tm.ngx_tm_min, tm.ngx_tm_sec);

    ngx_cached_err_log_time.data = p;


    if (ngx_cached_http_log_time.data == cached_http_log_time0) {
        p = cached_http_log_time1;
    } else {
        p = cached_http_log_time0;
    }

    ngx_snprintf((char *) p, sizeof("28/Sep/1970:12:00:00 +0600"),
                 "%02d/%s/%d:%02d:%02d:%02d %c%02d%02d",
                 tm.ngx_tm_mday, months[tm.ngx_tm_mon - 1],
                 tm.ngx_tm_year, tm.ngx_tm_hour,
                 tm.ngx_tm_min, tm.ngx_tm_sec,
                 ngx_gmtoff < 0 ? '-' : '+',
                 abs(ngx_gmtoff / 60), abs(ngx_gmtoff % 60));

    ngx_cached_http_log_time.data = p;


#if (NGX_THREADS)
    ngx_mutex_unlock(ngx_time_mutex);
#endif

}


size_t ngx_http_time(u_char *buf, time_t t)
{
    ngx_tm_t  tm;

    ngx_gmtime(t, &tm);

    return ngx_snprintf((char *) buf, sizeof("Mon, 28 Sep 1970 06:00:00 GMT"),
                                       "%s, %02d %s %4d %02d:%02d:%02d GMT",
                                       week[tm.ngx_tm_wday],
                                       tm.ngx_tm_mday,
                                       months[tm.ngx_tm_mon - 1],
                                       tm.ngx_tm_year,
                                       tm.ngx_tm_hour,
                                       tm.ngx_tm_min,
                                       tm.ngx_tm_sec);
}


void ngx_gmtime(time_t t, ngx_tm_t *tp)
{
    ngx_int_t  sec, min, hour, mday, mon, year, wday, yday, days;

    days = t / 86400;

    /* Jaunary 1, 1970 was Thursday */
    wday = (4 + days) % 7;

    t %= 86400;
    hour = t / 3600;
    t %= 3600;
    min = t / 60;
    sec = t % 60;

    /* the algorithm based on Gauss's formula */

    days = days - (31 + 28) + 719527;

    year = days * 400 / (365 * 400 + 100 - 4 + 1);
    yday = days - (365 * year + year / 4 - year / 100 + year / 400);

    mon = (yday + 31) * 12 / 367;
    mday = yday - (mon * 367 / 12 - 31);

    mon += 2;

    if (yday >= 306) {
        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday -= 306;
         */

        year++;
        mon -= 12;

        if (mday == 0) {
            /* Jaunary 31 */
            mon = 1;
            mday = 31;

        } else if (mon == 2) {

            if ((year % 4 == 0) && (year % 100 || (year % 400 == 0))) {
                if (mday > 29) {
                    mon = 3;
                    mday -= 29;
                }

            } else if (mday > 28) {
                mon = 3;
                mday -= 28;
            }
        }

/*
 *  there is no "yday" in Win32 SYSTEMTIME
 *
 *  } else {
 *      yday += 31 + 28;
 *
 *      if ((year % 4 == 0) && (year % 100 || (year % 400 == 0))) {
 *           yday++;
 *      }
 */
    }

    tp->ngx_tm_sec = (ngx_tm_sec_t) sec;
    tp->ngx_tm_min = (ngx_tm_min_t) min;
    tp->ngx_tm_hour = (ngx_tm_hour_t) hour;
    tp->ngx_tm_mday = (ngx_tm_mday_t) mday;
    tp->ngx_tm_mon = (ngx_tm_mon_t) mon;
    tp->ngx_tm_year = (ngx_tm_year_t) year;
    tp->ngx_tm_wday = (ngx_tm_wday_t) wday;
}
