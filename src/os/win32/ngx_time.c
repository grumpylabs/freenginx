
#include <ngx_config.h>
#include <ngx_core.h>


void ngx_gettimeofday(struct timeval *tp)
{
    uint64_t  intervals;
    FILETIME  ft;

    GetSystemTimeAsFileTime(&ft);

    /*
     * A file time is a 64-bit value that represents the number
     * of 100-nanosecond intervals that have elapsed since
     * 12:00 A.M. January 1, 1601 (UTC).
     *
     * Between January 1, 1970 (Epoch) and January 1, 1601 there are
     * 134744 days,
     * 11644473600 seconds or
     * 11644473600,000,000,0 100-nanosecond intervals.
     */

    intervals = ((uint64_t) ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    intervals -= 116444736000000000;

    tp->tv_sec = intervals / 10000000;
    tp->tv_usec = (intervals % 10000000) / 10;
}
