#ifndef _NGX_TIME_H_INCLUDED_
#define _NGX_TIME_H_INCLUDED_


#include <windows.h>

typedef unsigned int   ngx_msec_t;

typedef SYSTEMTIME     ngx_tm_t;
typedef FILETIME       ngx_mtime_t;

#define ngx_tm_sec     wSecond
#define ngx_tm_min     wMinute
#define ngx_tm_hour    wHour
#define ngx_tm_mday    wDay
#define ngx_tm_mon     wMonth
#define ngx_tm_year    wYear
#define ngx_tm_wday    wDayOfWeek

#define ngx_msleep     Sleep
#define ngx_localtime  GetLocalTime
#define ngx_msec       GetTickCount


#endif /* _NGX_TIME_H_INCLUDED_ */
