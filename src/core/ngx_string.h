#ifndef _NGX_STRING_H_INCLUDED_
#define _NGX_STRING_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    size_t    len;
    u_char   *data;
} ngx_str_t;


#define ngx_string(str)  { sizeof(str) - 1, (u_char *) str }
#define ngx_null_string  { 0, NULL }


#if (WIN32)

#define ngx_strncasecmp           strnicmp
#define ngx_strcasecmp            stricmp

#define ngx_snprintf              _snprintf
#define ngx_vsnprintf             _vsnprintf

#else

#define ngx_strncasecmp(s1, s2, n)                                           \
                          strncasecmp((const char *) s1, (const char *) s2, n)
#define ngx_strcasecmp(s1, s2)                                               \
                          strcasecmp((const char *) s1, (const char *) s2)

#define ngx_snprintf              snprintf
#define ngx_vsnprintf             vsnprintf

#endif


#define ngx_strncmp(s1, s2, n)                                               \
                          strncmp((const char *) s1, (const char *) s2, n)

/* msvc and icc compile strcmp() to inline loop */
#define ngx_strcmp(s1, s2)        strcmp((const char *) s1, (const char *) s2)

#define ngx_strstr(s1, s2)        strstr((const char *) s1, (const char *) s2)
#define ngx_strlen(s)             strlen((const char *) s)

/*
 * msvc and icc compile memset() to inline "rep stos"
 * while ZeroMemory and bzero are calls.
 *
 * icc can also inline mov's of a zeroed register for small blocks.
 */
#define ngx_memzero(buf, n)       memset(buf, 0, n)

/* msvc and icc compile memcpy() to inline "rep movs" */
#define ngx_memcpy(dst, src, n)   memcpy(dst, src, n)
#define ngx_cpymem(dst, src, n)   ((u_char *) memcpy(dst, src, n)) + n

/* msvc and icc compile memcmp() to inline loop */
#define ngx_memcmp                memcmp

u_char *ngx_cpystrn(u_char *dst, u_char *src, size_t n);
ngx_int_t ngx_rstrncmp(u_char *s1, u_char *s2, size_t n);
ngx_int_t ngx_atoi(u_char *line, size_t n);

void ngx_md5_text(u_char *text, u_char *md5);


#define  ngx_qsort                qsort


#define  ngx_value_helper(n)      #n
#define  ngx_value(n)             ngx_value_helper(n)


#endif /* _NGX_STRING_H_INCLUDED_ */
