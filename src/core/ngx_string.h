#ifndef _NGX_STRING_H_INCLUDED_
#define _NGX_STRING_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    size_t  len;
    char   *data;
} ngx_str_t;


#define ngx_string(str)  { sizeof(str) - 1, str }
#define ngx_null_string  { 0, NULL }


#if (WIN32)

#define ngx_strncasecmp           strnicmp
#define ngx_strcasecmp            stricmp

#define ngx_snprintf              _snprintf
#define ngx_vsnprintf             _vsnprintf

#else

#define ngx_strncasecmp           strncasecmp
#define ngx_strcasecmp            strcasecmp

#define ngx_snprintf              snprintf
#define ngx_vsnprintf             vsnprintf

#endif


#define ngx_strncmp               strncmp

/* msvc and icc compile strcmp() to inline loop */
#define ngx_strcmp                strcmp

#define ngx_strstr                strstr
#define ngx_strlen                strlen

/*
 * msvc and icc compile memset() to inline "rep stos"
 * while ZeroMemory and bzero are calls.
 *
 * icc can also inline mov's of a zeroed register for small blocks.
 */
#define ngx_memzero(buf, n)       memset(buf, 0, n)

/* msvc and icc compile memcpy() to inline "rep movs" */
#define ngx_memcpy(dst, src, n)   memcpy(dst, src, n)
#define ngx_cpymem(dst, src, n)   ((char *) memcpy(dst, src, n)) + n

/* msvc and icc compile memcmp() to inline loop */
#define ngx_memcmp                memcmp

char *ngx_cpystrn(char *dst, char *src, size_t n);
int ngx_rstrncmp(char *s1, char *s2, size_t n);
int ngx_atoi(char *line, size_t n);

void ngx_md5_text(char *text, u_char *md5);


#define  ngx_qsort                qsort


#define  ngx_value_helper(n)      #n
#define  ngx_value(n)             ngx_value_helper(n)


#endif /* _NGX_STRING_H_INCLUDED_ */
