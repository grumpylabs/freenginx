
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_CONFIG_H_INCLUDED_
#define _NGX_CONFIG_H_INCLUDED_


#include <ngx_auto_headers.h>


#if defined __DragonFly__ && !defined __FreeBSD__
#define __FreeBSD__        4
#define __FreeBSD_version  480101
#endif


#if (NGX_FREEBSD)
#include <ngx_freebsd_config.h>


#elif (NGX_LINUX)
#include <ngx_linux_config.h>


#elif (NGX_SOLARIS)
#include <ngx_solaris_config.h>


#elif (NGX_WIN32)
#include <ngx_win32_config.h>


#else /* POSIX */
#include <ngx_posix_config.h>

#endif


#ifndef NGX_HAVE_SO_SNDLOWAT
#define NGX_HAVE_SO_SNDLOWAT     1
#endif


#if !(NGX_WIN32)

#define ngx_signal_helper(n)     SIG##n
#define ngx_signal_value(n)      ngx_signal_helper(n)

/* TODO: #ifndef */
#define NGX_SHUTDOWN_SIGNAL      QUIT
#define NGX_TERMINATE_SIGNAL     TERM
#define NGX_NOACCEPT_SIGNAL      WINCH
#define NGX_RECONFIGURE_SIGNAL   HUP

#if (NGX_LINUXTHREADS)
#define NGX_REOPEN_SIGNAL        INFO
#define NGX_CHANGEBIN_SIGNAL     XCPU
#else
#define NGX_REOPEN_SIGNAL        USR1
#define NGX_CHANGEBIN_SIGNAL     USR2
#endif

#define ngx_cdecl
#define ngx_libc_cdecl

#endif



/* TODO: platform specific: array[NGX_INVALID_ARRAY_INDEX] must cause SIGSEGV */
#define NGX_INVALID_ARRAY_INDEX 0x80000000


#if 1
/* STUB: autoconf */
typedef int                ngx_int_t;
typedef u_int              ngx_uint_t;
typedef int                ngx_flag_t;
#define NGX_INT_T_LEN      sizeof("-2147483648") - 1

#else

typedef long               ngx_int_t;
typedef u_long             ngx_uint_t;
typedef long               ngx_flag_t;
#define NGX_INT_T_LEN      sizeof("-9223372036854775808") - 1

#endif

#define NGX_INT32_LEN      sizeof("-2147483648") - 1
#define NGX_INT64_LEN      sizeof("-9223372036854775808") - 1


#if (NGX_SOLARIS)
#define NGX_ALIGN       (_MAX_ALIGNMENT - 1)
#else
/* TODO: auto_conf */
#define NGX_ALIGN       (sizeof(unsigned long) - 1)  /* platform word */
#endif

#define ngx_align(p)    (u_char *) (((uintptr_t) p + NGX_ALIGN) & ~NGX_ALIGN)


/* TODO: auto_conf: ngx_inline   inline __inline __inline__ */
#ifndef ngx_inline
#define ngx_inline   __inline
#endif

#define NGX_ACCEPT_THRESHOLD   100

#ifndef INADDR_NONE  /* Solaris */
#define INADDR_NONE  ((unsigned int) -1)
#endif

#ifndef INET_ADDRSTRLEN  /* Win32 */
#define INET_ADDRSTRLEN  16
#endif

#define NGX_MAXHOSTNAMELEN 64
/*
#define NGX_MAXHOSTNAMELEN MAXHOSTNAMELEN
*/


#if ((__GNU__ == 2) && (__GNUC_MINOR__ < 8))
#define NGX_MAX_UINT32_VALUE  0xffffffffLL
#else
#define NGX_MAX_UINT32_VALUE  0xffffffff
#endif


#endif /* _NGX_CONFIG_H_INCLUDED_ */
