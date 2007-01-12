
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_WIN32_CONFIG_H_INCLUDED_
#define _NGX_WIN32_CONFIG_H_INCLUDED_


#define WIN32         0x0400
#define _WIN32_WINNT  0x0400


#define STRICT
#define WIN32_LEAN_AND_MEAN

/*
 * we need to include <windows.h> explicity before <winsock2.h> because
 * the warning 4201 is enabled in <windows.h>
 */
#include <windows.h>

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

#include <winsock2.h>
#include <mswsock.h>
#include <shellapi.h>
#include <stddef.h>    /* offsetof() */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef __WATCOMC__
#define _TIME_T_DEFINED
typedef long  time_t;
/* OpenWatcom defines time_t as "unsigned long" */
#endif

#include <time.h>      /* localtime(), strftime() */


#ifdef _MSC_VER

/* the end of the precompiled headers */
#pragma hdrstop

#pragma warning(default:4201)

/* disable some "-W4" level warnings */

/* 'type cast': from function pointer to data pointer */
#pragma warning(disable:4054)

/* 'type cast': from data pointer to function pointer */
#pragma warning(disable:4055)

/* unreferenced formal parameter */
#pragma warning(disable:4100)

/* FD_SET() and FD_CLR(): conditional expression is constant */
#pragma warning(disable:4127)

/* function 'ngx_handle_write_event' not inlined */
#pragma warning(disable:4710)

#endif


#ifdef __WATCOMC__

/* symbol 'ngx_rbtree_min' has been defined, but not referenced */
#pragma disable_message(202)

#endif


#ifdef __BORLANDC__

/* the end of the precompiled headers */
#pragma hdrstop

/* functions containing (for|while|some if) are not expanded inline */
#pragma warn -8027

/* unreferenced formal parameter */
#pragma warn -8057

#endif


#include <ngx_auto_config.h>


#define ngx_inline          __inline
#define ngx_cdecl           __cdecl


#ifdef _MSC_VER
typedef unsigned __int32    uint32_t;
typedef __int32             int32_t;
typedef unsigned __int16    uint16_t;
#define ngx_libc_cdecl      __cdecl

#elif defined __BORLANDC__
typedef unsigned __int32    uint32_t;
typedef __int32             int32_t;
typedef unsigned __int16    uint16_t;
#define ngx_libc_cdecl      __cdecl

#else /* __WATCOMC__ */
typedef unsigned int        uint32_t;
typedef int                 int32_t;
typedef unsigned short int  uint16_t;
#define ngx_libc_cdecl

#endif

typedef __int64             int64_t;
typedef unsigned __int64    uint64_t;
typedef u_int               uintptr_t;

typedef int                 ssize_t;
typedef __int64             off_t;
typedef uint32_t            in_addr_t;
typedef u_short             in_port_t;
typedef int                 sig_atomic_t;


#define NGX_PTR_SIZE            4
#define NGX_SIZE_T_LEN          sizeof("-2147483648") - 1
#define NGX_MAX_SIZE_T_VALUE    2147483647
#define NGX_TIME_T_LEN          sizeof("-2147483648") - 1
#define NGX_TIME_T_SIZE         4
#define NGX_OFF_T_LEN           sizeof("-9223372036854775807") - 1
#define NGX_MAX_OFF_T_VALUE     9223372036854775807
#define NGX_SIG_ATOMIC_T_SIZE   4


#define NGX_HAVE_LITTLE_ENDIAN  1
#define NGX_HAVE_NONALIGNED     1

#define NGX_THREADS       1


#define NGX_WIN_NT        200000


#ifndef NGX_HAVE_INHERITED_NONBLOCK
#define NGX_HAVE_INHERITED_NONBLOCK  1
#endif

#ifndef NGX_HAVE_WIN32_TRANSMITPACKETS
#define NGX_HAVE_WIN32_TRANSMITPACKETS  1
#define NGX_HAVE_WIN32_TRANSMITFILE     0
#endif

#ifndef NGX_HAVE_WIN32_TRANSMITFILE
#define NGX_HAVE_WIN32_TRANSMITFILE  1
#endif

#if (NGX_HAVE_WIN32_TRANSMITPACKETS) || (NGX_HAVE_WIN32_TRANSMITFILE)
#define NGX_HAVE_SENDFILE  1
#endif

#ifndef NGX_HAVE_SO_SNDLOWAT
/* setsockopt(SO_SNDLOWAT) returns error WSAENOPROTOOPT */
#define NGX_HAVE_SO_SNDLOWAT         0
#endif


#define ngx_random               rand


#endif /* _NGX_WIN32_CONFIG_H_INCLUDED_ */
