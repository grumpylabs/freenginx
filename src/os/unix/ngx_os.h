#ifndef _NGX_OS_H_INCLUDED_
#define _NGX_OS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_IO_SENDFILE    1
#define NGX_IO_ZEROCOPY    2

#if (HAVE_SENDFILE)
#define NGX_HAVE_SENDFILE  NGX_IO_SENDFILE
#else
#define NGX_HAVE_SENDFILE  0
#endif

#if (HAVE_ZEROCOPY)
#define NGX_HAVE_ZEROCOPY  NGX_IO_ZEROCOPY
#else
#define NGX_HAVE_ZEROCOPY  0
#endif



typedef struct {
    ssize_t       (*recv)(ngx_connection_t *c, char *buf, size_t size);
    ssize_t       (*recv_chain)(ngx_connection_t *c, ngx_chain_t *in);
    ssize_t       (*send)(ngx_connection_t *c, char *buf, size_t size);
    ngx_chain_t  *(*send_chain)(ngx_connection_t *c, ngx_chain_t *in);
    int             flags;
} ngx_os_io_t;


int ngx_os_init(ngx_log_t *log);
int ngx_daemon(ngx_log_t *log);
int ngx_posix_init(ngx_log_t *log);
int ngx_posix_post_conf_init(ngx_log_t *log);


ssize_t ngx_unix_recv(ngx_connection_t *c, char *buf, size_t size);
ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *entry);
ngx_chain_t *ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in);


extern ngx_os_io_t  ngx_os_io;
extern int          ngx_max_sockets;
extern int          ngx_inherited_nonblocking;


extern int          restart;
extern int          rotate;


#ifdef __FreeBSD__
#include <ngx_freebsd.h>
#endif


#ifdef __linux__
#include <ngx_linux.h>
#endif


#ifdef SOLARIS
#include <ngx_solaris.h>
#endif


#endif /* _NGX_OS_H_INCLUDED_ */
