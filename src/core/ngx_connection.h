#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_

#include <ngx_socket.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_hunk.h>
#include <ngx_array.h>
#include <ngx_string.h>
#include <ngx_server.h>

typedef struct ngx_connection_s  ngx_connection_t;

#ifdef NGX_EVENT
#include <ngx_event.h>
#endif

struct ngx_connection_s {
    ngx_socket_t     fd;
    void            *data;

#ifdef NGX_EVENT
    ngx_event_t      *read;
    ngx_event_t      *write;
#endif

    off_t             sent;

    void            (*handler)(ngx_connection_t *c);
    void             *ctx;
    ngx_server_t     *servers;

    ngx_log_t        *log;

    ngx_pool_t       *pool;
    int               pool_size;

    int               family;
    struct sockaddr  *sockaddr;
    socklen_t         socklen;
#if (HAVE_IOCP)
    struct sockaddr  *local_sockaddr;
    socklen_t         local_socklen;
    void             *listening;
#endif
    int               addr;
    int               addr_text_max_len;
    ngx_str_t         addr_text;

    ngx_hunk_t       *buffer;
    unsigned int      post_accept_timeout;

    int               number;

    unsigned          pipeline:1;
    unsigned          unexpected_eof:1;
};


#if 0
cached file
    int      fd;       -2 unused, -1 closed (but read or mmaped), >=0 open
    char    *name;

    void    *buf;      addr if read or mmaped
                       aiocb* if aio_read
                       OVERLAPPED if TransmitFile or TransmitPackets
                       NULL if sendfile

    size_t   buf_size; for plain read
    off_t    offset;   for plain read

    size_t   size;
    time_t   mod;
    char    *last_mod; 'Sun, 17 Mar 2002 19:39:50 GMT'
    char    *etag;     '"a6d08-1302-3c94f106"'
    char    *len;      '4866'

EV_VNODE        should notify by some signal if diretory tree is changed
                or stat if aged >= N seconds (big enough)
#endif


typedef struct {
    ssize_t       (*recv)(ngx_connection_t *c, char *buf, size_t size);
    void           *dummy_recv_chain;
    void           *dummy_send;
    ngx_chain_t  *(*send_chain)(ngx_connection_t *c, ngx_chain_t *in);
} ngx_os_io_t;


extern ngx_os_io_t  ngx_io;



extern ngx_chain_t *(*ngx_write_chain_proc)
                                        (ngx_connection_t *c, ngx_chain_t *in);


ssize_t ngx_recv_chain(ngx_connection_t *c, ngx_chain_t *ce);
#if 0
ngx_chain_t *ngx_write_chain(ngx_connection_t *c, ngx_chain_t *in, off_t flush);
#endif


/* TODO: move it to OS specific file */
#if (__FreeBSD__)
ngx_chain_t *ngx_freebsd_write_chain(ngx_connection_t *c, ngx_chain_t *in);
ngx_chain_t *ngx_aio_write_chain(ngx_connection_t *c, ngx_chain_t *in);
#endif


#endif /* _NGX_CONNECTION_H_INCLUDED_ */
