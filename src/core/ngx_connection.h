#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_

#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_server.h>

typedef struct ngx_connection_s  ngx_connection_t;

#ifdef NGX_EVENT
#include <ngx_event.h>
#endif

struct ngx_connection_s {
    ngx_socket_t      fd;
    void            *data;

#ifdef NGX_EVENT
    ngx_event_t      *read;
    ngx_event_t      *write;
#endif

    ngx_log_t        *log;
    ngx_server_t     *server;
    ngx_server_t     *servers;
    ngx_pool_t       *pool;
};


/*

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
*/

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
