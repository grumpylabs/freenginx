#ifndef _NGX_SOCKET_H_INCLUDED_
#define _NGX_SOCKET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_log.h>

#define INET_ADDRSTRLEN     16

typedef SOCKET  ngx_socket_t;
typedef int     socklen_t;

void ngx_init_sockets(ngx_log_t *log);

#define ngx_socket(af, type, proto, flags)                                    \
            WSASocket(af, type, proto, NULL, 0, flags)
#define ngx_socket_n        "WSASocket()"

int ngx_nonblocking(ngx_socket_t s);
#define ngx_nonblocking_n   "ioctlsocket(FIONBIO)"

#define ngx_close_socket    closesocket
#define ngx_close_socket_n  "closesocket()"



#endif /* _NGX_SOCKET_H_INCLUDED_ */
