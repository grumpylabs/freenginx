
#include <ngx_config.h>

#if !(HAVE_SENDFILE)

#include <ngx_core.h>
#include <ngx_log.h>
#include <ngx_socket.h>
#include <ngx_sendv.h>

int ngx_sendfile(ngx_socket_t s,
                 ngx_iovec_t *headers, int hdr_cnt,
                 ngx_fd_t fd, off_t offset, size_t nbytes,
                 ngx_iovec_t *trailers, int trl_cnt,
                 off_t *sent,
                 ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "ngx_sendfile: sendfile is not implemented");


    return NGX_ERROR;
}

#endif
