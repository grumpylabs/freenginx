
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_freebsd_init.h>


/*
 * sendfile() often sends 4K pages over ethernet in 3 packets: 2x1460 and 1176
 * or in 6 packets: 5x1460 and 892.  Besides although sendfile() allows
 * to pass the header and the trailer it never sends the header or the trailer
 * with the part of the file in one packet.  So we use TCP_NOPUSH (similar
 * to Linux's TCP_CORK) to postpone the sending - it not only sends the header
 * and the first part of the file in one packet but also sends 4K pages
 * in the full packets.
 *
 * Until FreeBSD 4.5 the turning TCP_NOPUSH off does not flush
 * the pending data that less than MSS so the data is sent with 5 second delay.
 * We do not use TCP_NOPUSH on FreeBSD prior to 4.5 although it can be used
 * for non-keepalive HTTP connections.
 */


ngx_chain_t *ngx_freebsd_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    int              rc, eintr;
    char            *prev;
    ssize_t          hsize, size;
    off_t            sent;
    struct iovec    *iov;
    struct sf_hdtr   hdtr;
    ngx_err_t        err;
    ngx_array_t      header, trailer;
    ngx_hunk_t      *file;
    ngx_chain_t     *ce, *tail;

    if (!c->write->ready) {
        return in;
    }

    do {
        ce = in;
        file = NULL;
        hsize = 0;
        eintr = 0;

        ngx_init_array(header, c->pool, 10, sizeof(struct iovec),
                       NGX_CHAIN_ERROR);
        ngx_init_array(trailer, c->pool, 10, sizeof(struct iovec),
                       NGX_CHAIN_ERROR);

        /* create the iovec and coalesce the neighbouring chain entries */

        prev = NULL;
        iov = NULL;

        for (ce = in; ce; ce = ce->next) {
            if (ngx_hunk_special(ce->hunk)) {
                continue;
            }

            if (!ngx_hunk_in_memory_only(ce->hunk)) {
                break;
            }

            if (prev == ce->hunk->pos) {
                iov->iov_len += ce->hunk->last - ce->hunk->pos;
                prev = ce->hunk->last;

            } else {
                ngx_test_null(iov, ngx_push_array(&header), NGX_CHAIN_ERROR);
                iov->iov_base = ce->hunk->pos;
                iov->iov_len = ce->hunk->last - ce->hunk->pos;
                prev = ce->hunk->last;
            }

            hsize += ce->hunk->last - ce->hunk->pos;
        }

        /* TODO: coalesce the neighbouring file hunks */

        if (ce && (ce->hunk->type & NGX_HUNK_FILE)) {
            file = ce->hunk;
            ce = ce->next;
        }

        /* create the iovec and coalesce the neighbouring chain entries */

        prev = NULL;
        iov = NULL;

        for ( /* void */; ce; ce = ce->next) {
            if (ngx_hunk_special(ce->hunk)) {
                continue;
            }

            if (!ngx_hunk_in_memory_only(ce->hunk)) {
                break;
            }

            if (prev == ce->hunk->pos) {
                iov->iov_len += ce->hunk->last - ce->hunk->pos;
                prev = ce->hunk->last;

            } else {
                ngx_test_null(iov, ngx_push_array(&trailer), NGX_CHAIN_ERROR);
                iov->iov_base = ce->hunk->pos;
                iov->iov_len = ce->hunk->last - ce->hunk->pos;
                prev = ce->hunk->last;
            }
        }

        tail = ce;

        if (file) {

            if (ngx_freebsd_use_tcp_nopush && !c->tcp_nopush) {
                c->tcp_nopush = 1;

ngx_log_debug(c->log, "NOPUSH");

                if (ngx_tcp_nopush(c->fd) == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                                  ngx_tcp_nopush_n " failed");
                    return NGX_CHAIN_ERROR;
                }
            }

            hdtr.headers = (struct iovec *) header.elts;
            hdtr.hdr_cnt = header.nelts;
            hdtr.trailers = (struct iovec *) trailer.elts;
            hdtr.trl_cnt = trailer.nelts;

            if (ngx_freebsd_sendfile_nbytes_bug == 0) {
                hsize = 0;
            }

            rc = sendfile(file->file->fd, c->fd, file->file_pos,
                          (size_t) (file->file_last - file->file_pos) + hsize,
                          &hdtr, &sent, 0);

            if (rc == -1) {
                err = ngx_errno;

                if (err == NGX_EINTR) {
                    eintr = 1;
                }

                if (err == NGX_EAGAIN || err == NGX_EINTR) {
                    ngx_log_error(NGX_LOG_INFO, c->log, err,
                                  "sendfile() sent only %qd bytes", sent);

                } else {
                    ngx_log_error(NGX_LOG_CRIT, c->log, err,
                                  "sendfile() failed");
                    return NGX_CHAIN_ERROR;
                }
            }

#if (NGX_DEBUG_WRITE_CHAIN)
            ngx_log_debug(c->log, "sendfile: %d, @%qd %qd:%d" _
                          rc _ file->file_pos _ sent _
                          (size_t) (file->file_last - file->file_pos) + hsize);
#endif

        } else {
            rc = writev(c->fd, (struct iovec *) header.elts, header.nelts);

            if (rc == -1) {
                err = ngx_errno;
                if (err == NGX_EAGAIN) {
                    ngx_log_error(NGX_LOG_INFO, c->log, err, "writev() EAGAIN");

                } else if (err == NGX_EINTR) {
                    eintr = 1;
                    ngx_log_error(NGX_LOG_INFO, c->log, err, "writev() EINTR");

                } else {
                    ngx_log_error(NGX_LOG_CRIT, c->log, err, "writev() failed");
                    return NGX_CHAIN_ERROR;
                }
            }

            sent = rc > 0 ? rc : 0;

#if (NGX_DEBUG_WRITE_CHAIN)
            ngx_log_debug(c->log, "writev: %qd" _ sent);
#endif
        }

        c->sent += sent;

        for (ce = in; ce && sent > 0; ce = ce->next) {

            if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
                size = ce->hunk->last - ce->hunk->pos;
            } else {
                size = ce->hunk->file_last - ce->hunk->file_pos;
            }

            if (sent >= size) {
                sent -= size;

                if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
                    ce->hunk->pos = ce->hunk->last;
                }

                if (ce->hunk->type & NGX_HUNK_FILE) {
                    ce->hunk->file_pos = ce->hunk->file_last;
                }

                continue;
            }

            if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
                ce->hunk->pos += sent;
            }

            if (ce->hunk->type & NGX_HUNK_FILE) {
                ce->hunk->file_pos += sent;
            }

            break;
        }

        ngx_destroy_array(&trailer);
        ngx_destroy_array(&header);

        in = ce;

    } while ((tail && tail == ce) || eintr);

    if (ce) {
        c->write->ready = 0;
    }

    return ce;
}
