
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_hunk.h>
#include <ngx_connection.h>
#include <ngx_sendv.h>
#include <ngx_sendfile.h>
#include <ngx_event_write.h>


ngx_chain_t *ngx_event_write(ngx_connection_t *c, ngx_chain_t *in,
                             off_t flush)
{
    int           rc;
    char         *last;
    off_t         sent;
    ngx_iovec_t  *iov;
    ngx_array_t  *header, *trailer;
    ngx_hunk_t   *file;
    ngx_chain_t  *ch;

    ch = in;
    file = NULL;

    ngx_test_null(header, ngx_create_array(c->pool, 10, sizeof(ngx_iovec_t)),
                  (ngx_chain_t *) -1);

    ngx_test_null(trailer, ngx_create_array(c->pool, 10, sizeof(ngx_iovec_t)),
                  (ngx_chain_t *) -1);

    do {
        header->nelts = 0;
        trailer->nelts = 0;

        if (ch->hunk->type & NGX_HUNK_IN_MEMORY) {
            last = NULL;
            iov = NULL;

            while (ch && (ch->hunk->type & NGX_HUNK_IN_MEMORY))
            {
                if (last == ch->hunk->pos.mem) {
                    iov->ngx_iov_len += ch->hunk->last.mem - ch->hunk->pos.mem;

                } else {
                    ngx_test_null(iov, ngx_push_array(header),
                                  (ngx_chain_t *) -1);
                    iov->ngx_iov_base = ch->hunk->pos.mem;
                    iov->ngx_iov_len = ch->hunk->last.mem - ch->hunk->pos.mem;
                    last = ch->hunk->last.mem;
                }

                ch = ch->next;
            }
        }

        if (ch && (ch->hunk->type & NGX_HUNK_FILE)) {
            file = ch->hunk;
            ch = ch->next;
        }

#if (HAVE_MAX_SENDFILE_IOVEC)
        if (file && header->nelts > HAVE_MAX_SENDFILE_IOVEC) {
            rc = ngx_sendv(c->fd, (ngx_iovec_t *) header->elts, header->nelts,
                           &sent);
        } else {
#endif
            if (ch && ch->hunk->type & NGX_HUNK_IN_MEMORY) {
                last = NULL;
                iov = NULL;

                while (ch && (ch->hunk->type & NGX_HUNK_IN_MEMORY)) {

                    if (last == ch->hunk->pos.mem) {
                        iov->ngx_iov_len +=
                                        ch->hunk->last.mem - ch->hunk->pos.mem;

                    } else {
                        ngx_test_null(iov, ngx_push_array(trailer),
                                      (ngx_chain_t *) -1);
                        iov->ngx_iov_base = ch->hunk->pos.mem;
                        iov->ngx_iov_len =
                                        ch->hunk->last.mem - ch->hunk->pos.mem;
                        last = ch->hunk->last.mem;
                    }

                    ch = ch->next;
                }
            }

            if (file) {
                rc = ngx_sendfile(c->fd,
                                  (ngx_iovec_t *) header->elts, header->nelts,
                                  file->file->fd, file->pos.file,
                                  (size_t) (file->last.file - file->pos.file),
                                  (ngx_iovec_t *) trailer->elts, trailer->nelts,
                                  &sent, c->log);
            } else {
                size_t sendv_sent;

                sendv_sent = 0;
                rc = ngx_sendv(c->fd, (ngx_iovec_t *) header->elts,
                               header->nelts, &sendv_sent);
                sent = sendv_sent;
                ngx_log_debug(c->log, "sendv: " QD_FMT _ sent);
            }
#if (HAVE_MAX_SENDFILE_IOVEC)
        }
#endif
        /* save sent for logging */

        if (rc == NGX_ERROR)
            return (ngx_chain_t *) -1;

        c->sent = sent;
        flush -= sent;

        for (ch = in; ch; ch = ch->next) {

            ngx_log_debug(c->log, "ch event write: %x %qx %qd" _
                          ch->hunk->type _
                          ch->hunk->pos.file _
                          ch->hunk->last.file - ch->hunk->pos.file);

            if (sent >= ch->hunk->last.file - ch->hunk->pos.file) {
                sent -= ch->hunk->last.file - ch->hunk->pos.file;
                ch->hunk->pos.file = ch->hunk->last.file;

                ngx_log_debug(c->log, "event write: " QX_FMT " 0 " QD_FMT _
                              ch->hunk->pos.file _ sent);

/*
                if (ch->hunk->type & NGX_HUNK_LAST)
                   break;
*/

                continue;
            }

            ch->hunk->pos.file += sent;

            ngx_log_debug(c->log, "event write: %qx %qd" _
                          ch->hunk->pos.file _
                          ch->hunk->last.file - ch->hunk->pos.file);

            break;
        }

    /* flush hunks if threaded state */
    } while (c->write->context && flush > 0);

    ngx_destroy_array(trailer);
    ngx_destroy_array(header);

    return ch;
}
