
#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_hunk.h>
#include <ngx_connection.h>
#include <ngx_sendv.h>
#include <ngx_sendfile.h>
#include <ngx_event_write.h>


ngx_chain_t *ngx_event_writer(ngx_connection_t *cn, ngx_chain_t *in,
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

    ngx_test_null(header, ngx_create_array(cn->pool, 10, sizeof(ngx_iovec_t)),
                  (ngx_chain_t *) -1);

    ngx_test_null(trailer, ngx_create_array(cn->pool, 10, sizeof(ngx_iovec_t)),
                  (ngx_chain_t *) -1);

    do {
        header->nelts = 0;
        trailer->nelts = 0;

        if (ch->hunk->type & (NGX_HUNK_IN_MEMORY | NGX_HUNK_FLUSH)) {
            last = NULL;
            iov = NULL;

            while (ch
                   && (ch->hunk->type & (NGX_HUNK_IN_MEMORY | NGX_HUNK_FLUSH)))
            {
                if (ch->hunk->type & NGX_HUNK_FLUSH)
                    continue;

                if (last == ch->hunk->pos.p) {
                    iov->ngx_iov_len += ch->hunk->last.p - ch->hunk->pos.p;

                } else {
                    ngx_test_null(iov, ngx_push_array(header),
                                  (ngx_chain_t *) -1);
                    iov->ngx_iov_base = ch->hunk->pos.p;
                    iov->ngx_iov_len = ch->hunk->last.p - ch->hunk->pos.p;
                    last = ch->hunk->last.p;
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
            rc = ngx_sendv(cn->fd, (ngx_iovec_t *) header->elts, header->nelts,
                           &sent);
        } else {
#endif
            if (ch && ch->hunk->type & (NGX_HUNK_IN_MEMORY | NGX_HUNK_FLUSH)) {
                last = NULL;
                iov = NULL;

                while (ch
                   && (ch->hunk->type & (NGX_HUNK_IN_MEMORY | NGX_HUNK_FLUSH)))
                {
                    if (ch->hunk->type & NGX_HUNK_FLUSH)
                        continue;

                    if (last == ch->hunk->pos.p) {
                        iov->ngx_iov_len += ch->hunk->last.p - ch->hunk->pos.p;

                    } else {
                        ngx_test_null(iov, ngx_push_array(trailer),
                                      (ngx_chain_t *) -1);
                        iov->ngx_iov_base = ch->hunk->pos.p;
                        iov->ngx_iov_len = ch->hunk->last.p - ch->hunk->pos.p;
                        last = ch->hunk->last.p;
                    }

                    ch = ch->next;
                }
            }

            if (file) {
                rc = ngx_sendfile(cn->fd,
                                  (ngx_iovec_t *) header->elts, header->nelts,
                                  file->fd, file->pos.f,
                                          (size_t) (file->last.f - file->pos.f),
                                  (ngx_iovec_t *) trailer->elts, trailer->nelts,
                                  &sent, cn->log);
            } else {
                rc = ngx_sendv(cn->fd, (ngx_iovec_t *) header->elts,
                               header->nelts, (size_t *) &sent);
            }
#if (HAVE_MAX_SENDFILE_IOVEC)
        }
#endif
        /* save sent for logging */

        if (rc == -1)
            return (ngx_chain_t *) -1;

        flush -= sent;

        for (ch = in; ch && !(ch->hunk->type & NGX_HUNK_LAST); ch = ch->next) {
            if (sent >= ch->hunk->last.f - ch->hunk->pos.f) {
                sent -= ch->hunk->last.f - ch->hunk->pos.f;
                ch->hunk->last.f = ch->hunk->pos.f;
                    continue;
            }

            ch->hunk->pos.f += sent;
            break;
        }

    } while (flush > 0);

    ngx_destroy_array(trailer);
    ngx_destroy_array(header);

    return ch;
}
