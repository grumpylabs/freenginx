
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


ssize_t
ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t  n;

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "read: %d, %p, %uz, %O", file->fd, buf, size, offset);

#if (NGX_HAVE_PREAD)

    n = pread(file->fd, buf, size, offset);

    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "pread() \"%s\" failed", file->name.data);
        return NGX_ERROR;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return NGX_ERROR;
        }

        file->sys_offset = offset;
    }

    n = read(file->fd, buf, size);

    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "read() \"%s\" failed", file->name.data);
        return NGX_ERROR;
    }

    file->sys_offset += n;

#endif

    file->offset += n;

    return n;
}


ssize_t
ngx_write_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t  n;

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "write: %d, %p, %uz, %O", file->fd, buf, size, offset);

#if (NGX_HAVE_PWRITE)

    n = pwrite(file->fd, buf, size, offset);

    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "pwrite() \"%s\" failed", file->name.data);
        return NGX_ERROR;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_CRIT, file->log, 0,
                      "pwrite() \"%s\" has written only %z of %uz",
                      file->name.data, n, size);
        return NGX_ERROR;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return NGX_ERROR;
        }

        file->sys_offset = offset;
    }

    n = write(file->fd, buf, size);

    if (n == -1) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "write() \"%s\" failed", file->name.data);
        return NGX_ERROR;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_CRIT, file->log, 0,
                      "write() \"%s\" has written only %z of %uz",
                      file->name.data, n, size);
        return NGX_ERROR;
    }

    file->sys_offset += n;

#endif

    file->offset += n;

    return n;
}


ngx_fd_t
ngx_open_tempfile(u_char *name, ngx_uint_t persistent, ngx_uint_t access)
{
    ngx_fd_t  fd;

    fd = open((const char *) name, O_CREAT|O_EXCL|O_RDWR,
              access ? access : 0600);

    if (fd != -1 && !persistent) {
        unlink((const char *) name);
    }

    return fd;
}


#define NGX_IOVS  8

ssize_t
ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *cl, off_t offset,
    ngx_pool_t *pool)
{
    u_char        *prev;
    size_t         size;
    ssize_t        n;
    ngx_array_t    vec;
    struct iovec  *iov, iovs[NGX_IOVS];

    /* use pwrite() if there is the only buf in a chain */

    if (cl->next == NULL) {
        return ngx_write_file(file, cl->buf->pos,
                              (size_t) (cl->buf->last - cl->buf->pos),
                              offset);
    }

    vec.elts = iovs;
    vec.size = sizeof(struct iovec);
    vec.nalloc = NGX_IOVS;
    vec.pool = pool;

    do {
        prev = NULL;
        iov = NULL;
        size = 0;

        vec.nelts = 0;

        /* create the iovec and coalesce the neighbouring bufs */

        while (cl && vec.nelts < IOV_MAX) {
            if (prev == cl->buf->pos) {
                iov->iov_len += cl->buf->last - cl->buf->pos;

            } else {
                iov = ngx_array_push(&vec);
                if (iov == NULL) {
                    return NGX_ERROR;
                }

                iov->iov_base = (void *) cl->buf->pos;
                iov->iov_len = cl->buf->last - cl->buf->pos;
            }

            size += cl->buf->last - cl->buf->pos;
            prev = cl->buf->last;
            cl = cl->next;
        }

        /* use pwrite() if there is the only iovec buffer */

        if (vec.nelts == 1) {
            iov = vec.elts;
            return ngx_write_file(file, (u_char *) iov[0].iov_base,
                                  iov[0].iov_len, offset);
        }

        if (file->sys_offset != offset) {
            if (lseek(file->fd, offset, SEEK_SET) == -1) {
                ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                              "lseek() \"%s\" failed", file->name.data);
                return NGX_ERROR;
            }

            file->sys_offset = offset;
        }

        n = writev(file->fd, vec.elts, vec.nelts);

        if (n == -1) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                          "writev() \"%s\" failed", file->name.data);
            return NGX_ERROR;
        }

        if ((size_t) n != size) {
            ngx_log_error(NGX_LOG_CRIT, file->log, 0,
                          "writev() \"%s\" has written only %z of %uz",
                          file->name.data, n, size);
            return NGX_ERROR;
        }

        file->sys_offset += n;
        file->offset += n;

    } while (cl);

    return n;
}


ngx_int_t
ngx_set_file_time(u_char *name, ngx_fd_t fd, time_t s)
{
    struct timeval  tv[2];

    tv[0].tv_sec = s;
    tv[0].tv_usec = 0;
    tv[1].tv_sec = s;
    tv[1].tv_usec = 0;

    if (utimes((char *) name, tv) != -1) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir)
{
    dir->dir = opendir((const char *) name->data);

    if (dir->dir == NULL) {
        return NGX_ERROR;
    }

    dir->valid_info = 0;

    return NGX_OK;
}


ngx_int_t
ngx_read_dir(ngx_dir_t *dir)
{
    dir->de = readdir(dir->dir);

    if (dir->de) {
#if (NGX_HAVE_D_TYPE)
        dir->type = dir->de->d_type;
        dir->valid_type = dir->type ? 1 : 0;
#else
        dir->valid_type = 0;
#endif
        return NGX_OK;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_open_glob(ngx_glob_t *gl)
{
    int  n;

    n = glob((char *) gl->pattern, GLOB_NOSORT, NULL, &gl->pglob);

    if (n == 0) {
        return NGX_OK;
    }

#ifdef GLOB_NOMATCH

    if (n == GLOB_NOMATCH && gl->test) {
        return NGX_OK;
    }

#endif

    return NGX_ERROR;
}


ngx_int_t
ngx_read_glob(ngx_glob_t *gl, ngx_str_t *name)
{
    size_t  count;

#ifdef GLOB_NOMATCH
    count = (size_t) gl->pglob.gl_pathc;
#else
    count = (size_t) gl->pglob.gl_matchc;
#endif

    if (gl->n < count) {

        name->len = (size_t) ngx_strlen(gl->pglob.gl_pathv[gl->n]);
        name->data = (u_char *) gl->pglob.gl_pathv[gl->n];
        gl->n++;

        return NGX_OK;
    }

    return NGX_DONE;
}


void
ngx_close_glob(ngx_glob_t *gl)
{
    globfree(&gl->pglob);
}


ngx_err_t
ngx_trylock_fd(ngx_fd_t fd)
{
    struct flock  fl;

    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        return ngx_errno;
    }

    return 0;
}


ngx_err_t
ngx_lock_fd(ngx_fd_t fd)
{
    struct flock  fl;

    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLKW, &fl) == -1) {
        return ngx_errno;
    }

    return 0;
}


ngx_err_t
ngx_unlock_fd(ngx_fd_t fd)
{
    struct flock  fl;

    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        return  ngx_errno;
    }

    return 0;
}


#if (NGX_HAVE_O_DIRECT)

ngx_int_t
ngx_directio_on(ngx_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (flags == -1) {
        return -1;
    }

    return fcntl(fd, F_SETFL, flags | O_DIRECT);
}


ngx_int_t
ngx_directio_off(ngx_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (flags == -1) {
        return -1;
    }

    return fcntl(fd, F_SETFL, flags & ~O_DIRECT);
}

#endif


#if (NGX_HAVE_STATFS)

size_t
ngx_fs_bsize(u_char *name)
{
    struct statfs  fs;

    if (statfs((char *) name, &fs) == -1) {
        return 512;
    }

    if ((fs.f_bsize % 512) != 0) {
        return 512;
    }

    return (size_t) fs.f_bsize;
}

#elif (NGX_HAVE_STATVFS)

size_t
ngx_fs_bsize(u_char *name)
{
    struct statvfs  fs;

    if (statvfs((char *) name, &fs) == -1) {
        return 512;
    }

    if ((fs.f_frsize % 512) != 0) {
        return 512;
    }

    return (size_t) fs.f_frsize;
}

#else

size_t
ngx_fs_bsize(u_char *name)
{
    return 512;
}

#endif
