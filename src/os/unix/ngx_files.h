#ifndef _NGX_FILES_H_INCLUDED_
#define _NGX_FILES_H_INCLUDED_


#include <ngx_config.h>

#include <ngx_types.h>
#include <ngx_alloc.h>
#include <ngx_hunk.h>
#include <ngx_file.h>


#define NGX_INVALID_FILE         -1
#define NGX_FILE_ERROR           -1



#define ngx_open_file            open
#define ngx_open_file_n          "open()"

#define ngx_close_file           close
#define ngx_close_file_n         "close()"

#define ngx_open_tempfile(name, persistent)                                 \
                                 open(name, O_CREAT|O_EXCL|O_RDWR, 0600)
#define ngx_open_tempfile_n      "open()"

ssize_t ngx_read_file(ngx_file_t *file, char *buf, size_t size, off_t offset);
#define ngx_read_file_n          "read()"

#define NGX_FILE_RDONLY          O_RDONLY

ssize_t ngx_write_file(ngx_file_t *file, char *buf, size_t size, off_t offset);

ssize_t ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *ce,
                                off_t offset, ngx_pool_t *pool);


#define ngx_mkdir(name)          mkdir(name, 0700)
#define ngx_mkdir_n              "mkdir()"


#define ngx_file_type(file, sb)  stat(file, sb)
#define ngx_file_type_n          "stat()"

#define ngx_stat_fd(fd, sb)      fstat(fd, sb)
#define ngx_stat_fd_n            "fstat()"

#define ngx_is_dir(sb)           (S_ISDIR(sb.st_mode))
#define ngx_is_file(sb)          (S_ISREG(sb.st_mode))
#define ngx_file_size(sb)        sb.st_size
#define ngx_file_mtime(sb)       sb.st_mtime


#endif /* _NGX_FILES_H_INCLUDED_ */
