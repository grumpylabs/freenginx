#ifndef _NGX_FILE_H_INCLUDED_
#define _NGX_FILE_H_INCLUDED_


#include <sys/types.h>
#include <sys/stat.h>

typedef int                      ngx_file_t;
typedef struct stat              ngx_file_info_t;


#define ngx_open_file            open
#define ngx_open_file_n          "open"

#define NGX_FILE_RDONLY          O_RDONLY


#define ngx_file_type(file, sb)  stat(file, sb)
#define ngx_file_type_n          "stat"

#define ngx_stat_fd(fd, sb)      fstat(fd, sb)
#define ngx_stat_fd_n            "fstat"

#define ngx_is_dir(sb)           (S_ISDIR(sb.st_mode))
#define ngx_file_size(sb)        sb.st_size
#define ngx_file_mtime(sb)       sb.st_mtime


#endif /* _NGX_FILE_H_INCLUDED_ */
