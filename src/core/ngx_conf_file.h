#ifndef _NGX_HTTP_CONF_FILE_H_INCLUDED_
#define _NGX_HTTP_CONF_FILE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 *        AAAA  number of agruments
 *      FF      command flags
 *    TT        command type, i.e. HTTP "location" or "server" command
 */

#define NGX_CONF_NOARGS      0x00000001
#define NGX_CONF_TAKE1       0x00000002
#define NGX_CONF_TAKE2       0x00000004
#define NGX_CONF_ARGS_NUMBER 0x0000ffff
#define NGX_CONF_ANY         0x00010000
#define NGX_CONF_1MORE       0x00020000
#define NGX_CONF_BLOCK       0x00040000
#define NGX_CONF_FLAG        0x00080000

#define NGX_MAIN_CONF        0x01000000



#define NGX_CONF_UNSET       -1


#define NGX_CONF_OK          NULL
#define NGX_CONF_ERROR       (void *) -1

#define NGX_CONF_BLOCK_DONE  1
#define NGX_CONF_FILE_DONE   2

#define NGX_MODULE           0, 0

#define NGX_CORE_MODULE      0x45524F43  /* "CORE" */
#define NGX_CONF_MODULE      0x464E4F43  /* "CONF" */


#define MAX_CONF_ERRSTR      256
extern  char ngx_conf_errstr[MAX_CONF_ERRSTR];


struct ngx_command_s {
    ngx_str_t  name;
    int        type;
    char    *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
    int        conf;
    int        offset;
    void      *bounds;
};

#define ngx_null_command   {ngx_null_string, 0, NULL, 0, 0, NULL}


struct ngx_open_file_s {
    ngx_fd_t   fd;
    ngx_str_t  name;
};


struct ngx_cycle_s {
    void         ****conf_ctx;
    ngx_pool_t      *pool;
    ngx_log_t       *log;
    ngx_array_t      listening;
    ngx_array_t      open_files;

    unsigned         one_process:1;
};


struct ngx_module_s {
    int             ctx_index;
    int             index;
    void           *ctx;
    ngx_command_t  *commands;
    int             type;
    int           (*init_module)(ngx_cycle_t *cycle, ngx_log_t *log);
    int           (*commit_module)(ngx_cycle_t *cycle, ngx_log_t *log);
    int           (*rollback_module)(ngx_cycle_t *cycle, ngx_log_t *log);
};


typedef struct {
    ngx_file_t   file;
    ngx_hunk_t  *hunk;
    int          line;
} ngx_conf_file_t;


typedef char *(*ngx_conf_handler_pt)(ngx_conf_t *cf,
                                     ngx_command_t *dummy, void *conf);


struct ngx_conf_s {
    char                 *name;
    ngx_array_t          *args;

    ngx_cycle_t          *cycle;
    ngx_pool_t           *pool;
    ngx_conf_file_t      *conf_file;
    ngx_log_t            *log;

    void                 *ctx;
    int                   module_type;
    int                   cmd_type;

    ngx_conf_handler_pt   handler;
    char                 *handler_conf;
};


#define ngx_get_conf(module)  ngx_conf_ctx[module.index]


#define ngx_conf_init_value(conf, default)                                   \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = default;                                                      \
    }

#define ngx_conf_init_unsigned_value(conf, default)                          \
    if (conf == (unsigned) NGX_CONF_UNSET) {                                 \
        conf = default;                                                      \
    }

#define ngx_conf_init_size_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = default;                                                      \
    }

#define ngx_conf_init_msec_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = default;                                                      \
    }

#define ngx_conf_merge_value(conf, prev, default)                            \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_msec_value(conf, prev, default)                       \
    if (conf == (ngx_msec_t) NGX_CONF_UNSET) {                               \
        conf = (prev == (ngx_msec_t) NGX_CONF_UNSET) ? default : prev;       \
    }

#define ngx_conf_merge_size_value(conf, prev, default)                       \
    if (conf == (ssize_t) NGX_CONF_UNSET) {                                   \
        conf = (prev == (ssize_t) NGX_CONF_UNSET) ? default : prev;           \
    }

#define ngx_conf_merge_str_value(conf, prev, default)                        \
    if (conf.len == 0) {                                                     \
        if (prev.len) {                                                      \
            conf.len = prev.len;                                             \
            conf.data = prev.data;                                           \
        } else {                                                             \
            conf.len = sizeof(default) - 1;                                  \
            conf.data = default;                                             \
        }                                                                    \
    }


#define addressof(addr)  ((int) &addr)


char *ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename);


char *ngx_conf_set_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_time_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


extern ngx_module_t     *ngx_modules[];
extern void          ****ngx_conf_ctx;


#endif /* _NGX_HTTP_CONF_FILE_H_INCLUDED_ */
