#ifndef _NGX_EVENT_PROXY_H_INCLUDED_
#define _NGX_EVENT_PROXY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_event_proxy_s  ngx_event_proxy_t;

typedef int (*ngx_event_proxy_input_filter_pt)(ngx_event_proxy_t *p,
                                                          ngx_chain_t *chain);
typedef int (*ngx_event_proxy_output_filter_pt)(void *data, ngx_hunk_t *hunk);


struct ngx_event_proxy_s {
    ngx_chain_t       *read_hunks;
    ngx_chain_t       *last_read_hunk;

    ngx_chain_t       *file_hunks;

    ngx_chain_t       *in_hunks;
    ngx_chain_t       *last_in_hunk;

    ngx_chain_t       *out_hunks;
    ngx_chain_t       *last_out_hunk;

    ngx_chain_t       *free_hunks;
#if 0
    ngx_chain_t       *last_free_hunk;
#endif

    ngx_hunk_t        *busy_hunk;

    ngx_event_proxy_input_filter_pt   input_filter;
    void              *input_data;

    ngx_event_proxy_output_filter_pt  output_filter;
    void              *output_data;

    unsigned           cachable:1;
    unsigned           block_upstream:1;
    unsigned           upstream_eof:1;
    unsigned           upstream_error:1;
    unsigned           downstream_eof:1;
    unsigned           downstream_error:1;

    int                upstream_level;
    int                downstream_level;

    int                hunks;
    ngx_bufs_t         bufs;

    off_t              temp_offset;
    off_t              max_temp_file_size;
    int                temp_file_write_size;

    ngx_connection_t  *upstream;
    ngx_connection_t  *downstream;

    ngx_pool_t        *pool;
    ngx_log_t         *log;

    ngx_chain_t       *preread_hunks;
#if 0
    ngx_chain_t       *last_preread_hunk;
#endif
    int                preread_size;

    ngx_file_t        *temp_file;
    ngx_path_t        *temp_path;
    char              *temp_file_warn;
};


int ngx_event_proxy_read_upstream(ngx_event_proxy_t *p);
int ngx_event_proxy_write_to_downstream(ngx_event_proxy_t *p);
int ngx_event_proxy_copy_input_filter(ngx_event_proxy_t *p, ngx_chain_t *chain);


#endif /* _NGX_EVENT_PROXY_H_INCLUDED_ */
