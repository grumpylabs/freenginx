#ifndef _NGX_HTTP_OUTPUT_FILTER_H_INCLUDED_
#define _NGX_HTTP_OUTPUT_FILTER_H_INCLUDED_


#include <ngx_hunk.h>
#include <ngx_conf_file.h>
#include <ngx_http.h>


#define NGX_HTTP_FILTER_NEED_IN_MEMORY      1
#define NGX_HTTP_FILTER_SSI_NEED_IN_MEMORY  2
#define NGX_HTTP_FILTER_NEED_TEMP           4


typedef struct {
    size_t        hunk_size;
} ngx_http_output_filter_conf_t;


typedef struct {
    ngx_hunk_t   *hunk;         /* the temporary hunk to copy */
    ngx_chain_t  *incoming;
    ngx_chain_t   in;           /* one chain entry for input */
    ngx_chain_t   out;          /* one chain entry for output */
} ngx_http_output_filter_ctx_t;


int ngx_http_output_filter(ngx_http_request_t *r, ngx_hunk_t *hunk);


extern ngx_module_t  ngx_http_output_filter_module;


#endif /* _NGX_HTTP_OUTPUT_FILTER_H_INCLUDED_ */
