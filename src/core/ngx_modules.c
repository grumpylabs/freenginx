
#include <ngx_config.h>
#include <ngx_core.h>


extern ngx_module_t  ngx_core_module;
extern ngx_module_t  ngx_errlog_module;

extern ngx_module_t  ngx_events_module;
extern ngx_module_t  ngx_event_core_module;
extern ngx_module_t  ngx_select_module;
#if (HAVE_POLL)
extern ngx_module_t  ngx_poll_module;
#endif
#if (HAVE_KQUEUE)
extern ngx_module_t  ngx_kqueue_module;
#endif
#if (HAVE_DEVPOLL)
extern ngx_module_t  ngx_devpoll_module;
#endif
#if (HAVE_IOCP)
extern ngx_module_t  ngx_iocp_module;
#elif (HAVE_AIO)
extern ngx_module_t  ngx_aio_module;
#endif


extern ngx_module_t  ngx_http_module;
extern ngx_module_t  ngx_http_core_module;

extern ngx_module_t  ngx_http_write_filter_module;
extern ngx_module_t  ngx_http_output_filter_module;
extern ngx_module_t  ngx_http_header_filter_module;

extern ngx_module_t  ngx_http_chunked_filter_module;
extern ngx_module_t  ngx_http_gzip_filter_module;
extern ngx_module_t  ngx_http_not_modified_filter_module;
extern ngx_module_t  ngx_http_range_filter_module;
extern ngx_module_t  ngx_http_charset_filter_module;

extern ngx_module_t  ngx_http_static_module;
extern ngx_module_t  ngx_http_index_module;
extern ngx_module_t  ngx_http_proxy_module;

extern ngx_module_t  ngx_http_log_module;


ngx_module_t *ngx_modules[] = {

    /* core */

    &ngx_core_module,
    &ngx_errlog_module,

    /* events */

    &ngx_events_module,
    &ngx_event_core_module,

    &ngx_select_module,
#if (HAVE_POLL)
    &ngx_poll_module,
#endif
#if (HAVE_KQUEUE)
    &ngx_kqueue_module,
#endif
#if (HAVE_DEVPOLL)
    &ngx_devpoll_module,
#endif
#if (HAVE_IOCP)
    &ngx_iocp_module,
#elif (HAVE_AIO)
    &ngx_aio_module,
#endif

    /* http */

    &ngx_http_module,

    &ngx_http_core_module,
    &ngx_http_write_filter_module,
    &ngx_http_output_filter_module,
    &ngx_http_header_filter_module,

    &ngx_http_chunked_filter_module,
    &ngx_http_gzip_filter_module,
    &ngx_http_not_modified_filter_module,
    &ngx_http_range_filter_module,
    /* &ngx_http_ssi_filter_module, */
    &ngx_http_charset_filter_module,

    /* &ngx_http_static_module, */
    &ngx_http_index_module,
    &ngx_http_proxy_module,

    &ngx_http_log_module,

    NULL
};
