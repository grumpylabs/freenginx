
#include <ngx_config.h>
#include <ngx_core.h>


char ngx_solaris_sysname[20];
char ngx_solaris_release[10];
char ngx_solaris_version[50];


ngx_os_io_t ngx_os_io = {
    ngx_unix_recv,
    NULL,
    NULL,
    ngx_writev_chain,
    0
};


int ngx_os_init(ngx_log_t *log)
{
    if (sysinfo(SI_SYSNAME, ngx_solaris_sysname, sizeof(ngx_solaris_sysname))
                                                                         == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, log, errno, "sysinfo(SI_SYSNAME) failed");
        return NGX_ERROR;
    }

    if (sysinfo(SI_RELEASE, ngx_solaris_release, sizeof(ngx_solaris_release))
                                                                         == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, log, errno, "sysinfo(SI_RELEASE) failed");
        return NGX_ERROR;
    }

    if (sysinfo(SI_VERSION, ngx_solaris_version, sizeof(ngx_solaris_version))
                                                                         == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, log, errno, "sysinfo(SI_SYSNAME) failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0, "OS: %s %s",
                  ngx_solaris_sysname, ngx_solaris_release);

    ngx_log_error(NGX_LOG_INFO, log, 0, "version: %s",
                  ngx_solaris_version);


    return ngx_posix_init(log);
}
