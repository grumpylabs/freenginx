#ifndef _NGX_FREEBSD_H_INCLUDED_
#define _NGX_FREEBSD_H_INCLUDED_


ngx_chain_t *ngx_freebsd_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in);


extern int ngx_freebsd_kern_osreldate;
extern int ngx_freebsd_hw_ncpu;
extern int ngx_freebsd_net_inet_tcp_sendspace;
extern int ngx_freebsd_sendfile_nbytes_bug;
extern int ngx_freebsd_kern_ipc_zero_copy_send;
extern int ngx_freebsd_use_tcp_nopush;


#endif /* _NGX_FREEBSD_H_INCLUDED_ */
