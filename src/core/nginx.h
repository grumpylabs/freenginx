#ifndef _NGINX_H_INCLUDED_
#define _NGINX_H_INCLUDED_


#define NGINX_VER          "nginx/0.0.2"
#define NGINX_CONF         (u_char *) "nginx.conf"
#define NGINX_PID          "nginx.pid"
#define NGINX_NEW_PID_EXT  ".newbin"
#define NGINX_NEW_PID      NGINX_PID NGINX_NEW_PID_EXT

#define NGINX_VAR          "NGINX"

extern ngx_module_t        ngx_core_module;

extern ngx_atomic_t        ngx_connection_counter;

extern ngx_int_t           ngx_process;


#endif /* _NGINX_H_INCLUDED_ */
