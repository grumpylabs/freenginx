#ifndef _NGINX_H_INCLUDED_
#define _NGINX_H_INCLUDED_


#define NGINX_VER      "nginx/0.0.1"
#define NGINX_CONF     "nginx.conf"
#define NGINX_PID      "nginx.pid"

#define NGINX_VAR      "NGINX="
#define NGINX_VAR_LEN  (sizeof(NGINX_VAR) - 1)

extern ngx_module_t    ngx_core_module;

extern ngx_uint_t      ngx_connection_counter;

extern ngx_int_t       ngx_process;


#endif /* _NGINX_H_INCLUDED_ */
