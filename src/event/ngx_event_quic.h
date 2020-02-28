
/*
 *
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <ngx_event_openssl.h>


struct ngx_quic_connection_s {
    ngx_str_t   scid;
    ngx_str_t   dcid;
    ngx_str_t   token;

    ngx_str_t   client_in;
    ngx_str_t   client_in_key;
    ngx_str_t   client_in_iv;
    ngx_str_t   client_in_hp;

    ngx_str_t   server_in;
    ngx_str_t   server_in_key;
    ngx_str_t   server_in_iv;
    ngx_str_t   server_in_hp;

    ngx_str_t   client_hs;
    ngx_str_t   client_hs_key;
    ngx_str_t   client_hs_iv;
    ngx_str_t   client_hs_hp;

    ngx_str_t   server_hs;
    ngx_str_t   server_hs_key;
    ngx_str_t   server_hs_iv;
    ngx_str_t   server_hs_hp;

    ngx_str_t   client_ad;
    ngx_str_t   client_ad_key;
    ngx_str_t   client_ad_iv;
    ngx_str_t   client_ad_hp;

    ngx_str_t   server_ad;
    ngx_str_t   server_ad_key;
    ngx_str_t   server_ad_iv;
    ngx_str_t   server_ad_hp;
};


uint64_t ngx_quic_parse_pn(u_char **pos, ngx_int_t len, u_char *mask);
uint64_t ngx_quic_parse_int(u_char **pos);
void ngx_quic_build_int(u_char **pos, uint64_t value);

ngx_int_t ngx_hkdf_extract(u_char *out_key, size_t *out_len,
    const EVP_MD *digest, const u_char *secret, size_t secret_len,
    const u_char *salt, size_t salt_len);
ngx_int_t ngx_hkdf_expand(u_char *out_key, size_t out_len,
    const EVP_MD *digest, const u_char *prk, size_t prk_len,
    const u_char *info, size_t info_len);


#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
