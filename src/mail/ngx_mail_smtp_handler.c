
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>


static ngx_int_t ngx_mail_smtp_helo(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_smtp_auth(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_smtp_mail(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_smtp_starttls(ngx_mail_session_t *s,
    ngx_connection_t *c);


static u_char  smtp_ok[] = "250 2.0.0 OK" CRLF;
static u_char  smtp_bye[] = "221 2.0.0 Bye" CRLF;
static u_char  smtp_next[] = "334 " CRLF;
static u_char  smtp_username[] = "334 VXNlcm5hbWU6" CRLF;
static u_char  smtp_password[] = "334 UGFzc3dvcmQ6" CRLF;
static u_char  smtp_invalid_command[] = "500 5.5.1 Invalid command" CRLF;
static u_char  smtp_invalid_argument[] = "501 5.5.4 Invalid argument" CRLF;
static u_char  smtp_auth_required[] = "530 5.7.1 Authentication required" CRLF;


void
ngx_mail_smtp_init_session(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_mail_core_srv_conf_t  *cscf;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    if (cscf->smtp_auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED) {
        if (ngx_mail_salt(s, c, cscf) != NGX_OK) {
            ngx_mail_session_internal_server_error(s);
            return;
        }
    }

    c->read->handler = ngx_mail_smtp_init_protocol;

    s->out = cscf->smtp_greeting;

    ngx_mail_send(c->write);
}


void
ngx_mail_smtp_init_protocol(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    s = c->data;

    if (s->buffer == NULL) {
        if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t))
            == NGX_ERROR)
        {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        s->buffer = ngx_create_temp_buf(c->pool, 512);
        if (s->buffer == NULL) {
            ngx_mail_session_internal_server_error(s);
            return;
        }
    }

    s->mail_state = ngx_smtp_start;
    c->read->handler = ngx_mail_smtp_auth_state;

    ngx_mail_smtp_auth_state(rev);
}


void
ngx_mail_smtp_auth_state(ngx_event_t *rev)
{
    ngx_int_t            rc;
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "smtp auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "smtp send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_mail_read_command(s);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    s->out.len = sizeof(smtp_ok) - 1;
    s->out.data = smtp_ok;

    if (rc == NGX_OK) {
        switch (s->mail_state) {

        case ngx_smtp_start:

            switch (s->command) {

            case NGX_SMTP_HELO:
            case NGX_SMTP_EHLO:
                rc = ngx_mail_smtp_helo(s, c);
                break;

            case NGX_SMTP_AUTH:
                rc = ngx_mail_smtp_auth(s, c);
                break;

            case NGX_SMTP_QUIT:
                s->quit = 1;
                s->out.len = sizeof(smtp_bye) - 1;
                s->out.data = smtp_bye;
                break;

            case NGX_SMTP_MAIL:
                rc = ngx_mail_smtp_mail(s, c);
                break;

            case NGX_SMTP_NOOP:
            case NGX_SMTP_RSET:
                break;

            case NGX_SMTP_STARTTLS:
                rc = ngx_mail_smtp_starttls(s, c);
                break;

            default:
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case ngx_smtp_auth_login_username:
            rc = ngx_mail_auth_login_username(s, c);

            s->out.len = sizeof(smtp_password) - 1;
            s->out.data = smtp_password;
            s->mail_state = ngx_smtp_auth_login_password;
            break;

        case ngx_smtp_auth_login_password:
            rc = ngx_mail_auth_login_password(s, c);
            break;

        case ngx_smtp_auth_plain:
            rc = ngx_mail_auth_plain(s, c, 0);
            break;

        case ngx_smtp_auth_cram_md5:
            rc = ngx_mail_auth_cram_md5(s, c);
            break;
        }
    }

    switch (rc) {

    case NGX_DONE:
        ngx_mail_auth(s);
        return;

    case NGX_ERROR:
        ngx_mail_session_internal_server_error(s);
        return;

    case NGX_MAIL_PARSE_INVALID_COMMAND:
        s->mail_state = ngx_smtp_start;
        s->state = 0; 

        s->out.len = sizeof(smtp_invalid_command) - 1;
        s->out.data = smtp_invalid_command;

        /* fall through */

    case NGX_OK:
        s->args.nelts = 0;
        s->buffer->pos = s->buffer->start;
        s->buffer->last = s->buffer->start;

        if (s->state) {
            s->arg_start = s->buffer->start;
        }

        ngx_mail_send(c->write);
    }
}


static ngx_int_t
ngx_mail_smtp_helo(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t                 *arg;
    ngx_mail_core_srv_conf_t  *cscf;
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t       *sslcf;
#endif

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    if (s->args.nelts != 1) {
        s->out.len = sizeof(smtp_invalid_argument) - 1;
        s->out.data = smtp_invalid_argument;
        s->state = 0;
        return NGX_OK;
    }

    arg = s->args.elts;

    s->smtp_helo.len = arg[0].len;

    s->smtp_helo.data = ngx_palloc(c->pool, arg[0].len);
    if (s->smtp_helo.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->smtp_helo.data, arg[0].data, arg[0].len);

    if (s->command == NGX_SMTP_HELO) {
        s->out = cscf->smtp_server_name;

    } else {
        s->esmtp = 1;

#if (NGX_MAIL_SSL)

        if (c->ssl == NULL) {
            sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

            if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
                s->out = cscf->smtp_starttls_capability;
                return NGX_OK;
            }

            if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
                s->out = cscf->smtp_starttls_only_capability;
                return NGX_OK;
            }
        }
#endif

        s->out = cscf->smtp_capability;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_mail_smtp_auth(ngx_mail_session_t *s, ngx_connection_t *c)
{
    u_char                    *p;
    ngx_str_t                 *arg, salt;
    ngx_uint_t                 n;
    ngx_mail_core_srv_conf_t  *cscf;
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t       *sslcf;

    if (c->ssl == NULL) {
        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

        if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }
    }

#endif

    if (s->args.nelts == 0) {
        s->out.len = sizeof(smtp_invalid_argument) - 1;
        s->out.data = smtp_invalid_argument;
        s->state = 0;
        return NGX_OK;
    }

    if (s->args.nelts != 1) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;

    if (arg[0].len == 5) {

        if (ngx_strncasecmp(arg[0].data, (u_char *) "LOGIN", 5) == 0) {

            if (s->args.nelts != 1) {
                return NGX_MAIL_PARSE_INVALID_COMMAND;
            }

            s->out.len = sizeof(smtp_username) - 1;
            s->out.data = smtp_username;
            s->mail_state = ngx_smtp_auth_login_username;

            return NGX_OK;

        } else if (ngx_strncasecmp(arg[0].data, (u_char *) "PLAIN", 5) == 0) {

            s->out.len = sizeof(smtp_next) - 1;
            s->out.data = smtp_next;
            s->mail_state = ngx_smtp_auth_plain;

            return NGX_OK;
        }

    } else if (arg[0].len == 8
               && ngx_strncasecmp(arg[0].data, (u_char *) "CRAM-MD5", 8) == 0)
    {
        if (s->args.nelts != 1) {
            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

        if (!(cscf->smtp_auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        p = ngx_palloc(c->pool,
                       sizeof("334 " CRLF) - 1
                       + ngx_base64_encoded_length(s->salt.len));
        if (p == NULL) {
            return NGX_ERROR;
        }

        p[0] = '3'; p[1]= '3'; p[2] = '4'; p[3]= ' ';
        salt.data = &p[4];
        s->salt.len -= 2;

        ngx_encode_base64(&salt, &s->salt);

        s->salt.len += 2;
        n = 4 + salt.len;
        p[n++] = CR; p[n++] = LF;

        s->out.len = n;
        s->out.data = p;
        s->mail_state = ngx_smtp_auth_cram_md5;

        return NGX_OK;
    }

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}


static ngx_int_t
ngx_mail_smtp_mail(ngx_mail_session_t *s, ngx_connection_t *c)
{
    u_char      ch;
    ngx_str_t   mail;
    ngx_uint_t  i;

    if (c->log->log_level >= NGX_LOG_INFO) {
        mail.len = s->buffer->last - s->buffer->start;
        mail.data = s->buffer->start;

        for (i = 0; i < mail.len; i++) {
            ch = mail.data[i];

            if (ch != CR && ch != LF) {
                continue;
            }

            mail.data[i] = ' ';
        }

        while (i) {
            if (mail.data[i - 1] != ' ') {
                break;
            }

            i--;
        }

        mail.len = i;

        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "client was rejected: \"%V\"", &mail);
    }

    s->out.len = sizeof(smtp_auth_required) - 1;
    s->out.data = smtp_auth_required;

    return NGX_OK;
}


static ngx_int_t
ngx_mail_smtp_starttls(ngx_mail_session_t *s, ngx_connection_t *c)
{
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t  *sslcf;

    if (c->ssl == NULL) {
        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
        if (sslcf->starttls) {

            /*
             * RFC3207 requires us to discard any knowledge
             * obtained from client before STARTTLS.
             */

            s->smtp_helo.len = 0;
            s->smtp_helo.data = NULL;

            c->read->handler = ngx_mail_starttls_handler;
            return NGX_OK;
        }
    }

#endif

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}
