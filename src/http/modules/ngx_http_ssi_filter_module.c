
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_SSI_MAX_PARAMS   16

#define NGX_HTTP_SSI_COMMAND_LEN  31
#define NGX_HTTP_SSI_PARAM_LEN    31
#define NGX_HTTP_SSI_PARAMS_N     4

#define NGX_HTTP_SSI_ERROR        1

#define NGX_HTTP_SSI_DATE_LEN     2048


typedef struct {
    ngx_flag_t        enable;
    ngx_flag_t        silent_errors;
    ngx_flag_t        ignore_recycled_buffers;

    ngx_array_t      *types;     /* array of ngx_str_t */

    size_t            min_file_chunk;
    size_t            value_len;
} ngx_http_ssi_conf_t;


typedef struct {
    ngx_buf_t         *buf;

    u_char            *pos;
    u_char            *copy_start;
    u_char            *copy_end;

    ngx_str_t          command;
    ngx_array_t        params;
    ngx_table_elt_t   *param;
    ngx_table_elt_t    params_array[NGX_HTTP_SSI_PARAMS_N];

    ngx_chain_t       *in;
    ngx_chain_t       *out;
    ngx_chain_t      **last_out;
    ngx_chain_t       *busy;
    ngx_chain_t       *free;

    ngx_uint_t         state;
    ngx_uint_t         saved_state;
    size_t             saved;
    size_t             looked;

    size_t             value_len;

    ngx_uint_t         output;        /* unsigned  output:1; */

    ngx_str_t          timefmt;
    ngx_str_t          errmsg;
} ngx_http_ssi_ctx_t;


typedef ngx_int_t (*ngx_http_ssi_command_pt) (ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **);


typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                index;

    ngx_uint_t                mandatory;
} ngx_http_ssi_param_t;


typedef struct {
    ngx_str_t                 name;
    ngx_http_ssi_command_pt   handler;
    ngx_http_ssi_param_t     *params;

    unsigned                  conditional:1;
    unsigned                  flush:1;
} ngx_http_ssi_command_t;


typedef enum {
    ssi_start_state = 0,
    ssi_tag_state,
    ssi_comment0_state,
    ssi_comment1_state,
    ssi_sharp_state,
    ssi_precommand_state,
    ssi_command_state,
    ssi_preparam_state,
    ssi_param_state,
    ssi_preequal_state,
    ssi_prevalue_state,
    ssi_double_quoted_value_state,
    ssi_quoted_value_state,
    ssi_quoted_symbol_state,
    ssi_postparam_state,
    ssi_comment_end0_state,
    ssi_comment_end1_state,
    ssi_error_state,
    ssi_error_end0_state,
    ssi_error_end1_state
} ngx_http_ssi_state_e;


static ngx_int_t ngx_http_ssi_output(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx);
static ngx_int_t ngx_http_ssi_parse(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx);

static ngx_int_t ngx_http_ssi_echo(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_config(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_include(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_if(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_else(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_endif(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);

static ngx_http_variable_value_t *
    ngx_http_ssi_date_gmt_local_variable(ngx_http_request_t *r, uintptr_t gmt);

static char *ngx_http_ssi_types(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_ssi_add_variables(ngx_conf_t *cf);
static void *ngx_http_ssi_create_conf(ngx_conf_t *cf);
static char *ngx_http_ssi_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_ssi_filter_init(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_ssi_filter_commands[] = {

    { ngx_string("ssi"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_conf_t, enable),
      NULL },

    { ngx_string("ssi_silent_errors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_conf_t, silent_errors),
      NULL },

    { ngx_string("ssi_ignore_recycled_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_conf_t, ignore_recycled_buffers),
      NULL },

    { ngx_string("ssi_min_file_chunk"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_conf_t, min_file_chunk),
      NULL },

    { ngx_string("ssi_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_ssi_types,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


    
static ngx_http_module_t  ngx_http_ssi_filter_module_ctx = {
    ngx_http_ssi_add_variables,            /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ssi_create_conf,              /* create location configuration */
    ngx_http_ssi_merge_conf                /* merge location configuration */
};  


ngx_module_t  ngx_http_ssi_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_ssi_filter_module_ctx,       /* module context */
    ngx_http_ssi_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_http_ssi_filter_init,              /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t (*ngx_http_next_header_filter) (ngx_http_request_t *r);
static ngx_int_t (*ngx_http_next_body_filter) (ngx_http_request_t *r,
    ngx_chain_t *in);


static u_char ngx_http_ssi_string[] = "<!--";

static ngx_str_t ngx_http_ssi_none = ngx_string("(none)");


#define  NGX_HTTP_SSI_ECHO_VAR         0
#define  NGX_HTTP_SSI_ECHO_DEFAULT     1

#define  NGX_HTTP_SSI_CONFIG_ERRMSG    0
#define  NGX_HTTP_SSI_CONFIG_TIMEFMT   1

#define  NGX_HTTP_SSI_INCLUDE_VIRTUAL  0
#define  NGX_HTTP_SSI_INCLUDE_FILE     1

#define  NGX_HTTP_SSI_IF_EXPR          0


static ngx_http_ssi_param_t  ngx_http_ssi_echo_params[] = {
    { ngx_string("var"), NGX_HTTP_SSI_ECHO_VAR, 1 },
    { ngx_string("default"), NGX_HTTP_SSI_ECHO_DEFAULT, 0 },
    { ngx_null_string, 0, 0 }
};

static ngx_http_ssi_param_t  ngx_http_ssi_include_params[] = {
    { ngx_string("virtual"), NGX_HTTP_SSI_INCLUDE_VIRTUAL, 0 },
#if 0
    { ngx_string("file"), NGX_HTTP_SSI_INCLUDE_FILE, 0 },
#endif
    { ngx_null_string, 0, 0 }
};


static ngx_http_ssi_param_t  ngx_http_ssi_config_params[] = {
    { ngx_string("errmsg"), NGX_HTTP_SSI_CONFIG_ERRMSG, 0 },
    { ngx_string("timefmt"), NGX_HTTP_SSI_CONFIG_TIMEFMT, 0 },
    { ngx_null_string, 0, 0 }
};


static ngx_http_ssi_param_t  ngx_http_ssi_if_params[] = {
    { ngx_string("expr"), NGX_HTTP_SSI_IF_EXPR, 0 },
    { ngx_null_string, 0, 0 }
};


static ngx_http_ssi_param_t  ngx_http_ssi_no_params[] = {
    { ngx_null_string, 0, 0 }
};


static ngx_http_ssi_command_t  ngx_http_ssi_commands[] = {
    { ngx_string("echo"), ngx_http_ssi_echo, ngx_http_ssi_echo_params, 0, 0 },
    { ngx_string("config"), ngx_http_ssi_config,
                       ngx_http_ssi_config_params, 0, 0 },
    { ngx_string("include"), ngx_http_ssi_include,
                       ngx_http_ssi_include_params, 0, 1 },

    { ngx_string("if"), ngx_http_ssi_if, ngx_http_ssi_if_params, 0, 0 },
    { ngx_string("else"), ngx_http_ssi_else, ngx_http_ssi_no_params, 1, 0 },
    { ngx_string("endif"), ngx_http_ssi_endif, ngx_http_ssi_no_params, 1, 0 },

    { ngx_null_string, NULL, NULL, 0, 0 }
};


static ngx_http_variable_t  ngx_http_ssi_vars[] = {

    { ngx_string("date_local"), ngx_http_ssi_date_gmt_local_variable, 0,
      NGX_HTTP_VAR_NOCACHABLE, 0 },

    { ngx_string("date_gmt"), ngx_http_ssi_date_gmt_local_variable, 1,
      NGX_HTTP_VAR_NOCACHABLE, 0 },

    { ngx_null_string, NULL, 0, 0, 0 }
};



static ngx_int_t
ngx_http_ssi_header_filter(ngx_http_request_t *r)
{
    ngx_uint_t            i;
    ngx_str_t            *type;
    ngx_http_ssi_ctx_t   *ctx;
    ngx_http_ssi_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_ssi_filter_module);

    if (!conf->enable
        || r->headers_out.content_type.len == 0)
    {
        return ngx_http_next_header_filter(r);
    }


    type = conf->types->elts;
    for (i = 0; i < conf->types->nelts; i++) {
        if (r->headers_out.content_type.len >= type[i].len
            && ngx_strncasecmp(r->headers_out.content_type.data,
                               type[i].data, type[i].len) == 0)
        {
            goto found;
        }
    }

    return ngx_http_next_header_filter(r);


found:

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ssi_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_ssi_filter_module);


    ctx->value_len = conf->value_len;
    ctx->last_out = &ctx->out;

    ctx->output = 1;

    ctx->params.elts = ctx->params_array;
    ctx->params.size = sizeof(ngx_table_elt_t);
    ctx->params.nalloc = NGX_HTTP_SSI_PARAMS_N;
    ctx->params.pool = r->pool;

    ctx->timefmt.len = sizeof("%A, %d-%b-%Y %H:%M:%S %Z") - 1;
    ctx->timefmt.data = (u_char *) "%A, %d-%b-%Y %H:%M:%S %Z";

    ctx->errmsg.len =
              sizeof("[an error occurred while processing the directive]") - 1;
    ctx->errmsg.data = (u_char *)
                     "[an error occurred while processing the directive]";

    r->filter_need_in_memory = 1;

    if (r->main == NULL) {
        r->headers_out.content_length_n = -1;
        if (r->headers_out.content_length) {
            r->headers_out.content_length->hash = 0;
            r->headers_out.content_length = NULL;
        }

        r->headers_out.last_modified_time = -1;
        if (r->headers_out.last_modified) {
            r->headers_out.last_modified->hash = 0;
            r->headers_out.last_modified = NULL;
        }
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_ssi_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                rc;
    ngx_uint_t               i;
    ngx_buf_t               *b;
    ngx_chain_t             *cl;
    ngx_table_elt_t         *param;
    ngx_http_ssi_ctx_t      *ctx;
    ngx_http_ssi_conf_t     *conf;
    ngx_http_ssi_param_t    *prm;
    ngx_http_ssi_command_t  *cmd;
    ngx_str_t               *params[NGX_HTTP_SSI_MAX_PARAMS];

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssi_filter_module);

    if (ctx == NULL || (in == NULL && ctx->in == NULL && ctx->busy == NULL)) {
        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_ssi_filter_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ssi filter \"%V\"", &r->uri);

    while (ctx->in || ctx->buf) {

        if (ctx->buf == NULL ){
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;
            ctx->pos = ctx->buf->pos;
        }

        if (ctx->state == ssi_start_state) {
            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->pos;
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "saved: %d state: %d", ctx->saved, ctx->state);

            rc = ngx_http_ssi_parse(r, ctx);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %d, looked: %d %p-%p",
                           rc, ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (ctx->copy_start != ctx->copy_end) {

                if (ctx->output) {

                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "saved: %d", ctx->saved);

                    if (ctx->saved) {

                        if (ctx->free) {
                            cl = ctx->free;
                            ctx->free = ctx->free->next;
                            b = cl->buf;
                            ngx_memzero(b, sizeof(ngx_buf_t));

                        } else {
                            b = ngx_calloc_buf(r->pool);
                            if (b == NULL) {
                                return NGX_ERROR;
                            }

                            cl = ngx_alloc_chain_link(r->pool);
                            if (cl == NULL) {
                                return NGX_ERROR;
                            }

                            cl->buf = b;
                        }

                        b->memory = 1;
                        b->pos = ngx_http_ssi_string;
                        b->last = ngx_http_ssi_string + ctx->saved;

                        *ctx->last_out = cl;
                        ctx->last_out = &cl->next;

                        ctx->saved = 0;
                    }

                    if (ctx->free) {
                        cl = ctx->free;
                        ctx->free = ctx->free->next;
                        b = cl->buf;

                    } else {
                        b = ngx_alloc_buf(r->pool);
                        if (b == NULL) {
                            return NGX_ERROR;
                        }

                        cl = ngx_alloc_chain_link(r->pool);
                        if (cl == NULL) {
                            return NGX_ERROR;
                        }

                        cl->buf = b;
                    }

                    ngx_memcpy(b, ctx->buf, sizeof(ngx_buf_t));

                    b->pos = ctx->copy_start;
                    b->last = ctx->copy_end;
                    b->shadow = NULL;
                    b->last_buf = 0;
                    b->recycled = 0;

                    if (b->in_file) {
                        if (conf->min_file_chunk < (size_t) (b->last - b->pos))
                        {
                            b->file_last = b->file_pos + (b->last - b->start);
                            b->file_pos += b->pos - b->start;

                        } else {
                            b->in_file = 0;
                        }
                    }

                    cl->next = NULL;
                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;

                } else {
                    ctx->saved = 0;
                }
            }

            if (ctx->state == ssi_start_state) {
                ctx->copy_start = ctx->pos;
                ctx->copy_end = ctx->pos;

            } else {
                ctx->copy_start = NULL;
                ctx->copy_end = NULL;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            if (rc == NGX_OK) {

                for (cmd = ngx_http_ssi_commands; cmd->handler; cmd++) {
                    if (cmd->name.len == 0) {
                        cmd = (ngx_http_ssi_command_t *) cmd->handler;
                    }

                    if (cmd->name.len != ctx->command.len
                        || ngx_strncmp(cmd->name.data, ctx->command.data,
                                       ctx->command.len) != 0)
                    {
                        continue;
                    }

                    break;
                }

                if (cmd->name.len == 0 && ctx->output) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "invalid SSI command: \"%V\"", &ctx->command);
                    goto ssi_error;
                }

                if (!ctx->output && !cmd->conditional) {
                    continue;
                }

                ngx_memzero(params,
                            NGX_HTTP_SSI_MAX_PARAMS * sizeof(ngx_str_t *));

                param = ctx->params.elts;


                for (i = 0; i < ctx->params.nelts; i++) {

                    for (prm = cmd->params; prm->name.len; prm++) {

                        if (param[i].key.len != prm->name.len
                            || ngx_strncmp(param[i].key.data, prm->name.data,
                                           prm->name.len) != 0)
                        {
                            continue;
                        }

                        if (params[prm->index]) {
                            ngx_log_error(NGX_LOG_ERR,
                                          r->connection->log, 0,
                                          "duplicate \"%V\" parameter "
                                          "in \"%V\" SSI command",
                                          &param[i].key, &ctx->command);

                            goto ssi_error;
                        }

                        params[prm->index] = &param[i].value;

                        break;
                    }

                    if (prm->name.len == 0) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "invalid parameter name: \"%V\" "
                                      "in \"%V\" SSI command",
                                      &param[i].key, &ctx->command);

                        goto ssi_error;
                    }
                }

                for (prm = cmd->params; prm->name.len; prm++) {
                    if (prm->mandatory && params[prm->index] == 0) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "mandatory \"%V\" parameter is absent "
                                      "in \"%V\" SSI command",
                                      &prm->name, &ctx->command);

                        goto ssi_error;
                    }
                }

                if (cmd->flush && ctx->out) {
                    rc = ngx_http_ssi_output(r, ctx);

                    if (rc == NGX_ERROR) {
                        return NGX_ERROR;
                    }
                }

                if (cmd->handler(r, ctx, params) == NGX_OK) {
                    continue;
                }
            }


            /* rc == NGX_HTTP_SSI_ERROR */

    ssi_error:

            if (conf->silent_errors) {
                continue;
            }

            if (ctx->free) {
                cl = ctx->free;
                ctx->free = ctx->free->next;
                b = cl->buf;
                ngx_memzero(b, sizeof(ngx_buf_t));

            } else {
                b = ngx_calloc_buf(r->pool);
                if (b == NULL) {
                    return NGX_ERROR;
                }

                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                cl->buf = b;
            }

            b->memory = 1;
            b->pos = ctx->errmsg.data;
            b->last = ctx->errmsg.data + ctx->errmsg.len;

            cl->next = NULL;
            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            continue;
        }

        if (ctx->buf->last_buf || ctx->buf->recycled) {

            if (b == NULL) {
                if (ctx->free) {
                    cl = ctx->free;
                    ctx->free = ctx->free->next;
                    b = cl->buf;
                    ngx_memzero(b, sizeof(ngx_buf_t));

                } else {
                    b = ngx_calloc_buf(r->pool);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }

                    cl = ngx_alloc_chain_link(r->pool);
                    if (cl == NULL) {
                        return NGX_ERROR;
                    }

                    cl->buf = b;
                }

                b->sync = 1;

                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            b->last_buf = ctx->buf->last_buf;
            b->shadow = ctx->buf;

            if (conf->ignore_recycled_buffers == 0)  {
                b->recycled = ctx->buf->recycled;
            }
        }

        ctx->buf = NULL;

        ctx->saved = ctx->looked;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }

    return ngx_http_ssi_output(r, ctx);
}


static ngx_int_t
ngx_http_ssi_output(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    rc = ngx_http_next_body_filter(r, ctx->out);

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;

    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {

        b = ctx->busy->buf;

        if (ngx_buf_size(b) != 0) {
            break;
        }

#if (NGX_HAVE_WRITE_ZEROCOPY)
        if (b->zerocopy_busy) {
            break;
        }
#endif

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        cl = ctx->busy;
        ctx->busy = cl->next;
        cl->next = ctx->free;
        ctx->free = cl;
    }

    return rc;
}


static ngx_int_t
ngx_http_ssi_parse(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx)
{
    u_char                *p, *last, *copy_end, ch;
    size_t                 looked;
    ngx_http_ssi_state_e   state;

    state = ctx->state;
    looked = ctx->looked;
    last = ctx->buf->last;
    copy_end = ctx->copy_end;

    for (p = ctx->pos; p < last; p++) {

        ch = *p;

        if (state == ssi_start_state) {

            /* the tight loop */

            for ( ;; ) {
                if (ch == '<') {
                    copy_end = p;
                    looked = 1;
                    state = ssi_tag_state;

                    goto tag_started;
                }

                if (++p == last) {
                    break;
                }

                ch = *p;
            }

            ctx->pos = p;
            ctx->looked = looked;
            ctx->copy_end = p;

            if (ctx->copy_start == NULL) {
                ctx->copy_start = ctx->buf->pos;
            }

            return NGX_AGAIN;

        tag_started:

            continue;
        }

        switch (state) {

        case ssi_start_state:
            break;

        case ssi_tag_state:
            switch (ch) {
            case '!':
                looked = 2;
                state = ssi_comment0_state;
                break;

            case '<':
                copy_end = p;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_comment0_state:
            switch (ch) {
            case '-':
                looked = 3;
                state = ssi_comment1_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = ssi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_comment1_state:
            switch (ch) {
            case '-':
                looked = 4;
                state = ssi_sharp_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = ssi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_sharp_state:
            switch (ch) {
            case '#':
                if (ctx->copy_start) {
                    ctx->saved = 0;
                }
                looked = 0;
                state = ssi_precommand_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = ssi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_precommand_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            default:
                ctx->command.len = 1;
                ctx->command.data = ngx_palloc(r->pool,
                                               NGX_HTTP_SSI_COMMAND_LEN + 1);
                if (ctx->command.data == NULL) {
                    return NGX_ERROR;
                }

                ctx->command.data[0] = ch;
                ctx->params.nelts = 0;
                state = ssi_command_state;
                break;
            }

            break;

        case ssi_command_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = ssi_preparam_state;
                break;

            case '-':
                state = ssi_comment_end0_state;
                break;

            default:
                ctx->command.data[ctx->command.len++] = ch;

                if (ctx->command.len == NGX_HTTP_SSI_COMMAND_LEN) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "the \"%V\" SSI command is too long",
                                  &ctx->command);

                    state = ssi_error_state;
                    break;
                }
            }

            break;

        case ssi_preparam_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '-':
                state = ssi_comment_end0_state;
                break;

            default:
                ctx->param = ngx_array_push(&ctx->params);
                if (ctx->param == NULL) {
                    return NGX_ERROR;
                }

                ctx->param->key.len = 1;
                ctx->param->key.data = ngx_palloc(r->pool,
                                                  NGX_HTTP_SSI_PARAM_LEN + 1);
                if (ctx->param->key.data == NULL) {
                    return NGX_ERROR;
                }

                ctx->param->key.data[0] = ch;

                ctx->param->value.len = 0;
                ctx->param->value.data = ngx_palloc(r->pool,
                                                    ctx->value_len + 1);
                if (ctx->param->value.data == NULL) {
                    return NGX_ERROR;
                }

                state = ssi_param_state;
                break;
            }

            break;

        case ssi_param_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = ssi_preequal_state;
                break;

            case '=':
                state = ssi_prevalue_state;
                break;

            case '-':
                state = ssi_error_end0_state;

                ctx->param->key.data[ctx->param->key.len++] = ch;
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "invalid \"%V\" parameter in \"%V\" SSI command",
                              &ctx->param->key, &ctx->command);
                break;

            default:
                ctx->param->key.data[ctx->param->key.len++] = ch;

                if (ctx->param->key.len == NGX_HTTP_SSI_PARAM_LEN) {
                    state = ssi_error_state;
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V\" parameter in "
                                  "\"%V\" SSI command",
                                  &ctx->param->key, &ctx->command);
                    break;
                }
            }

            break;

        case ssi_preequal_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '=':
                state = ssi_prevalue_state;
                break;

            default:
                if (ch == '-') {
                    state = ssi_error_end0_state;
                } else {
                    state = ssi_error_state;
                }

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol after \"%V\" "
                              "parameter in \"%V\" SSI command",
                              ch, &ctx->param->key, &ctx->command);
                break;
            }

            break;

        case ssi_prevalue_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '"':
                state = ssi_double_quoted_value_state;
                break;

            case '\'':
                state = ssi_quoted_value_state;
                break;

            default:
                if (ch == '-') {
                    state = ssi_error_end0_state;
                } else {
                    state = ssi_error_state;
                }

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol before value of "
                              "\"%V\" parameter in \"%V\" SSI command",
                              ch, &ctx->param->key, &ctx->command);
                break;
            }

            break;

        case ssi_double_quoted_value_state:
            switch (ch) {
            case '\\':
                ctx->saved_state = ssi_double_quoted_value_state;
                state = ssi_quoted_symbol_state;
                break;

            case '"':
                state = ssi_postparam_state;
                break;

            default:
                ctx->param->value.data[ctx->param->value.len++] = ch;

                if (ctx->param->value.len == ctx->value_len) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V\" value of \"%V\" parameter "
                                  "in \"%V\" SSI command",
                                  &ctx->param->value, &ctx->param->key,
                                  &ctx->command);
                    state = ssi_error_state;
                    break;
                }
            }

            break;

        case ssi_quoted_value_state:
            switch (ch) {
            case '\\':
                ctx->saved_state = ssi_quoted_value_state;
                state = ssi_quoted_symbol_state;
                break;

            case '\'':
                state = ssi_postparam_state;
                break;

            default:
                ctx->param->value.data[ctx->param->value.len++] = ch;

                if (ctx->param->value.len == ctx->value_len) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V\" value of \"%V\" parameter "
                                  "in \"%V\" SSI command",
                                  &ctx->param->value, &ctx->param->key,
                                  &ctx->command);
                    state = ssi_error_state;
                    break;
                }
            }

            break;

        case ssi_quoted_symbol_state:
            ctx->param->value.data[ctx->param->value.len++] = ch;

            if (ctx->param->value.len == ctx->value_len) {
                if (ctx->param->value.len == ctx->value_len) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V\" value of \"%V\" parameter "
                                  "in \"%V\" SSI command",
                                  &ctx->param->value, &ctx->param->key,
                                  &ctx->command);
                    state = ssi_error_state;
                    break;
                }
            }

            state = ctx->saved_state;
            break;

        case ssi_postparam_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = ssi_preparam_state;
                break;

            case '-':
                state = ssi_comment_end0_state;
                break;

            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol after \"%V\" value "
                              "of \"%V\" parameter in \"%V\" SSI command",
                              ch, &ctx->param->value, &ctx->param->key,
                              &ctx->command);
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_comment_end0_state:
            switch (ch) {
            case '-':
                state = ssi_comment_end1_state;
                break;

            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol in \"%V\" SSI command",
                              ch, &ctx->command);
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_comment_end1_state:
            switch (ch) {
            case '>':
                ctx->state = ssi_start_state;
                ctx->pos = p + 1;
                ctx->looked = looked;
                ctx->copy_end = copy_end;

                if (ctx->copy_start == NULL && copy_end) {
                    ctx->copy_start = ctx->buf->pos;
                }

                return NGX_OK;

            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol in \"%V\" SSI command",
                              ch, &ctx->command);
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_error_state:
            switch (ch) {
            case '-':
                state = ssi_error_end0_state;
                break;

            default:
                break;
            }

            break;

        case ssi_error_end0_state:
            switch (ch) {
            case '-':
                state = ssi_error_end1_state;
                break;

            default:
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_error_end1_state:
            switch (ch) {
            case '>':
                ctx->state = ssi_start_state;
                ctx->pos = p + 1;
                ctx->looked = looked;
                ctx->copy_end = copy_end;

                if (ctx->copy_start == NULL && copy_end) {
                    ctx->copy_start = ctx->buf->pos;
                }

                return NGX_HTTP_SSI_ERROR;

            default:
                state = ssi_error_state;
                break;
            }

            break;
        }
    }

    ctx->state = state;
    ctx->pos = p;
    ctx->looked = looked;

    ctx->copy_end = (state == ssi_start_state) ? p : copy_end;

    if (ctx->copy_start == NULL && ctx->copy_end) {
        ctx->copy_start = ctx->buf->pos;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_ssi_echo(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    ngx_uint_t                  i;
    ngx_buf_t                  *b;
    ngx_str_t                  *var, *value;
    ngx_chain_t                *cl;
    ngx_http_variable_value_t  *vv;

    var = params[NGX_HTTP_SSI_ECHO_VAR];

    for (i = 0; i < var->len; i++) {
        var->data[i] = ngx_tolower(var->data[i]);
    }

    vv = ngx_http_get_variable(r, var);

    if (vv == NULL) {
        return NGX_HTTP_SSI_ERROR;
    }

    if (vv == NGX_HTTP_VAR_NOT_FOUND) {
        value = params[NGX_HTTP_SSI_ECHO_DEFAULT];

        if (value == NULL) {
            value = &ngx_http_ssi_none;

        } else if (value->len == 0) {
            return NGX_OK;
        }

    } else {
        value = &vv->text;

        if (value->len == 0) {
            return NGX_OK;
        }
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_SSI_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_HTTP_SSI_ERROR;
    }

    b->memory = 1;
    b->pos = value->data;
    b->last = value->data + value->len;

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_config(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    ngx_str_t  *value;

    value = params[NGX_HTTP_SSI_CONFIG_TIMEFMT];

    if (value) {
        ctx->timefmt = *value;
    }

    value = params[NGX_HTTP_SSI_CONFIG_ERRMSG];

    if (value) {
        ctx->errmsg = *value;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_include(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    u_char                      ch, *p, **value, *data;
    size_t                     *size, len, prefix;
    ngx_uint_t                  i, j, n, bracket;
    ngx_str_t                   uri, args, name;
    ngx_array_t                 lengths, values;
    ngx_http_variable_value_t  *vv;

    /* TODO: file, virtual vs file */

    uri = *params[NGX_HTTP_SSI_INCLUDE_VIRTUAL];
    args.len = 0;
    args.data = NULL;
    prefix = 0;

    n = ngx_http_script_variables_count(&uri);

    if (n > 0) {

        if (ngx_array_init(&lengths, r->pool, 8, sizeof(size_t *)) != NGX_OK) {
            return NGX_HTTP_SSI_ERROR;
        }

        if (ngx_array_init(&values, r->pool, 8, sizeof(u_char *)) != NGX_OK) {
            return NGX_HTTP_SSI_ERROR;
        }

        len = 0;

        for (i = 0; i < uri.len; /* void */ ) {

            name.len = 0;

            if (uri.data[i] == '$') {

                if (++i == uri.len) {
                    goto invalid_variable;
                }

                if (uri.data[i] == '{') {
                    bracket = 1;

                    if (++i == uri.len) {
                        goto invalid_variable;
                    }

                    name.data = &uri.data[i];

                } else {
                    bracket = 0;
                    name.data = &uri.data[i];
                }

                for ( /* void */ ; i < uri.len; i++, name.len++) {
                    ch = uri.data[i];

                    if (ch == '}' && bracket) {
                        i++;
                        bracket = 0;
                        break;
                    }

                    if ((ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9')
                        || ch == '_')
                    {
                        continue;
                    }

                    break;
                }

                if (bracket) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "the closing bracket in \"%V\" "
                                  "variable is missing", &name);
                    return NGX_HTTP_SSI_ERROR;
                }

                if (name.len == 0) {
                    goto invalid_variable;
                }

                for (j = 0; j < name.len; j++) {
                    name.data[j] = ngx_tolower(name.data[j]);
                }

                vv = ngx_http_get_variable(r, &name);

                if (vv == NULL) {
                    return NGX_HTTP_SSI_ERROR;
                }

                if (vv == NGX_HTTP_VAR_NOT_FOUND) {
                    continue;
                }

                name = vv->text;

            } else {
                name.data = &uri.data[i];

                while (i < uri.len && uri.data[i] != '$') {
                    i++;
                    name.len++;
                }
            }

            len += name.len;

            size = ngx_array_push(&lengths);
            if (size == NULL) {
                return NGX_HTTP_SSI_ERROR;
            }

            *size = name.len;

            value = ngx_array_push(&values);
            if (value == NULL) {
                return NGX_HTTP_SSI_ERROR;
            }

            *value = name.data;
        }

        size = lengths.elts;
        value = values.elts;

        for (i = 0; i < values.nelts; i++) {
            if (size[i] != 0) {
                if (*value[i] != '/') {
                    for (prefix = r->uri.len; prefix; prefix--) {
                        if (r->uri.data[prefix - 1] == '/') {
                            len += prefix;
                            break;
                        }
                    }
                }

                break;
            }
        }

        p = ngx_palloc(r->pool, len);
        if (p == NULL) {
            return NGX_HTTP_SSI_ERROR;
        }

        uri.len = len;
        uri.data = p;

        if (prefix) {
            p = ngx_cpymem(p, r->uri.data, prefix);
        }

        for (i = 0; i < values.nelts; i++) {
            p = ngx_cpymem(p, value[i], size[i]);
        }

    } else {
        if (uri.data[0] != '/') {
            for (prefix = r->uri.len; prefix; prefix--) {
                if (r->uri.data[prefix - 1] == '/') {
                    break;
                }
            }

            if (prefix) {
                len = prefix + uri.len;

                data = ngx_palloc(r->pool, len);
                if (data == NULL) {
                    return NGX_HTTP_SSI_ERROR;
                }

                p = ngx_cpymem(data, r->uri.data, prefix);
                ngx_memcpy(p, uri.data, uri.len);

                uri.len = len;
                uri.data = data;
            }
        }
    }

    for (i = 0; i < uri.len; i++) {
        if (uri.data[i] == '?') {
            args.len = uri.len - i - 1;
            args.data = &uri.data[i + 1];
            uri.len -= args.len + 1;

            break;
        }
    }

    if (ngx_http_subrequest(r, &uri, &args) != NGX_OK) {
        return NGX_HTTP_SSI_ERROR;
    }

    return NGX_OK;

invalid_variable:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "invalid variable name in \"%V\"", &uri);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_ssi_if(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    ngx_str_t                  *expr, var;
    ngx_uint_t                  i;
    ngx_http_variable_value_t  *vv;

    expr = params[NGX_HTTP_SSI_IF_EXPR];

    if (expr->data[0] != '$') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid variable name in \"%V\"", expr);
        return NGX_HTTP_SSI_ERROR;
    }

    var.len = expr->len - 1;
    var.data = expr->data + 1;

    for (i = 0; i < var.len; i++) {
        var.data[i] = ngx_tolower(var.data[i]);
    }

    vv = ngx_http_get_variable(r, &var);

    if (vv == NULL) {
        return NGX_HTTP_SSI_ERROR;
    }

    if (vv != NGX_HTTP_VAR_NOT_FOUND && vv->text.len != 0) {
        ctx->output = 1;

    } else {
        ctx->output = 0;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_else(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    ctx->output = !ctx->output;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_endif(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    ctx->output = 1;

    return NGX_OK;
}


static ngx_http_variable_value_t *
ngx_http_ssi_date_gmt_local_variable(ngx_http_request_t *r, uintptr_t gmt)
{
    ngx_http_ssi_ctx_t         *ctx;
    ngx_http_variable_value_t  *vv;
    struct tm                   tm;
    char                        buf[NGX_HTTP_SSI_DATE_LEN];

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssi_filter_module);

    if (ctx->timefmt.len == sizeof("%s") - 1
        && ctx->timefmt.data[0] == '%' && ctx->timefmt.data[1] == 's')
    {
        vv->value = ngx_time() + (gmt ? 0 : ngx_gmtoff);

        vv->text.data = ngx_palloc(r->pool, NGX_TIME_T_LEN);
        if (vv->text.data == NULL) {
            return NULL;
        }

        vv->text.len = ngx_sprintf(vv->text.data, "%T", vv->value)
                       - vv->text.data;
        return vv;
    }

    if (gmt) {
        ngx_libc_gmtime(&tm);
    } else {
        ngx_libc_localtime(&tm);
    }

    vv->value = ngx_time() + (gmt ? 0 : ngx_gmtoff);

    vv->text.len = strftime(buf, NGX_HTTP_SSI_DATE_LEN,
                            (char *) ctx->timefmt.data, &tm);
    if (vv->text.len == 0) {
        return NULL;
    }

    vv->text.data = ngx_palloc(r->pool, vv->text.len);
    if (vv->text.data == NULL) {
        return NULL;
    }

    ngx_memcpy(vv->text.data, buf, vv->text.len);

    return vv;
}


static char *
ngx_http_ssi_types(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssi_conf_t *scf = conf;

    ngx_str_t   *value, *type;
    ngx_uint_t   i;

    if (scf->types == NULL) {
        scf->types = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (scf->types == NULL) {
            return NGX_CONF_ERROR;
        }

        type = ngx_array_push(scf->types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->len = sizeof("text/html") - 1;
        type->data = (u_char *) "text/html";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "text/html") == 0) {
            continue;
        }

        type = ngx_array_push(scf->types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->len = value[i].len;

        type->data = ngx_palloc(cf->pool, type->len + 1);
        if (type->data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_cpystrn(type->data, value[i].data, type->len + 1);
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ssi_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ssi_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->handler = v->handler;
        var->data = v->data;
    }

    return NGX_OK; 
}


static void *
ngx_http_ssi_create_conf(ngx_conf_t *cf)
{
    ngx_http_ssi_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssi_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->types = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->silent_errors = NGX_CONF_UNSET;
    conf->ignore_recycled_buffers = NGX_CONF_UNSET;

    conf->min_file_chunk = NGX_CONF_UNSET_SIZE;
    conf->value_len = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_ssi_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ssi_conf_t *prev = parent;
    ngx_http_ssi_conf_t *conf = child;

    ngx_str_t  *type;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->silent_errors, prev->silent_errors, 0);
    ngx_conf_merge_value(conf->ignore_recycled_buffers,
                         prev->ignore_recycled_buffers, 0);

    ngx_conf_merge_size_value(conf->min_file_chunk, prev->min_file_chunk, 1024);
    ngx_conf_merge_size_value(conf->value_len, prev->value_len, 256);

    if (conf->types == NULL) {
        if (prev->types == NULL) {
            conf->types = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
            if (conf->types == NULL) {
                return NGX_CONF_ERROR;
            }

            type = ngx_array_push(conf->types);
            if (type == NULL) {
                return NGX_CONF_ERROR;
            }

            type->len = sizeof("text/html") - 1;
            type->data = (u_char *) "text/html";

        } else {
            conf->types = prev->types;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ssi_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ssi_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ssi_body_filter;

    return NGX_OK;
}
