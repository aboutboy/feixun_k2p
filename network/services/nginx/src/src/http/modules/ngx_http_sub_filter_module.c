
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
typedef struct {
    ngx_http_complex_value_t   match;
    ngx_http_complex_value_t   value;
    ngx_str_t                  name;
    ngx_flag_t                 tail;
} ngx_http_sub_pair_t;


typedef struct {
    ngx_str_t                  match;
    ngx_http_complex_value_t  *value;
    ngx_str_t                  name;
    ngx_flag_t                 tail;
    ngx_uint_t                 id;
} ngx_http_sub_match_t;



typedef struct {
    ngx_uint_t                 match_len;
    u_char                     shift[256];
    ngx_str_t                  name;
} ngx_http_sub_tables_t;


typedef struct {
    ngx_uint_t                 dynamic; /* unsigned dynamic:1; */

    ngx_array_t               *pairs;

    ngx_http_sub_tables_t     *tables;
    ngx_uint_t                 tables_len;

    ngx_flag_t                 once;
    ngx_flag_t                 last_modified;

    ngx_array_t               *matches;

	ngx_array_t               *nocachePass;

    ngx_hash_t                insertJS_in_hash;

} ngx_http_sub_loc_conf_t;


typedef struct {
    ngx_str_t                  saved;
    ngx_str_t                  looked;

    ngx_uint_t                 once;   /* unsigned  once:1 */

    ngx_buf_t                 *buf;

    u_char                    *pos;
    u_char                    *copy_start;
    u_char                    *copy_end;

    ngx_chain_t               *in;
    ngx_chain_t               *out;
    ngx_chain_t              **last_out;
    ngx_chain_t               *busy;
    ngx_chain_t               *free;

    ngx_str_t                 *sub;
    ngx_uint_t                 applied;

    ngx_int_t                  offset;
    ngx_uint_t                 index;

    ngx_http_sub_tables_t     *table;
    ngx_http_sub_match_t      *match;
} ngx_http_sub_ctx_t;


static ngx_int_t ngx_http_sub_output(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx);
static ngx_int_t ngx_http_sub_parse(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx);

static char * ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_sub_filter_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_tail_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_tail_filter_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_sub_create_conf(ngx_conf_t *cf);
static char *ngx_http_sub_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static void ngx_http_sub_init_singletables(ngx_http_sub_tables_t *tables, ngx_http_sub_match_t *match);
static ngx_int_t ngx_http_sub_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_sub_filter_commands[] = {

    { ngx_string("sub_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_sub_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sub_filter_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_sub_filter_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      { ngx_string("sub_tail"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_tail_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      { ngx_string("sub_tail_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_tail_filter_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sub_filter_once"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sub_loc_conf_t, once),
      NULL },

    { ngx_string("sub_filter_last_modified"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sub_loc_conf_t, last_modified),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_sub_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_sub_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_sub_create_conf,              /* create location configuration */
    ngx_http_sub_merge_conf                /* merge location configuration */
};


ngx_module_t  ngx_http_sub_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_sub_filter_module_ctx,       /* module context */
    ngx_http_sub_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

void *
ngx_http_get_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash)
{
    u_char      c, *lowcase;
    size_t      len;
    ngx_uint_t  i, hash;

    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lzj debug, ngx http get content type \"%V\"", &r->uri);
    if (types_hash->size == 0) {
        return NULL;
    }

    if (r->headers_out.content_type.len == 0) {
        return NULL;
    }

    len = r->headers_out.content_type_len;

    if (r->headers_out.content_type_lowcase == NULL) {

        lowcase = ngx_pnalloc(r->pool, len);
        if (lowcase == NULL) {
            return NULL;
        }

        r->headers_out.content_type_lowcase = lowcase;

        hash = 0;

        for (i = 0; i < len; i++) {
            c = ngx_tolower(r->headers_out.content_type.data[i]);
            hash = ngx_hash(hash, c);
            lowcase[i] = c;
        }

        r->headers_out.content_type_hash = hash;
    }

    return ngx_hash_find(types_hash, r->headers_out.content_type_hash,
                         r->headers_out.content_type_lowcase, len);
}


static ngx_int_t ngx_http_sub_header_filter(ngx_http_request_t *r)
{
    ngx_str_t                *m;
    ngx_uint_t               n;
    ngx_http_sub_ctx_t       *ctx;
    ngx_http_sub_pair_t      *pair, *pairs;
    ngx_http_sub_match_t     *match, *retmatch;
    ngx_http_sub_loc_conf_t  *slcf;
    ngx_http_sub_match_t     *matches;

    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lzj debug, ngx http sub header filter \"%V\"", &r->uri);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_sub_header_filter");

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);

    //n = mimetype_test_content_type(r, slcf->tables, slcf->tables_len);
    retmatch = ngx_http_get_content_type(r, &slcf->insertJS_in_hash);

    if (slcf->pairs == NULL
        || r->headers_out.content_length_n == 0
        || retmatch == NULL)
    {
        //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_sub_header_filter %d", slcf->tables_len);
        return ngx_http_next_header_filter(r);
    }

    n= retmatch->id;
    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_sub_header_filter %d", n);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sub_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (slcf->dynamic == 0) {
        
        matches = slcf->matches->elts;
        ctx->table = &slcf->tables[n];
        ctx->match = &matches[n];

        //ngx_log_debug2 (NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "head_filter %d tail:%d", n, ctx->match->tail);
    } else {
        pairs = slcf->pairs->elts;
        //n = slcf->pairs->nelts;
        pair = &pairs[n];

        match = ngx_pcalloc(r->pool, sizeof(ngx_http_sub_match_t));
        if (match == NULL) {
            return NGX_ERROR;
        }

        match->value = &pair->value;

        if (pair->match.lengths == NULL) {
            match->match = pair->match.value;
        }else{

            m =&match->match;
            if (ngx_http_complex_value(r, &pair->match, m) != NGX_OK) {
                return NGX_ERROR;
            }

            if (m->len == 0){
                return ngx_http_next_header_filter(r);
            }else {
                ngx_strlow(m->data, m->data, m->len);
            }
        }

        ctx->table = ngx_palloc(r->pool, sizeof(ngx_http_sub_tables_t));
        if (ctx->table == NULL) {
            return NGX_ERROR;
        }

        ctx->match = ngx_palloc(r->pool, sizeof(ngx_array_t));
        if (ctx->match == NULL) {
            return NGX_ERROR;
        }

        ctx->match = match;
        ngx_http_sub_init_singletables(ctx->table, ctx->match);

        //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "head_filter tail:%d", match->tail);
    }

    ngx_http_set_ctx(r, ctx, ngx_http_sub_filter_module);

    if(0 == ctx->match->tail){

        ctx->saved.data = ngx_pnalloc(r->pool, ctx->table->match_len - 1);
        if (ctx->saved.data == NULL) {
            return NGX_ERROR;
        }

        ctx->looked.data = ngx_pnalloc(r->pool, ctx->table->match_len - 1);
        if (ctx->looked.data == NULL) {
            return NGX_ERROR;
        }
    }

    ctx->offset = ctx->table->match_len - 1;
    ctx->last_out = &ctx->out;

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        ngx_http_clear_content_length(r);

        if (!slcf->last_modified) {
            ngx_http_clear_last_modified(r);
            ngx_http_clear_etag(r);

        } else {
            ngx_http_weak_etag(r);
        }
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t ngx_http_replace_filter(ngx_http_sub_ctx_t *ctx, ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_str_t                 *sub;
    ngx_chain_t               *cl;
    ngx_http_sub_match_t      *match;
    ngx_http_sub_loc_conf_t   *slcf;

    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lzj debug, ngx http replace filter \"%V\"", &r->uri);

    if (ctx->once && (ctx->buf == NULL || ctx->in == NULL)) {
        if (ctx->busy) {
            if (ngx_http_sub_output(r, ctx) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */
    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }


    while (ctx->in || ctx->buf) {
        if (ctx->buf == NULL) {
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;
            ctx->pos = ctx->buf->pos;
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last) {
            rc = ngx_http_sub_parse(r, ctx);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %i, looked: \"%V\" %p-%p",
                           rc, &ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (ctx->saved.len) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "saved: \"%V\"", &ctx->saved);

                cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                b = cl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->pos = ngx_pnalloc(r->pool, ctx->saved.len);
                if (b->pos == NULL) {
                    return NGX_ERROR;
                }

                ngx_memcpy(b->pos, ctx->saved.data, ctx->saved.len);
                b->last = b->pos + ctx->saved.len;
                b->memory = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                ctx->saved.len = 0;
            }

            if (ctx->copy_start != ctx->copy_end) {
                cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                b = cl->buf;

                ngx_memcpy(b, ctx->buf, sizeof(ngx_buf_t));

                b->pos = ctx->copy_start;
                b->last = ctx->copy_end;
                b->shadow = NULL;
                b->last_buf = 0;
                b->last_in_chain = 0;
                b->recycled = 0;

                if (b->in_file) {
                    b->file_last = b->file_pos + (b->last - ctx->buf->pos);
                    b->file_pos += b->pos - ctx->buf->pos;
                }

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }

            cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);

            if (ctx->sub == NULL) {
                ctx->sub = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
                if (ctx->sub == NULL) {
                    return NGX_ERROR;
                }
            }

            sub = &ctx->sub[ctx->index];
            if (sub->data == NULL) {
                match = ctx->match;

                if (ngx_http_complex_value(r, match[ctx->index].value, sub) != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

            if (sub->len) {
                b->memory = 1;
                b->pos = sub->data;
                b->last = sub->data + sub->len;

                r->injectJS = 1;
#if 0
                if(r->cachehit){
                    ngx_mylog_write(r, " IP:%V HIT  %V http://%V%V", &r->connection->addr_text,
                          &r->headers_out.content_type, &r->headers_in.server, &r->unparsed_uri);
                }else{
                    if(r->nocache){
                        ngx_mylog_write(r, " IP:%V MISS(Cache-control:No-Cache) %V http://%V%V", 
                            &r->connection->addr_text, 
                            &r->headers_out.content_type, &r->headers_in.server, &r->unparsed_uri);
                    }else if(r->nostore){
                        ngx_mylog_write(r, " IP:%V MISS(Cache-control:No-Store) %V http://%V%V",
                            &r->connection->addr_text, 
                            &r->headers_out.content_type, &r->headers_in.server, &r->unparsed_uri);
                    }else if(r->cachectrlPrivate){ 
                        ngx_mylog_write(r, " IP:%V MISS(Cache-control:Private) %V http://%V%V",
                            &r->connection->addr_text, 
                            &r->headers_out.content_type, &r->headers_in.server, &r->unparsed_uri);
                    }else{
                        ngx_mylog_write(r, " IP:%V MISS %V http://%V%V", &r->connection->addr_text, 
                            &r->headers_out.content_type, &r->headers_in.server, &r->unparsed_uri);
                    }
                }
#endif
            } else {
                b->sync = 1;
            }

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->index = 0;
            ctx->once = slcf->once && (++ctx->applied == 1);

            continue;
        }

        if (ctx->looked.len
            && (ctx->buf->last_buf || ctx->buf->last_in_chain))
        {
            cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->pos = ctx->looked.data;
            b->last = b->pos + ctx->looked.len;
            b->memory = 1;

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->looked.len = 0;
        }

        if (ctx->buf->last_buf || ctx->buf->flush || ctx->buf->sync
            || ngx_buf_in_memory(ctx->buf))
        {
            if (b == NULL) {
                cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                b = cl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->sync = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            b->last_buf = ctx->buf->last_buf;
            b->last_in_chain = ctx->buf->last_in_chain;
            b->flush = ctx->buf->flush;
            b->shadow = ctx->buf;

            b->recycled = ctx->buf->recycled;
        }

        ctx->buf = NULL;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }

    return ngx_http_sub_output(r, ctx);
}

static ngx_int_t ngx_http_addtail_filter(ngx_http_sub_ctx_t *ctx, ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t             *buf;
    ngx_uint_t             last;
    ngx_chain_t           *cl, *nl;
    ngx_http_sub_match_t      *match;
  //  ngx_str_t                 *sub;


    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lzj, in ngx http addtail filter-------------------------+ :%V",&r->connection->addr_text);

    last = 0;

    for (cl = in; cl; cl = cl->next) {
         if (cl->buf->last_buf) {
             last = 1;
             break;
         }
    }

    if (!last) {
        return ngx_http_next_body_filter(r, in);
    }

    buf = ngx_calloc_buf(r->pool);
    if (buf == NULL) {
        return NGX_ERROR;
    }

#if 0
    if (ctx->sub == NULL) {
        ctx->sub = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
        if (ctx->sub == NULL) {
            return NGX_ERROR;
        }
    }

    sub = ctx->sub;
    if (sub->data == NULL) {
        match = ctx->match;

        if (ngx_http_complex_value(r, match->value, sub) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    buf->pos = sub->data;
    buf->last = buf->pos + sub->len;
#else
    match = ctx->match;
    buf->pos = match->value->value.data;
    buf->last = buf->pos + match->value->value.len;
#endif
    buf->start = buf->pos;
    buf->end = buf->last;
    buf->last_buf = 1;
    buf->memory = 1;

    if (ngx_buf_size(cl->buf) == 0) {
        cl->buf = buf;
    } else {
        nl = ngx_alloc_chain_link(r->pool);
        if (nl == NULL) {
            return NGX_ERROR;
        }

        nl->buf = buf;
        nl->next = NULL;
        cl->next = nl;
        cl->buf->last_buf = 0;
    }

    r->injectJS = 1;

#if 0
    if(r->cachehit){
        ngx_mylog_write(r, " IP:%V HIT  %V http://%V%V", &r->connection->addr_text, 
            &r->headers_out.content_type, &r->headers_in.server, &r->unparsed_uri);
    }else{
        if(r->nocache){
            ngx_mylog_write(r, " IP:%V MISS(Cache-control:No-Cache) %V http://%V%V", &r->connection->addr_text, 
                &r->headers_out.content_type, &r->headers_in.server, &r->unparsed_uri);
         }else if(r->nostore){
            ngx_mylog_write(r, " IP:%V MISS(Cache-control:No-Store) %V http://%V%V", &r->connection->addr_text, 
                &r->headers_out.content_type, &r->headers_in.server, &r->unparsed_uri);
         }else if(r->cachectrlPrivate){ 
            ngx_mylog_write(r, " IP:%V MISS(Cache-control:Private) %V http://%V%V", &r->connection->addr_text, 
                &r->headers_out.content_type, &r->headers_in.server, &r->unparsed_uri);
         }else{
            ngx_mylog_write(r, " IP:%V MISS %V http://%V%V", &r->connection->addr_text, 
                &r->headers_out.content_type, &r->headers_in.server, &r->unparsed_uri);
         }
   }
#endif
    
    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "mylog1 :%V", &r->uri);

    return ngx_http_next_body_filter(r, in);
}


static ngx_int_t ngx_http_sub_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_sub_ctx_t        *ctx;
    ngx_http_sub_match_t     *match;
    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lzj debug, ngx http sub body filter \"%V\"", &r->uri);
    ctx = ngx_http_get_module_ctx(r, ngx_http_sub_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }
    
    if ((in == NULL
         && ctx->buf == NULL
         && ctx->in == NULL
         && ctx->busy == NULL))
    {
        return ngx_http_next_body_filter(r, in);
    }

    match = ctx->match;
    if(match->tail){
        return ngx_http_addtail_filter(ctx, r, in);
    }else{
        return ngx_http_replace_filter(ctx, r, in);
    }

    return NGX_ERROR;
}

static ngx_int_t ngx_http_sub_output(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lzj debug, ngx http sub output \"%V\"", &r->uri);
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sub out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in sub");
            ngx_debug_point();
            return NGX_ERROR;
        }
        b = cl->buf;
    }

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

        cl = ctx->busy;
        b = cl->buf;

        if (ngx_buf_size(b) != 0) {
            break;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (ngx_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= NGX_HTTP_SUB_BUFFERED;

    } else {
        r->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}


static ngx_int_t ngx_http_sub_parse(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx)
{
    u_char                   *p, *last, *pat, *pat_end, c;
    ngx_str_t                *m;
    ngx_int_t                 offset, start, next, end, len, rc;
    ngx_uint_t                shift;
    ngx_http_sub_match_t     *match;
    ngx_http_sub_tables_t    *table;
    ngx_http_sub_loc_conf_t  *slcf;

    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "lzj debug, ngx http sub parse \"%V\"", &r->uri);
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);
    table = ctx->table;

    offset = ctx->offset;
    end = ctx->buf->last - ctx->pos;

    if (ctx->once) {
        /* sets start and next to end */
        offset = end + (ngx_int_t) table->match_len - 1;
        goto again;
    }

    while (offset < end) {

        c = offset < 0 ? ctx->looked.data[ctx->looked.len + offset]
                       : ctx->pos[offset];

        c = ngx_tolower(c);

        shift = table->shift[c];
        if (shift > 0) {
            offset += shift;
            continue;
        }

        /* a potential match */

        start = offset - (ngx_int_t) table->match_len + 1;
        match = ctx->match;

        if (slcf->once && ctx->sub && ctx->sub[0].data) {
            goto next;
        }

        m = &match[0].match;

        pat = m->data;
        pat_end = m->data + m->len;

        if (start >= 0) {
            p = ctx->pos + start;

        } else {
            last = ctx->looked.data + ctx->looked.len;
            p = last + start;

            while (p < last && pat < pat_end) {
                if (ngx_tolower(*p) != *pat) {
                    goto next;
                }

                p++;
                pat++;
            }

            p = ctx->pos;
        }

        while (p < ctx->buf->last && pat < pat_end) {
            if (ngx_tolower(*p) != *pat) {
                goto next;
            }

            p++;
            pat++;
        }

        if (pat != pat_end) {
            /* partial match */
            goto again;
        }

        ctx->offset = offset + (ngx_int_t) m->len;
        next = start + (ngx_int_t) m->len;
        end = ngx_max(next, 0);
        rc = NGX_OK;

        goto done;

next:
        offset++;
        ctx->index = 0;
    }

again:
    ctx->offset = offset;
    start = offset - (ngx_int_t) table->match_len + 1;
    next = start;
    rc = NGX_AGAIN;

done:
    /* send [ - looked.len, start ] to client */
    ctx->saved.len = ctx->looked.len + ngx_min(start, 0);
    ngx_memcpy(ctx->saved.data, ctx->looked.data, ctx->saved.len);

    ctx->copy_start = ctx->pos;
    ctx->copy_end = ctx->pos + ngx_max(start, 0);

    /* save [ next, end ] in looked */
    len = ngx_min(next, 0);
    p = ctx->looked.data;
    p = ngx_movemem(p, p + ctx->looked.len + len, - len);

    len = ngx_max(next, 0);
    p = ngx_cpymem(p, ctx->pos + len, end - len);
    ctx->looked.len = p - ctx->looked.data;

    /* update position */
    ctx->pos += end;
    ctx->offset -= end;

    return rc;
}


static char *ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sub_loc_conf_t *slcf = conf;

    ngx_str_t                         *value;
    ngx_http_sub_pair_t               *pair;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[2].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty search pattern");
        return NGX_CONF_ERROR;
    }

    if (slcf->pairs == NULL) {
        slcf->pairs = ngx_array_create(cf->pool, 1, sizeof(ngx_http_sub_pair_t));
        if (slcf->pairs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (slcf->pairs->nelts == 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "number of search patterns exceeds 255");
        return NGX_CONF_ERROR;
    }

    ngx_strlow(value[2].data, value[2].data, value[2].len);

    pair = ngx_array_push(slcf->pairs);
    if (pair == NULL) {
        return NGX_CONF_ERROR;
    }

    pair->name= value[1];
    pair->tail = 0;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pair->match;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ccv.complex_value->lengths != NULL) {
        slcf->dynamic = 1;
    } else {
        ngx_strlow(pair->match.value.data, pair->match.value.data, pair->match.value.len);
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[3];
    ccv.complex_value = &pair->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *ngx_http_sub_filter_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sub_loc_conf_t *slcf = conf;

    ngx_str_t                         *value;
    ngx_http_sub_pair_t               *pair;
    ngx_http_compile_complex_value_t   ccv;
    ngx_fd_t          fd;
    ngx_str_t    *fileInfo;
    off_t        file_size;
    ssize_t      n;
    ngx_file_t   file;

    value = cf->args->elts;

    if (value[2].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty search pattern");
        return NGX_CONF_ERROR;
    }

    if (slcf->pairs == NULL) {
        slcf->pairs = ngx_array_create(cf->pool, 1, sizeof(ngx_http_sub_pair_t));
        if (slcf->pairs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (slcf->pairs->nelts == 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "number of search patterns exceeds 255");
        return NGX_CONF_ERROR;
    }

    ngx_strlow(value[2].data, value[2].data, value[2].len);

    pair = ngx_array_push(slcf->pairs);
    if (pair == NULL) {
        return NGX_CONF_ERROR;
    }

    pair->name= value[1];
    pair->tail = 0;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pair->match;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ccv.complex_value->lengths != NULL) {
        slcf->dynamic = 1;
    } else {
        ngx_strlow(pair->match.value.data, pair->match.value.data, pair->match.value.len);
    }


    fd = ngx_open_file(value[3].data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                 ngx_open_file_n " \"%s\" failed",
                 value[3].data);
        return NGX_CONF_ERROR;
   }

   file.fd = fd;
   file.name.len = value[3].len;
   file.name.data = value[3].data;
   file.offset = 0;
   file.log = cf->log;

   if (ngx_fd_info(fd, &file.info) == NGX_FILE_ERROR) {
         ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                          ngx_fd_info_n " \"%s\" failed", value[3].data);
		 return NGX_CONF_ERROR;
   }

    file_size = ngx_file_size(&file.info);
    fileInfo = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    fileInfo->len = file_size;
    fileInfo->data = ngx_pcalloc(cf->pool, file_size);
    n = ngx_read_file(&file, fileInfo->data, file_size, 0);
    if(n == 0){
         return NGX_CONF_ERROR;
    }
    
    //ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, " %s file", fileInfo->data);

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = fileInfo;
    ccv.complex_value = &pair->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}



static char *ngx_http_tail_filter_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sub_loc_conf_t *slcf = conf;

    ngx_str_t                         *value;
    ngx_http_sub_pair_t               *pair;
    //ngx_http_compile_complex_value_t   ccv;
    ngx_fd_t          fd;
    ngx_str_t    *fileInfo;
    off_t        file_size;
    ssize_t      n;
    ngx_file_t   file;

    value = cf->args->elts;

    if (value[2].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty replace pattern");
        return NGX_CONF_ERROR;
    }

    if (slcf->pairs == NULL) {
        slcf->pairs = ngx_array_create(cf->pool, 1, sizeof(ngx_http_sub_pair_t));
        if (slcf->pairs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (slcf->pairs->nelts == 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "number of search patterns exceeds 255");
        return NGX_CONF_ERROR;
    }

    pair = ngx_array_push(slcf->pairs);
    if (pair == NULL) {
        return NGX_CONF_ERROR;
    }


    pair->name = value[1];
    pair->tail = 1;

    slcf->dynamic = 0;
    fd = ngx_open_file(value[2].data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                 ngx_open_file_n " \"%s\" failed",
                 value[2].data);
        return NGX_CONF_ERROR;
   }

   file.fd = fd;
   file.name.len = value[2].len;
   file.name.data = value[2].data;
   file.offset = 0;
   file.log = cf->log;

   if (ngx_fd_info(fd, &file.info) == NGX_FILE_ERROR) {
         ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                          ngx_fd_info_n " \"%s\" failed", value[2].data);
		 return NGX_CONF_ERROR;
   }

    file_size = ngx_file_size(&file.info);
    fileInfo = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    fileInfo->len = file_size;
    fileInfo->data = ngx_pcalloc(cf->pool, file_size);
    n = ngx_read_file(&file, fileInfo->data, file_size, 0);
    if(n == 0){
	 if(strcmp(file.name.data,"/etc/nginx/ij.js") == 0)
	 {
         	return NGX_CONF_OK;
         }
         return NGX_CONF_ERROR;
    }

#if 0
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = fileInfo;
    ccv.complex_value = &pair->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
#endif

    pair->value.value.data = (unsigned char*)fileInfo->data;
    pair->value.value.len = file_size;
    //ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_http_tail_filter");

    return NGX_CONF_OK;
}

static char *ngx_http_tail_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sub_loc_conf_t *slcf = conf;

    ngx_str_t                         *value;
    ngx_http_sub_pair_t               *pair;
    ngx_http_compile_complex_value_t   ccv;

    //ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "lzj, in ngx http tail filter");
    value = cf->args->elts;

    if (value[2].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty replace pattern");
        return NGX_CONF_ERROR;
    }

    if (slcf->pairs == NULL) {
        slcf->pairs = ngx_array_create(cf->pool, 1, sizeof(ngx_http_sub_pair_t));
        if (slcf->pairs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (slcf->pairs->nelts == 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "number of search patterns exceeds 255");
        return NGX_CONF_ERROR;
    }

    pair = ngx_array_push(slcf->pairs);
    if (pair == NULL) {
        return NGX_CONF_ERROR;
    }


    pair->name = value[1];
    pair->tail = 1;

    slcf->dynamic = 0;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));


    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pair->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    //ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_http_tail_filter");

    return NGX_CONF_OK;
}


static void *ngx_http_sub_create_conf(ngx_conf_t *cf)
{
    ngx_http_sub_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sub_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->dynamic = 0;
     *     conf->pairs = NULL;
     *     conf->tables = NULL;
     *     conf->matches = NULL;
     */

    slcf->once = NGX_CONF_UNSET;
    slcf->last_modified = NGX_CONF_UNSET;

    return slcf;
}

static char *ngx_http_sub_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_uint_t                i, n;
    ngx_http_sub_pair_t      *pairs;
    ngx_http_sub_match_t     *matches;
    ngx_http_sub_loc_conf_t  *prev = parent;
    ngx_http_sub_loc_conf_t  *conf = child;
    ngx_array_t         insertJSArray;
    ngx_hash_key_t     *hk;
    ngx_hash_init_t     hash;


    ngx_conf_merge_value(conf->once, prev->once, 1);
    ngx_conf_merge_value(conf->last_modified, prev->last_modified, 0);

    if (conf->pairs == NULL) {
        conf->dynamic = prev->dynamic;
        conf->pairs = prev->pairs;
        conf->matches = prev->matches;
        conf->tables = prev->tables;
    }

    if (conf->pairs && conf->dynamic == 0 && conf->tables == NULL) {
        pairs = conf->pairs->elts;
        n = conf->pairs->nelts;

        matches = ngx_palloc(cf->pool, sizeof(ngx_http_sub_match_t) * n);
        if (matches == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < n; i++) {
            matches[i].match = pairs[i].match.value;
            matches[i].value = &pairs[i].value;
            matches[i].name = pairs[i].name;
            matches[i].tail = pairs[i].tail;
        }

        conf->matches = ngx_palloc(cf->pool, sizeof(ngx_array_t));
        if (conf->matches == NULL) {
            return NGX_CONF_ERROR;
        }

        conf->matches->elts = matches;
        conf->matches->nelts = n;

        conf->tables = ngx_palloc(cf->pool, sizeof(ngx_http_sub_tables_t)*n);
        if (conf->tables == NULL) {
            return NGX_CONF_ERROR;
        }

        for(i=0; i<conf->matches->nelts; i++){
            ngx_http_sub_init_singletables(&conf->tables[i], &matches[i]);
        }
        conf->tables_len = conf->matches->nelts;

        if (ngx_array_init(&insertJSArray, cf->temp_pool, 32, sizeof(ngx_hash_key_t))!= NGX_OK){
           return NGX_CONF_ERROR;
        }

	for(i=0; i<conf->tables_len; i++){
           hk = ngx_array_push(&insertJSArray);
           if (hk == NULL) {
              return NGX_CONF_ERROR;
            }

            hk->key = matches[i].name;
            hk->key_hash = ngx_hash_key_lc(matches[i].name.data,matches[i].name.len);
            hk->value = &matches[i];

            matches[i].id =i;
        }

        hash.hash = &conf->insertJS_in_hash;
        hash.key = ngx_hash_key_lc;
        hash.max_size = 128;
        hash.bucket_size = ngx_align(64, ngx_cacheline_size);
        hash.name = "insertJS_in_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, insertJSArray.elts, insertJSArray.nelts) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static void ngx_http_sub_init_singletables(ngx_http_sub_tables_t *table, ngx_http_sub_match_t *match)
{
    ngx_uint_t  min, j;
    u_char      c;

    table->name = match->name;
    table->match_len = match->match.len;

    if(match->tail){
        return;
    }

    min = ngx_min(table->match_len, 255);
    ngx_memset(table->shift, min, 256);

    for (j = 0; j < min; j++) {
        c = match->match.data[table->match_len - 1 - j];
        table->shift[c] = ngx_min(table->shift[c], (u_char)j);
    }
}

static ngx_int_t ngx_http_sub_filter_init(ngx_conf_t *cf)
{
    ngx_conf_log_error(NGX_LOG_DEBUG_HTTP, cf, 0, "tail_filter");

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_sub_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_sub_body_filter;

    return NGX_OK;
}


