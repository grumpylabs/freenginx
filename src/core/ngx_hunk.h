#ifndef _NGX_HUNK_H_INCLUDED_
#define _NGX_HUNK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* hunk type */

/* the hunk is in memory */
#define NGX_HUNK_IN_MEMORY    0x0001
/* the hunk's content can be changed */
#define NGX_HUNK_TEMP         0x0002
/* the hunk's content is in cache and can not be changed */
#define NGX_HUNK_MEMORY       0x0004
/* the hunk's content is mmap()ed and can not be changed */
#define NGX_HUNK_MMAP         0x0008

#define NGX_HUNK_RECYCLED     0x0010

/* the hunk is in file */
#define NGX_HUNK_FILE         0x0100

#define NGX_HUNK_STORAGE      (NGX_HUNK_IN_MEMORY                            \
                               |NGX_HUNK_TEMP|NGX_HUNK_MEMORY|NGX_HUNK_MMAP  \
                               |NGX_HUNK_RECYCLED|NGX_HUNK_FILE)

/* hunk flags */

/* in thread state flush means to write the hunk completely before return */
/* in event state flush means to start to write the hunk */
#define NGX_HUNK_FLUSH        0x1000
/* last hunk */
#define NGX_HUNK_LAST         0x2000
#define NGX_HUNK_LAST_SHADOW  0x4000
#define NGX_HUNK_TEMP_FILE    0x8000


typedef void *                   ngx_hunk_tag_t;

typedef struct ngx_hunk_s        ngx_hunk_t;

struct ngx_hunk_s {
    char            *pos;
    char            *last;
    off_t            file_pos;
    off_t            file_last;

    int              type;
    char            *start;         /* start of hunk */
    char            *end;           /* end of hunk */
    char            *pre_start;     /* start of pre-allocated hunk */
    char            *post_end;      /* end of post-allocated hunk */
    ngx_hunk_tag_t   tag;
    ngx_file_t      *file;
    ngx_hunk_t      *shadow;
    /* STUB */ int   num;
};


typedef struct ngx_chain_s       ngx_chain_t;

struct ngx_chain_s {
    ngx_hunk_t  *hunk;
    ngx_chain_t *next;
};


typedef struct {
    int          num;
    ssize_t      size;
} ngx_bufs_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_hunk_in_memory_only(h)                                           \
         ((h->type & (NGX_HUNK_IN_MEMORY|NGX_HUNK_FILE)) == NGX_HUNK_IN_MEMORY)
/*
    ((h->type & (NGX_HUNK_TEMP|NGX_HUNK_MEMORY|NGX_HUNK_MMAP|NGX_HUNK_FILE)) \
                  == (h->type & (NGX_HUNK_TEMP|NGX_HUNK_MEMORY|NGX_HUNK_MMAP)))

*/

#define ngx_hunk_special(h)                                                  \
        (h->type == (h->type & (NGX_HUNK_FLUSH|NGX_HUNK_LAST)))


#define ngx_hunk_size(h)                                                     \
        ((h->type & NGX_HUNK_IN_MEMORY) ? h->last - h->pos:                  \
                                         (size_t) (h->file_last - h->file_pos))


ngx_hunk_t *ngx_create_temp_hunk(ngx_pool_t *pool, int size,
                                 int before, int after);

#define ngx_alloc_hunk(pool) ngx_palloc(pool, sizeof(ngx_hunk_t))
#define ngx_calloc_hunk(pool) ngx_pcalloc(pool, sizeof(ngx_hunk_t))

#define ngx_alloc_chain_entry(pool) ngx_palloc(pool, sizeof(ngx_chain_t))

#define ngx_add_hunk_to_chain(chain, h, pool, error)                         \
            do {                                                             \
                ngx_test_null(chain, ngx_alloc_chain_entry(pool), error);    \
                chain->hunk = h;                                             \
                chain->next = NULL;                                          \
            } while (0);

#define ngx_alloc_ce_and_set_hunk  ngx_add_hunk_to_chain


#define ngx_chain_add_ce(chain, last, ce)                                    \
            if (chain) {                                                     \
                *last = ce;                                                  \
            } else {                                                         \
                chain = ce;                                                  \
            }                                                                \
            last = &ce->next


int ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **ch, ngx_chain_t *in);
void ngx_chain_update_chains(ngx_chain_t **free, ngx_chain_t **busy,
                             ngx_chain_t **out, ngx_hunk_tag_t tag);



#endif /* _NGX_HUNK_H_INCLUDED_ */
