#ifndef _HS_CTX_H
#define _HS_CTX_H

#include <pthread.h>
#include <uuid/uuid.h>

#include <glusterfs/mem-pool.h>
#include <glusterfs/refcount.h>
#include <glusterfs/locking.h>

#include "hs.h"
#include "hs-mem-types.h"
#include "khash.h"

static inline void
hs_purge(const char *k, struct hs *v) {
    if (k)
        GF_FREE((void *)k);
    if (v)
        GF_REF_PUT(v);
}

static inline void
hs_map_init(struct hs_ctx *ctx) {
    pthread_rwlock_init(&ctx->lock, NULL);
    ctx->map = kh_init(hs);
}

static inline void
hs_map_destroy(struct hs_ctx *ctx) {
    const char *kvar = NULL;
    struct hs *vvar = NULL;

    pthread_rwlock_wrlock(&ctx->lock);
    {
        kh_foreach(ctx->map, kvar, vvar, hs_purge(kvar, vvar));
        kh_destroy(hs, ctx->map);
    }
    pthread_rwlock_unlock(&ctx->lock);

    pthread_rwlock_destroy(&ctx->lock);
}

static inline void
hs_map_clear(struct hs_ctx *ctx) {
    const char *kvar = NULL;
    struct hs *vvar = NULL;

    pthread_rwlock_wrlock(&ctx->lock);
    {
        kh_foreach(ctx->map, kvar, vvar, hs_purge(kvar, vvar));
        kh_clear(hs, ctx->map); 
    }
    pthread_rwlock_unlock(&ctx->lock);
}

static inline struct hs *
hs_map_get(struct hs_ctx *ctx, uuid_t gfid) {
    khiter_t k = -1;    
    struct hs *vvar = NULL;

    pthread_rwlock_rdlock(&ctx->lock);
    {
        k = kh_get(hs, ctx->map, uuid_utoa(gfid));
        if (k != kh_end(ctx->map)) {
            vvar = kh_val(ctx->map, k);
            //GF_REF_GET(vvar);
        }
    }
    pthread_rwlock_unlock(&ctx->lock);

    return vvar;
}

static inline int 
hs_map_put(struct hs_ctx *ctx, uuid_t gfid, struct hs *vvar) {
    int ret = -1;
    khiter_t k = -1;

    pthread_rwlock_wrlock(&ctx->lock);
    {
        k = kh_put(hs, ctx->map, uuid_utoa(gfid), &ret);
        switch (ret) {
            case -1:
                break;
            case 0:
                GF_REF_PUT(kh_val(ctx->map, k));
                kh_val(ctx->map, k) = vvar;
                break;
            default:
                kh_key(ctx->map, k) = gf_strdup(uuid_utoa(gfid));
                kh_val(ctx->map, k) = vvar;
                break;
        }
    }
    pthread_rwlock_unlock(&ctx->lock);

    return ret;
}

static inline struct idx *
idx_from_needle(struct needle *needle, uint64_t offset) {
    struct idx *idx = NULL;

    idx = GF_CALLOC(1, sizeof(*idx)+NAME_MAX+1, gf_hs_mt_idx);    
    if (!idx)      
        goto out;

    gf_uuid_copy(idx->gfid, needle->gfid);
    idx->name_len = needle->name_len;
    idx->size = needle->size;
    if (needle->flags & F_DELETED)
        idx->offset = 0;
    else
        idx->offset = offset;
    gf_strncpy(idx->name, needle->data, needle->name_len);

out:
    return idx;
}

static inline void 
mem_idx_release(void *to_free) {
    struct mem_idx *mem_idx = (struct mem_idx *)to_free;

    if (!mem_idx)
        return;

    GF_FREE(mem_idx);
}

static inline struct mem_idx *
mem_idx_from_needle(struct needle *needle, uint64_t offset) {
    struct mem_idx *mem_idx = NULL;

    mem_idx = GF_CALLOC(1, sizeof(*mem_idx)+needle->name_len, gf_hs_mt_mem_idx);
    if (!mem_idx)      
        goto out;

    GF_REF_INIT(mem_idx, mem_idx_release);
    mem_idx->name_len = needle->name_len;
    mem_idx->size = needle->size;
    mem_idx->offset = offset;
    gf_strncpy(mem_idx->name, needle->data, needle->name_len);

out:
    return mem_idx;
}

static inline struct mem_idx *
mem_idx_from_idx(struct idx *idx) {
    struct mem_idx *mem_idx = NULL;

    mem_idx = GF_CALLOC(1, sizeof(*mem_idx)+idx->name_len, gf_hs_mt_mem_idx);
    if (!mem_idx)
        goto out;

    GF_REF_INIT(mem_idx, mem_idx_release);
    mem_idx->name_len = idx->name_len;
    mem_idx->size = idx->size;
    mem_idx->offset = idx->offset;
    gf_strncpy(mem_idx->name, idx->name, idx->name_len);

out:
    return mem_idx;
}

static inline void
mem_idx_purge(const char *k, struct mem_idx *v) {
    if (k)
        GF_FREE((void *)k);
    if (v)
        GF_REF_PUT(v);
}

static inline void
mem_idx_map_init(struct hs *hs) {
    pthread_rwlock_init(&hs->map_lock, NULL);
    hs->map = kh_init(mem_idx);    
}

static inline void
mem_idx_map_destroy(struct hs *hs) {
    const char *kvar = NULL;
    struct mem_idx *vvar = NULL;

    pthread_rwlock_wrlock(&hs->map_lock);
    {
        kh_foreach(hs->map, kvar, vvar, mem_idx_purge(kvar, vvar));
        kh_destroy(mem_idx, hs->map);
    }
    pthread_rwlock_unlock(&hs->map_lock);

    pthread_rwlock_destroy(&hs->map_lock);
}

static inline void
mem_idx_map_clear(struct hs *hs) {
    const char *kvar = NULL;
    struct mem_idx *vvar = NULL;

    pthread_rwlock_wrlock(&hs->map_lock);
    {
        kh_foreach(hs->map, kvar, vvar, mem_idx_purge(kvar, vvar));
        kh_clear(mem_idx, hs->map);
    }
    pthread_rwlock_unlock(&hs->map_lock);
}

static inline struct mem_idx *
mem_idx_map_get(struct hs *hs, uuid_t gfid) {
    khiter_t k = -1;
    struct mem_idx *vvar = NULL;

    pthread_rwlock_rdlock(&hs->map_lock);
    {
        k = kh_get(mem_idx, hs->map, uuid_utoa(gfid));
        if (k != kh_end(hs->map)) {
            vvar = kh_val(hs->map, k);
            //GF_REF_GET(vvar);
        }
    }
    pthread_rwlock_unlock(&hs->map_lock);

    return vvar;    
}

static inline int
mem_idx_map_put(struct hs *hs, uuid_t gfid, struct mem_idx *vvar) {
    int ret = -1;
    khiter_t k = -1;

    pthread_rwlock_wrlock(&hs->map_lock);
    {
        k = kh_put(mem_idx, hs->map, uuid_utoa(gfid), &ret);
        switch (ret) {
            case -1:
                break;
            case 0:
                GF_REF_PUT(kh_val(hs->map, k));
                kh_val(hs->map, k) = vvar;
                break;
            default:
                kh_key(hs->map, k) = gf_strdup(uuid_utoa(gfid));
                kh_val(hs->map, k) = vvar;
                break;
        }
    }
    pthread_rwlock_unlock(&hs->map_lock);

    return ret;
}

static inline void
dentry_release(void *to_free) {
    struct dentry *den = (struct dentry *)to_free;

    if (!den)
        return;

    if (den->mem_idx)
        GF_REF_PUT(den->mem_idx);
    GF_FREE(den);
}

static inline struct dentry *
dentry_from_needle(struct needle *needle, struct mem_idx *mem_idx) {
    struct dentry *den = NULL;

    den = GF_CALLOC(1, sizeof(*den), gf_hs_mt_dentry);
    if (!den)
        goto out;

    GF_REF_INIT(den, dentry_release);
    gf_uuid_copy(den->gfid, needle->gfid);
    if (needle->flags & F_DELETED)
        den->type = NON_T;
    else
        den->type = REG_T;
    GF_REF_GET(mem_idx);
    den->mem_idx = mem_idx;

out:
    return den;    
}

static inline struct dentry *
dentry_from_idx(struct idx *idx, struct mem_idx *mem_idx) {
    struct dentry *den = NULL;

    den = GF_CALLOC(1, sizeof(*den), gf_hs_mt_dentry);
    if (!den)
        goto out;

    GF_REF_INIT(den, dentry_release);
    gf_uuid_copy(den->gfid, idx->gfid);
    if (idx->offset > 0)
        den->type = REG_T;
    else
        den->type = NON_T;
    GF_REF_GET(mem_idx);
    den->mem_idx = mem_idx;

out:
    return den;
}

static inline struct dentry *
dentry_from_dir(const char *path, uuid_t gfid) {
    struct dentry *den = NULL;

    den = GF_CALLOC(1, sizeof(*den), gf_hs_mt_dentry);
    if (!den)
        goto out;

    GF_REF_INIT(den, dentry_release);
    gf_uuid_copy(den->gfid, gfid);
    den->type = DIR_T;
    den->mem_idx = NULL;

out:
    return den;  
}

static inline void
dentry_purge(const char *k, struct dentry *v) {
    if (k)
        GF_FREE((void *)k);
    if (v)
        GF_REF_PUT(v);
}

static inline void
dentry_map_init(struct hs *hs) {
    pthread_rwlock_init(&hs->lk_lock, NULL);
    hs->lookup = kh_init(dentry);    
}

static inline void
dentry_map_destroy(struct hs *hs) {
    const char *kvar = NULL;
    struct dentry *vvar = NULL;

    pthread_rwlock_wrlock(&hs->lk_lock);
    {
        kh_foreach(hs->lookup, kvar, vvar, dentry_purge(kvar, vvar));
        kh_destroy(dentry, hs->lookup);
    }
    pthread_rwlock_unlock(&hs->lk_lock);

    pthread_rwlock_destroy(&hs->lk_lock);
}

static inline void
dentry_map_clear(struct hs *hs) {
    const char *kvar = NULL;
    struct dentry *vvar = NULL;

    pthread_rwlock_wrlock(&hs->lk_lock);
    {
        kh_foreach(hs->lookup, kvar, vvar, dentry_purge(kvar, vvar));
        kh_clear(dentry, hs->lookup);
    }
    pthread_rwlock_unlock(&hs->lk_lock);
}

static inline struct dentry *
dentry_map_get(struct hs *hs, const char *name) {
    khiter_t k = -1;    
    struct dentry *vvar = NULL;

    pthread_rwlock_rdlock(&hs->lk_lock);
    {
        k = kh_get(dentry, hs->lookup, name);
        if (k != kh_end(hs->lookup)) {
            vvar = kh_val(hs->lookup, k);
            //GF_REF_GET(vvar);
        }
    }
    pthread_rwlock_unlock(&hs->lk_lock);

    return vvar;    
}

static inline int
dentry_map_put(struct hs *hs, const char *name, struct dentry *vvar) {
    int ret = -1;
    khiter_t k = -1;

    pthread_rwlock_wrlock(&hs->lk_lock);
    {
        k = kh_put(dentry, hs->lookup, name, &ret);
        switch (ret) {
            case -1:
                break;
            case 0:
                GF_REF_PUT(kh_val(hs->lookup, k));
                kh_val(hs->lookup, k) = vvar;
                break;
            default:
                kh_key(hs->lookup, k) = gf_strdup(name);
                kh_val(hs->lookup, k) = vvar;
                break;
        }
    }
    pthread_rwlock_unlock(&hs->lk_lock);

    return ret;
}

struct hs_ctx *hs_ctx_init(xlator_t *this);
void hs_ctx_free(struct hs_ctx *ctx);
void hs_dump(khash_t(hs) *map, const char *k, struct hs *v);
struct hs *hs_init(xlator_t *this, const char *rpath, struct hs *parent);    

#endif