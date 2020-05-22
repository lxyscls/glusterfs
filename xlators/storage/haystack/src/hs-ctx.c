#include <dirent.h>
#include <sys/types.h>
#include <uuid/uuid.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <glusterfs/mem-pool.h>
#include <glusterfs/dict.h>
#include <glusterfs/refcount.h>
#include <glusterfs/syscall.h>
#include <glusterfs/common-utils.h>
#include <glusterfs/glusterfs.h>
#include <glusterfs/compat.h>

#include "hs.h"
#include "hs-mem-types.h"

#define COFLAG (O_RDWR | O_CREAT | O_APPEND)
#define OFLAG (O_RDWR | O_APPEND)
#define MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

int
hs_mem_idx_print(dict_t *d, char *k, data_t *v, void *_unused) {
    struct hs_mem_idx *mem_idx = (struct hs_mem_idx *)v->data;

    if (mem_idx) {
        printf("%s : %s %s %lu\n", k, uuid_utoa(mem_idx->buf.ia_gfid), mem_idx->name, mem_idx->offset);
    }

    return 0;
}

static void 
hs_mem_idx_free(void *to_free) {
    struct hs_mem_idx *mem_idx = (struct hs_mem_idx *)to_free;

    if (!mem_idx) {
        return;
    }

    LOCK_DESTROY(&mem_idx->lock);
    GF_FREE(mem_idx);
}

static int
hs_mem_idx_purge(dict_t *d, char *k, data_t *v, void *_unused) {
    struct hs_mem_idx *mem_idx = (struct hs_mem_idx *)v->data;

    if (mem_idx) {
        GF_REF_PUT(mem_idx);
    }

    return 0;
}

struct hs_idx *
hs_idx_init_from_needle(struct hs_needle *needle, uint64_t offset) {
    struct hs_idx *idx = NULL;

    if (!needle) {
        goto out;
    }

    idx = GF_CALLOC(1, sizeof(*idx)+NAME_MAX+1, gf_common_mt_char);    
    if (!idx) {
        goto out;
    }

    gf_uuid_copy(idx->gfid, needle->gfid);
    idx->buf = needle->buf;
    idx->name_len = needle->name_len;
    idx->size = needle->size;
    if (needle->flags & DELETED) {
        idx->offset = 0;
    } else {
        idx->offset = offset;
    }
    gf_strncpy(idx->name, needle->data, needle->name_len);

out:
    return idx;
}

struct hs_mem_idx *
hs_mem_idx_init_from_needle(struct hs_needle *needle, uint64_t offset) {
    struct hs_mem_idx *mem_idx = NULL;

    if (!needle) {
        goto out;
    }

    mem_idx = GF_CALLOC(1, sizeof(*mem_idx)+needle->name_len, gf_hs_mt_hs_mem_idx);
    if (!mem_idx) {
        goto out;
    }

    GF_REF_INIT(mem_idx, hs_mem_idx_free);
    LOCK_INIT(&mem_idx->lock);
    mem_idx->buf = needle->buf;
    mem_idx->name_len = needle->name_len;
    mem_idx->size = needle->size;
    mem_idx->offset = offset;
    gf_strncpy(mem_idx->name, needle->data, needle->name_len);

out:
    return mem_idx;
}

struct hs_mem_idx *
hs_mem_idx_init_from_idx(struct hs_idx *idx) {
    struct hs_mem_idx *mem_idx = NULL;

    if (!idx) {
        goto out;
    }

    mem_idx = GF_CALLOC(1, sizeof(*mem_idx)+idx->name_len, gf_hs_mt_hs_mem_idx);
    if (!mem_idx) {
        goto out;
    }

    GF_REF_INIT(mem_idx, hs_mem_idx_free);
    LOCK_INIT(&mem_idx->lock);
    mem_idx->buf = idx->buf;
    mem_idx->name_len = idx->name_len;
    mem_idx->size = idx->size;
    mem_idx->offset = idx->offset;
    gf_strncpy(mem_idx->name, idx->name, idx->name_len);

out:
    return mem_idx;
}

static int
hs_slow_build(struct hs *hs) {
    int ret = -1;
    char *log_rpath = NULL;
    char *idx_rpath = NULL;
    int log_fd = -1;
    int idx_fd = -1;
    struct stat stbuf = {0};
    struct hs_super super = {0};
    ssize_t size = -1;
    uint64_t offset = 0;
    struct hs_needle *needle = NULL;
    struct hs_mem_idx *mem_idx = NULL;
    struct hs_idx *idx = NULL;

    log_rpath = GF_CALLOC(1, strlen(hs->real_path)+1+strlen(".log")+1, gf_common_mt_char);
    if (!log_rpath) {
        ret = -1;
        goto err;
    }
    sprintf(log_rpath, "%s/.log", hs->real_path);

    idx_rpath = GF_CALLOC(1, strlen(hs->real_path)+1+strlen(".idx")+1, gf_common_mt_char);
    if (!idx_rpath) {
        ret = -1;
        goto err;
    }
    sprintf(idx_rpath, "%s/.idx", hs->real_path);

    needle = GF_CALLOC(1, sizeof(*needle)+NAME_MAX+1, gf_common_mt_char);
    if (!needle) {
        ret = -1;
        goto err;
    }

    log_fd = sys_open(log_rpath, OFLAG, MODE);
    if (log_fd == -1) {
        ret = -1;
        goto err;
    }
    
    ret = sys_stat(idx_rpath, &stbuf);
    if (!ret) {
        sys_unlink(idx_rpath);
    }
    
    idx_fd = sys_open(idx_rpath, COFLAG, MODE);
    if (idx_fd == -1) {
        ret = -1;
        goto err;
    }

    super.version = HSVERSION;
    gf_uuid_copy(super.gfid, hs->gfid);

    size = sys_pwrite(idx_fd, &super, sizeof(super), 0);
    if (size != sizeof(super)) {
        ret = -1;
        goto err;
    }    

    size = sys_pread(log_fd, &super, sizeof(super), offset);
    if (size != sizeof(super) || super.version != HSVERSION || gf_uuid_compare(super.gfid, hs->gfid)) {
        ret = -1;
        goto err;
    }

    offset += size;

    int i = 0;
    while (_gf_true) {
        size = sys_pread(log_fd, needle, sizeof(*needle)+NAME_MAX+1, offset);
        if (size == 0) {
            break;
        }

        /* broken file */
        if (size < sizeof(*needle)) {          
            ret = -1;
            goto err;
        }

        if (!gf_uuid_is_null(needle->gfid)) {         
            ret = dict_get_bin(hs->mem, uuid_utoa(needle->gfid), (void **)&mem_idx);
            if (needle->flags & DELETED) {            
                if (!ret) {                    
                    dict_del(hs->mem, uuid_utoa(needle->gfid));
                    GF_REF_PUT(mem_idx);
                }
            } else {
                if (!ret) {
                    GF_REF_PUT(mem_idx);                
                }

                mem_idx = hs_mem_idx_init_from_needle(needle, offset);
                if (mem_idx) {
                    ret = dict_set_static_bin(hs->mem, uuid_utoa(needle->gfid), mem_idx, sizeof(*mem_idx)+mem_idx->name_len);
                    if (ret) {
                        GF_REF_PUT(mem_idx);
                        ret = -1;
                        goto err; /* log for set fail */
                    }
                } else {
                    ret = -1;
                    goto err; /* log for mem_idx_init fail */
                }
            }

            /* idx seq != log seq is fatal! */
            idx = hs_idx_init_from_needle(needle, offset);
            if (idx) {
                size = sys_write(hs->idx_fd, idx, sizeof(*idx)+idx->name_len);
                if (size != sizeof(*idx)+idx->name_len) {
                    GF_FREE(idx);
                    ret = -1;
                    goto err; /* log for write fail */
                }
                GF_FREE(idx);
            }
        }

        offset += (sizeof(struct hs_needle) + needle->name_len + needle->size);
        
        ++i;
    }

    hs->log_fd = log_fd;
    hs->idx_fd = idx_fd;
    GF_FREE(log_rpath);
    GF_FREE(idx_rpath);
    GF_FREE(needle);
    
    return 0;

err:
    if (log_fd >= 0) {
        sys_close(log_fd);
    }
    if (idx_fd >= 0) {
        sys_close(idx_fd);
    }
    dict_foreach(hs->mem, hs_mem_idx_purge, NULL);
    GF_FREE(log_rpath);
    GF_FREE(idx_rpath);
    GF_FREE(needle);

    return ret;
}

static int
hs_orphan_build(struct hs *hs) {
    int ret = -1;
    int fd = -1;
    ssize_t size = -1;
    char *log_rpath = NULL;
    struct hs_needle *needle = NULL;
    struct hs_mem_idx *mem_idx = NULL;
    struct hs_idx *idx = NULL;
    uint64_t offset = 0;

    log_rpath = GF_CALLOC(1, strlen(hs->real_path)+1+strlen(".log")+1, gf_common_mt_char);
    if (!log_rpath) {
        ret = -1;
        goto err;
    }
    sprintf(log_rpath, "%s/.log", hs->real_path);

    needle = GF_CALLOC(1, sizeof(*needle)+NAME_MAX+1, gf_common_mt_char);
    if (!needle) {
        ret = -1;
        goto err;
    }

    fd = sys_open(log_rpath, OFLAG, MODE);
    if (fd == -1) {
        ret = -1;
        goto err;
    }

    offset = hs->log_offset;

    int i = 0;
    while (_gf_true) {
        size = sys_pread(fd, needle, sizeof(*needle)+NAME_MAX+1, offset);
        if (size == 0) {
            break;
        }

        /* broken file */
        if (size < sizeof(*needle)) {          
            ret = -1;
            goto err;
        }

        if (!gf_uuid_is_null(needle->gfid)) {         
            ret = dict_get_bin(hs->mem, uuid_utoa(needle->gfid), (void **)&mem_idx);
            if (needle->flags & DELETED) {            
                if (!ret) {                    
                    dict_del(hs->mem, uuid_utoa(needle->gfid));
                    GF_REF_PUT(mem_idx);
                }
            } else {
                if (!ret) {
                    GF_REF_PUT(mem_idx);                
                }

                mem_idx = hs_mem_idx_init_from_needle(needle, offset);
                if (mem_idx) {
                    ret = dict_set_static_bin(hs->mem, uuid_utoa(needle->gfid), mem_idx, sizeof(*mem_idx)+mem_idx->name_len);
                    if (ret) {
                        GF_REF_PUT(mem_idx);
                        ret = -1;
                        goto err; /* log for set fail */
                    }
                } else {
                    ret = -1;
                    goto err; /* log for mem_idx_init fail */
                }
            }

            idx = hs_idx_init_from_needle(needle, offset);
            if (idx) {
                size = sys_write(hs->idx_fd, idx, sizeof(*idx)+idx->name_len);
                if (size != sizeof(*idx)+idx->name_len) {
                    GF_FREE(idx);
                    ret = -1;
                    goto err; /* log for write fail */
                }
                GF_FREE(idx);
            }
        }

        offset += (sizeof(struct hs_needle) + needle->name_len + needle->size);       

        ++i; 
    }

    hs->log_fd = fd;
    GF_FREE(log_rpath);    
    GF_FREE(needle);
    
    return 0;    

err:
    if (fd > 0) {
        sys_close(fd);
    }

    dict_foreach(hs->mem, hs_mem_idx_purge, NULL);
    sys_close(hs->idx_fd);
    hs->idx_fd = -1;
    GF_FREE(log_rpath);
    GF_FREE(needle);
    return ret;
}

static int
hs_quick_build(struct hs *hs) {
    int fd = -1;
    int ret = -1;
    char *rpath = NULL;
    struct stat stbuf = {0};
    ssize_t size = -1;
    struct hs_super super = {0};
    struct hs_idx *idx = NULL;
    struct hs_mem_idx *mem_idx =NULL;
    ssize_t offset = 0;

    rpath = GF_CALLOC(1, strlen(hs->real_path)+1+strlen(".idx")+1, gf_common_mt_char);
    if (!rpath) {
        ret = -1;
        goto err;
    }
    sprintf(rpath, "%s/.idx", hs->real_path);

    idx = GF_CALLOC(1, sizeof(*idx)+NAME_MAX+1, gf_hs_mt_hs_idx);
    if (!idx) {
        ret = -1;
        goto err;
    }    

    ret = sys_stat(rpath, &stbuf);
    if (ret != 0 && errno == ENOENT) {
        goto err;
    }

    fd = sys_open(rpath, OFLAG, MODE);
    if (fd == -1) {
        ret = -1;
        goto err;
    }

    size = sys_pread(fd, &super, sizeof(super), offset);
    if (size != sizeof(super) || super.version != HSVERSION || gf_uuid_compare(super.gfid, hs->gfid)) {
        sys_close(fd);
        ret = -1;
        goto err;
    }

    offset += size;
    hs->log_offset = size;

    int i = 0;
    while (_gf_true) {
        size = sys_pread(fd, idx, sizeof(*idx)+NAME_MAX+1, offset);
        if (size == 0) {
            break;
        }

        if (size < sizeof(*idx)) {
            sys_ftruncate(fd, offset);
            break;
        }

        if (!gf_uuid_is_null(idx->gfid)) {            
            ret = dict_get_bin(hs->mem, uuid_utoa(idx->gfid), (void **)&mem_idx);
            if (idx->offset == 0) {            
                if (!ret) {                    
                    dict_del(hs->mem, uuid_utoa(idx->gfid));
                    GF_REF_PUT(mem_idx);
                }
            } else {
                if (!ret) {
                    GF_REF_PUT(mem_idx);               
                }

                mem_idx = hs_mem_idx_init_from_idx(idx);
                if (mem_idx) {
                    ret = dict_set_static_bin(hs->mem, uuid_utoa(idx->gfid), mem_idx, sizeof(*mem_idx)+mem_idx->name_len);
                    if (ret) {
                        GF_REF_PUT(mem_idx);
                        ret = -1;
                        goto err; /* log for set fail */
                    }
                } else {
                    ret = -1;
                    goto err; /* log for mem_idx_init fail*/
                }                                
            }
        }
        
        offset += (sizeof(*idx) + idx->name_len);
        hs->log_offset = idx->offset + sizeof(struct hs_needle) + idx->name_len + idx->size;        

        ++i;
    }

    hs->idx_fd = fd;
    GF_FREE(rpath);
    GF_FREE(idx);

    return 0;

err:
    if (fd >= 0) {
        sys_close(fd);
    }

    dict_foreach(hs->mem, hs_mem_idx_purge, NULL);
    GF_FREE(rpath);
    GF_FREE(idx);
    return ret;
}

static int
hs_build(struct hs *hs) {
    int ret = -1;
    struct stat stbuf = {0};
    char *log_rpath = NULL;
    char *idx_rpath = NULL;
    int log_fd = -1;
    int idx_fd = -1;
    ssize_t size = -1;
    struct hs_super super = {0};

    log_rpath = GF_CALLOC(1, strlen(hs->real_path)+1+strlen(".log")+1, gf_common_mt_char);
    if (!log_rpath) {
        ret = -1;
        goto err;
    }
    sprintf(log_rpath, "%s/.log", hs->real_path);

    idx_rpath = GF_CALLOC(1, strlen(hs->real_path)+1+strlen(".idx")+1, gf_common_mt_char);
    if (!idx_rpath) {
        ret = -1;
        goto err;
    }
    sprintf(idx_rpath, "%s/.idx", hs->real_path);

    ret = sys_stat(log_rpath, &stbuf);
    if (ret != 0 && errno == ENOENT) {
        goto new;
    }

    ret = hs_quick_build(hs);
    if (ret != 0) {
        ret = hs_slow_build(hs);
    } else {
        ret = hs_orphan_build(hs);
    }

    if (ret != 0) {
        ret = -1;
        goto err;
    }

    return 0;

new:
    log_fd = sys_open(log_rpath, COFLAG, MODE);
    if (log_fd == -1) {
        ret = -1;
        goto err;
    }

    ret = sys_stat(idx_rpath, &stbuf);
    if (!ret) {
        sys_unlink(idx_rpath);
    }
    
    idx_fd = sys_open(idx_rpath, COFLAG, MODE);
    if (idx_fd == -1) {
        ret = -1;
        goto err;
    }

    super.version = HSVERSION;
    gf_uuid_copy(super.gfid, hs->gfid);
    
    size = sys_pwrite(log_fd, &super, sizeof(super), 0);
    if (size != sizeof(super)) {
        ret = -1;
        goto err;
    }

    size = sys_pwrite(idx_fd, &super, sizeof(super), 0);
    if (size != sizeof(super)) {
        ret = -1;
        goto err;
    }

    hs->log_fd = log_fd;
    hs->idx_fd = idx_fd;
    GF_FREE(log_rpath);
    GF_FREE(idx_rpath);

    return 0;

err:
    if (log_fd >= 0) {
        sys_close(log_fd);
    }
    if (idx_fd >= 0) {
        sys_close(idx_fd);
    }
    GF_FREE(log_rpath);
    GF_FREE(idx_rpath);

    return ret;
}

int
hs_print(dict_t *d, char *k, data_t *v, void *_unused) {
    struct hs *hs = (struct hs *)v->data;

    if (hs) {
        printf("%s : %s\n", uuid_utoa(hs->gfid), hs->real_path);
    }

    dict_foreach(hs->mem, hs_mem_idx_print, NULL);

    return 0;
}

static void 
hs_free(void *to_free) {
    struct hs *hs = (struct hs *)to_free;

    if (!hs) {
        return;
    }

    dict_foreach(hs->mem, hs_mem_idx_purge, NULL);
    dict_unref(hs->mem);
    GF_FREE(hs->real_path);
    GF_FREE(hs);
}

static int
hs_purge(dict_t *d, char *k, data_t *v, void *_unused) {
    struct hs *hs = (struct hs *)v->data;

    if (hs) {
        GF_REF_PUT(hs);
    }

    return 0;
}

struct hs *
hs_init(const char *rpath, struct hs *parent) {
    ssize_t size = -1;
    int ret = -1;
    uuid_t gfid = {0}; 
    struct hs *hs = NULL;

    /* invalid directory */
    size = sys_lgetxattr(rpath, "trusted.gfid", gfid, sizeof(gfid));
    if (size != sizeof(gfid)) {
        goto err;
    }

    hs = (void *)GF_CALLOC(1, sizeof(struct hs), gf_hs_mt_hs);
    if (!hs) {
        goto err;
    } else {
        GF_REF_INIT(hs, hs_free);
    }

    gf_uuid_copy(hs->gfid, gfid);

    hs->real_path = gf_strdup(rpath);
    if (!hs->real_path) {
        goto err;
    }

    hs->mem = dict_new();
    if (!hs->mem) {
        goto err;
    }

    hs->log_fd = -1;
    hs->idx_fd = -1;
    hs->log_offset = 0;

    ret = hs_build(hs);
    if (ret < 0) {
        goto err;
    }

    hs->parent = parent;
    return hs;

err:
    if (hs) {
        GF_REF_PUT(hs);
    }
    return NULL;
}

/*
** It is obvious that only root directory is fatal. 
*/
static struct hs *
hs_scan(const char *rpath, struct hs *parent, struct hs_ctx *ctx) {
    struct hs *hs = NULL;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    struct dirent scratch[2] = {{0}};
    char *child_rpath = NULL;
    struct stat stbuf = {0};
    int ret = -1;

    hs = hs_init(rpath, parent);
    if (!hs) {
        goto err;
    }

    dir = sys_opendir(rpath);
    if (!dir) {
        goto err;
    }

    while ((entry=sys_readdir(dir, scratch)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
            continue;
        }

        child_rpath = GF_MALLOC(strlen(rpath)+1+strlen(entry->d_name)+1, gf_common_mt_char);
        if (child_rpath) {
            sprintf(child_rpath, "%s/%s", rpath, entry->d_name);
            ret = sys_lstat(child_rpath, &stbuf);
            if (!ret && S_ISDIR(stbuf.st_mode)) {
                hs_scan(child_rpath, hs, ctx);
            }
            GF_FREE(child_rpath);
        }
    }
    sys_closedir(dir);

    ret = dict_set_static_bin(ctx->hs_dict, uuid_utoa(hs->gfid), hs, sizeof(*hs));
    if (ret != 0) {
        goto err;
    }

    return hs;

err:
    if (hs) {
        GF_REF_PUT(hs);
    }
    return NULL;
}

void
hs_ctx_free(struct hs_ctx *ctx) {
    if (!ctx) {
        return;
    }

    dict_foreach(ctx->hs_dict, hs_purge, NULL);
    dict_unref(ctx->hs_dict);
    GF_FREE(ctx);
}

struct hs_ctx *
hs_ctx_init(const char *rpath) {
    struct hs_ctx *ctx = NULL;

    ctx = (void *)GF_CALLOC(1, sizeof(struct hs_ctx), gf_hs_mt_hs_ctx);
    if (!ctx) {
        goto err;
    }

    ctx->hs_dict = dict_new();
    if (!ctx->hs_dict) {
        goto err;
    }

    ctx->root = hs_scan(rpath, NULL, ctx);
    if (!ctx->root) {
        goto err;
    }

    return ctx;

err:
    hs_ctx_free(ctx);
    return NULL;
}