#include <dirent.h>
#include <sys/types.h>
#include <uuid/uuid.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <alloca.h>

#ifdef HAVE_LIB_Z
#include "zlib.h"
#endif

#include <glusterfs/mem-pool.h>
#include <glusterfs/dict.h>
#include <glusterfs/refcount.h>
#include <glusterfs/syscall.h>
#include <glusterfs/common-utils.h>
#include <glusterfs/glusterfs.h>
#include <glusterfs/compat.h>
#include <glusterfs/logging.h>
#include <glusterfs/locking.h>
#include <glusterfs/list.h>
#include <glusterfs/xlator.h>

#include "hs.h"
#include "hs-mem-types.h"
#include "hs-messages.h"

#define COFLAG (O_RDWR | O_CREAT | O_APPEND)
#define OFLAG (O_RDWR | O_APPEND)
#define MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define BUFF_SIZE (128*1024)

static __thread char build_buf[BUFF_SIZE] = {0};

#define HS_DENTRY_PURGE(k, v)                    \
    do {                                         \
        GF_FREE(k);                              \
        GF_FREE(v);                              \
    } while (0)

#define HS_MEM_IDX_PURGE(k, v)                   \
    do {                                         \
        GF_FREE(k);                              \
        GF_REF_PUT((struct mem_idx *)v);         \
    } while (0)    

void
hs_mem_idx_dump(khash_t(mem_idx) *map, char *k, struct mem_idx *v) {
    if (v) {
        printf("%s : %s %s %lu\n", k, uuid_utoa(v->buf.ia_gfid), v->name, v->offset);
    }
}

void 
hs_mem_idx_release(void *to_free) {
    struct mem_idx *mem_idx = (struct mem_idx *)to_free;

    if (!mem_idx) {
        return;
    }

    LOCK_DESTROY(&mem_idx->lock);
    GF_FREE(mem_idx);
}

struct idx *
hs_idx_from_needle(struct needle *needle, uint64_t offset) {
    struct idx *idx = NULL;

    idx = GF_CALLOC(1, sizeof(*idx)+NAME_MAX+1, gf_hs_mt_idx);    
    if (!idx) {
        gf_msg(THIS->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc idx (%s %s).", needle->data, uuid_utoa(needle->gfid));        
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

struct dentry *
hs_dentry_from_needle(struct needle *needle) {
    struct dentry *den = NULL;

    den = GF_CALLOC(1, sizeof(*den), gf_hs_mt_dentry);
    if (!den) {
        gf_msg(THIS->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc dentry (%s %s).", needle->data, uuid_utoa(needle->gfid));
        goto out;
    }

    gf_uuid_copy(den->gfid, needle->gfid);
    den->type = REG_T;

out:
    return den;    
}

struct mem_idx *
hs_mem_idx_from_needle(struct needle *needle, uint64_t offset) {
    struct mem_idx *mem_idx = NULL;

    mem_idx = GF_CALLOC(1, sizeof(*mem_idx)+needle->name_len, gf_hs_mt_mem_idx);
    if (!mem_idx) {
        gf_msg(THIS->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc mem idx (%s %s).", needle->data, uuid_utoa(needle->gfid));        
        goto out;
    }

    GF_REF_INIT(mem_idx, hs_mem_idx_release);
    LOCK_INIT(&mem_idx->lock);
    mem_idx->buf = needle->buf;
    mem_idx->name_len = needle->name_len;
    mem_idx->size = needle->size;
    mem_idx->offset = offset;
    gf_strncpy(mem_idx->name, needle->data, needle->name_len);

out:
    return mem_idx;
}

struct dentry *
hs_dentry_from_idx(struct idx *idx) {
    struct dentry *den = NULL;

    den = GF_CALLOC(1, sizeof(*den), gf_hs_mt_dentry);
    if (!den) {
        gf_msg(THIS->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc dentry (%s %s).", idx->name, uuid_utoa(idx->gfid));
        goto out;
    }

    gf_uuid_copy(den->gfid, idx->gfid);
    den->type = REG_T;

out:
    return den;
}

struct mem_idx *
hs_mem_idx_from_idx(struct idx *idx) {
    struct mem_idx *mem_idx = NULL;

    mem_idx = GF_CALLOC(1, sizeof(*mem_idx)+idx->name_len, gf_hs_mt_mem_idx);
    if (!mem_idx) {
        gf_msg(THIS->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc mem idx (%s %s).", idx->name, uuid_utoa(idx->gfid));
        goto out;
    }

    GF_REF_INIT(mem_idx, hs_mem_idx_release);
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
hs_slow_build(xlator_t *this, struct hs *hs) {
    int ret = -1;
    char *log_path = NULL;
    char *idx_path = NULL;
    int log_fd = -1;
    int idx_fd = -1;
    struct stat stbuf = {0};
    struct super super = {0};
    ssize_t size = -1;
    uint64_t offset = 0;
    struct needle *needle = NULL;
    struct mem_idx *mem_idx = NULL;
    struct idx *idx = NULL;
    struct dentry *den = NULL;
    uint64_t left = 0;
    uint64_t shift = 0;
    ssize_t wsize = -1;
    struct hs_private *priv = NULL;
    uint32_t crc = 0;
    khiter_t k = -1;
    khiter_t kk = -1;
    char *kvar = NULL;
    void *vvar = NULL;

    priv = this->private;

    MAKE_LOG_PATH(log_path, this, hs->path);
    MAKE_IDX_PATH(idx_path, this, hs->path);

    ret = sys_stat(idx_path, &stbuf);
    if (!ret) {
        if (S_ISREG(stbuf.st_mode)) {
            sys_unlink(idx_path);
        } else {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BAD_IDX_FILE,
                "Idx file is not a regular file: %s.", hs->path);
            ret = -1;
            goto err;
        }
    }

    log_fd = sys_open(log_path, OFLAG, MODE);
    if (log_fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_OPEN_FAILED,
            "Fail to open log file: %s.", hs->path);
        ret = -1;
        goto err;
    }
    
    idx_fd = sys_open(idx_path, COFLAG, MODE);
    if (idx_fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_CREATE_FAILED,
            "Fail to create idx file: %s.", hs->path);
        ret = -1;
        goto err;
    } 

    size = sys_pread(log_fd, &super, sizeof(super), offset);
    if (size != sizeof(super) || super.version != HSVERSION || gf_uuid_compare(super.gfid, hs->gfid)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BROKEN_FILE,
            "Broken super in log file: %s.", hs->path);        
        ret = -1;
        goto err;
    }

    size = sys_pwrite(idx_fd, &super, sizeof(super), 0);
    if (size != sizeof(super)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_WRITE_FAILED,
            "Fail to write super into idx file: %s.", hs->path);
        ret = -1;
        goto err;
    }    

    offset += sizeof(super);
    hs->log_offset = sizeof(super);

    shift = 0;
    while (_gf_true) {
        size = sys_pread(log_fd, build_buf+shift, BUFF_SIZE-shift, offset);
        if (size < 0) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_READ_FAILED,
                "Fail to read log file: %s.", hs->path);     
            ret = -1;
            goto err;
        }

        if (size == 0) {
            if (shift > 0) {
                gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                    "Broken needle: %s.", hs->path);                 
                ret = -1;
                goto err;
            }
            break;
        }

        /* incomplete needle */
        if (shift+size < sizeof(*needle)) {
            gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                "Broken needle: %s.", hs->path);             
            ret = -1;
            goto err;
        }

        left = 0;
        while (left+sizeof(*needle) <= shift+size) {
            needle = (struct needle *)(build_buf+left);

            /* incomplete name or payload */
            if (left+sizeof(*needle)+needle->name_len+needle->size > shift+size) {
                memcpy(build_buf, build_buf+left, shift+size-left);
                shift = shift+size-left;
                left = 0;
                break;                
            }

#ifdef HAVE_LIB_Z
            crc = crc32(0L, Z_NULL, 0);
            if (priv->startup_crc_check) {
                crc = crc32(crc, (char *)needle+sizeof(*needle)+needle->name_len, needle->size);
                if (crc != needle->crc) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BROKEN_NEEDLE,
                        "CRC check failed (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
                    ret = -1;
                    goto err;
                }
            }
#endif
            mem_idx = NULL;
            den = NULL;

            k = kh_get(mem_idx, hs->map, uuid_utoa(needle->gfid));
            kk = kh_get(dentry, hs->lookup, needle->data);
            if (needle->flags & DELETED) {
                if (k != kh_end(hs->map)) {
                    GF_FREE(kh_key(hs->map, k));
                    GF_REF_PUT(kh_val(hs->map, k));
                    kh_del(mem_idx, hs->map, k);
                }

                if (kk != kh_end(hs->lookup)) {
                    GF_FREE(kh_key(hs->lookup, kk));
                    GF_FREE(kh_val(hs->lookup, kk));
                    kh_del(dentry, hs->lookup, kk);
                }                
            } else {
                mem_idx = hs_mem_idx_from_needle(needle, hs->log_offset);
                if (!mem_idx) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                        "Fail to init mem idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
                    ret = -1;
                    goto err;                     
                }

                if (k == kh_end(hs->map)) {
                    k = kh_put(mem_idx, hs->map, uuid_utoa(needle->gfid), &ret);
                    switch (ret) {
                        case -1:
                            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_ADD_FAILED,
                                "Fail to add mem idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid)); 
                            ret = -1;
                            goto err;
                        default:
                            kh_key(hs->map, k) = gf_strdup(uuid_utoa(needle->gfid));
                            kh_val(hs->map, k) = mem_idx;
                            break;
                    }           
                } else {
                    GF_REF_PUT(kh_val(hs->map, k));
                    kh_val(hs->map, k) = mem_idx;
                }

                den = hs_dentry_from_needle(needle);
                if (!den) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                        "Fail to init dentry (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
                    ret = -1;
                    goto err;                    
                }

                if (kk == kh_end(hs->lookup)) {
                    kk = kh_put(dentry, hs->lookup, needle->data, &ret);
                    switch (ret) {
                        case -1:
                            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_ADD_FAILED,
                                "Fail to add dentry (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid)); 
                            ret = -1;
                            goto err;
                        default:
                            kh_key(hs->lookup, kk) = gf_strdup(needle->data);
                            kh_val(hs->lookup, kk) = den;
                            break;
                    }           
                } else {
                    GF_FREE(kh_val(hs->lookup, kk));
                    kh_val(hs->lookup, kk) = den;
                }                 
            }

            idx = hs_idx_from_needle(needle, hs->log_offset);
            if (!idx) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                    "Fail to init idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));                     
                ret = -1;
                goto err;
            }

            wsize = sys_write(idx_fd, idx, sizeof(*idx)+idx->name_len);
            if (wsize != sizeof(*idx)+idx->name_len) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_WRITE_FAILED,
                    "Fail to write idx (%s/%s %s) into idx file.", hs->path, idx->name, uuid_utoa(needle->gfid));
                GF_FREE(idx);
                ret = -1;
                goto err;
            }
            GF_FREE(idx);

            left += (sizeof(*needle) + needle->name_len + needle->size);
            hs->log_offset += (sizeof(*needle) + needle->name_len + needle->size);
        }

        if (left > 0 && left <= shift+size && left+sizeof(*needle) > shift+size) {
            memcpy(build_buf, build_buf+left, shift+size-left);
            shift = shift+size-left;         
        }        

        offset += size;
    }

    hs->log_fd = log_fd;
    hs->idx_fd = idx_fd;
    
    return 0;

err:
    if (log_fd >= 0) {
        sys_close(log_fd);
    }
    if (idx_fd >= 0) {
        sys_close(idx_fd);
    }

    if (mem_idx) {
        GF_REF_PUT(mem_idx);
    }

    if (den) {
        GF_FREE(den);
    }

    kh_foreach(hs->map, kvar, vvar, HS_MEM_IDX_PURGE(kvar, vvar));
    kh_clear(mem_idx, hs->map);

    kh_foreach(hs->lookup, kvar, vvar, HS_DENTRY_PURGE(kvar, vvar));
    kh_clear(dentry, hs->lookup);      

    return ret;
}

static int
hs_orphan_build(xlator_t *this, struct hs *hs) {
    int ret = -1;
    int fd = -1;
    ssize_t size = -1;
    char *log_path = NULL;
    struct needle *needle = NULL;
    struct mem_idx *mem_idx = NULL;
    struct idx *idx = NULL;
    struct dentry *den = NULL;
    uint64_t offset = 0;
    uint64_t left = 0;
    uint64_t shift = 0;
    ssize_t wsize = -1;
    uint32_t crc = 0;
    struct hs_private *priv = NULL;
    khiter_t k = -1;
    khiter_t kk = -1;
    char *kvar = NULL;
    void *vvar = NULL;

    priv = this->private;

    MAKE_LOG_PATH(log_path, this, hs->path);
    fd = sys_open(log_path, OFLAG, MODE);
    if (fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_OPEN_FAILED,
            "Fail to open log file: %s.", hs->path);          
        ret = -1;
        goto err;
    }

    offset = hs->log_offset;

    shift = 0;
    while (_gf_true) {
        size = sys_pread(fd, build_buf+shift, BUFF_SIZE-shift, offset);
        if (size < 0) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_READ_FAILED,
                "Fail to read log file: %s.", hs->path);   
            ret = -1;
            goto err;
        }

        if (size == 0) {
            if (shift > 0) {
                gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                    "Broken needle: %s.", hs->path);                 
                ret = -1;
                goto err;
            }
            break;
        }

        /* incomplete needle */
        if (shift+size < sizeof(*needle)) {          
            gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                "Broken needle: %s.", hs->path);         
            ret = -1;
            goto err;
        }

        left = 0;
        while (left+sizeof(*needle) <= shift+size) {
            needle = (struct needle *)(build_buf+left);

            /* incomplete name or payload */
            if (left+sizeof(*needle)+needle->name_len+needle->size > shift+size) {
                memcpy(build_buf, build_buf+left, shift+size-left);
                shift = shift+size-left;
                left = 0;
                break;           
            }

#ifdef HAVE_LIB_Z
            crc = crc32(0L, Z_NULL, 0);
            if (priv->startup_crc_check) {
                crc = crc32(crc, (char *)needle+sizeof(*needle)+needle->name_len, needle->size);
                if (crc != needle->crc) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BROKEN_NEEDLE,
                        "CRC check failed (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
                    ret = -1;
                    goto err;
                }
            }
#endif
            mem_idx = NULL;
            den = NULL;

            k = kh_get(mem_idx, hs->map, uuid_utoa(needle->gfid));
            kk = kh_get(dentry, hs->lookup, needle->data);
            if (needle->flags & DELETED) {
                if (k != kh_end(hs->map)) {
                    GF_FREE(kh_key(hs->map, k));
                    GF_REF_PUT(kh_val(hs->map, k));
                    kh_del(mem_idx, hs->map, k);
                }

                if (kk != kh_end(hs->lookup)) {
                    GF_FREE(kh_key(hs->lookup, kk));
                    GF_FREE(kh_val(hs->lookup, kk));
                    kh_del(dentry, hs->lookup, kk);
                }                
            } else {
                mem_idx = hs_mem_idx_from_needle(needle, hs->log_offset);
                if (!mem_idx) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                        "Fail to init mem idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
                    ret = -1;
                    goto err;                     
                }

                if (k == kh_end(hs->map)) {
                    k = kh_put(mem_idx, hs->map, uuid_utoa(needle->gfid), &ret);
                    switch (ret) {
                        case -1:
                            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_ADD_FAILED,
                                "Fail to add mem idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid)); 
                            ret = -1;
                            goto err;
                        default:
                            kh_key(hs->map, k) = gf_strdup(uuid_utoa(needle->gfid));
                            kh_val(hs->map, k) = mem_idx;
                            break;
                    }           
                } else {
                    GF_REF_PUT(kh_val(hs->map, k));
                    kh_val(hs->map, k) = mem_idx;
                }

                den = hs_dentry_from_needle(needle);
                if (!den) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                        "Fail to init dentry (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
                    ret = -1;
                    goto err;                    
                }

                if (kk == kh_end(hs->lookup)) {
                    kk = kh_put(dentry, hs->lookup, needle->data, &ret);
                    switch (ret) {
                        case -1:
                            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_ADD_FAILED,
                                "Fail to add dentry (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid)); 
                            ret = -1;
                            goto err;
                        default:
                            kh_key(hs->lookup, kk) = gf_strdup(needle->data);
                            kh_val(hs->lookup, kk) = den;
                            break;
                    }           
                } else {
                    GF_FREE(kh_val(hs->lookup, kk));
                    kh_val(hs->lookup, kk) = den;
                }                 
            }

            idx = hs_idx_from_needle(needle, hs->log_offset);
            if (!idx) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                    "Fail to init idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));                     
                ret = -1;
                goto err;
            }

            wsize = sys_write(hs->idx_fd, idx, sizeof(*idx)+idx->name_len);
            if (wsize != sizeof(*idx)+idx->name_len) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_WRITE_FAILED,
                    "Fail to write idx (%s/%s %s) into idx file.", hs->path, idx->name, uuid_utoa(needle->gfid));
                GF_FREE(idx);
                ret = -1;
                goto err;
            }
            GF_FREE(idx);

            left += (sizeof(*needle) + needle->name_len + needle->size); 
            hs->log_offset += (sizeof(*needle) + needle->name_len + needle->size);  
        }

        if (left > 0 && left <= shift+size && left+sizeof(*needle) > shift+size) {
            memcpy(build_buf, build_buf+left, shift+size-left);
            shift = shift+size-left;         
        }

        offset += size;
    }

    hs->log_fd = fd;
    
    return 0;    

err:
    if (fd > 0) {
        sys_close(fd);
    }

    if (mem_idx) {
        GF_REF_PUT(mem_idx);
    }

    if (den) {
        GF_FREE(den);
    }

    kh_foreach(hs->map, kvar, vvar, HS_MEM_IDX_PURGE(kvar, vvar));
    kh_clear(mem_idx, hs->map);

    kh_foreach(hs->lookup, kvar, vvar, HS_DENTRY_PURGE(kvar, vvar));
    kh_clear(dentry, hs->lookup);      

    sys_close(hs->idx_fd);
    hs->idx_fd = -1;

    return ret;
}

static int
hs_quick_build(xlator_t *this, struct hs *hs) {
    int fd = -1;
    int ret = -1;
    char *idx_path = NULL;
    struct stat stbuf = {0};
    ssize_t size = -1;
    struct super super = {0};
    struct idx *idx = NULL;
    struct mem_idx *mem_idx = NULL;
    struct dentry *den = NULL;
    uint64_t offset = 0;
    uint64_t left = 0;
    uint64_t shift = 0;
    khiter_t k = -1;
    khiter_t kk = -1;
    char *kvar = NULL;
    void *vvar = NULL;

    MAKE_IDX_PATH(idx_path, this, hs->path);
    ret = sys_stat(idx_path, &stbuf);
    if (ret != 0) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_STAT_FAILED,
            "Idx file stat failed: %s.", hs->path);
        ret = -1;     
        goto err;
    }

    fd = sys_open(idx_path, OFLAG, MODE);
    if (fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_OPEN_FAILED,
            "Fail to open idx file: %s.", hs->path);        
        ret = -1;
        goto err;
    }

    size = sys_pread(fd, &super, sizeof(super), offset);
    if (size != sizeof(super) || super.version != HSVERSION || gf_uuid_compare(super.gfid, hs->gfid)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BROKEN_FILE,
            "Broken super in idx file: %s.", hs->path);          
        sys_close(fd);
        ret = -1;
        goto err;
    }

    offset = sizeof(super);
    hs->log_offset = sizeof(super);

    shift = 0;
    while (_gf_true) {
        size = sys_pread(fd, build_buf+shift, BUFF_SIZE-shift, offset);
        if (size < 0) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_READ_FAILED,
                "Fail to read idx file: %s.", hs->path);               
            ret = -1;
            goto err;
        }

        if (size == 0) { 
            if (shift > 0) {
                gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_IDX,
                    "Broken idx: %s.", hs->path); 
                sys_ftruncate(fd, offset-shift);
            }
            break;
        }

        if (shift+size < sizeof(*idx)) {
            gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_IDX,
                "Broken idx: %s.", hs->path); 
            sys_ftruncate(fd, offset-shift);
            break;
        }

        left = 0;
        while (left+sizeof(*idx) <= shift+size) {
            idx = (struct idx *)(build_buf+left);

            /* incomplete name */
            if (left+sizeof(*idx)+idx->name_len > shift+size) {
                memcpy(build_buf, build_buf+left, shift+size-left);
                shift = shift+size-left;
                left = 0;
                break;
            }

            mem_idx = NULL;
            den = NULL;
        
            k = kh_get(mem_idx, hs->map, uuid_utoa(idx->gfid));
            kk = kh_get(dentry, hs->lookup, idx->name);
            if (idx->offset == 0) {
                if (k != kh_end(hs->map)) {
                    GF_FREE(kh_key(hs->map, k));
                    GF_REF_PUT(kh_val(hs->map, k));
                    kh_del(mem_idx, hs->map, k);
                }

                if (kk != kh_end(hs->lookup)) {
                    GF_FREE(kh_key(hs->lookup, kk));
                    GF_FREE(kh_val(hs->lookup, kk));
                    kh_del(dentry, hs->lookup, kk);
                }
            } else {
                mem_idx = hs_mem_idx_from_idx(idx);
                if (!mem_idx) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                        "Fail to init mem idx (%s/%s %s).", hs->path, idx->name, uuid_utoa(idx->gfid));
                    ret = -1;
                    goto err;
                }

                if (k == kh_end(hs->map)) {
                    k = kh_put(mem_idx, hs->map, uuid_utoa(idx->gfid), &ret);
                    switch (ret) {
                        case -1:
                            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_ADD_FAILED,
                                "Fail to add mem idx (%s/%s %s).", hs->path, idx->name, uuid_utoa(idx->gfid)); 
                            ret = -1;
                            goto err;
                        default:
                            kh_key(hs->map, k) = gf_strdup(uuid_utoa(idx->gfid));
                            kh_val(hs->map, k) = mem_idx;
                            break;
                    }           
                } else {
                    GF_REF_PUT(kh_val(hs->map, k));
                    kh_val(hs->map, k) = mem_idx;
                }

                den = hs_dentry_from_idx(idx);
                if (!den) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                        "Fail to init dentry (%s/%s %s).", hs->path, idx->name, uuid_utoa(idx->gfid));
                    ret = -1;
                    goto err;                    
                }

                if (kk == kh_end(hs->lookup)) {
                    kk = kh_put(dentry, hs->lookup, idx->name, &ret);
                    switch (ret) {
                        case -1:
                            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_ADD_FAILED,
                                "Fail to add dentry (%s/%s %s).", hs->path, idx->name, uuid_utoa(idx->gfid)); 
                            ret = -1;
                            goto err;
                        default:
                            kh_key(hs->lookup, kk) = gf_strdup(idx->name);
                            kh_val(hs->lookup, kk) = den;
                            break;
                    }           
                } else {
                    GF_FREE(kh_val(hs->lookup, kk));
                    kh_val(hs->lookup, kk) = den;
                }                
            }            

            left += (sizeof(*idx) + idx->name_len);
            hs->log_offset = idx->offset + sizeof(struct needle) + idx->name_len + idx->size;
        }

        if (left > 0 && left <= shift+size && left+sizeof(*idx) > shift+size) {
            memcpy(build_buf, build_buf+left, shift+size-left);
            shift = shift+size-left;
        }

        offset += size;
    }

    hs->idx_fd = fd;

    return 0;

err:
    if (fd >= 0) {
        sys_close(fd);
    }

    if (mem_idx) {
        GF_REF_PUT(mem_idx);
    }

    if (den) {
        GF_FREE(den);
    }

    kh_foreach(hs->map, kvar, vvar, HS_MEM_IDX_PURGE(kvar, vvar));
    kh_clear(mem_idx, hs->map);

    kh_foreach(hs->lookup, kvar, vvar, HS_DENTRY_PURGE(kvar, vvar));
    kh_clear(dentry, hs->lookup);    

    return ret;
}

static int
hs_build(xlator_t *this, struct hs *hs) {
    int ret = -1;
    struct stat stbuf = {0};
    char *log_path = NULL;

    MAKE_LOG_PATH(log_path, this, hs->path);
    ret = sys_stat(log_path, &stbuf);
    if (ret != 0) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_STAT_FAILED,
            "Log file %s stat failed.", log_path);
        ret = -1;
        goto err;
    }

    ret = hs_quick_build(this, hs);
    if (ret < 0) {
        ret = hs_slow_build(this, hs);
    } else {
        ret = hs_orphan_build(this, hs);
    }

    if (ret < 0) {
        ret = -1;
        goto err;
    }

    return 0;

err:
    return ret;
}

void
hs_dump(khash_t(hs) *map, char *k, struct hs *v) {
#ifdef IDXDUMP    
    char *kvar = NULL;
    struct mem_idx *vvar = NULL;
#endif

    if (k && v) {
        printf("%s : %s, %d needles %d buckets\n", k, v->path, kh_size(v->map), kh_n_buckets(v->map));
    }

#ifdef IDXDUMP
    kh_foreach(v->map, kvar, vvar, hs_mem_idx_dump(v->map, kvar, vvar));
#endif
}

static void 
hs_release(void *to_free) {
    struct hs *hs = (struct hs *)to_free;
    struct hs *child_hs = NULL;
    struct hs *tmp = NULL;
    char *kvar = NULL;
    void *vvar = NULL;

    if (!hs) {
        return;
    }

    kh_foreach(hs->map, kvar, vvar, HS_MEM_IDX_PURGE(kvar, vvar));
    kh_destroy(mem_idx, hs->map);

    kh_foreach(hs->lookup, kvar, vvar, HS_DENTRY_PURGE(kvar, vvar));
    kh_destroy(dentry, hs->lookup);

    sys_close(hs->log_fd);
    sys_close(hs->idx_fd);

    if (hs->parent) {
        LOCK(&hs->parent->lock);
        {
            list_del(&hs->me);
        }
        UNLOCK(&hs->parent->lock);
    }

    list_for_each_entry_safe(child_hs, tmp, &hs->children, me) {
        GF_REF_PUT(child_hs);
    }

    LOCK_DESTROY(&hs->lock);
    pthread_rwlock_destroy(&hs->map_lock);
    pthread_rwlock_destroy(&hs->lk_lock);
    GF_FREE(hs->path);
    GF_FREE(hs);
}

static int
hs_purge(char *k, struct hs *v) {
    if (k) {
        GF_FREE(k);
    }

    if (v) {
        GF_REF_PUT(v);
    }

    return 0;
}

struct hs *
hs_init(xlator_t *this, const char *path, struct hs *parent) {
    ssize_t size = -1;
    int ret = -1;
    uuid_t gfid = {0}; 
    struct hs *hs = NULL;
    char *real_path = NULL;

    MAKE_REAL_PATH(real_path, this, path);
    size = sys_lgetxattr(real_path, "trusted.gfid", gfid, sizeof(gfid));
    if (size != sizeof(gfid)) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_GFID_OPERATION_FAILED,
            "Missing or wrong gfid: %s.", path);
        goto err;
    }

    hs = (void *)GF_CALLOC(1, sizeof(struct hs), gf_hs_mt_hs);
    if (!hs) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc haystack: %s.", path);
        goto err;
    }

    LOCK_INIT(&hs->lock);
    INIT_LIST_HEAD(&hs->children);
    INIT_LIST_HEAD(&hs->me);

    gf_uuid_copy(hs->gfid, gfid);
    hs->path = gf_strdup(path);

    pthread_rwlock_init(&hs->map_lock, NULL);
    hs->map = kh_init(mem_idx);
    if (!hs->map) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc mem idx map: %s.", path);
        goto err;        
    }

    pthread_rwlock_init(&hs->lk_lock, NULL);
    hs->lookup = kh_init(dentry);
    if (!hs->lookup) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc lookup table: %s.", path);
        goto err;
    }

    hs->log_fd = -1;
    hs->idx_fd = -1;
    hs->log_offset = 0;

    ret = hs_build(this, hs);
    if (ret < 0) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_BUILD_FAILED,
            "Fail to build haystack: %s.", path);
        goto err;
    }

    if (parent) {
        hs->parent = parent;
        LOCK(&hs->parent->lock);
        {
            list_add(&hs->me, &hs->parent->children);
        }
        UNLOCK(&hs->parent->lock);
    }

    GF_REF_INIT(hs, hs_release);
    return hs;

err:
    if (hs) {        
#if 0
        if (hs->parent) {
            LOCK(&hs->parent->lock);
            {
                list_del(&hs->me);
            }
            UNLOCK(&hs->parent->lock);
        }
#endif
        if (hs->path) {
            GF_FREE(hs->path);
        }

        LOCK_DESTROY(&hs->lock);
        pthread_rwlock_destroy(&hs->map_lock);
        pthread_rwlock_destroy(&hs->lk_lock);
        kh_destroy(mem_idx, hs->map);
        kh_destroy(dentry,hs->lookup);
        GF_FREE(hs);
    }
    return NULL;
}

static struct hs *
hs_setup(xlator_t *this, const char *path, struct hs *parent, struct hs_ctx *ctx) {
    struct hs *hs = NULL;
    struct hs *child_hs = NULL;
    DIR *dir = NULL;
    char *real_path = NULL;
    char *child_path = NULL;    
    struct dirent *entry = NULL;
    struct dirent scratch[2] = {{0}};
    struct stat stbuf = {0};
    int ret = -1;
    struct dentry *den = NULL;
    khiter_t k = -1;

    hs = hs_init(this, path, parent);
    if (!hs) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_INIT_FAILED, 
            "Fail to init haystack: %s.", path);         
        goto err;
    }

    MAKE_REAL_PATH(real_path, this, hs->path);
    dir = sys_opendir(real_path);
    if (!dir) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_DIR_OPERATION_FAILED, 
            "Fail to open directory: %s", path);     
        goto err;
    }

    while ((entry=sys_readdir(dir, scratch)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
            continue;
        }

        MAKE_CHILD_PATH(child_path, path, entry->d_name);
        MAKE_REAL_PATH(real_path, this, child_path);
        
        ret = sys_lstat(real_path, &stbuf);
        if (ret < 0) {
            gf_msg(this->name, GF_LOG_WARNING, errno, H_MSG_LSTAT_FAILED,
                "Fail to lstat: %s", child_path);
        } else if (S_ISDIR(stbuf.st_mode)) {
            child_hs = hs_setup(this, child_path, hs, ctx);
            if (!child_hs) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_SCAN_FAILED,
                    "Fail to setup child haystack: %s.", child_path);
                goto err;
            }

            den = GF_CALLOC(1, sizeof(*den), gf_hs_mt_dentry);
            if (!den) {
                gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
                    "Fail to alloc dentry: %s.", entry->d_name);
            }

            gf_uuid_copy(den->gfid, child_hs->gfid);
            den->type = DIR_T;
            
            k = kh_put(dentry, hs->lookup, entry->d_name, &ret);
            switch (ret) {
                case -1:
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_ADD_FAILED,
                        "Fail to add dentry into lookup table: (%s %s).", path, entry->d_name);
                    goto err;
                    break;
                case 0:
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DUP_GFID,
                        "Duplicate directory: %s.", entry->d_name);
                    GF_FREE(den);
                    break;
                default:
                    kh_key(hs->lookup, k) = gf_strdup(entry->d_name);
                    kh_val(hs->lookup, k) = den;
                    break;
            }
        }
    }

    LOCK(&ctx->lock);
    {
        k = kh_put(hs, ctx->map, uuid_utoa(hs->gfid), &ret);
        switch (ret) {
            case -1:
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_ADD_FAILED,
                    "Fail to add hs into ctx: (%s %s).", path, uuid_utoa(hs->gfid));
                break;
            case 0:
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DUP_GFID,
                    "Duplicate gfid: (%s %s).", path, uuid_utoa(hs->gfid));
                break;
            default:
                kh_key(ctx->map, k) = gf_strdup(uuid_utoa(hs->gfid));
                kh_val(ctx->map, k) = hs;
                break;
        }
    }
    UNLOCK(&ctx->lock);

    if (ret <= 0) {
        goto err;
    }

    sys_closedir(dir);

    return hs;

err:
    if (dir) {
        sys_closedir(dir);
    }

    if (hs) {
        GF_REF_PUT(hs);
    }

    GF_FREE(den);

    return NULL;
}

void
hs_ctx_free(struct hs_ctx *ctx) {
    char *kvar = NULL;
    struct hs *vvar = NULL;

    if (!ctx) {
        return;
    }

    kh_foreach(ctx->map, kvar, vvar, hs_purge(kvar, vvar));
    kh_destroy(hs, ctx->map);
    LOCK_DESTROY(&ctx->lock);

    GF_FREE(ctx);
}

struct hs_ctx *
hs_ctx_init(xlator_t *this) {
    struct hs_ctx *ctx = NULL;

    ctx = (void *)GF_CALLOC(1, sizeof(struct hs_ctx), gf_hs_mt_hs_ctx);
    if (!ctx) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc haystack context.");
        goto err;
    }

    LOCK_INIT(&ctx->lock);

    ctx->map = kh_init(hs);
    if (!ctx->map) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc haystack context map.");        
        goto err;
    }

    ctx->root = hs_setup(this, "/", NULL, ctx);
    if (!ctx->root) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_SCAN_FAILED,
            "Fail to setup haystack: /.");  
        goto err;
    }

    return ctx;

err:
    hs_ctx_free(ctx);
    return NULL;
}