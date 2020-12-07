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
#include <glusterfs/inode.h>

#include "hs.h"
#include "hs-ctx.h"
#include "hs-helpers.h"
#include "hs-mem-types.h"
#include "hs-messages.h"

#define OFLAG1 (O_RDWR | O_APPEND)
#define OFLAG2 (O_RDWR | O_DSYNC | O_APPEND)

#define CFLAG1 (O_CREAT | O_RDWR | O_APPEND)
#define CFLAG2 (O_CREAT | O_RDWR | O_DSYNC | O_APPEND)

#define MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

#define BUFF_SIZE (max(sizeof(struct idx), sizeof(struct needle)) + NAME_MAX + 1)

void
mem_idx_dump(khash_t(mem_idx) *map, const char *k, struct mem_idx *v) {
    if (v) {
        printf("%s : %s %lu\n", k, v->name, v->offset);
    }
}

static int
hs_slow_build(xlator_t *this, struct hs *hs) {
    int ret = -1;
    int op_ret = -1;
    ssize_t size = 0;
    ssize_t wsize = 0;
    char *idx_path = NULL;
    char *log_path = NULL;
    int idx_fd = -1;
    int log_fd = -1;
    struct stat stbuf = {0};
    struct super super = {0};
    struct needle *needle = NULL;
    struct idx *idx = NULL;
    struct mem_idx *mem_idx = NULL;
    struct dentry *den = NULL;
    char buff[BUFF_SIZE] = {0};

    MAKE_LOG_PATH(log_path, this, hs->path);
    MAKE_IDX_PATH(idx_path, this, hs->path);

    op_ret = sys_stat(idx_path, &stbuf);
    if (!op_ret) {
        if (S_ISREG(stbuf.st_mode)) {
            sys_unlink(idx_path);
        } else {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BROKEN_FILE,
                "Idx file is not a regular file: %s.", hs->path);
            ret = -1;
            goto err;
        }        
    }

    log_fd = sys_open(log_path, OFLAG2, MODE);
    if (log_fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_OPEN_FAILED,
            "Failed to open log file: %s.", hs->path);
        ret = -1;
        goto err;
    }

#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
    posix_fadvise(log_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif    

    idx_fd = sys_open(idx_path, CFLAG1, MODE);
    if (idx_fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_CREATE_FAILED,
            "Failed to create idx file: %s.", hs->path);
        ret = -1;
        goto err;
    }

#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
    posix_fadvise(idx_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

    size = sys_pread(log_fd, &super, sizeof(super), 0);
    if (size != sizeof(super) || super.version != HSVERSION || gf_uuid_compare(super.gfid, hs->gfid)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BROKEN_FILE,
            "Broken super in log file: %s.", hs->path);        
        ret = -1;
        goto err;
    }

    size = sys_write(idx_fd, &super, sizeof(super));
    if (size != sizeof(super)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_WRITE_FAILED,
            "Failed to write super into idx file: %s.", hs->path);
        ret = -1;
        goto err;
    }

    hs->pos = sizeof(super);

    while (_gf_true) {
        mem_idx = NULL;
        den = NULL;
        idx = NULL;

        size = sys_pread(log_fd, buff, BUFF_SIZE, hs->pos);
        if (size < 0) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_READ_FAILED,
                "Failed to read log file: %s.", hs->path);     
            ret = -1;
            goto err;            
        } else if (size == 0) {
            break;
        } else if (size < sizeof(struct needle)) {
            gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                "Broken needle: %s.", hs->path);             
            ret = -1;
            goto err;
        }

        needle = (struct needle *)buff;

#ifdef HAVE_LIB_Z
        struct hs_private *priv = this->private;

        if (priv->startup_crc_check) {
            uint32_t crc = 0;
            uint32_t nsize = sizeof(struct needle) + needle->name_len + needle->size;
            
            char *nbuff = GF_CALLOC(1, nsize, gf_hs_mt_crc_buf);
            if (!nbuff) {
                gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
                    "Failed to alloc crc buf: %s.", hs->path);
                ret = -1;
                goto err;
            }

            size = sys_pread(log_fd, nbuff, nsize, hs->pos);
            if (size < 0) {
                gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_READ_FAILED,
                    "Failed to read log file: %s.", hs->path);
                GF_FREE(nbuff);
                ret = -1;
                goto err;
            } else if (size != nsize) {
                gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                    "Broken needle: %s.", hs->path);
                GF_FREE(nbuff);
                ret = -1;
                goto err;            
            }
            
            crc = crc32(0L, Z_NULL, 0);
            crc = crc32(crc, nbuff+sizeof(struct needle)+needle->name_len, needle->size);
            if (crc != needle->crc) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BROKEN_NEEDLE,
                    "CRC check failed (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
                GF_FREE(nbuff);
                ret = -1;
                goto err;
            }

            GF_FREE(nbuff);
        }
#endif
        mem_idx = mem_idx_init(needle->data, needle->name_len, needle->size, hs->pos);
        if (!mem_idx) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_MEM_IDX_INIT_FAILED,
                "Failed to init mem idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
            ret = -1;
            goto err;                  
        }

        ret = mem_idx_map_put(hs, needle->gfid, mem_idx);
        if (ret == 0) {
            gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_MEM_IDX_UPDATE,
                "Update mem idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));                 
        } else if (ret == -1) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_MEM_IDX_ADD_FAILED,
                "Failed to add mem idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid)); 
            ret = -1;
            goto err;             
        }            

        den = dentry_init(needle->gfid, (needle->flags & F_DELETED) ? NON_T : REG_T, mem_idx);
        if (!den) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_INIT_FAILED,
                "Failed to init dentry (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
            ret = -1;
            goto err;                    
        }

        ret = dentry_map_put(hs, needle->data, den);
        if (ret == 0) {
            gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_DENTRY_UPDATE,
                "Update dentry (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));                
        } else if (ret == -1) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_ADD_FAILED,
                "Failed to add dentry (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
            goto err;
        }

        idx = idx_from_needle(needle, hs->pos);
        if (!idx) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                "Failed to init idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));                     
            ret = -1;
            goto err;
        }

        wsize = sys_write(idx_fd, idx, sizeof(*idx)+idx->name_len);
        if (wsize != sizeof(*idx)+idx->name_len) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_WRITE_FAILED,
                "Failed to write idx (%s/%s %s) into idx file.", hs->path, idx->name, uuid_utoa(needle->gfid));
            GF_FREE(idx);
            ret = -1;
            goto err;
        }

        hs->pos += sizeof(struct needle) + needle->name_len + needle->size;

        GF_FREE(idx);
        GF_REF_PUT(den);
        GF_REF_PUT(mem_idx);        
    }

    hs->log_fd = log_fd;
    hs->idx_fd = idx_fd;
    
    return 0;
err:
    if (log_fd >= 0)
        sys_close(log_fd);
    if (idx_fd >= 0)
        sys_close(idx_fd);

    if (den)
        GF_REF_PUT(den);        
    if (mem_idx)
        GF_REF_PUT(mem_idx);

    mem_idx_map_clear(hs);
    dentry_map_clear(hs);

    return ret;
}

static int
hs_orphan_build(xlator_t *this, struct hs *hs) {
    int ret = 0;
    int fd = -1;
    ssize_t size = 0;
    ssize_t wsize = 0;
    char *path = NULL;
    struct needle *needle = NULL;
    struct idx *idx = NULL;    
    struct mem_idx *mem_idx = NULL;
    struct dentry *den = NULL;
    char buff[BUFF_SIZE] = {0};

    MAKE_LOG_PATH(path, this, hs->path);
    fd = sys_open(path, OFLAG2, MODE);
    if (fd < 0) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_OPEN_FAILED,
            "Failed to open log file: %s.", hs->path);
        ret = -1;
        goto err;    
    }

#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif    

    while (_gf_true) {
        mem_idx = NULL;
        den = NULL; 
        idx = NULL;

        size = sys_pread(fd, buff, BUFF_SIZE, hs->pos);
        if (size < 0) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_READ_FAILED,
                "Failed to read log file: %s.", hs->path);   
            ret = -1;
            goto err;
        } else if (size == 0) {
            break;
        } else if (size < sizeof(struct needle)) {
            gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                "Broken needle: %s.", hs->path);         
            ret = -1;
            goto err;            
        }

        needle = (struct needle *)buff;

#ifdef HAVE_LIB_Z
        struct hs_private *priv = this->private;

        if (priv->startup_crc_check) {
            uint32_t crc = 0;
            uint32_t nsize = sizeof(struct needle) + needle->name_len + needle->size;
            
            char *nbuff = GF_CALLOC(1, nsize, gf_hs_mt_crc_buf);
            if (!nbuff) {
                gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
                    "Failed to alloc crc buf: %s.", hs->path);
                ret = -1;
                goto err;
            }

            size = sys_pread(fd, nbuff, nsize, hs->pos);
            if (size < 0) {
                gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_READ_FAILED,
                    "Failed to read log file: %s.", hs->path);
                GF_FREE(nbuff);
                ret = -1;
                goto err;
            } else if (size != nsize) {
                gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                    "Broken needle: %s.", hs->path);
                GF_FREE(nbuff);
                ret = -1;
                goto err;            
            }
            
            crc = crc32(0L, Z_NULL, 0);
            crc = crc32(crc, nbuff+sizeof(struct needle)+needle->name_len, needle->size);
            if (crc != needle->crc) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BROKEN_NEEDLE,
                    "CRC check failed (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
                GF_FREE(nbuff);
                ret = -1;
                goto err;
            }

            GF_FREE(nbuff);
        }
#endif

        mem_idx = mem_idx_init(needle->data, needle->name_len, needle->size, hs->pos);
        if (!mem_idx) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_MEM_IDX_INIT_FAILED,
                "Failed to init mem idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
            ret = -1;
            goto err;                  
        }

        ret = mem_idx_map_put(hs, needle->gfid, mem_idx);
        if (ret == 0) {
            gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_MEM_IDX_UPDATE,
                "Update mem idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));                 
        } else if (ret == -1) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_MEM_IDX_ADD_FAILED,
                "Failed to add mem idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
            goto err;             
        }            

        den = dentry_init(needle->gfid, (needle->flags & F_DELETED) ? NON_T : REG_T, mem_idx);
        if (!den) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_INIT_FAILED,
                "Failed to init dentry (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
            ret = -1;
            goto err;                    
        }

        ret = dentry_map_put(hs, needle->data, den);
        if (ret == 0) {
            gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_DENTRY_UPDATE,
                "Update dentry (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));                
        } else if (ret == -1) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_ADD_FAILED,
                "Failed to add dentry (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));
            goto err;
        }

        idx = idx_from_needle(needle, hs->pos);
        if (!idx) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                "Failed to init idx (%s/%s %s).", hs->path, needle->data, uuid_utoa(needle->gfid));                     
            ret = -1;
            goto err;
        }

        wsize = sys_write(hs->idx_fd, idx, sizeof(*idx)+idx->name_len);
        if (wsize != sizeof(*idx)+idx->name_len) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_WRITE_FAILED,
                "Failed to write idx (%s/%s %s) into idx file.", hs->path, idx->name, uuid_utoa(needle->gfid));
            GF_FREE(idx);
            ret = -1;
            goto err;
        }

        hs->pos += sizeof(struct needle) + needle->name_len + needle->size;
        
        GF_FREE(idx);
        GF_REF_PUT(den);
        GF_REF_PUT(mem_idx);
    }

    hs->log_fd = fd;
    
    return 0;    

err:
    if (fd >= 0)
        sys_close(fd);
    sys_close(hs->idx_fd);
    hs->idx_fd = -1;        

    if (den)
        GF_REF_PUT(den);
    if (mem_idx)
        GF_REF_PUT(mem_idx);

    mem_idx_map_clear(hs);
    dentry_map_clear(hs);

    return ret;    
}

static int
hs_quick_build(xlator_t *this, struct hs *hs) {
    int ret = 0;
    int fd = -1;
    int op_ret = -1;
    ssize_t size = 0;
    char *path = NULL;
    struct stat stbuf = {0};
    struct super super = {0};
    struct idx *idx = NULL;
    struct mem_idx *mem_idx = NULL;
    struct dentry *den = NULL;
    char buff[BUFF_SIZE] = {0};
    uint64_t offset = 0;

    MAKE_IDX_PATH(path, this, hs->path);
    op_ret = sys_stat(path, &stbuf);
    if (op_ret != 0) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_STAT_FAILED,
            "Idx file stat failed: %s.", hs->path);
        ret = -1;     
        goto err;
    }

    fd = sys_open(path, OFLAG1, MODE);
    if (fd < 0) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_OPEN_FAILED,
            "Failed to open idx file: %s.", hs->path);        
        ret = -1;
        goto err;        
    }

#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

    size = sys_pread(fd, &super, sizeof(super), 0);
    if (size != sizeof(super) || super.version != HSVERSION || gf_uuid_compare(super.gfid, hs->gfid)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BROKEN_FILE,
            "Broken super in idx file: %s.", hs->path);
        ret = -1;
        goto err;
    } 

    offset = sizeof(super);
    hs->pos = sizeof(super);

    while (_gf_true) {
        mem_idx = NULL;
        den = NULL;

        size = sys_pread(fd, buff, BUFF_SIZE, offset);
        if (size < 0) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_READ_FAILED,
                "Failed to read idx file: %s.", hs->path);               
            ret = -1;
            goto err;
        } else if (size == 0) {
            break;
        } else if (size < sizeof(struct idx)) {
            gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_IDX,
                "Broken idx: %s.", hs->path); 
            sys_ftruncate(fd, offset);
            break;            
        }

        idx = (struct idx *)buff;

        mem_idx = mem_idx_init(idx->name, idx->name_len, idx->size, idx->offset);
        if (!mem_idx) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_MEM_IDX_INIT_FAILED,
                "Failed to init mem idx (%s/%s %s).", hs->path, idx->name, uuid_utoa(idx->gfid));
            ret = -1;
            goto err;
        }

        ret = mem_idx_map_put(hs, idx->gfid, mem_idx);
        if (ret == 0) {
            gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_MEM_IDX_UPDATE,
                "Update mem idx (%s/%s %s).", hs->path, idx->name, uuid_utoa(idx->gfid));   
        } else if (ret == -1) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_MEM_IDX_ADD_FAILED,
                "Failed to add mem idx (%s/%s %s).", hs->path, idx->name, uuid_utoa(idx->gfid)); 
            goto err;             
        }            

        den = dentry_init(idx->gfid, (idx->offset != F_DELETED) ? REG_T : NON_T, mem_idx);
        if (!den) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_INIT_FAILED,
                "Failed to init dentry (%s/%s %s).", hs->path, idx->name, uuid_utoa(idx->gfid));
            ret = -1;
            goto err;                    
        }

        ret = dentry_map_put(hs, idx->name, den);
        if (ret == 0) {
            gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_DENTRY_UPDATE,
                "Update dentry (%s/%s %s).", hs->path, idx->name, uuid_utoa(idx->gfid));                
        } else if (ret == -1) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_ADD_FAILED,
                "Failed to add dentry (%s/%s %s).", hs->path, idx->name, uuid_utoa(idx->gfid));
            goto err;
        }

        hs->pos = idx->offset + sizeof(struct needle) + idx->name_len + idx->size;
        offset += sizeof(struct idx) + idx->name_len;

        GF_REF_PUT(den);
        GF_REF_PUT(mem_idx);
    }

    hs->idx_fd = fd;

    return 0;
err:
    if (fd >= 0)
        sys_close(fd);

    if (den)
        GF_REF_PUT(den);        
    if (mem_idx)
        GF_REF_PUT(mem_idx);

    mem_idx_map_clear(hs);
    dentry_map_clear(hs); 

    return ret;
}

static int
hs_scratch(xlator_t *this, struct hs *parent, struct hs *hs) {
    int ret = -1;
    char *log_path = NULL;
    char *idx_path = NULL;
    int log_fd = -1;
    int idx_fd = -1;
    ssize_t size = -1;
    struct super super = {0};
    struct dentry *den = NULL;

    super.version = HSVERSION;
    gf_uuid_copy(super.gfid, hs->gfid);

    MAKE_LOG_PATH(log_path, this, hs->path);
    log_fd = sys_open(log_path, CFLAG2, MODE);
    if (log_fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_CREATE_FAILED,
            "Failed to create log file: %s.", hs->path);
        ret = -1;
        goto err;
    }

    size = sys_write(log_fd, &super, sizeof(super));
    if (size != sizeof(super)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_WRITE_FAILED,
            "Failed to write super into log file: %s.", hs->path);
        ret = -1;
        goto err;
    }  
    
    MAKE_IDX_PATH(idx_path, this, hs->path);
    idx_fd = sys_open(idx_path, CFLAG1, MODE);
    if (idx_fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_CREATE_FAILED,
            "Failed to create idx file: %s.", hs->path);
        ret = -1;
        goto err;
    }

    size = sys_write(idx_fd, &super, sizeof(super));
    if (size != sizeof(super)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_WRITE_FAILED,
            "Failed to write super into idx file: %s.", hs->path);
        ret = -1;
        goto err;
    }

    den = dentry_init(hs->gfid, DIR_T, NULL);
    if (!den) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_INIT_FAILED,
            "Failed to init dentry (%s/%s %s).", hs->path, ".", uuid_utoa(hs->gfid));
        ret = -1;
        goto err;
    }

    ret = dentry_map_put(hs, ".", den);
    if (ret == 0) {
        gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_DENTRY_UPDATE,
            "Update dentry (%s/%s %s).", hs->path, ".", uuid_utoa(hs->gfid));                
    } else if (ret == -1) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_ADD_FAILED,
            "Failed to add dentry (%s/%s %s).", hs->path, ".", uuid_utoa(hs->gfid));
        goto err;
    }

    if (!parent) {
        if (!__is_root_gfid(hs->gfid)) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_DANGLING,
                "Dangling path %s.", hs->path);
            ret = -1;
            goto err;
        }

        hs->log_fd = log_fd;
        hs->idx_fd = idx_fd;
        hs->pos = sizeof(super);

        return 0;
    }

    den = dentry_init(parent->gfid, DIR_T, NULL);
    if (!den) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_INIT_FAILED,
            "Failed to init dentry (%s/%s %s).", parent->path, "..", uuid_utoa(parent->gfid));
        ret = -1;
        goto err;
    }

    ret = dentry_map_put(hs, "..", den);
    if (ret == 0) {
        gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_DENTRY_UPDATE,
            "Update dentry (%s/%s %s).", parent->path, "..", uuid_utoa(parent->gfid));                
    } else if (ret == -1) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_ADD_FAILED,
            "Failed to add dentry (%s/%s %s).", parent->path, "..", uuid_utoa(parent->gfid));
        goto err;
    }

    hs->log_fd = log_fd;
    hs->idx_fd = idx_fd;
    hs->pos = sizeof(super);

    return 0;

err:
    if (log_fd >= 0) {
        sys_close(log_fd);
        if (log_path)
            sys_unlink(log_path);
    }

    if (idx_fd >= 0) {
        sys_close(idx_fd);
        if (idx_path)
            sys_unlink(idx_path);
    }
    return ret;

}

static int
hs_build(xlator_t *this, struct hs *parent, struct hs *hs) {
    int ret = -1;
    struct stat stbuf = {0};
    char *log_path = NULL;
    struct dentry *den = NULL;

    MAKE_LOG_PATH(log_path, this, hs->path);
    ret = sys_stat(log_path, &stbuf);
    if (ret != 0) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_STAT_FAILED,
            "Log file %s stat failed.", log_path);
        ret = -1;
        goto err;
    }

    ret = (hs_quick_build(this, hs) < 0) ? hs_slow_build(this, hs) : hs_orphan_build(this, hs);
    if (ret < 0)
        goto err;

    den = dentry_init(hs->gfid, DIR_T, NULL);
    if (!den) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_INIT_FAILED,
            "Failed to init dentry (%s/%s %s).", hs->path, ".", uuid_utoa(hs->gfid));
        ret = -1;
        goto err;
    }

    ret = dentry_map_put(hs, ".", den);
    if (ret == 0) {
        gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_DENTRY_UPDATE,
            "Update dentry (%s/%s %s).", hs->path, ".", uuid_utoa(hs->gfid));                
    } else if (ret == -1) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_ADD_FAILED,
            "Failed to add dentry (%s/%s %s).", hs->path, ".", uuid_utoa(hs->gfid));
        goto err;
    }

    if (!parent) {
        if (!__is_root_gfid(hs->gfid)) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_DANGLING,
                "Dangling path %s.", hs->path);
            ret = -1;
            goto err;
        }
        return 0;
    }

    den = dentry_init(parent->gfid, DIR_T, NULL);
    if (!den) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_INIT_FAILED,
            "Failed to init dentry (%s/%s %s).", parent->path, "..", uuid_utoa(parent->gfid));
        ret = -1;
        goto err;
    }

    ret = dentry_map_put(hs, "..", den);
    if (ret == 0) {
        gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_DENTRY_UPDATE,
            "Update dentry (%s/%s %s).", parent->path, "..", uuid_utoa(parent->gfid));                
    } else if (ret == -1) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_ADD_FAILED,
            "Failed to add dentry (%s/%s %s).", parent->path, "..", uuid_utoa(parent->gfid));
        goto err;
    }    

err:
    return ret;
}

void
hs_dump(khash_t(hs) *map, const char *k, struct hs *v) {
    if (k && v) {
        printf("%s : %s, %d needles %d buckets\n", k, v->path, kh_size(v->map), kh_n_buckets(v->map));
    }

#ifdef IDXDUMP
    const char *kvar = NULL;
    struct mem_idx *vvar = NULL;
    kh_foreach(v->map, kvar, vvar, mem_idx_dump(v->map, kvar, vvar));
#endif
}

static void 
hs_release(void *to_free) {
    struct hs *hs = (struct hs *)to_free;

    if (!hs)
        return;

    /*
    * dentry map should be destroied before mem_idx map.
    */
    dentry_map_destroy(hs);
    mem_idx_map_destroy(hs);

    sys_close(hs->log_fd);
    sys_close(hs->idx_fd);

    if (hs->parent) {
        pthread_rwlock_wrlock(&hs->parent->lock);
        {
            list_del(&hs->me);
        }
        pthread_rwlock_unlock(&hs->parent->lock);
        GF_REF_PUT(hs->parent);
    }

    pthread_rwlock_destroy(&hs->lock);
    GF_FREE(hs->path);
    GF_FREE(hs);
}

struct hs *
hs_init(xlator_t *this, struct hs *parent, const char *path, gf_boolean_t scratch) {
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

    hs = (void *)GF_CALLOC(1, sizeof(*hs), gf_hs_mt_hs);
    if (!hs) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Failed to alloc haystack: %s.", path);
        goto err;
    }

    pthread_rwlock_init(&hs->lock, NULL);
    INIT_LIST_HEAD(&hs->children);
    INIT_LIST_HEAD(&hs->me);

    gf_uuid_copy(hs->gfid, gfid);
    hs->path = gf_strdup(path);

    mem_idx_map_init(hs);
    if (!hs->map) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_MEM_IDX_MAP_INIT_FAILED,
            "Failed to alloc mem idx map: %s.", path);
        goto err;        
    }

    dentry_map_init(hs);
    if (!hs->lookup) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_DENTRY_MAP_INIT_FAILED,
            "Failed to alloc lookup table: %s.", path);
        goto err;
    }

    hs->log_fd = -1;
    hs->idx_fd = -1;
    hs->pos = 0;

    if (scratch) {
        ret = hs_scratch(this, parent, hs);
        if (ret < 0) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_BUILD_FAILED,
                "Failed to build haystack: %s.", path);
            goto err;            
        }
    } else {
        ret = hs_build(this, parent, hs);
        if (ret < 0) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_BUILD_FAILED,
                "Failed to build haystack: %s.", path);
            goto err;
        }      
    }

#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
    posix_fadvise(hs->log_fd, 0, 0, POSIX_FADV_NORMAL);
    posix_fadvise(hs->idx_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

    if (parent) {
        hs->parent = GF_REF_GET(parent);
        pthread_rwlock_wrlock(&hs->parent->lock);
        {
            list_add(&hs->me, &hs->parent->children);
        }
        pthread_rwlock_unlock(&hs->parent->lock);
    }

    GF_REF_INIT(hs, hs_release);
    return hs;

err:
    if (hs) {        
        dentry_map_destroy(hs);
        mem_idx_map_destroy(hs);

        if (hs->parent) {
            pthread_rwlock_wrlock(&hs->parent->lock);
            {
                list_del(&hs->me);
            }
            pthread_rwlock_unlock(&hs->parent->lock);
            GF_REF_PUT(hs->parent);
        }
            
        pthread_rwlock_destroy(&hs->lock);
        GF_FREE(hs->path);        
        GF_FREE(hs);
    }
    return NULL;
}

static struct hs *
hs_setup(xlator_t *this, struct hs_ctx *ctx, struct hs *parent, const char *path) {
    int ret = -1;
    struct hs *hs = NULL;
    struct hs *child = NULL;
    struct hs *tmp = NULL;
    DIR *dir = NULL;
    char *real_path = NULL;
    char *child_path = NULL;    
    struct dirent *entry = NULL;
    struct dirent scratch[2] = {{0}};
    struct stat stbuf = {0};
    struct dentry *den = NULL;

    hs = hs_init(this, parent, path, _gf_false);
    if (!hs) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_INIT_FAILED, 
            "Failed to init haystack: %s.", path);         
        goto err;
    }

    MAKE_REAL_PATH(real_path, this, hs->path);
    dir = sys_opendir(real_path);
    if (!dir) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_DIR_OPERATION_FAILED, 
            "Failed to open directory: %s", path);     
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
                "Failed to lstat: %s", child_path);
        } else if (S_ISDIR(stbuf.st_mode)) {
            child = hs_setup(this, ctx, hs, child_path);
            if (!child) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_SCAN_FAILED,
                    "Failed to setup child haystack: %s.", child_path);
                goto err;
            }

            den = dentry_init(child->gfid, DIR_T, NULL);
            if (!den) {
                gf_msg(THIS->name, GF_LOG_ERROR, ENOMEM, H_MSG_DENTRY_INIT_FAILED,
                    "Failed to alloc dentry for directory (%s %s).", child_path, uuid_utoa(child->gfid)); 
                goto err;
            }

            ret = dentry_map_put(hs, entry->d_name, den);
            if (ret == 0) {
                gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_DENTRY_DUP,
                    "Duplicate sub directory: %s.", entry->d_name);
            } else if (ret == -1) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_ADD_FAILED,
                    "Failed to add dentry into lookup table: (%s %s).", path, entry->d_name);
                goto err;
            }

            GF_REF_PUT(den);
            GF_REF_PUT(child);
        }
    }

    ret = hs_map_put(ctx, hs->gfid, hs);
    if (ret == 0) {
        gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_HS_DUP,
            "Duplicate directory: (%s %s).", path, uuid_utoa(hs->gfid));
    } else if (ret == -1) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_ADD_FAILED,
            "Failed to add hs into ctx: (%s %s).", path, uuid_utoa(hs->gfid));
        goto err;
    }

    sys_closedir(dir);

    return hs;

err:
    if (dir) 
        sys_closedir(dir);
    if (den)
        GF_REF_PUT(den);
    if (hs) {
        list_for_each_entry_safe(child, tmp, &hs->children, me) {
            GF_REF_PUT(child);
        }
        GF_REF_PUT(hs);
    }

    return NULL;
}

void
hs_ctx_free(struct hs_ctx *ctx) {
    if (!ctx)
        return;

    hs_map_destroy(ctx);
    GF_FREE(ctx);
}

struct hs_ctx *
hs_ctx_init(xlator_t *this) {
    struct hs_ctx *ctx = NULL;

    ctx = (void *)GF_CALLOC(1, sizeof(struct hs_ctx), gf_hs_mt_hs_ctx);
    if (!ctx) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Failed to alloc haystack context.");
        goto err;
    }

    hs_map_init(ctx);
    if (!ctx->map) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_HS_CTX_INIT_FAILED,
            "Failed to init haystack context map.");        
        goto err;
    }

    ctx->root = hs_setup(this, ctx, NULL, "/");
    if (!ctx->root) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_SCAN_FAILED,
            "Failed to setup haystack: /.");  
        goto err;
    }

    return ctx;

err:
    hs_ctx_free(ctx);
    return NULL;
}