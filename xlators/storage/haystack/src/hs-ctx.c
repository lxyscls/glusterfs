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

int
hs_mem_idx_dump(dict_t *d, char *k, data_t *v, void *_unused) {
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
hs_idx_from_needle(struct hs_needle *needle, uint64_t offset) {
    struct hs_idx *idx = NULL;

    idx = GF_CALLOC(1, sizeof(*idx)+NAME_MAX+1, gf_common_mt_char);    
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

struct hs_mem_idx *
hs_mem_idx_from_needle(struct hs_needle *needle, uint64_t offset) {
    struct hs_mem_idx *mem_idx = NULL;

    mem_idx = GF_CALLOC(1, sizeof(*mem_idx)+needle->name_len, gf_hs_mt_hs_mem_idx);
    if (!mem_idx) {
        gf_msg(THIS->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc mem idx (%s %s).", needle->data, uuid_utoa(needle->gfid));        
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
hs_mem_idx_from_idx(struct hs_idx *idx) {
    struct hs_mem_idx *mem_idx = NULL;

    mem_idx = GF_CALLOC(1, sizeof(*mem_idx)+idx->name_len, gf_hs_mt_hs_mem_idx);
    if (!mem_idx) {
        gf_msg(THIS->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc mem idx (%s %s).", idx->name, (idx->gfid));
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
    char *buff = NULL;
    uint64_t left = 0;
    uint64_t shift = 0;
    ssize_t wsize = -1;
    xlator_t *this = NULL;

    this = THIS;

    log_rpath = GF_CALLOC(1, strlen(hs->real_path)+1+strlen(".log")+1, gf_common_mt_char);
    if (!log_rpath) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_NOMEM,
            "Fail to alloc log file path: %s/.log.", hs->real_path);      
        ret = -1;
        goto err;
    }
    sprintf(log_rpath, "%s/.log", hs->real_path);

    idx_rpath = GF_CALLOC(1, strlen(hs->real_path)+1+strlen(".idx")+1, gf_common_mt_char);
    if (!idx_rpath) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_NOMEM,
            "Fail to alloc idx file path: %s/.idx.", hs->real_path);        
        ret = -1;
        goto err;
    }
    sprintf(idx_rpath, "%s/.idx", hs->real_path);

    buff = GF_CALLOC(1, BUFF_SIZE, gf_common_mt_char);
    if (!buff) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc build buffer: %s.", hs->real_path);
        ret = -1;
        goto err;
    }

    log_fd = sys_open(log_rpath, OFLAG, MODE);
    if (log_fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_OPEN_FAILED,
            "Fail to open log file: %s.", log_rpath);
        ret = -1;
        goto err;
    }
    
    ret = sys_stat(idx_rpath, &stbuf);
    if (!ret) {
        if (S_ISREG(stbuf.st_mode)) {
            sys_unlink(idx_rpath);
        } else {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BAD_IDX_FILE,
                "Idx file is not a regular file: %s", idx_rpath);
            ret = -1;
            goto err;
        }
    }
    
    idx_fd = sys_open(idx_rpath, COFLAG, MODE);
    if (idx_fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_CREATE_FAILED,
            "Fail to create idx file: %s.", idx_rpath);
        ret = -1;
        goto err;
    } 

    size = sys_pread(log_fd, &super, sizeof(super), offset);
    if (size != sizeof(super) || super.version != HSVERSION || gf_uuid_compare(super.gfid, hs->gfid)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BROKEN_FILE,
            "Broken super in log file: %s.", log_rpath);        
        ret = -1;
        goto err;
    }

    size = sys_pwrite(idx_fd, &super, sizeof(super), 0);
    if (size != sizeof(super)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_WRITE_FAILED,
            "Fail to write super into idx file: %s.", idx_rpath);        
        ret = -1;
        goto err;
    }    

    offset += sizeof(super);
    hs->log_offset = sizeof(super);

    shift = 0;
    while (_gf_true) {
        size = sys_pread(log_fd, buff+shift, BUFF_SIZE-shift, offset);
        if (size < 0) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_READ_FAILED,
                "Fail to read log file: %s.", log_rpath);            
            ret = -1;
            goto err;
        }

        if (size == 0) {
            if (shift > 0) {
                gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                    "Broken needle: %s.", log_rpath);                 
                ret = -1;
                goto err;
            }
            break;
        }

        /* incomplete needle */
        if (shift+size < sizeof(*needle)) {
            gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                "Broken needle: %s.", log_rpath);             
            ret = -1;
            goto err;
        }

        left = 0;
        while (left+sizeof(*needle) <= shift+size) {
            needle = (struct hs_needle *)(buff+left);

            /* incomplete name or payload */
            if (left+sizeof(*needle)+needle->name_len+needle->size > shift+size) {
                memcpy(buff, buff+left, shift+size-left);
                shift = shift+size-left;
                left = 0;
                break;                
            }
    
            ret = dict_get_bin(hs->idx_dict, uuid_utoa(needle->gfid), (void **)&mem_idx);
            if (needle->flags & DELETED) {            
                if (!ret) {                    
                    dict_del(hs->idx_dict, uuid_utoa(needle->gfid));
                    GF_REF_PUT(mem_idx);
                }
            } else {
                if (!ret) {
                    GF_REF_PUT(mem_idx);                
                }

                mem_idx = hs_mem_idx_from_needle(needle, hs->log_offset);
                if (!mem_idx) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                        "Fail to init mem idx (%s/%s %s).", hs->real_path, needle->data, uuid_utoa(needle->gfid));
                    ret = -1;
                    goto err;                     
                }

                ret = dict_set_static_bin(hs->idx_dict, uuid_utoa(needle->gfid), mem_idx, sizeof(*mem_idx)+mem_idx->name_len);
                if (ret) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_ADD_FAILED,
                        "Fail to add mem idx (%s/%s %s).", hs->real_path, needle->data, uuid_utoa(needle->gfid));                         
                    GF_REF_PUT(mem_idx);
                    ret = -1;
                    goto err;
                }
            }

            idx = hs_idx_from_needle(needle, hs->log_offset);
            if (!idx) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                    "Fail to init idx (%s/%s %s).", hs->real_path, needle->data, uuid_utoa(needle->gfid));                     
                ret = -1;
                goto err;
            }

            wsize = sys_write(idx_fd, idx, sizeof(*idx)+idx->name_len);
            if (wsize != sizeof(*idx)+idx->name_len) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_WRITE_FAILED,
                    "Fail to write idx (%s/%s %s) into idx file.", hs->real_path, idx->name, uuid_utoa(needle->gfid));
                GF_FREE(idx);
                ret = -1;
                goto err;
            }
            GF_FREE(idx);

            left += (sizeof(*needle) + needle->name_len + needle->size);
            hs->log_offset += (sizeof(struct hs_needle) + needle->name_len + needle->size);
        }

        if (left > 0 && left <= shift+size && left+sizeof(*needle) > shift+size) {
            memcpy(buff, buff+left, shift+size-left);
            shift = shift+size-left;         
        }        

        offset += size;
    }

    hs->log_fd = log_fd;
    hs->idx_fd = idx_fd;
    GF_FREE(log_rpath);
    GF_FREE(idx_rpath);
    GF_FREE(buff);
    
    return 0;

err:
    if (log_fd >= 0) {
        sys_close(log_fd);
    }
    if (idx_fd >= 0) {
        sys_close(idx_fd);
    }
    
    dict_foreach(hs->idx_dict, hs_mem_idx_purge, NULL);
    dict_reset(hs->idx_dict);

    GF_FREE(log_rpath);
    GF_FREE(idx_rpath);
    GF_FREE(buff);

    return ret;
}

static int
hs_orphan_build(struct hs *hs) {
    int ret = -1;
    int fd = -1;
    ssize_t size = -1;
    char *rpath = NULL;
    struct hs_needle *needle = NULL;
    struct hs_mem_idx *mem_idx = NULL;
    struct hs_idx *idx = NULL;
    uint64_t offset = 0;
    char *buff = NULL;
    uint64_t left = 0;
    uint64_t shift = 0;
    ssize_t wsize = -1;
    xlator_t *this = NULL;

    this = THIS;

    rpath = GF_CALLOC(1, strlen(hs->real_path)+1+strlen(".log")+1, gf_common_mt_char);
    if (!rpath) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_NOMEM,
            "Fail to alloc log file path: %s/.log.", hs->real_path);
        ret = -1;
        goto err;
    }
    sprintf(rpath, "%s/.log", hs->real_path);

    buff = GF_CALLOC(1, BUFF_SIZE, gf_common_mt_char);
    if (!buff) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc build buffer: %s.", hs->real_path);
        ret = -1;
        goto err;
    }

    fd = sys_open(rpath, OFLAG, MODE);
    if (fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_OPEN_FAILED,
            "Fail to open log file: %s.", rpath);          
        ret = -1;
        goto err;
    }

    offset = hs->log_offset;

    shift = 0;
    while (_gf_true) {
        size = sys_pread(fd, buff+shift, BUFF_SIZE-shift, offset);
        if (size < 0) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_READ_FAILED,
                "Fail to read log file: %s.", rpath);   
            ret = -1;
            goto err;
        }

        if (size == 0) {
            if (shift > 0) {
                gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                    "Broken needle: %s.", rpath);                 
                ret = -1;
                goto err;
            }
            break;
        }

        /* incomplete needle */
        if (shift+size < sizeof(*needle)) {          
            gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_NEEDLE,
                "Broken needle: %s.", rpath);         
            ret = -1;
            goto err;
        }

        left = 0;
        while (left+sizeof(*needle) <= shift+size) {
            needle = (struct hs_needle *)(buff+left);

            /* incomplete name or payload */
            if (left+sizeof(*needle)+needle->name_len+needle->size > shift+size) {
                memcpy(buff, buff+left, shift+size-left);
                shift = shift+size-left;
                left = 0;
                break;           
            }
       
            ret = dict_get_bin(hs->idx_dict, uuid_utoa(needle->gfid), (void **)&mem_idx);
            if (needle->flags & DELETED) {            
                if (!ret) {                    
                    dict_del(hs->idx_dict, uuid_utoa(needle->gfid));
                    GF_REF_PUT(mem_idx);
                }
            } else {
                if (!ret) {
                    GF_REF_PUT(mem_idx);                
                }

                mem_idx = hs_mem_idx_from_needle(needle, hs->log_offset);
                if (!mem_idx) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                        "Fail to init mem idx (%s/%s %s).", hs->real_path, needle->data, uuid_utoa(needle->gfid));                        
                    ret = -1;
                    goto err;
                }

                ret = dict_set_static_bin(hs->idx_dict, uuid_utoa(needle->gfid), mem_idx, sizeof(*mem_idx)+mem_idx->name_len);
                if (ret) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_ADD_FAILED,
                        "Fail to add mem idx (%s/%s %s).", hs->real_path, needle->data, uuid_utoa(needle->gfid));                        
                    GF_REF_PUT(mem_idx);
                    ret = -1;
                    goto err;
                }                    
            }

            idx = hs_idx_from_needle(needle, hs->log_offset);
            if (!idx) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                    "Fail to init idx (%s/%s %s).", hs->real_path, needle->data, uuid_utoa(needle->gfid));                     
                ret = -1;
                goto err;
            }

            wsize = sys_write(hs->idx_fd, idx, sizeof(*idx)+idx->name_len);
            if (wsize != sizeof(*idx)+idx->name_len) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_WRITE_FAILED,
                    "Fail to write idx (%s/%s %s) into idx file.", hs->real_path, idx->name, uuid_utoa(needle->gfid));
                GF_FREE(idx);
                ret = -1;
                goto err;
            }
            GF_FREE(idx);

            left += (sizeof(*needle) + needle->name_len + needle->size); 
            hs->log_offset += (sizeof(*needle) + needle->name_len + needle->size);  
        }

        if (left > 0 && left <= shift+size && left+sizeof(*needle) > shift+size) {
            memcpy(buff, buff+left, shift+size-left);
            shift = shift+size-left;         
        }

        offset += size;
    }

    hs->log_fd = fd;
    GF_FREE(rpath);    
    GF_FREE(buff);
    
    return 0;    

err:
    if (fd > 0) {
        sys_close(fd);
    }

    dict_foreach(hs->idx_dict, hs_mem_idx_purge, NULL);
    dict_reset(hs->idx_dict);

    sys_close(hs->idx_fd);
    hs->idx_fd = -1;

    GF_FREE(rpath);
    GF_FREE(buff);

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
    uint64_t offset = 0;
    char *buff = NULL;
    uint64_t left = 0;
    uint64_t shift = 0;
    xlator_t *this = NULL;

    this = THIS;

    rpath = GF_CALLOC(1, strlen(hs->real_path)+1+strlen(".idx")+1, gf_common_mt_char);
    if (!rpath) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc idx file path: %s/.idx.", hs->real_path);        
        ret = -1;
        goto err;
    }
    sprintf(rpath, "%s/.idx", hs->real_path);

    ret = sys_stat(rpath, &stbuf);
    if (ret != 0) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_STAT_FAILED,
            "idx file %s is missing.", rpath);
        ret = -1;     
        goto err;
    }

    buff = GF_CALLOC(1, BUFF_SIZE, gf_common_mt_char);
    if (!buff) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc build buffer: %s.", hs->real_path);
        ret = -1;
        goto err;
    }    

    fd = sys_open(rpath, OFLAG, MODE);
    if (fd == -1) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_OPEN_FAILED,
            "Fail to open idx file: %s.", rpath);        
        ret = -1;
        goto err;
    }

    size = sys_pread(fd, &super, sizeof(super), offset);
    if (size != sizeof(super) || super.version != HSVERSION || gf_uuid_compare(super.gfid, hs->gfid)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_BROKEN_FILE,
            "Broken super in idx file: %s.", rpath);          
        sys_close(fd);
        ret = -1;
        goto err;
    }

    offset = sizeof(super);
    hs->log_offset = sizeof(super);

    shift = 0;
    while (_gf_true) {
        size = sys_pread(fd, buff+shift, BUFF_SIZE-shift, offset);
        if (size < 0) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_READ_FAILED,
                "Fail to read idx file: %s.", rpath);               
            ret = -1;
            goto err;
        }

        if (size == 0) { 
            if (shift > 0) {
                gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_IDX,
                    "Broken idx: %s.", rpath); 
                sys_ftruncate(fd, offset-shift);
            }
            break;
        }

        if (shift+size < sizeof(*idx)) {
            gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_BROKEN_IDX,
                "Broken idx: %s.", rpath); 
            sys_ftruncate(fd, offset-shift);
            break;
        }

        left = 0;
        while (left+sizeof(*idx) <= shift+size) {
            idx = (struct hs_idx *)(buff+left);

            /* incomplete name */
            if (left+sizeof(*idx)+idx->name_len > shift+size) {
                memcpy(buff, buff+left, shift+size-left);
                shift = shift+size-left;
                left = 0;
                break;
            }
        
            ret = dict_get_bin(hs->idx_dict, uuid_utoa(idx->gfid), (void **)&mem_idx);
            if (idx->offset == 0) {    
                if (!ret) {                    
                    dict_del(hs->idx_dict, uuid_utoa(idx->gfid));
                    GF_REF_PUT(mem_idx);
                }
            } else {
                if (!ret) {
                    GF_REF_PUT(mem_idx);               
                }

                mem_idx = hs_mem_idx_from_idx(idx);
                if (!mem_idx) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_INIT_FAILED,
                        "Fail to init mem idx (%s/%s %s).", hs->real_path, idx->name, uuid_utoa(idx->gfid));
                    ret = -1;
                    goto err;
                }
                
                ret = dict_set_static_bin(hs->idx_dict, uuid_utoa(idx->gfid), mem_idx, sizeof(*mem_idx)+mem_idx->name_len);
                if (ret) {
                    gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_IDX_ADD_FAILED,
                        "Fail to add mem idx (%s/%s %s).", hs->real_path, idx->name, uuid_utoa(idx->gfid));
                    GF_REF_PUT(mem_idx);
                    ret = -1;
                    goto err;
                }                                                
            }

            left += (sizeof(*idx) + idx->name_len);
            hs->log_offset = idx->offset + sizeof(struct hs_needle) + idx->name_len + idx->size;
        }

        if (left > 0 && left <= shift+size && left+sizeof(*idx) > shift+size) {
            memcpy(buff, buff+left, shift+size-left);
            shift = shift+size-left;
        }

        offset += size;
    }

    hs->idx_fd = fd;
    GF_FREE(rpath);
    GF_FREE(buff);

    return 0;

err:
    if (fd >= 0) {
        sys_close(fd);
    }

    dict_foreach(hs->idx_dict, hs_mem_idx_purge, NULL);
    dict_reset(hs->idx_dict);
    GF_FREE(rpath);
    GF_FREE(buff);
    return ret;
}

static int
hs_build(struct hs *hs) {
    int ret = -1;
    struct stat stbuf = {0};
    char *log_rpath = NULL;
    xlator_t *this = NULL;

    this = THIS;

    log_rpath = GF_CALLOC(1, strlen(hs->real_path)+1+strlen(".log")+1, gf_common_mt_char);
    if (!log_rpath) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc log file path: %s/.log.", hs->real_path);
        ret = -1;
        goto err;
    }
    sprintf(log_rpath, "%s/.log", hs->real_path);

    ret = sys_stat(log_rpath, &stbuf);
    if (ret != 0) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_STAT_FAILED,
            "Log file %s is missing.", log_rpath);
        ret = -1;
        goto err;
    }

    ret = hs_quick_build(hs);
    if (ret < 0) {
        ret = hs_slow_build(hs);
    } else {
        ret = hs_orphan_build(hs);
    }

    if (ret < 0) {
        ret = -1;
        goto err;
    }

    GF_FREE(log_rpath);
    return 0;

err:
    GF_FREE(log_rpath);
    return ret;
}

int
hs_dump(dict_t *d, char *k, data_t *v, void *_unused) {
    struct hs *hs = (struct hs *)v->data;

    if (hs) {
        printf("%s : %s\n", uuid_utoa(hs->gfid), hs->real_path);
    }

    dict_foreach(hs->idx_dict, hs_mem_idx_dump, NULL);

    return 0;
}

static void 
hs_release(void *to_free) {
    struct hs *hs = (struct hs *)to_free;
    struct hs *child_hs = NULL;
    struct hs *tmp = NULL;

    if (!hs) {
        return;
    }

    dict_foreach(hs->idx_dict, hs_mem_idx_purge, NULL);
    dict_unref(hs->idx_dict);

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
    xlator_t *this = NULL;

    this = THIS;

    /* invalid directory */
    size = sys_lgetxattr(rpath, "trusted.gfid", gfid, sizeof(gfid));
    if (size != sizeof(gfid)) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_GFID_OPERATION_FAILED,
            "Missing or wrong gfid: %s.", rpath);
        goto err;
    }

    hs = (void *)GF_CALLOC(1, sizeof(struct hs), gf_hs_mt_hs);
    if (!hs) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc haystack: %s.", rpath);
        goto err;
    }

    LOCK_INIT(&hs->lock);
    INIT_LIST_HEAD(&hs->children);
    INIT_LIST_HEAD(&hs->me);

    gf_uuid_copy(hs->gfid, gfid);

    hs->real_path = gf_strdup(rpath);
    if (!hs->real_path) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Strdup failed: %s.", rpath);
        goto err;
    }

    hs->idx_dict = dict_new();
    if (!hs->idx_dict) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc idx dict: %s.", rpath);
        goto err;
    }

    hs->log_fd = -1;
    hs->idx_fd = -1;
    hs->log_offset = 0;

    ret = hs_build(hs);
    if (ret < 0) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_BUILD_FAILED,
            "Fail to build haystack: %s.", rpath);
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
        if (hs->real_path) {
            GF_FREE(hs->real_path);
        }

        LOCK_DESTROY(&hs->lock);
        dict_unref(hs->idx_dict);
        GF_FREE(hs);
    }
    return NULL;
}

static struct hs *
hs_setup(const char *rpath, struct hs *parent, struct hs_ctx *ctx) {
    struct hs *hs = NULL;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    struct dirent scratch[2] = {{0}};
    char *child_rpath = NULL;
    struct stat stbuf = {0};
    int ret = -1;
    xlator_t *this = NULL;

    this = THIS;

    hs = hs_init(rpath, parent);
    if (!hs) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_INIT_FAILED, 
            "Fail to init haystack: %s.", rpath);         
        goto err;
    }

    dir = sys_opendir(rpath);
    if (!dir) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_DIR_OPERATION_FAILED, 
            "Fail to open directory: %s", rpath);     
        goto err;
    }

    child_rpath = GF_MALLOC(strlen(rpath)+1+NAME_MAX+1, gf_common_mt_char);
    if (!child_rpath) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc child path: %s.", rpath);
        goto err;            
    }

    while ((entry=sys_readdir(dir, scratch)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
            continue;
        }
        
        sprintf(child_rpath, "%s/%s", rpath, entry->d_name);
        ret = sys_lstat(child_rpath, &stbuf);
        if (ret < 0) {
            gf_msg(this->name, GF_LOG_WARNING, errno, H_MSG_LSTAT_FAILED,
                "Fail to lstat: %s", child_rpath);
        } else if (S_ISDIR(stbuf.st_mode)) {
            if (!hs_setup(child_rpath, hs, ctx)) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_SCAN_FAILED,
                    "Fail to setup child haystack: %s.", child_rpath);
                goto err;
            }
        }
    }

    ret = dict_set_static_bin(ctx->hs_dict, uuid_utoa(hs->gfid), hs, sizeof(*hs));
    if (ret != 0) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_ADD_FAILED,
            "Fail to add haystack into context: %s", rpath);
        goto err;
    }

    sys_closedir(dir);
    GF_FREE(child_rpath);

    return hs;

err:
    if (dir) {
        sys_closedir(dir);
    }
    GF_FREE(child_rpath);

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
    xlator_t *this = NULL;

    this = THIS;

    ctx = (void *)GF_CALLOC(1, sizeof(struct hs_ctx), gf_hs_mt_hs_ctx);
    if (!ctx) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc haystack context: %s.", rpath);
        goto err;
    }

    ctx->hs_dict = dict_new();
    if (!ctx->hs_dict) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc haystack context dict: %s.", rpath);        
        goto err;
    }

    ctx->root = hs_setup(rpath, NULL, ctx);
    if (!ctx->root) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_SCAN_FAILED,
            "Fail to setup haystack: %s.", rpath);  
        goto err;
    }

    return ctx;

err:
    hs_ctx_free(ctx);
    return NULL;
}