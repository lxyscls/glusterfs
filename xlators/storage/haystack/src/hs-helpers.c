#include <stdint.h>
#include <uuid/uuid.h>
#include <errno.h>
#include <sys/stat.h>

#include <glusterfs/fd.h>
#include <glusterfs/xlator.h>
#include <glusterfs/logging.h>
#include <glusterfs/iatt.h>
#include <glusterfs/common-utils.h>
#include <glusterfs/syscall.h>
#include <glusterfs/refcount.h>
#include <glusterfs/compat-uuid.h>
#include <glusterfs/mem-pool.h>
#include <glusterfs/fd.h>

#include "hs.h"
#include "hs-ctx.h"
#include "hs-messages.h"
#include "hs-mem-types.h"

int
hs_do_lookup(xlator_t *this, struct hs *hs, uuid_t gfid, struct iatt *buf, lookup_t **lk) {
    int ret = -1;
    struct stat lstatbuf = {0};
    char *real_path = NULL;
    char *log_path = NULL;
    
    struct hs_private *priv = NULL;
    struct hs_ctx *ctx = NULL;
    struct hs *child = NULL;
    struct mem_idx *mem_idx = NULL;

    VALIDATE_OR_GOTO(this, out);

    if (!hs) {
        priv = this->private;
        ctx = priv->ctx;

        hs = ctx->root;
        GF_REF_GET(hs);
    }

    if (!gf_uuid_compare(hs->gfid, gfid)) {
        if (buf) {
            MAKE_REAL_PATH(real_path, this, hs->path);
            ret = sys_lstat(real_path, &lstatbuf);
            if (ret) {       
                gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_LSTAT_FAILED,
                    "Fail to lstat: %s.", real_path);                
                goto out;
            }

            iatt_from_stat(buf, &lstatbuf);

            gf_uuid_copy(buf->ia_gfid, gfid);
            buf->ia_ino = gfid_to_ino(buf->ia_gfid);
            buf->ia_flags |= IATT_INO;
        }

        *lk = lookup_t_init(hs, NULL, DIR_T);
        if (*lk == NULL) {
            gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_LOOKUPT_INIT_FAILED,
                "Fail to alloc lookup_t: %s.", uuid_utoa(gfid));
            ret = -1;
            goto out;            
        }

        goto out;
    }

    mem_idx = mem_idx_map_get(hs, gfid);
    if (mem_idx) {
        if (mem_idx->offset == 0) {
            gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_MEM_IDX_DEL,
                "File has been deleted: %s.", uuid_utoa(gfid));
            ret = -1;
            goto out;
        }

        if (buf) {
            MAKE_LOG_PATH(log_path, this, hs->path);
            ret = sys_lstat(log_path, &lstatbuf);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_LSTAT_FAILED,
                    "Fail to lstat: %s.", log_path);
                goto out;
            }

            lstatbuf.st_size = mem_idx->size;
            iatt_from_stat(buf, &lstatbuf);

            gf_uuid_copy(buf->ia_gfid, gfid);
            buf->ia_ino = gfid_to_ino(buf->ia_gfid);
            buf->ia_flags |= IATT_INO;
        }

        *lk = lookup_t_init(hs, mem_idx, REG_T);
        if (*lk == NULL) {
            gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_LOOKUPT_INIT_FAILED,
                "Fail to alloc lookup_t: %s.", uuid_utoa(gfid));
            ret = -1;
            goto out;
        }

        goto out;  
    }

    pthread_rwlock_rdlock(&hs->lock);
    {
        list_for_each_entry(child, &hs->children, me) {
            GF_REF_GET(child);
            ret = hs_do_lookup(this, child, gfid, buf, lk);
            if (*lk || ret != 0) {
                break;
            }
        }
    }
    pthread_rwlock_unlock(&hs->lock);   

out:
    if (*lk == NULL) {
        if (hs)
            GF_REF_PUT(hs);
        if (mem_idx)
            GF_REF_PUT(mem_idx);
    }
    
    return ret;
}

static int
__hs_fd_ctx_get(fd_t *fd, xlator_t *this, struct hs_fd **hfd_p, int *op_errno_p)
{
    int ret = -1;
    uint64_t tmp_hfd = 0;
    int op_errno = 0;
    char *real_path = NULL;
    DIR *dir = NULL;

    struct hs_fd *hfd = NULL;
    lookup_t *lk = NULL;

    // fastpath
    ret = __fd_ctx_get(fd, this, &tmp_hfd);
    if (ret == 0) {
        hfd = (struct hs_fd *)(long)tmp_hfd;
        goto out;
    }

    if (!fd_is_anonymous(fd)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_READ_FAILED,
               "Failed to get fd context for a non-anonymous fd, "
               "gfid: %s",
               uuid_utoa(fd->inode->gfid));
        ret = -1;
        op_errno = EINVAL;
        goto out;
    }

    // slowpath
    ret = hs_do_lookup(this, NULL, fd->inode->gfid, NULL, &lk);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_LOOKUPT_FIND_FAILED,
               "Failed to do lookup (%s)", uuid_utoa(fd->inode->gfid));
        ret = -1;
        op_errno = EINVAL;
        goto out;
    }

    hfd = GF_CALLOC(1, sizeof(*hfd), gf_hs_mt_lookup_t);
    if (!hfd) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_HFD_INIT_FAILED,
            "Fail to alloc hfd: %p.", fd);        
        ret = -1;
        op_errno = ENOMEM;
        goto out;
    }

    if (fd->inode->ia_type == IA_IFDIR) {
        if (lk->type != DIR_T) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_LOOKUP_TYPE_MISMATCH,
                "Underly lookup_t is not a directory.");
            ret = -1;
            op_errno = EINVAL;
            goto out;
        }

        MAKE_REAL_PATH(real_path, this, lk->hs->path);
        dir = sys_opendir(real_path);
        if (!dir) {
            op_errno = errno;
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_OPENDIR_FAILED,
                "Fail to open directory: %s.", real_path);
            ret = -1;
            goto out;
        }
    }

    if (fd->inode->ia_type == IA_IFREG) {
        if (lk->type != REG_T) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_LOOKUP_TYPE_MISMATCH,
                "Underly lookup_t is not a file.");
            ret = -1;
            op_errno = EINVAL;
            goto out;
        }
    }

    hfd->dir = dir;
    hfd->hs = lk->hs;
    hfd->mem_idx = lk->mem_idx;

    ret = __fd_ctx_set(fd, this, (uint64_t)(long)hfd);
    if (ret != 0) {
        ret = -1;
        op_errno = ENOMEM;
        goto out;
    }

    ret = 0;
out:
    if (ret < 0) {
        if (op_errno_p)
            *op_errno_p = op_errno;
        if (dir)
            sys_closedir(dir);
        if (hfd)
            GF_FREE(hfd);
        if (lk)
            lookup_t_release(lk);
    }

    if (hfd_p && ret == 0)
        *hfd_p = hfd;
    
    return ret;
}

int
hs_fd_ctx_get(fd_t *fd, xlator_t *this, struct hs_fd **hfd, int *op_errno)
{
    int ret;

    LOCK(&fd->inode->lock);
    {
        ret = __hs_fd_ctx_get(fd, this, hfd, op_errno);
    }
    UNLOCK(&fd->inode->lock);

    return ret;
}