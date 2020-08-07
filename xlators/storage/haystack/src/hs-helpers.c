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

#include "hs.h"
#include "hs-ctx.h"
#include "hs-messages.h"
#include "hs-mem-types.h"

static lookup_t *
__hs_do_lookup(xlator_t *this, struct hs *hs, uuid_t gfid, struct iatt *buf) {
    int op_ret = -1;
    int op_errno = 0;
    struct stat lstatbuf = {0};
    char *real_path = NULL;
    char *log_path = NULL;
    
    lookup_t *lk = NULL;
    struct hs *child = NULL;
    struct mem_idx *mem_idx = NULL;

    if (!gf_uuid_compare(hs->gfid, gfid)) {
        if (buf) {
            MAKE_REAL_PATH(real_path, this, hs->path);

            op_ret = sys_lstat(real_path, &lstatbuf);
            if (op_ret == -1) {
                op_errno = errno;                
                gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_LSTAT_FAILED,
                    "Fail to lstat: %s.", real_path);                
                goto out;
            }

            iatt_from_stat(buf, &lstatbuf);

            gf_uuid_copy(buf->ia_gfid, gfid);
            buf->ia_ino = gfid_to_ino(buf->ia_gfid);
            buf->ia_flags |= IATT_INO;
        }

        lk = lookup_t_from_hs(hs);
        if (!lk) {
            gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_LOOKUP_INIT_FAILED,
                "Fail to alloc lookup_t: %s.", uuid_utoa(gfid));
            op_errno = ENOMEM;
            goto out;            
        }

        goto out;
    }

    mem_idx = mem_idx_map_get(hs, gfid);
    if (mem_idx) {
        if (mem_idx->offset == 0) {
            gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_MEM_IDX_DEL,
                "File has been deleted: %s.", uuid_utoa(gfid));
            op_errno = ENOENT;
            goto out;
        }

        if (buf) {
            MAKE_LOG_PATH(log_path, this, hs->path);
            op_ret = sys_lstat(log_path, &lstatbuf);
            if (op_ret == -1) {
                op_errno = errno;
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

        lk = lookup_t_from_mem_idx(mem_idx);
        if (!lk) {
            gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_LOOKUP_INIT_FAILED,
                "Fail to alloc lookup_t: %s.", uuid_utoa(gfid));
            op_errno = ENOMEM;
            goto out;
        }

        goto out;  
    }

    pthread_rwlock_rdlock(&hs->lock);
    {
        list_for_each_entry(child, &hs->children, me) {
            GF_REF_GET(child);
            lk = __hs_do_lookup(this, child, gfid, buf);
            if (lk || errno != 0) {
                op_errno = errno;
                break;
            }
        }
    }
    pthread_rwlock_unlock(&hs->lock);   

out:
    if (!lk) {
        if (hs)
            GF_REF_PUT(hs);
        if (mem_idx)
            GF_REF_PUT(mem_idx);
    }

    errno = op_errno;
    
    return lk;
}

lookup_t *
hs_do_lookup(xlator_t *this, uuid_t gfid, struct iatt *buf) {
    struct hs_private *priv = NULL;
    struct hs_ctx *ctx = NULL;
    lookup_t *lk = NULL;

    VALIDATE_OR_GOTO(this, out);

    priv = this->private;
    ctx = priv->ctx;

    GF_REF_GET(ctx->root);
    lk = __hs_do_lookup(this, ctx->root, gfid, buf);

out:
    if (!this)
        errno = EINVAL;
    return lk;
}

#if 0
static int
__hs_fd_ctx_get(fd_t *fd, xlator_t *this, struct hs_fd **hfd_p, int *op_errno_p) {
    uint64_t tmp_hfd = 0;

    int ret = -1;
    char *real_path = NULL;
    char *unlink_path = NULL;
    int _fd = -1;
    int op_errno = 0;
    DIR *dir = NULL;

    struct hs_private *priv = NULL;
    struct hs_ctx *ctx = NULL;
    struct hs *hs = NULL;
    struct hs_fd *hfd = NULL;

    priv = this->private;

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
        op_errno = EINVAL;
        goto out;
    }

    hs = hs_map_get(ctx, fd->inode->gfid);
    if (!hs) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_MISSING,
            "No such directory: %s.", loc->path);        
        op_ret = -1;
        op_errno = ENOENT;
        goto out;
    }
    GF_REF_GET(hs);

    MAKE_HANDLE_PATH(real_path, this, fd->inode->gfid, NULL);
    if (!real_path) {
        gf_msg(this->name, GF_LOG_ERROR, 0, P_MSG_READ_FAILED,
               "Failed to create handle path (%s)", uuid_utoa(fd->inode->gfid));
        ret = -1;
        op_errno = EINVAL;
        goto out;
    }
    pfd = GF_CALLOC(1, sizeof(*pfd), gf_posix_mt_posix_fd);
    if (!pfd) {
        op_errno = ENOMEM;
        goto out;
    }
    pfd->fd = -1;

    if (fd->inode->ia_type == IA_IFDIR) {
        dir = sys_opendir(real_path);
        if (!dir) {
            op_errno = errno;
            gf_msg(this->name, GF_LOG_ERROR, op_errno, P_MSG_READ_FAILED,
                   "Failed to get anonymous fd for "
                   "real_path: %s.",
                   real_path);
            GF_FREE(pfd);
            pfd = NULL;
            goto out;
        }
        _fd = dirfd(dir);
    }

    /* Using fd->flags in case we choose to have anonymous
     * fds with different flags some day. As of today it
     * would be GF_ANON_FD_FLAGS and nothing else.
     */
    if (fd->inode->ia_type == IA_IFREG) {
        _fd = open(real_path, fd->flags);
        if ((_fd == -1) && (errno == ENOENT)) {
            POSIX_GET_FILE_UNLINK_PATH(priv->base_path, fd->inode->gfid,
                                       unlink_path);
            _fd = open(unlink_path, fd->flags);
        }
        if (_fd == -1) {
            op_errno = errno;
            gf_msg(this->name, GF_LOG_ERROR, op_errno, P_MSG_READ_FAILED,
                   "Failed to get anonymous fd for "
                   "real_path: %s.",
                   real_path);
            GF_FREE(pfd);
            pfd = NULL;
            goto out;
        }
    }

    pfd->fd = _fd;
    pfd->dir = dir;
    pfd->flags = fd->flags;

    ret = __fd_ctx_set(fd, this, (uint64_t)(long)pfd);
    if (ret != 0) {
        op_errno = ENOMEM;
        if (_fd != -1)
            sys_close(_fd);
        if (dir)
            sys_closedir(dir);
        GF_FREE(pfd);
        pfd = NULL;
        goto out;
    }

    ret = 0;
out:
    if (ret < 0 && op_errno_p)
        *op_errno_p = op_errno;

    if (hfd_p)
        *hfd_p = hfd;
    return ret;
}

int
hs_fd_ctx_get(fd_t *fd, xlator_t *this, struct hs_fd **hfd_p, int *op_errno_p)
{
    int ret;

    LOCK(&fd->inode->lock);
    {
        ret = __hs_fd_ctx_get(fd, this, hfd_p, op_errno_p);
    }
    UNLOCK(&fd->inode->lock);

    return ret;
}
#endif