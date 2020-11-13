#include <stdint.h>
#include <errno.h>
#include <dirent.h>

#include <glusterfs/stack.h>
#include <glusterfs/xlator.h>
#include <glusterfs/fd.h>
#include <glusterfs/dict.h>
#include <glusterfs/logging.h>
#include <glusterfs/common-utils.h>
#include <glusterfs/syscall.h>
#include <glusterfs/glusterfs-fops.h>
#include <glusterfs/compat-uuid.h>
#include <glusterfs/gf-dirent.h>
#include <glusterfs/compat.h>
#include "glusterfs3-xdr.h"

#include "hs.h"
#include "hs-ctx.h"
#include "hs-messages.h"
#include "hs-mem-types.h"

int32_t
hs_opendir(call_frame_t *frame, xlator_t *this, loc_t *loc, fd_t *fd, dict_t *xdata) {
    int32_t op_ret = -1;
    int32_t op_errno = 0;
    char *real_path = NULL;
    DIR *dir = NULL;

    struct hs_private *priv = NULL;
    struct hs_ctx *ctx = NULL;
    struct hs *hs = NULL;
    struct hs_fd *hfd = NULL;

    VALIDATE_OR_GOTO(frame, out);
    VALIDATE_OR_GOTO(this, out);
    VALIDATE_OR_GOTO(loc, out);
    VALIDATE_OR_GOTO(fd, out);
    VALIDATE_OR_GOTO(this->private, out);

    priv = this->private;
    ctx = priv->ctx;
    
    if (gf_uuid_is_null(loc->gfid)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_INODE_HANDLE_CREATE,
            "null gfid for path %s", loc->path);        
        op_ret = -1;
        op_errno = ESTALE;
        goto out;
    }

    hs = hs_map_get(ctx, loc->gfid);
    if (!hs) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_MISSING,
            "No such directory: %s.", loc->path);        
        op_ret = -1;
        op_errno = ENOENT;
        goto out;
    }

    hfd = GF_CALLOC(1, sizeof(*hfd), gf_hs_mt_hs_fd);
    if (!hfd) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_HFD_INIT_FAILED,
            "Fail to alloc hfd: %s.", loc->path);
        op_ret = -1;
        op_errno = EINVAL;
        goto out;
    }

    MAKE_REAL_PATH(real_path, this, hs->path);
    dir = sys_opendir(real_path);
    if (!dir) {
        op_errno = errno;
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_OPENDIR_FAILED,
            "Fail to open directory: %s.", real_path);
        op_ret = -1;
        goto out;
    }

    hfd->hs = hs;
    hfd->dir = dir;
    hfd->dir_eof = -1;

    op_ret = fd_ctx_set(fd, this, (uint64_t)(long)hfd);
    if (op_ret)
        gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_HFD_ADD_FAILED,
            "Fail to set hfd into ctx: %s.", loc->path);

    op_ret = 0;
out:
    if (op_ret) {
        if (hs)
            GF_REF_PUT(hs);
        if (dir)
            sys_closedir(dir);
        if (hfd)
            GF_FREE(hfd);
    }

    STACK_UNWIND_STRICT(opendir, frame, op_ret, op_errno, fd, NULL);
    return 0;
}

int32_t
hs_releasedir(xlator_t *this, fd_t *fd) {
    int ret = 0;
    uint64_t tmp_hfd = 0;

    struct hs_fd *hfd = NULL;

    VALIDATE_OR_GOTO(this, out);
    VALIDATE_OR_GOTO(fd, out);

    ret = fd_ctx_del(fd, this, &tmp_hfd);
    if (ret < 0) {
        gf_msg_debug(this->name, 0, "hfd from fd=%p is NULL", fd);
        goto out;
    }

    hfd = (struct hs_fd *)(long)tmp_hfd;
    if (!hfd->hs)
        gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_HFD_NULL,
            "hfd->hs is NULL for fd=%p", fd);

    if (!hfd->dir)
        gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_HFD_NULL,
            "hdf->dir is NULL for fd=%p", fd);

out:
    if (hfd) {
        if (hfd->hs)
            GF_REF_PUT(hfd->hs);
        if (hfd->dir)
            sys_closedir(hfd->dir);
        GF_FREE(hfd);
    }
    return 0;
}

static int32_t
hs_do_readdir(call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
                 off_t off, int whichop, dict_t *dict) {
    int ret = -1;
    int32_t op_ret = -1;
    int32_t op_errno = 0; 
    gf_dirent_t entries;
    DIR *dir = NULL;
    int count = 0;
    off_t in_case = -1;
    off_t last_off = 0;
    size_t filled = 0;
    size_t this_size = 0;
    struct dirent *entry = NULL;
    struct dirent scratch[2] = {{0}};
    gf_dirent_t *this_entry = NULL;
    khint32_t next = 0;
    char *in = NULL;
    uuid_t gfid;

    struct hs_fd *hfd = NULL;
    struct hs *hs = NULL;
    struct mem_idx *mem_idx = NULL; 

    VALIDATE_OR_GOTO(frame, out);
    VALIDATE_OR_GOTO(this, out);
    VALIDATE_OR_GOTO(fd, out);

    INIT_LIST_HEAD(&entries.list);

    ret = hs_fd_ctx_get(fd, this, &hfd, &op_errno);
    if (ret < 0) {
        gf_msg(this->name, GF_LOG_WARNING, op_errno, H_MSG_HFD_NULL,
            "hfd is NULL, fd=%p", fd);
        op_ret = -1;
        goto out;
    }

    dir = hfd->dir;
    if (!dir) {
        gf_msg(this->name, GF_LOG_WARNING, EINVAL, H_MSG_HFD_NULL,
               "dir is NULL for fd=%p", fd);
        op_ret = -1;
        op_errno = EINVAL;
        goto out;
    }

    hs = hfd->hs;
    if (!hs) {
        gf_msg(this->name, GF_LOG_WARNING, EINVAL, H_MSG_HFD_NULL,
            "hs is NULL for fd=%p.", fd);
        op_ret = -1;
        op_errno = EINVAL;
        goto out;
    }

    if (hfd->dir_eof >= 0)
        goto log_read;

    if (!off)
        rewinddir(dir);
    else
        seekdir(dir, off);

    while (filled <= size) {
        in_case = (u_long)telldir(dir);
        if (in_case == -1) {
            op_errno = errno;
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_DIR_OPERATION_FAILED,
                   "telldir failed on dir=%p", dir);
            op_ret = -1;
            goto out;
        }

        errno = 0;
        entry = sys_readdir(dir, scratch);
        if (!entry || errno != 0) {
            if (errno == EBADF) {
                op_errno = errno;
                gf_msg(this->name, GF_LOG_WARNING, errno,
                       H_MSG_DIR_OPERATION_FAILED, "readdir failed on dir=%p",
                       dir);
                op_ret = -1;
                goto out;
            }
            break;
        }

        if (!strcmp(entry->d_name, ".log") || !strcmp(entry->d_name, ".idx"))
            continue;
        
        this_size = max(sizeof(gf_dirent_t), sizeof(gfs3_dirplist)) + strlen(entry->d_name) + 1;
        if (this_size + filled > size) {
            seekdir(dir, in_case);
            break;
        }

        this_entry = gf_dirent_for_name(entry->d_name);
        if (!this_entry) {
            gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_GF_DIRENT_CREATE_FAILED,
                "Could not create gf_dirent for entry %s.", entry->d_name);
            op_ret = -1;
            op_errno = EBADF;            
            goto out;
        }

        last_off = (u_long)telldir(dir);
        this_entry->d_off = last_off;
        this_entry->d_ino = entry->d_ino;
        this_entry->d_type = entry->d_type;

        list_add_tail(&this_entry->list, &entries.list);

        filled += this_size;
        count++;        
    }

    if (!sys_readdir(dir, scratch) && (errno == 0))
        hfd->dir_eof = last_off;

log_read:
    next = off - hfd->dir_eof;

    pthread_rwlock_rdlock(&hs->map_lock);
    {
        while (filled <= size) {
            __MEM_IDX_MAP_GET_NEXT(hs->map, next, in, mem_idx);
            if (!mem_idx)
                break;
            
            this_size = max(sizeof(gf_dirent_t), sizeof(gfs3_dirplist)) + mem_idx->name_len;
            if (this_size + filled > size)
                break;
            
            this_entry = gf_dirent_for_name(mem_idx->name);
            if (!this_entry) {
                gf_msg(THIS->name, GF_LOG_ERROR, ENOMEM, H_MSG_GF_DIRENT_CREATE_FAILED,
                    "Could not create gf_dirent for entry %s.", mem_idx->name);
                op_ret = -1;
                op_errno = EBADF;
                pthread_rwlock_unlock(&hs->map_lock);            
                goto out;
            }

            this_entry->d_off = next + hfd->dir_eof;
            gf_uuid_parse(in, gfid);
            this_entry->d_ino = gfid_to_ino(gfid);
            this_entry->d_type = DT_REG;

            list_add_tail(&this_entry->list, &entries.list);

            filled += this_size;
            count++;             
        }
    }
    pthread_rwlock_unlock(&hs->map_lock);

out:
    if (op_errno == 0)
        op_ret = count;

    if (whichop == GF_FOP_READDIR)
        STACK_UNWIND_STRICT(readdir, frame, op_ret, op_errno, &entries, NULL);
    else
        STACK_UNWIND_STRICT(readdirp, frame, op_ret, op_errno, &entries, NULL);

    gf_dirent_free(&entries);

    return 0;
}

int32_t
hs_readdir(call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
    off_t off, dict_t *xdata) {
    hs_do_readdir(frame, this, fd, size, off, GF_FOP_READDIR, xdata);
    return 0;
}

int32_t
hs_readdirp(call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
    off_t off, dict_t *dict) {
    hs_do_readdir(frame, this, fd, size, off, GF_FOP_READDIRP, dict);
    return 0;    
}