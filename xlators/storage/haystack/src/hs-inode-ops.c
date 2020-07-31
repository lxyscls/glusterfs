#include <stdint.h>
#include <uuid/uuid.h>
#include <errno.h>
#include <sys/stat.h>

#include <glusterfs/stack.h>
#include <glusterfs/xlator.h>
#include <glusterfs/dict.h>
#include <glusterfs/common-utils.h>
#include <glusterfs/iatt.h>
#include <glusterfs/syscall.h>

#include "hs.h"
#include "hs-ctx.h"
#include "hs-messages.h"

static void
do_lookup(xlator_t *this, struct hs *hs, uuid_t gfid, struct iatt *buf, int32_t *op_ret, int32_t *op_errno) {
    int ret = -1;
    struct stat lstatbuf = {0};
    char *real_path = NULL;
    char *log_path = NULL;
    struct hs *child = NULL;
    struct mem_idx *mem_idx = NULL;

    VALIDATE_OR_GOTO(this, out);
    VALIDATE_OR_GOTO(hs, out);
    VALIDATE_OR_GOTO(buf, out);

    GF_REF_GET(hs);

    if (!gf_uuid_compare(hs->gfid, gfid)) {
        MAKE_REAL_PATH(real_path, this, hs->path);

        ret = sys_lstat(real_path, &lstatbuf);
        if (ret == -1) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_LSTAT_FAILED,
                "Fail to lstat: %s.", real_path);
            *op_ret = ret;
            *op_errno = errno;
            goto out;
        }

        iatt_from_stat(buf, &lstatbuf);

        gf_uuid_copy(buf->ia_gfid, gfid);
        buf->ia_ino = gfid_to_ino(buf->ia_gfid);
        buf->ia_flags |= IATT_INO;

        *op_ret = 0;
        *op_errno = 0;
        goto out;
    }

    mem_idx = mem_idx_map_get(hs, gfid);
    if (mem_idx) {
        GF_REF_GET(mem_idx);

        if (mem_idx->offset == 0) {
            *op_ret = -1;
            *op_errno = ENOENT;
            goto out;
        }

        MAKE_LOG_PATH(log_path, this, hs->path);
        ret = sys_lstat(log_path, &lstatbuf);
        if (ret == -1) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_LSTAT_FAILED,
                "Fail to lstat: %s.", log_path);
            *op_ret = ret;
            *op_errno = errno;
            goto out;
        }

        lstatbuf.st_size = mem_idx->size;
        iatt_from_stat(buf, &lstatbuf);

        gf_uuid_copy(buf->ia_gfid, gfid);
        buf->ia_ino = gfid_to_ino(buf->ia_gfid);
        buf->ia_flags |= IATT_INO;

        *op_ret = 0;
        *op_errno = 0;
        goto out;  
    }

    pthread_rwlock_rdlock(&hs->lock);
    {
        list_for_each_entry(child, &hs->children, me) {
            do_lookup(this, child, gfid, buf, op_ret, op_errno);
            if (!(*op_ret == -1 && *op_errno == 0))
                break;
        }
    }
    pthread_rwlock_unlock(&hs->lock);   

out:
    if (hs)
        GF_REF_PUT(hs);
    if (mem_idx)
        GF_REF_PUT(mem_idx);
}

int32_t 
hs_lookup(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t * xdata) {
    struct iatt buf = {0};
    struct iatt postparent = {0};
    struct stat lstatbuf = {0};
    int32_t op_ret = -1;
    int32_t op_errno = 0;
    char *real_path = NULL;
    char *child_path = NULL;
    char *log_path = NULL;

    struct hs_private *priv = NULL;
    struct hs_ctx *ctx = NULL;
    struct hs *hs = NULL;
    struct mem_idx *mem_idx = NULL;
    struct dentry *den = NULL;

    VALIDATE_OR_GOTO(frame, out);
    VALIDATE_OR_GOTO(this, out);
    VALIDATE_OR_GOTO(loc, out);
    VALIDATE_OR_GOTO(this->private, out);

    priv = this->private;
    ctx = priv->ctx;

    if (loc_is_nameless(loc)) {
        if (gf_uuid_is_null(loc->gfid)) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_INODE_HANDLE_CREATE,
                "null gfid for path %s", loc->path);
            op_ret = -1;
            op_errno = ESTALE;
            goto out;
        }

        do_lookup(this, ctx->root, loc->gfid, &buf, &op_ret, &op_errno);
        if (op_ret == -1 && op_errno == 0) {
            op_errno = ENOENT;
        }
    } else {
        if (gf_uuid_is_null(loc->pargfid) || !loc->name) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_ENTRY_HANDLE_CREATE,
                "null pargfid/name for path %s", loc->path);
            op_ret = -1;
            op_errno = ESTALE;
            goto out;
        }

        hs = hs_map_get(ctx, loc->pargfid);
        if (!hs) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_MISSING,
                "No such directory: %s.", uuid_utoa(loc->pargfid));
            op_ret = -1;
            op_errno = ESTALE;
            goto out;
        }
        GF_REF_GET(hs);

        den = dentry_map_get(hs, loc->name);
        if (!den) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_MISSING,
                "No such dentry: %s.", loc->name);
            op_ret = -1;
            op_errno = ENOENT;
            goto out;
        }
        GF_REF_GET(den);

        if (den->type == DIR_T) {
            MAKE_CHILD_PATH(child_path, hs->path, loc->name);
            MAKE_REAL_PATH(real_path, this, child_path);

            op_ret = sys_lstat(real_path, &lstatbuf);
            if (op_ret == -1) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_LSTAT_FAILED,
                    "Fail to lstat: %s.", child_path);
                op_errno = errno;
                goto out;
            }

            iatt_from_stat(&buf, &lstatbuf);

            gf_uuid_copy(buf.ia_gfid, den->gfid);
            buf.ia_ino = gfid_to_ino(buf.ia_gfid);
            buf.ia_flags |= IATT_INO;            
        } else if (den->type == NON_T) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_DEL,
                "No such file: %s.", loc->name);
            op_ret = -1;
            op_errno = ENOENT;
            goto out;
        } else { // REG_T
            MAKE_LOG_PATH(log_path, this, hs->path);

            op_ret = sys_lstat(log_path, &lstatbuf);
            if (op_ret == -1) {
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_LSTAT_FAILED,
                    "Fail to lstat: %s.", log_path);
                op_errno = errno;
                goto out;
            }

            mem_idx = den->mem_idx;
            GF_REF_GET(mem_idx);

            lstatbuf.st_size = mem_idx->size;
            iatt_from_stat(&buf, &lstatbuf);

            gf_uuid_copy(buf.ia_gfid, den->gfid);
            buf.ia_ino = gfid_to_ino(buf.ia_gfid);
            buf.ia_flags |= IATT_INO;            
        }
    }

out:
    if (hs)
        GF_REF_PUT(hs);
    if (mem_idx)
        GF_REF_PUT(mem_idx);
    if (den)
        GF_REF_PUT(den);
    if (op_ret == 0)
        op_errno = 0;

    STACK_UNWIND_STRICT(lookup, frame, op_ret, op_errno,
                    (loc) ? loc->inode : NULL, &buf, NULL, &postparent);

    return 0;
}