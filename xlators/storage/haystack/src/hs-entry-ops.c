#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <uuid/uuid.h>

#include <glusterfs/stack.h>
#include <glusterfs/xlator.h>
#include <glusterfs/dict.h>
#include <glusterfs/iatt.h>
#include <glusterfs/common-utils.h>
#include <glusterfs/compat-uuid.h>
#include <glusterfs/logging.h>
#include <glusterfs/refcount.h>
#include <glusterfs/syscall.h>

#include "hs.h"
#include "hs-ctx.h"
#include "hs-messages.h"

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
    struct dentry *den = NULL;
    lookup_t *lk = NULL;

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

        lk = hs_do_lookup(this, NULL, loc->gfid, &buf);
        if (!lk) {
            op_ret = -1;
            op_errno = ESTALE;
        } else
            op_ret = 0;
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

        den = dentry_map_get(hs, loc->name);
        if (!den) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_MISSING,
                "No such dentry: %s.", loc->name);
            op_ret = -1;
            op_errno = ENOENT;
            goto out;
        }

        if (den->type == DIR_T) {
            MAKE_CHILD_PATH(child_path, hs->path, loc->name);
            MAKE_REAL_PATH(real_path, this, child_path);

            op_ret = sys_lstat(real_path, &lstatbuf);
            if (op_ret == -1) {
                op_errno = errno;                
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_LSTAT_FAILED,
                    "Fail to lstat: %s.", child_path);
                goto out;
            }

            iatt_from_stat(&buf, &lstatbuf);

            gf_uuid_copy(buf.ia_gfid, den->gfid);
            buf.ia_flags |= IATT_GFID;
            buf.ia_ino = gfid_to_ino(buf.ia_gfid);
            buf.ia_flags |= IATT_INO;            
        } else if (den->type == NON_T) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_DEL,
                "File has been deleted: %s.", loc->name);
            op_ret = -1;
            op_errno = ENOENT;
            goto out;
        } else { // REG_T
            MAKE_LOG_PATH(log_path, this, hs->path);

            op_ret = sys_lstat(log_path, &lstatbuf);
            if (op_ret == -1) {
                op_errno = errno;                
                gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_LSTAT_FAILED,
                    "Fail to lstat: %s.", log_path);
                goto out;
            }

            lstatbuf.st_size = den->mem_idx->size;
            iatt_from_stat(&buf, &lstatbuf);

            gf_uuid_copy(buf.ia_gfid, den->gfid);
            buf.ia_flags |= IATT_GFID;
            buf.ia_ino = gfid_to_ino(buf.ia_gfid);
            buf.ia_flags |= IATT_INO;            
        }
    }

out:
    if (hs)
        GF_REF_PUT(hs);
    if (den)
        GF_REF_PUT(den);
    if (lk)
        lookup_t_release(lk);
    if (op_ret == 0)
        op_errno = 0;

    STACK_UNWIND_STRICT(lookup, frame, op_ret, op_errno,
                    (loc) ? loc->inode : NULL, &buf, NULL, &postparent);

    return 0;
}