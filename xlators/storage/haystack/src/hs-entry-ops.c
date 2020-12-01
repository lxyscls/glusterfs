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
#include <glusterfs/compat.h>

#include "hs.h"
#include "hs-ctx.h"
#include "hs-helpers.h"
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
                    "Failed to lstat: %s.", child_path);
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
                    "Failed to lstat: %s.", log_path);
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

    STACK_UNWIND_STRICT(lookup, frame, op_ret, op_errno,
                    (loc) ? loc->inode : NULL, &buf, NULL, &postparent);

    return 0;
}

int32_t 
hs_mkdir(call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode, mode_t umask, dict_t *xdata) {
    int ret = 0;
    int32_t op_ret = -1;
    int32_t op_errno = 0;
    struct iatt stbuf = {0};
    struct stat lstatbuf = {0};    
    uuid_t uuid_req = {0};
    char *child_path = NULL;
    char *real_path = NULL;

    struct hs_private *priv = NULL;
    struct hs_ctx *ctx = NULL;
    struct hs *parhs = NULL, *hs = NULL;
    struct dentry *den = NULL;

    VALIDATE_OR_GOTO(frame, out);
    VALIDATE_OR_GOTO(this, out);
    VALIDATE_OR_GOTO(loc, out);
    VALIDATE_OR_GOTO(this->private, out);

    priv = this->private;
    ctx = priv->ctx;

    ret = dict_get_gfuuid(xdata, "gfid-req", &uuid_req);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, H_MSG_NULL_GFID,
            "Failed to get gfid from dict for %s.", loc->path);
        op_ret = -1;
        op_errno = EINVAL;
        goto out;
    }

    if (gf_uuid_is_null(uuid_req)) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, H_MSG_NULL_GFID,
            "gfid is null for %s.", loc->path);
        op_ret = -1;
        op_errno = EINVAL;
        goto out;
    }

    if (gf_uuid_is_null(loc->pargfid) || !loc->name) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_ENTRY_HANDLE_CREATE,
            "null pargfid/name for path %s", loc->path);
        op_ret = -1;
        op_errno = ESTALE;
        goto out;
    }

    parhs = hs_map_get(ctx, loc->pargfid);
    if (!parhs) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_MISSING,
            "No directory for gfid %s.", uuid_utoa(loc->pargfid));
        op_ret = -1;
        op_errno = EINVAL;
        goto out;
    }

    MAKE_CHILD_PATH(child_path, parhs->path, loc->name);
    MAKE_REAL_PATH(real_path, this, child_path);

    op_ret = sys_mkdir(real_path, mode);
    if (op_ret == -1) {
        op_errno = errno;
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_MKDIR_FAILED,
            "mkdir of %s failed.", child_path);
        goto out;
    }

    op_ret = sys_lsetxattr(real_path, "trusted.gfid", uuid_req, sizeof(uuid_req), XATTR_CREATE);
    if (op_ret == -1) {
        op_errno = errno;
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_GFID_OPERATION_FAILED,
            "Failed to set gfid (%s) on %s.", uuid_utoa(uuid_req), child_path);
        sys_rmdir(real_path);
        goto out;
    }

    hs = hs_init(this, parhs, child_path, _gf_true);
    if (!hs) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_INIT_FAILED, 
            "Failed to init haystack: %s.", child_path);
        op_ret = -1;
        op_errno = ESTALE;
        goto out;        
    }

    den = dentry_init(hs->gfid, DIR_T, NULL);
    if (!den) {
        gf_msg(THIS->name, GF_LOG_ERROR, ENOMEM, H_MSG_DENTRY_INIT_FAILED,
            "Failed to alloc dentry for directory (%s %s).", child_path, uuid_utoa(hs->gfid));
        op_ret = -1;
        op_errno = ENOMEM;
        goto out;
    }

    ret = dentry_map_put(parhs, loc->name, den);
    if (ret == 0) {
        gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_DENTRY_DUP,
            "Duplicate sub directory: %s.", loc->name);
    } else if (ret == -1) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DENTRY_ADD_FAILED,
            "Failed to add dentry into lookup table: (%s %s).", loc->name, parhs->path);
        op_ret = -1;
        op_errno = ESTALE;
        goto out;
    }

    ret = hs_map_put(ctx, hs->gfid, hs);
    if (ret == 0) {
        gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_HS_DUP,
            "Duplicate directory: (%s %s).", uuid_utoa(hs->gfid), child_path);
    } else if (ret == -1) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_ADD_FAILED,
            "Failed to add hs into ctx: (%s %s).", uuid_utoa(hs->gfid), child_path);
        op_ret = -1;
        op_errno = ESTALE;
        goto out;
    }   

    op_ret = sys_lstat(real_path, &lstatbuf);
    if (op_ret == -1) {      
        op_errno = errno; 
        gf_msg(this->name, GF_LOG_WARNING, errno, H_MSG_LSTAT_FAILED,
            "Failed to lstat: %s.", real_path);
        goto out;            
    } else {
        iatt_from_stat(&stbuf, &lstatbuf);

        gf_uuid_copy(stbuf.ia_gfid, hs->gfid);
        stbuf.ia_flags |= IATT_GFID;
        stbuf.ia_ino = gfid_to_ino(stbuf.ia_gfid);
        stbuf.ia_flags |= IATT_INO;
    }    

    op_ret = 0;

out:
    if (den)
        GF_REF_PUT(den);
    if (hs)
        GF_REF_PUT(hs);        
    if (parhs)
        GF_REF_PUT(parhs);

    STACK_UNWIND_STRICT(mkdir, frame, op_ret, op_errno,
        (loc) ? loc->inode : NULL, &stbuf, NULL, NULL, NULL);
    
    return 0;
}