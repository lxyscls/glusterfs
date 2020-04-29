#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <glusterfs/xlator.h>
#include <glusterfs/dict.h>
#include <glusterfs/glusterfs.h>
#include <glusterfs/syscall.h>
#include <glusterfs/mem-pool.h>
#include <glusterfs/inode.h>
#include <glusterfs/common-utils.h>
#include <glusterfs/logging.h>
#include <glusterfs/compat.h>
#include <glusterfs/stack.h>
#include <glusterfs/iatt.h>

#include "hs.h"
#include "hs-mem-types.h"
#include "hs-messages.h"

int32_t
hs_lookup(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
    int32_t op_ret = -1;
    int32_t op_errno = 0;
    struct hs_private *priv = NULL;
    struct iatt buf = {
        0,
    };
    struct iatt postparent = {
        0,
    };
    dict_t *xattr = NULL;

    VALIDATE_OR_GOTO(frame, out);
    VALIDATE_OR_GOTO(this, out);
    VALIDATE_OR_GOTO(loc, out);
    VALIDATE_OR_GOTO(this->private, out);

    priv = this->private;

out:
    if (op_ret == 0)
        op_errno = 0;
    STACK_UNWIND_STRICT(lookup, frame, op_ret, op_errno,
                        (loc) ? loc->inode : NULL, &buf, xattr, &postparent);

    if (xattr)
        dict_unref(xattr);

    return 0;
}

int
hs_init(xlator_t *this)
{
    struct hs_private *_private = NULL;
    data_t *dir_data = NULL;
    struct stat buf = {
        0,
    };
    int ret = 0;
    int op_ret = -1;
    int op_errno = 0;
    ssize_t size = -1;
    uuid_t gfid = {
        0,
    };
    static uuid_t rootgfid = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    dir_data = dict_get(this->options, "directory");

    if (this->children) {
        gf_msg(this->name, GF_LOG_CRITICAL, 0, H_MSG_SUBVOLUME_ERROR,
               "FATAL: storage/haystack cannot have subvolumes");
        ret = -1;
        goto out;
    }

    if (!this->parents) {
        gf_msg(this->name, GF_LOG_WARNING, 0, H_MSG_VOLUME_DANGLING,
               "Volume is dangling. Please check the volume file.");
    }

    if (!dir_data) {
        gf_msg(this->name, GF_LOG_CRITICAL, 0, H_MSG_EXPORT_DIR_MISSING,
               "Export directory not specified in volume file.");
        ret = -1;
        goto out;
    }

    umask(000);  // umask `masking' is done at the client side

    /* Check whether the specified directory exists, if not log it. */
    op_ret = sys_stat(dir_data->data, &buf);
    if ((op_ret != 0) || !S_ISDIR(buf.st_mode)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DIR_OPERATION_FAILED,
               "Directory '%s' doesn't exist, exiting.", dir_data->data);
        ret = -1;
        goto out;
    }

    _private = GF_CALLOC(1, sizeof(*_private), gf_hs_mt_hs_private);
    if (!_private) {
        ret = -1;
        goto out;
    }

    _private->base_path = gf_strdup(dir_data->data);
    _private->base_path_length = dir_data->len - 1;

    /* Now check if the export directory has some other 'gfid',
       other than that of root '/' */
    size = sys_lgetxattr(dir_data->data, "trusted.gfid", gfid, 16);
    if (size == 16) {
        if (!__is_root_gfid(gfid)) {
            gf_msg(this->name, GF_LOG_WARNING, errno, H_MSG_GFID_SET_FAILED,
                   "%s: gfid (%s) is not that of glusterfs '/' ",
                   dir_data->data, uuid_utoa(gfid));
            ret = -1;
            goto out;
        }
    } else if (size != -1) {
        /* Wrong 'gfid' is set, it should be error */
        gf_msg(this->name, GF_LOG_WARNING, errno, H_MSG_GFID_SET_FAILED,
               "%s: wrong value set as gfid", dir_data->data);
        ret = -1;
        goto out;
    } else if ((size == -1) && (errno != ENODATA) && (errno != ENOATTR)) {
        /* Wrong 'gfid' is set, it should be error */
        gf_msg(this->name, GF_LOG_WARNING, errno, H_MSG_GFID_SET_FAILED,
               "%s: failed to fetch gfid", dir_data->data);
        ret = -1;
        goto out;
    } else {
        /* First time volume, set the GFID */
        size = sys_lsetxattr(dir_data->data, "trusted.gfid", rootgfid, 16,
                             XATTR_CREATE);
        if (size == -1) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_GFID_SET_FAILED,
                   "%s: failed to set gfid", dir_data->data);
            ret = -1;
            goto out;
        }
    }

    /* performing open dir on brick dir locks the brick dir
     * and prevents it from being unmounted
     */
    _private->mount_lock = sys_opendir(dir_data->data);
    if (!_private->mount_lock) {
        ret = -1;
        op_errno = errno;
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DIR_OPERATION_FAILED,
               "Could not lock brick directory (%s)", strerror(op_errno));
        goto out;
    }

    this->private = (void *)_private;

out:
    if (ret) {
        if (_private) {
            GF_FREE(_private->base_path);
            GF_FREE(_private);
        }

        this->private = NULL;
    }
    return ret;
}

void
hs_fini(xlator_t *this)
{
    struct hs_private *priv = this->private;
    if (!priv)
        return;    

    GF_FREE(priv->base_path);
    GF_FREE(priv);
    this->private = NULL;

    return;
}

xlator_api_t xlator_api = {
    .init = hs_init,
    .fini = hs_fini
};