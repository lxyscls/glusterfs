#include <sys/stat.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <errno.h>

#include <glusterfs/xlator.h>
#include <glusterfs/mem-pool.h>
#include <glusterfs/syscall.h>
#include <glusterfs/compat-errno.h>
#include <glusterfs/logging.h>
#include <glusterfs/options.h>

#include "hs.h"
#include "hs-mem-types.h"
#include "hs-messages.h"

int32_t
mem_acct_init(xlator_t *this) {
    int ret = -1;

    if (!this)
        return ret;

    ret = xlator_mem_acct_init(this, gf_hs_mt_end + 1);

    if (ret != 0) {
        return ret;
    }

    return ret;
}

int
haystack_init(xlator_t *this) {
    int ret = -1;
    struct stat buf;
    uuid_t gfid;
    ssize_t size = -1;
    struct hs_private *private = NULL;
    static uuid_t rootgfid = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    char *k = NULL;
    struct hs *v = NULL;

    if (this->children) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_SUBVOLUME_ERROR,
            "storage/haystack cannot have subvolumes.");
        ret = -1;
        goto out;
    }

    private = GF_CALLOC(1, sizeof(*private), gf_hs_mt_hs_private);
    if (!private) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Fail to alloc haystack private.");
        ret = -1;
        goto out;
    }

    this->private = private;

    ret = dict_get_str(this->options, "directory", &private->base_path);
    if (ret < 0) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_EXPORT_DIR_MISSING,
            "Export directory not specified in volume file.");
        goto out;
    }
    private->base_path_length = strlen(private->base_path);

    ret = sys_stat(private->base_path, &buf);
    if (ret != 0 || !S_ISDIR(buf.st_mode)) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_DIR_OPERATION_FAILED,
            "Directory '%s' doesn't exist, exiting.", private->base_path);
        ret = -1;
        goto out;
    }

    size = sys_lgetxattr(private->base_path, "trusted.gfid", gfid, sizeof(gfid));
    if (size == 16) {
        if (!__is_root_gfid(gfid)) {
            gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_GFID_OPERATION_FAILED,
                "Gfid (%s) is not that of glusterfs %s.", uuid_utoa(gfid), private->base_path);            
            ret = -1;
            goto out;
        }
    } else if (size != -1) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_GFID_OPERATION_FAILED,
            "Wrong value set as gfid: %s.", private->base_path);
        ret = -1;
        goto out;
    } else if ((size == -1) && (errno != ENODATA) && (errno != ENOATTR)) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_GFID_OPERATION_FAILED, 
            "Fail to fetch gfid: %s.", private->base_path);
        ret = -1;
        goto out;
    } else {
        ret = sys_lsetxattr(private->base_path, "trusted.gfid", rootgfid, 16,
                             XATTR_CREATE);
        if (ret == -1) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_GFID_OPERATION_FAILED, 
                "Fail to set gfid: %s.", private->base_path);
            goto out;
        }
    }

    GF_OPTION_INIT("startup-crc-check", private->startup_crc_check, bool, out);

    umask(000);
    
    private->mount_lock = sys_opendir(private->base_path);
    if (!private->mount_lock) {
        gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_DIR_OPERATION_FAILED, 
            "Could not lock brick directory: %s.", private->base_path);        
        ret = -1;
        goto out;
    }

    private->ctx = hs_ctx_init(this, private->base_path);
    if (!private->ctx) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_CTX_FAILED,
            "%s: failed to setup haystack context", private->base_path);        
        ret = -1;
        goto out;
#ifdef HSDEBUG
    } else {
        kh_foreach(private->ctx->map, k, v, hs_dump(k, v));
#endif
    }

out:
    if (ret) {
        if (private) {
            GF_FREE(private->base_path);
            hs_ctx_free(private->ctx);
            GF_FREE(private);
        }

        this->private = NULL;
    }
    return ret;
}

void
haystack_fini(xlator_t *this) {
    struct hs_private *private = this->private;

    if (!private) {
        return;
    }

    GF_FREE(private->base_path);
    hs_ctx_free(private->ctx);
    GF_FREE(private);
}

struct xlator_fops fops;

struct volume_options hs_options[] = {
    {.key = {"directory"},
     .type = GF_OPTION_TYPE_PATH,
     .default_value = "{{brick.path}}"},
    {.key = {"startup-crc-check"}, .type = GF_OPTION_TYPE_BOOL},
    {.key = {NULL}},
};

xlator_api_t xlator_api = {
    .init = haystack_init,
    .fini = haystack_fini,
    .mem_acct_init = mem_acct_init,
    .fops = &fops,
    .options = hs_options,
};