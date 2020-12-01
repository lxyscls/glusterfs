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
#include <glusterfs/defaults.h>

#include "hs.h"
#include "hs-ctx.h"
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

    gf_msg(this->name, GF_LOG_INFO, 0, H_MSG_DEBUG,
        "needle size %d, idx size %d, mem idx size %d, ref size %d, lock size %d.", 
        sizeof(struct needle), sizeof(struct idx), sizeof(struct mem_idx),
        sizeof(gf_ref_t), sizeof(gf_lock_t));

    if (this->children) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_SUBVOLUME_ERROR,
            "storage/haystack cannot have subvolumes.");
        ret = -1;
        goto out;
    }

    private = GF_CALLOC(1, sizeof(*private), gf_hs_mt_hs_private);
    if (!private) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, H_MSG_NOMEM,
            "Failed to alloc haystack private.");
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
            "Failed to fetch gfid: %s.", private->base_path);
        ret = -1;
        goto out;
    } else {
        ret = sys_lsetxattr(private->base_path, "trusted.gfid", rootgfid, 16,
                             XATTR_CREATE);
        if (ret == -1) {
            gf_msg(this->name, GF_LOG_ERROR, errno, H_MSG_GFID_OPERATION_FAILED, 
                "Failed to set gfid: %s.", private->base_path);
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

    private->ctx = hs_ctx_init(this);
    if (!private->ctx) {
        gf_msg(this->name, GF_LOG_ERROR, 0, H_MSG_HS_CTX_INIT_FAILED,
            "%s: failed to setup haystack context", private->base_path);        
        ret = -1;
        goto out;
#ifdef HSDUMP
    } else {
        const char *kvar = NULL;
        struct hs *vvar = NULL;        
        kh_foreach(private->ctx->map, kvar, vvar, hs_dump(private->ctx->map, kvar, vvar));
#endif
    }

    ret = 0;

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

int
haystack_notify(xlator_t *this, int32_t event, void *data, ...)
{
    int ret = 0;

    switch (event) {
        case GF_EVENT_PARENT_UP:
            default_notify(this, GF_EVENT_CHILD_UP, data);
            break;
        case GF_EVENT_PARENT_DOWN:
            default_notify(this->parents->xlator, GF_EVENT_CHILD_DOWN, data);
            break;
        default:
            break;
    }

    return ret;
}

struct volume_options hs_options[] = {
    {.key = {"directory"},
     .type = GF_OPTION_TYPE_PATH,
     .default_value = "{{brick.path}}"},
    {.key = {"startup-crc-check"}, .type = GF_OPTION_TYPE_BOOL},
    {.key = {NULL}},
};

struct xlator_fops fops = {
    .lookup = hs_lookup,
    .mkdir = hs_mkdir,
    .opendir = hs_opendir,
    .readdir = hs_readdir,
    .readdirp = hs_readdirp,
    .stat = hs_stat
};

struct xlator_cbks cbks = {
    .releasedir = hs_releasedir,
};

xlator_api_t xlator_api = {
    .init = haystack_init,
    .fini = haystack_fini,
    .notify = haystack_notify,
    .mem_acct_init = mem_acct_init,
    .fops = &fops,
    .cbks = &cbks,
    .options = hs_options,
    .identifier = "haystack",
    .category = GF_EXPERIMENTAL,
};