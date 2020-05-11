#include <sys/stat.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <attr/xattr.h>
#include <errno.h>

#include <glusterfs/xlator.h>
#include <glusterfs/mem-pool.h>
#include <glusterfs/syscall.h>

#include "hs.h"
#include "hs-mem-types.h"
#include "hs-messages.h"

int
haystack_init(xlator_t *this) {
    int ret = 0;
    struct stat buf;
    uuid_t gfid;
    ssize_t size = -1;
    struct hs_private *private = NULL;
    static uuid_t rootgfid = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    if (this->children) {
        ret = -1;
        goto out;
    }

    private = GF_CALLOC(1, sizeof(*private), gf_hs_mt_hs_private);
    if (!private) {
        ret = -1;
        goto out;
    }

    ret = dict_get_str(this->options, "directory", &private->base_path);
    if (ret < 0) {
        goto out;
    }
    private->base_path_length = strlen(private->base_path);

    ret = sys_stat(private->base_path, &buf);
    if ((ret != 0) || !S_ISDIR(buf.st_mode)) {
        ret = -1;
        goto out;
    }

    size = sys_lgetxattr(private->base_path, "trusted.gfid", gfid, sizeof(gfid));
    if (size == 16) {
        if (!__is_root_gfid(gfid)) {
            ret = -1;
            goto out;
        }
    } else if (size != -1) {
        ret = -1;
        goto out;
    } else if ((size == -1) && (errno != ENODATA) && (errno != ENOATTR)) {
        ret = -1;
        goto out;
    } else {
        size = sys_lsetxattr(private->base_path, "trusted.gfid", rootgfid, 16,
                             XATTR_CREATE);
        if (size == -1) {
            ret = -1;
            goto out;
        }
    }

    umask(000);
    
    private->mount_lock = sys_opendir(private->base_path);
    if (!private->mount_lock) {
        ret = -1;
        goto out;
    }

    private->ctx = hs_ctx_init(private->base_path);
    if (!private->ctx) {
        ret = -1;
        goto out;
    }

    this->private = private;

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

struct volume_options hs_options[] = {
    {.key = {"directory"},
     .type = GF_OPTION_TYPE_PATH,
     .default_value = "{{brick.path}}"},
     {.key = {NULL}},
};

xlator_api_t xlator_api = {
    .init = haystack_init,
    .fini = haystack_fini,
    .options = hs_options,
};