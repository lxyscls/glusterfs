#include <dirent.h>
#include <sys/types.h>
#include <uuid/uuid.h>

#include <glusterfs/mem-pool.h>
#include <glusterfs/dict.h>
#include <glusterfs/refcount.h>
#include <glusterfs/syscall.h>

#include "hs.h"
#include "hs-mem-types.h"

static void 
hs_free(void *to_free) {
    struct hs *hs = (struct hs *)to_free;

    if (!hs) {
        return;
    }

    GF_FREE(hs->gfid);
    GF_FREE(hs->real_path);
    GF_FREE(hs);
}

struct hs *
hs_init(const char *rpath, struct hs *parent) {
    struct hs *hs = NULL;
    uuid_t gfid = {
        0,
    };
    ssize_t size = -1;

    hs = (void *)GF_CALLOC(1, sizeof(struct hs), gf_hs_mt_hs);
    if (!hs) {
        return NULL;
    } else {
        GF_REF_INIT(hs, hs_free);
    }

    size = sys_lgetxattr(rpath, "trusted.gfid", gfid, sizeof(gfid));
    if (size != sizeof(gfid)) {
        GF_REF_PUT(hs);
        return NULL;
    }

    hs->gfid = gf_strdup(uuid_utoa(gfid));
    hs->real_path = gf_strdup(rpath);
    hs->parent = parent;

    return hs;
}

static struct hs *
hs_scan(const char *rpath, struct hs *parent, struct hs_ctx *ctx) {
    struct hs *hs = NULL;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    struct dirent scratch[2] = {
        {
            0,
        },
    };
    char *child_path = NULL;
    struct stat stbuf = {
        0,
    };
    int ret = 0;
    data_t *data = NULL;

    hs = hs_init(rpath, parent);
    if (!hs) {
        return NULL;
    }

    dir = sys_opendir(rpath);
    if (!dir) {
        GF_REF_PUT(hs);
        return NULL;
    }

    while ((entry=sys_readdir(dir, scratch)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
            continue;
        }

        child_path = GF_MALLOC(strlen(rpath)+1+strlen(entry->d_name)+1, gf_common_mt_char);
        if (child_path) {
            sprintf(child_path, "%s/%s", rpath, entry->d_name);
            ret = sys_lstat(child_path, &stbuf);
            if (!ret && S_ISDIR(stbuf.st_mode)) {
                hs_scan(child_path, hs, ctx);
            }
            GF_FREE(child_path);
        }
    }
    sys_closedir(dir);

    data = bin_to_data(hs, sizeof(*hs));
    if (!data) {
        GF_REF_PUT(hs);
        return NULL;
    }

    ret = dict_setn(ctx->hs_dict, hs->gfid, GF_UUID_BUF_SIZE-1, data);
    if (ret) {
        GF_REF_PUT(hs);
        return NULL;
    }

    return hs;
}

int
hs_print(dict_t *d, char *k, data_t *v, void *_unused) {
    struct hs *hs = (struct hs *)v->data;

    if (hs) {
        printf("%s : %s\n", hs->gfid, hs->real_path);
    }

    return 0;
}

static int
hs_purge(dict_t *d, char *k, data_t *v, void *_unused) {
    struct hs *hs = (struct hs *)v->data;

    if (hs) {
        GF_REF_PUT(hs);
    }

    return 0;
}

void
hs_ctx_free(struct hs_ctx *ctx) {
    if (!ctx) {
        return;
    }

    dict_foreach(ctx->hs_dict, hs_purge, NULL);
    GF_FREE(ctx);
}

struct hs_ctx *
hs_ctx_init(const char *rpath) {
    struct hs_ctx *ctx = NULL;

    ctx = (void *)GF_CALLOC(1, sizeof(struct hs_ctx), gf_hs_mt_hs_ctx);
    if (!ctx) {
        return NULL;
    }

    ctx->hs_dict = dict_new();
    if (!ctx->hs_dict) {
        GF_FREE(ctx);
        return NULL;
    }

    ctx->root = hs_scan(rpath, NULL, ctx);
    if (!ctx->root) {
        dict_unref(ctx->hs_dict);
        GF_FREE(ctx);
        return NULL;
    }

    return ctx;
}