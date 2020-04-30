#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <glusterfs/syscall.h>
#include <glusterfs/list.h>
#include <glusterfs/mem-types.h>
#include <glusterfs/compat-uuid.h>
#include <glusterfs/mem-pool.h>

#include <glusterfs/common-utils.h>

#include "hs.h"
#include "hs-mem-types.h"

struct hs *hs_scan(char *path, struct hs *parent, struct hs_ctx *ctx) {
    struct hs *hs = NULL, *child = NULL;
    uuid_t gfid = {
        0,
    };
    ssize_t size = -1;
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

    hs = (void *)GF_CALLOC(1, sizeof(struct hs), gf_hs_mt_hs);
    if (!hs) {
        return NULL;
    }

    INIT_LIST_HEAD(&hs->list);
    INIT_LIST_HEAD(&hs->children);
    INIT_LIST_HEAD(&hs->hash);

    size = sys_lgetxattr(path, "trusted.gfid", gfid, sizeof(gfid));
    if (size != sizeof(gfid)) {
        GF_FREE(hs);
        return NULL;
    }

    gf_uuid_copy(hs->gfid, gfid);
    hs->real_path = gf_strdup(path);
    hs->parent = parent;    

    dir = sys_opendir(path);
    if (!dir) {
        free(hs->real_path);
        GF_FREE(hs);
        return NULL;
    }

    while ((entry=sys_readdir(dir, scratch)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
            continue;
        }

        child_path = GF_MALLOC(strlen(path)+1+strlen(entry->d_name)+1, gf_common_mt_char);
        if (child_path) {
            sprintf(child_path, "%s/%s", path, entry->d_name);
            ret = sys_lstat(child_path, &stbuf);
            if (!ret && S_ISDIR(stbuf.st_mode)) {
                child = hs_scan(child_path, hs, ctx);
                if (child) {
                    list_add(&child->list, &hs->children);                    
                }
            }
            GF_FREE(child_path);
        }
    }
    sys_closedir(dir);

    list_add(&hs->hash, &ctx->hs_hash[((gfid[15] + (gfid[14] << 8)) % ctx->hashsize)]);

    return hs;
}

struct hs_ctx *hs_ctx_init(char *path) {
    int i = 0;
    struct hs_ctx *ctx = NULL;

    ctx = (void *)GF_CALLOC(1, sizeof(struct hs_ctx), gf_hs_mt_hs_ctx);
    if (!ctx) {
        return NULL;
    }

    ctx->hashsize = 128;
    ctx->hs_hash = (void *)GF_CALLOC(ctx->hashsize, sizeof(struct list_head), gf_common_mt_list_head);
    if (!ctx->hs_hash) {
        GF_FREE(ctx);
        return NULL;
    }

    for (i = 0; i < ctx->hashsize; i++) {
        INIT_LIST_HEAD(&ctx->hs_hash[i]);
    }

    ctx->root = hs_scan(path, NULL, ctx);
    if (!ctx->root) {
        GF_FREE(ctx->hs_hash);
        GF_FREE(ctx);
        return NULL;
    }

    return ctx;
}

int main(int argc, char *argv[]) {
    struct hs_ctx *ctx = hs_ctx_init(argv[1]);
    struct hs *hs = NULL;
    struct hs *child = NULL;
    int i = 0;

    if (!ctx) {
        return -1;
    }

    for (i = 0; i < ctx->hashsize; i++) {
        list_for_each_entry(hs, &ctx->hs_hash[i], hash) {
            printf("%s : %s\n", hs->real_path, uuid_utoa(hs->gfid));
            list_for_each_entry(child, &hs->children, list) {
                printf("\t%s : %s\n", child->real_path, uuid_utoa(child->gfid));
            }
        }
    }

    return 0;
}