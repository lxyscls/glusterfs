#ifndef _HS_H
#define _HS_H

#include <stdint.h>
#include <dirent.h>

#include <glusterfs/glusterfs.h>
#include <glusterfs/dict.h>
#include <glusterfs/refcount.h>
#include <glusterfs/compat.h>
#include <glusterfs/iatt.h>

struct hs_ctx {
    dict_t *hs_dict;

    struct hs *root;
};

struct hs {
    GF_REF_DECL;

    char *gfid;
    char *real_path;
    struct hs *parent;

    dict_t *mem;
    int logfd;
    int idxfd;
};

struct hs_needle {
    int header;
    char gfid[GF_UUID_BUF_SIZE];
    char name[NAME_MAX+1];
    struct iatt buf;
    uint32_t size;
    char *data;
    int footer;
};

struct hs_idx {
    char gfid[GF_UUID_BUF_SIZE];
    uint64_t offset;
    uint32_t size;
};

struct hs_mem_idx {
    uint64_t offset;
    uint32_t size;
};

struct hs_private {
    char *base_path;
    int32_t base_path_length;

    /* lock for brick dir */
    DIR *mount_lock;

    struct hs_ctx *ctx;
};

struct hs_ctx *hs_ctx_init(const char *rpath);
void hs_ctx_free(struct hs_ctx *ctx);
struct hs *hs_init(const char *rpath, struct hs *parent);

#endif