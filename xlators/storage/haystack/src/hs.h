#ifndef _HS_H
#define _HS_H

#include <stdint.h>
#include <dirent.h>

#include <glusterfs/dict.h>
#include <glusterfs/refcount.h>
#include <glusterfs/compat.h>
#include <glusterfs/iatt.h>
#include <glusterfs/locking.h>

#define HSVERSION 0x00000001
#define DELETED (1<<0)

struct hs_ctx {
    dict_t *hs_dict;

    struct hs *root;
};

struct hs {
    GF_REF_DECL;

    uuid_t gfid;
    char *real_path;
    struct hs *parent;

    dict_t *mem;

    int log_fd;
    int idx_fd;
    uint64_t log_offset; // only used when startup.
};

struct hs_super {
    int version;
    uuid_t gfid;
} __attribute__ ((packed));

struct hs_needle {
    uuid_t gfid;
    struct iatt buf;
    uint8_t flags;
    uint8_t name_len;
    uint32_t size;
    char data[0]; /* name + data */
} __attribute__ ((packed));

struct hs_idx {
    uuid_t gfid;
    struct iatt buf;
    uint8_t name_len;
    uint32_t size;
    uint64_t offset;
    char name[0];
} __attribute__ ((packed));

struct hs_mem_idx {
    GF_REF_DECL;

    gf_lock_t lock;
    struct iatt buf;
    uint8_t name_len;
    uint32_t size;
    uint64_t offset; // 0: DELETED, 1: CREATED
    char name[0];
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
int hs_print(dict_t *d, char *k, data_t *v, void *_unused);
struct hs *hs_init(const char *rpath, struct hs *parent);

#endif