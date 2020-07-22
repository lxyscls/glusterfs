#ifndef _HS_H
#define _HS_H

#include <stdint.h>
#include <dirent.h>
#include <pthread.h>
#include <alloca.h>
#include <string.h>

#include <glusterfs/dict.h>
#include <glusterfs/refcount.h>
#include <glusterfs/compat.h>
#include <glusterfs/iatt.h>
#include <glusterfs/locking.h>
#include <glusterfs/list.h>
#include <glusterfs/glusterfs.h>
#include <glusterfs/xlator.h>
#include <glusterfs/stack.h>

#include "khash.h"

#define HSVERSION 1
#define DELETED (1<<0)

KHASH_MAP_INIT_STR(hs, struct hs *)
KHASH_MAP_INIT_STR(mem_idx, struct mem_idx *)

struct super {
    uint8_t version;
    uuid_t gfid;
    uint16_t epoch;
} __attribute__ ((packed));

struct needle {
    uuid_t gfid;
    struct iatt buf;
    uint8_t flags;
    uint32_t crc;
    uint8_t name_len;
    uint32_t size;
    char data[0]; /* name + data */
} __attribute__ ((packed));

struct idx {
    uuid_t gfid;
    struct iatt buf;
    uint8_t name_len;
    uint32_t size;
    uint64_t offset;
    char name[0];
} __attribute__ ((packed));

struct mem_idx {
    GF_REF_DECL;

    gf_lock_t lock;
    struct iatt buf;
    uint8_t name_len;
    uint32_t size;
    uint64_t offset; // 0: DELETED, 1: CREATED
    char name[0];
};

struct hs {
    GF_REF_DECL;
    gf_lock_t lock;

    uuid_t gfid;
    char *path;

    struct hs *parent;
    struct list_head children;
    struct list_head me;

    pthread_rwlock_t rwlock;
    khash_t(mem_idx) *map;

    int log_fd;
    int idx_fd;
    uint64_t log_offset; // only used when startup.
};

struct hs_ctx {
    gf_lock_t lock;
    khash_t(hs) *map;

    struct hs *root;
};

struct hs_private {
    char *base_path;
    int32_t base_path_length;
    gf_boolean_t startup_crc_check;

    /* lock for brick dir */
    DIR *mount_lock;

    struct hs_ctx *ctx;
};

#define HS_BASE_PATH(this)                                                     \
    (((struct hs_private *)this->private)->base_path)

#define HS_BASE_PATH_LEN(this)                                                 \
    (((struct hs_private *)this->private)->base_path_length)

#define MAKE_REAL_PATH(var, this, path)                                        \
    do {                                                                       \
        size_t var_len = strlen(path) + HS_BASE_PATH_LEN(this) + 1;            \
        var = alloca(var_len);                                                 \
        strcpy(var, HS_BASE_PATH(this));                                       \
        strcpy(&var[HS_BASE_PATH_LEN(this)], path);                            \
    } while (0)

#define MAKE_LOG_PATH(var, this, path)                                         \
    do {                                                                       \
        size_t path_len = strlen(path);                                        \
        size_t var_len = path_len + HS_BASE_PATH_LEN(this) + 5 + 1;            \
        var = alloca(var_len);                                                 \
        strcpy(var, HS_BASE_PATH(this));                                       \
        strcpy(&var[HS_BASE_PATH_LEN(this)], path);                            \
        strcpy(&var[HS_BASE_PATH_LEN(this)+path_len], "/.log");                \
    } while (0)

#define MAKE_IDX_PATH(var, this, path)                                         \
    do {                                                                       \
        size_t path_len = strlen(path);                                        \
        size_t var_len = path_len + HS_BASE_PATH_LEN(this) + 5 + 1;            \
        var = alloca(var_len);                                                 \
        strcpy(var, HS_BASE_PATH(this));                                       \
        strcpy(&var[HS_BASE_PATH_LEN(this)], path);                            \
        strcpy(&var[HS_BASE_PATH_LEN(this)+path_len], "/.idx");                \
    } while (0)

#define MAKE_CHILD_PATH(var, path, child)                                      \
    do {                                                                       \
        size_t path_len = strlen(path);                                        \
        size_t var_len = path_len + strlen(child) + 1 + 1;                     \
        var = alloca(var_len);                                                 \
        strcpy(var, path);                                                     \
        strcpy(&var[path_len], "/");                                           \
        strcpy(&var[path_len+1], child);                                       \
    } while (0)               

struct hs_ctx *hs_ctx_init(xlator_t *this);
void hs_ctx_free(struct hs_ctx *ctx);
void hs_dump(khash_t(hs) *map, char *k, struct hs *v);
struct hs *hs_init(xlator_t *this, const char *rpath, struct hs *parent);

#endif