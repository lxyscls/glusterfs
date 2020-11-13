#ifndef _HS_H
#define _HS_H

#include <stdint.h>
#include <uuid/uuid.h>
#include <pthread.h>
#include <dirent.h>
#include <string.h>
#include <alloca.h>

#include <glusterfs/refcount.h>
#include <glusterfs/locking.h>
#include <glusterfs/glusterfs.h>
#include <glusterfs/stack.h>
#include <glusterfs/xlator.h>
#include <glusterfs/dict.h>

#include "khash.h"

#define HSVERSION 1
#define F_DELETED (1<<0)

#define NON_T (1<<0)
#define DIR_T (1<<1)
#define REG_T (1<<2)

KHASH_MAP_INIT_STR(hs, struct hs *)
KHASH_MAP_INIT_STR(mem_idx, struct mem_idx *)
KHASH_MAP_INIT_STR(dentry, struct dentry *)

struct _lookup;
typedef struct _lookup lookup_t;

struct super {
    uint8_t version;
    uuid_t gfid;
    uint16_t epoch;
} __attribute__ ((packed));

struct needle {
    uuid_t gfid;
    uint8_t flags;
    uint32_t crc;
    uint8_t name_len;
    uint32_t size;
    char data[0]; /* name + data */
} __attribute__ ((packed));

struct idx {
    uuid_t gfid;
    uint8_t name_len;
    uint32_t size;
    uint64_t offset;
    char name[0];
} __attribute__ ((packed));

struct hs_fd {
    DIR *dir;
    off_t dir_eof;
    struct hs *hs;
    struct mem_idx *mem_idx;
};

struct _lookup {
    uint8_t type;
    struct hs *hs;
    struct mem_idx *mem_idx;
};

struct dentry {
    GF_REF_DECL;

    uuid_t gfid;
    uint8_t type;
    struct mem_idx *mem_idx;
};

struct mem_idx {
    GF_REF_DECL;

    uint8_t name_len;
    uint32_t size;
    uint64_t offset; // 0: DELETED, 1: CREATED
    char name[0];
};

struct hs {
    GF_REF_DECL;

    uuid_t gfid;
    char *path;

    pthread_rwlock_t lock;
    struct hs *parent;
    struct list_head children;
    struct list_head me;

    pthread_rwlock_t map_lock;
    khash_t(mem_idx) *map;

    pthread_rwlock_t lk_lock;
    khash_t(dentry) *lookup;

    int log_fd;
    int idx_fd;
    uint64_t pos;
};

struct hs_ctx {
    pthread_rwlock_t lock;
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
        size_t var_len = path_len + HS_BASE_PATH_LEN(this) + (path_len > 1 ? 6 : 5);            \
        var = alloca(var_len);                                                 \
        strcpy(var, HS_BASE_PATH(this));                                       \
        strcpy(&var[HS_BASE_PATH_LEN(this)], path);                            \
        if (path_len > 1)                                                      \
            strcpy(&var[HS_BASE_PATH_LEN(this)+path_len], "/.log");            \
        else                                                                   \
            strcpy(&var[HS_BASE_PATH_LEN(this)+path_len], ".log");             \
    } while (0)

#define MAKE_IDX_PATH(var, this, path)                                         \
    do {                                                                       \
        size_t path_len = strlen(path);                                        \
        size_t var_len = path_len + HS_BASE_PATH_LEN(this) + (path_len > 1 ? 6 : 5);            \
        var = alloca(var_len);                                                 \
        strcpy(var, HS_BASE_PATH(this));                                       \
        strcpy(&var[HS_BASE_PATH_LEN(this)], path);                            \
        if (path_len > 1)                                                      \
            strcpy(&var[HS_BASE_PATH_LEN(this)+path_len], "/.idx");            \
        else                                                                   \
            strcpy(&var[HS_BASE_PATH_LEN(this)+path_len], ".idx");             \
    } while (0)

#define MAKE_CHILD_PATH(var, path, child)                                      \
    do {                                                                       \
        size_t path_len = strlen(path);                                        \
        size_t var_len = path_len + strlen(child) + (path_len > 1 ? 2 : 1);    \
        var = alloca(var_len);                                                 \
        strcpy(var, path);                                                     \
        if (path_len > 1) {                                                    \
            strcpy(&var[path_len], "/");                                       \
            strcpy(&var[path_len+1], child);                                   \
        } else {                                                               \
            strcpy(&var[path_len], child);                                     \
        }                                                                      \
    } while (0)

/* helper functions */
int
hs_fd_ctx_get(fd_t *fd, xlator_t *this, struct hs_fd **hfd, int *op_errno);
lookup_t *
hs_do_lookup(xlator_t *this, struct hs *hs, uuid_t gfid, struct iatt *buf);

int32_t 
hs_lookup(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t * xdata);

int32_t
hs_opendir(call_frame_t *frame, xlator_t *this, loc_t *loc, fd_t *fd, dict_t *xdata);
int32_t
hs_releasedir(xlator_t *this, fd_t *fd);
int32_t
hs_readdir(call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size, off_t off, dict_t *xdata);
int32_t
hs_readdirp(call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size, off_t off, dict_t *dict);
int32_t
hs_releasedir(xlator_t *this, fd_t *fd);
int32_t
hs_stat(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata);

#endif