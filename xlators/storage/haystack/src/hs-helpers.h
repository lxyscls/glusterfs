#ifndef _HS_HELPERS_H
#define _HS_HELPERS_H

#include "hs.h"

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

#endif