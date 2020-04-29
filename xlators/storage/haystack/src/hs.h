#ifndef _HS_H
#define _HS_H

#include <sys/types.h>
#include <dirent.h>

struct hs_private {
    char *base_path;
    int32_t base_path_length;

    /* lock for brick dir */
    DIR *mount_lock;    
};

#endif