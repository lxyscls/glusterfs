/*
   Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef __POSIX_MEM_TYPES_H__
#define __POSIX_MEM_TYPES_H__

#include <glusterfs/mem-types.h>

enum gf_hs_mem_types_ {
    gf_hs_mt_hs_private = gf_common_mt_end + 1,
    gf_hs_mt_hs_ctx,
    gf_hs_mt_hs,
    gf_hs_mt_end
};
#endif
