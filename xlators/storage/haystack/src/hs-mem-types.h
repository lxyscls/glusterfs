#ifndef __HS_MEM_TYPES_H__
#define __HS_MEM_TYPES_H__

#include <glusterfs/mem-types.h>

enum gf_hs_mem_types_ {
    gf_hs_mt_hs_private = gf_common_mt_end + 1,
    gf_hs_mt_hs_ctx,
    gf_hs_mt_hs,
    gf_hs_mt_idx,
    gf_hs_mt_mem_idx,
    gf_hs_mt_needle,
    gf_hs_mt_dentry,
    gf_hs_mt_hs_fd,
    gf_hs_mt_lookup_t,
    gf_hs_mt_end
};
#endif
