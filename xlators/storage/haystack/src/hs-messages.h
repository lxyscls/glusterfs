#ifndef _HS_MESSAGES_H
#define _HS_MESSAGES_H

#include <glusterfs/glfs-message-id.h>

GLFS_MSGID(HAYSTACK, H_MSG_DEBUG, H_MSG_SUBVOLUME_ERROR, H_MSG_NOMEM, H_MSG_EXPORT_DIR_MISSING, 
        H_MSG_DIR_OPERATION_FAILED, H_MSG_GFID_OPERATION_FAILED, 
        H_MSG_HS_CTX_INIT_FAILED, H_MSG_HS_SCAN_FAILED, H_MSG_HS_BUILD_FAILED, H_MSG_HS_INIT_FAILED, H_MSG_HS_ADD_FAILED, H_MSG_HS_DUP, H_MSG_HS_MISSING,
        H_MSG_MEM_IDX_MAP_INIT_FAILED, H_MSG_MEM_IDX_INIT_FAILED, H_MSG_MEM_IDX_ADD_FAILED, H_MSG_MEM_IDX_UPDATE,
        H_MSG_DENTRY_MAP_INIT_FAILED, H_MSG_DENTRY_INIT_FAILED, H_MSG_DENTRY_ADD_FAILED, H_MSG_DENTRY_UPDATE, H_MSG_DENTRY_DUP, H_MSG_DENTRY_MISSING, H_MSG_DENTRY_DEL,
        H_MSG_IDX_INIT_FAILED,
        H_MSG_OPEN_FAILED, H_MSG_LSTAT_FAILED, H_MSG_STAT_FAILED, H_MSG_READ_FAILED, H_MSG_WRITE_FAILED, H_MSG_CREATE_FAILED,
        H_MSG_BROKEN_FILE, H_MSG_BROKEN_IDX, H_MSG_BROKEN_NEEDLE,
        H_MSG_INVALID_GFID);

#endif