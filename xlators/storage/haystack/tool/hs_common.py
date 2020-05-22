import uuid

'''
struct iatt {
    uint64_t ia_flags;
    uint64_t ia_ino;     /* inode number */
    uint64_t ia_dev;     /* backing device ID */
    uint64_t ia_rdev;    /* device ID (if special file) */
    uint64_t ia_size;    /* file size in bytes */
    uint32_t ia_nlink;   /* Link count */
    uint32_t ia_uid;     /* user ID of owner */
    uint32_t ia_gid;     /* group ID of owner */
    uint32_t ia_blksize; /* blocksize for filesystem I/O */
    uint64_t ia_blocks;  /* number of 512B blocks allocated */
    int64_t ia_atime;    /* last access time */
    int64_t ia_mtime;    /* last modification time */
    int64_t ia_ctime;    /* last status change time */
    int64_t ia_btime;    /* creation time. Fill using statx */
    uint32_t ia_atime_nsec;
    uint32_t ia_mtime_nsec;
    uint32_t ia_ctime_nsec;
    uint32_t ia_btime_nsec;
    uint64_t ia_attributes;      /* chattr related:compressed, immutable,
                                  * append only, encrypted etc.*/
    uint64_t ia_attributes_mask; /* Mask for the attributes */

    uuid_t ia_gfid;
    ia_type_t ia_type; /* type of file */
    ia_prot_t ia_prot; /* protection */
};
'''
IATT_FMT = "=5Q4IQ4q4I2Q16sii"

'''
struct hs_super {
    int version;
    uuid_t gfid;
} __attribute__ ((packed));
'''
SUPER_FMT = "=i16s"

'''
struct hs_needle {
    uuid_t gfid;
    struct iatt buf;
    uint8_t flags;
    uint8_t name_len;
    uint32_t size;
    char data[0]; /* name + data */
} __attribute__ ((packed));
'''
NEEDLE_FMT_1 = "=16s"
NEEDLE_FMT_2 = "=2BI"

'''
struct hs_idx {
    uuid_t gfid;
    struct iatt buf;
    uint8_t name_len;
    uint32_t size;
    uint64_t offset;
    char name[0];
} __attribute__ ((packed));
'''
IDX_FMT_1 = "=16s"
IDX_FMT_2 = "=BIQ"

ROOTGFID = uuid.UUID("00000000-0000-0000-0000-000000000001")
LEVELS = 3
DIRS = 3
FILES = 100
HSVERSION = 0x00000001
