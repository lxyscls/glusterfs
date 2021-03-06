import xattr
import uuid
import sys
import os
import struct
import time
import random
import getopt
from hs_common import *
import zlib

ORPHAN = False
SLOW = False
LEVELS = 3
DIRS = 3
FILES = 100

def gen_needle(gfid):
    buf = ''
    for _ in range(1024):
        buf = buf + struct.pack('B', random.randrange(0, 255))

    crc = zlib.crc32(buf) & 0xffffffff

    ret = struct.pack(NEEDLE_FMT, gfid.bytes, 0, crc, len(gfid.hex)+1, 1024)
    ret = ret + struct.pack('32sc', gfid.hex, '\0')
    ret = ret + buf

    return ret

def gen_idx(gfid, offset):
    ret = struct.pack(IDX_FMT, gfid.bytes, len(gfid.hex)+1, 1024, offset)
    ret = ret + struct.pack('32sc', gfid.hex, '\0')

    return ret

def gen_iatt(gfid):
    t = int(time.time())

    return struct.pack(IATT_FMT, 0, 0, 0, 0, 1024, 1, 0, 0, 512, 2, 
        t, t, t, t, 0, 0, 0, 0, 0, 0, gfid.bytes, 0, 0)

def fill_super(fd, gfid):
    fd.write(struct.pack(SUPER_FMT, HSVERSION, gfid.bytes, 0))

def fill_files(parpath, gfid):
    log_fd = open(parpath + "/.log", "w+")
    fill_super(log_fd, gfid)

    if not SLOW:
        idx_fd = open(parpath + "/.idx", "w+")
        fill_super(idx_fd, gfid)

    offset = struct.calcsize(SUPER_FMT)

    for i in range(FILES):
        id = uuid.uuid4()

        needle = gen_needle(id)        
        idx = gen_idx(id, offset)        
        
        log_fd.write(needle)

        if not SLOW:
            if ORPHAN:
                if i < FILES-(FILES/3):
                    idx_fd.write(idx)
            else:
                idx_fd.write(idx)

        offset = offset + len(needle)
    
    log_fd.close()
    if not SLOW:
        idx_fd.close()

def gen_dir(parpath, path, gfid, level):
    if level > LEVELS:
        return
    
    fullpath = (parpath + "/" + path).rstrip("/")

    os.mkdir(fullpath)
    xattr.setxattr(fullpath, "trusted.gfid", gfid.bytes)
    fill_files(fullpath, gfid)

    for _ in range(DIRS):
        id = uuid.uuid4()
        gen_dir(fullpath, id.hex, id, level+1)


if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], "L:D:F:os")

    if not args:
        print "You should supply a root path!"
        sys.exit(0)

    for o, a in opts:
        if o == '-L':
            LEVELS = int(a)
        elif o == '-D':
            DIRS = int(a)
        elif o == '-F':
            FILES = int(a)
        elif o == '-o':
            ORPHAN = True
        elif o == '-s':
            SLOW = True
        else:
            assert False, "unhandled option"

    root_path = args[0]
    try:
        os.stat(root_path)
        print "You should clean the root path!"
        sys.exit(0)
    except OSError:
        pass

    gen_dir(root_path, "", ROOTGFID, 0)
