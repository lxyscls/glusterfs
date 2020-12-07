import os
import getopt
import sys
import struct
import uuid
from hs_common import *

def dump_needle(dir, noff):
    if noff:
        with open(dir + "/.log", 'r') as f:
            assert f.read(struct.calcsize(SUPER_FMT))
            
            f.seek(noff)
            needle = f.read(struct.calcsize(NEEDLE_FMT) + 33 + 1024)
            assert needle

            gfid = struct.unpack_from('16c', needle)
            print(uuid.UUID(bytes=gfid))
    else:
        with open(dir + "/.log", 'r') as f:
            assert f.read(struct.calcsize(SUPER_FMT))
            while True:
                needle = f.read(struct.calcsize(NEEDLE_FMT) + 33 + 1024)
                if not needle:
                    break

                gfid = struct.unpack_from('16c', needle)
                print(uuid.UUID(bytes=gfid))


def dump_idx(dir, ioff):
    if ioff:
        with open(dir + "/.idx", 'r') as f:
            assert f.read(struct.calcsize(SUPER_FMT))

            f.seek(ioff)
            idx = f.read(struct.calcsize(IDX_FMT) + 33)
            assert idx

            gfid = struct.unpack_from('16c', idx)
            print(uuid.UUID(bytes=gfid))
    else:
        with open(dir + "/.idx", 'r') as f:
            assert f.read(struct.calcsize(SUPER_FMT))
            while True:
                idx = f.read(struct.calcsize(IDX_FMT) + 33)
                if not idx:
                    break

                gfid = struct.unpack_from('16c', idx)
                print(uuid.UUID(bytes=gfid))
                

def dump(dir, needle, idx, noff, ioff):
    if needle:
        dump_needle(dir, noff)
    if idx:
        dump_idx(dir, ioff)

if __name__ == '__main__':
    noff, ioff = 0, 0
    needle, idx = True, False

    opts, args = getopt.getopt(sys.argv[1:], "niO:o:")

    if not args:
        print "You should supply a path!"
        sys.exit(0)

    for o, a in opts:
        if o == '-n':
           NEEDLE = True 
        elif o == '-i':
            IDX = True
        elif o == '-O':
            noff = int(a)
        elif o == '-o':
            ioff = int(a)
        else:
            assert False, "unhandled option"

    dump(args[0], needle, idx, noff, ioff)