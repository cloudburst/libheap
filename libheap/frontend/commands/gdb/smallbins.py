from __future__ import print_function

import struct

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    import sys
    sys.exit()

from libheap.printutils import print_value
from libheap.printutils import print_title
from libheap.printutils import print_error

from libheap.ptmalloc.ptmalloc import ptmalloc

from libheap.ptmalloc.malloc_chunk import malloc_chunk
from libheap.ptmalloc.malloc_state import malloc_state

from libheap.debugger.pygdbpython import get_inferior


class smallbins(gdb.Command):
    """Walk and print the small bins."""

    def __init__(self):
        super(smallbins, self).__init__("smallbins", gdb.COMMAND_USER,
                                        gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        ptm = ptmalloc()
        inferior = get_inferior()

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        if ptm.SIZE_SZ == 4:
            pad_width = 33
        elif ptm.SIZE_SZ == 8:
            pad_width = 31

        # XXX: from old heap command, replace
        main_arena = gdb.selected_frame().read_var('main_arena')
        arena_address = main_arena.address
        ar_ptr = malloc_state(arena_address, inferior=inferior)

        # mchunkptr bins in struct malloc_state
        if ptm.SIZE_SZ == 4:
            bins_offset = 4 + 4 + 40 + 4 + 4  # 56
            sb_base = int(ar_ptr.address) + bins_offset
        elif ptm.SIZE_SZ == 8:
            bins_offset = 4 + 4 + 80 + 8 + 8  # 104
            sb_base = int(ar_ptr.address) + bins_offset

        if len(arg) == 0:
            sb_num = None
        else:
            sb_num = int(arg.split(" ")[0])

            if (sb_num * 2) > ptm.NBINS:
                print_error("Invalid smallbin number")
                return

        print_title("smallbins", end="")

        for sb in range(2, ptm.NBINS + 2, 2):
            if sb_num is not None and sb_num != 0:
                sb = sb_num*2

            offset = sb_base + (sb - 2) * ptm.SIZE_SZ
            try:
                mem = inferior.read_memory(offset, 2 * ptm.SIZE_SZ)
                if ptm.SIZE_SZ == 4:
                    fd, bk = struct.unpack("<II", mem)
                elif ptm.SIZE_SZ == 8:
                    fd, bk = struct.unpack("<QQ", mem)
            except RuntimeError:
                print_error("Invalid smallbin addr {0:#x}".format(offset))
                return

            print("")
            print("[ sb {:02} ] ".format(int(sb / 2)), end="")
            print("{:#x}{:>{width}}".format(int(offset), "-> ", width=5),
                  end="")
            print_value("[ {:#x} | {:#x} ] ".format(int(fd), int(bk)))

            while (1):
                if fd == (offset - 2 * ptm.SIZE_SZ):
                    break

                chunk = malloc_chunk(fd, inuse=False)
                print("")
                print_value("{:>{width}}{:#x} | {:#x} ] ".format("[ ",
                            int(chunk.fd), int(chunk.bk), width=pad_width))
                print("({})".format(int(ptm.chunksize(chunk))), end="")
                fd = chunk.fd

            if sb_num is not None:  # only print one smallbin
                break

        print("")
