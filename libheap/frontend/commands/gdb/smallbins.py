from __future__ import print_function

import sys
import struct

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    sys.exit()

from libheap.ptmalloc.ptmalloc import ptmalloc

from libheap.frontend.printutils import print_value
from libheap.frontend.printutils import print_title
from libheap.frontend.printutils import print_error

from libheap.ptmalloc.malloc_chunk import malloc_chunk
from libheap.ptmalloc.malloc_state import malloc_state


class smallbins(gdb.Command):
    """Walk and print the small bins."""

    def __init__(self, debugger=None, version=None):
        super(smallbins, self).__init__("smallbins", gdb.COMMAND_OBSCURE,
                                        gdb.COMPLETE_NONE)

        if debugger is not None:
            self.dbg = debugger
        else:
            print_error("Please specify a debugger")
            sys.exit()

        self.version = version

    def invoke(self, arg, from_tty):
        ptm = ptmalloc(debugger=self.dbg)

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        if ptm.SIZE_SZ == 4:
            pad_width = 27
        elif ptm.SIZE_SZ == 8:
            pad_width = 31

        # XXX: from old heap command, replace
        main_arena = self.dbg.read_variable("main_arena")
        arena_address = self.dbg.format_address(main_arena.address)
        ar_ptr = malloc_state(arena_address, debugger=self.dbg,
                              version=self.version)

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
                mem = self.dbg.read_memory(offset, 2 * ptm.SIZE_SZ)
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
            if fd == (offset - 2 * ptm.SIZE_SZ):
                print("[ {:#x} | {:#x} ] ".format(int(fd), int(bk)), end="")
            else:
                print_value("[ {:#x} | {:#x} ] ".format(int(fd), int(bk)))

            while (1):
                if fd == (offset - 2 * ptm.SIZE_SZ):
                    break

                chunk = malloc_chunk(fd, inuse=False, debugger=self.dbg)
                print("")
                print_value("{:>{width}}{:#x} | {:#x} ] ".format("[ ",
                            int(chunk.fd), int(chunk.bk), width=pad_width))
                print("({})".format(int(ptm.chunksize(chunk))), end="")
                fd = chunk.fd

            if sb_num is not None:  # only print one smallbin
                break

        print("")
