from __future__ import print_function

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    import sys
    sys.exit()

from libheap.printutils import print_value
from libheap.printutils import print_header

from libheap.ptmalloc.ptmalloc import ptmalloc

from libheap.ptmalloc.malloc_chunk import malloc_chunk
from libheap.ptmalloc.malloc_state import malloc_state

from libheap.debugger.pygdbpython import get_inferior
from libheap.debugger.pygdbpython import read_variable


class freebins(gdb.Command):
    """Walk and print the nonempty free bins."""

    def __init__(self):
        super(freebins, self).__init__("freebins", gdb.COMMAND_USER,
                                       gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        "modified from jp's phrack printing"

        ptm = ptmalloc()
        inferior = get_inferior()

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        # XXX: from old heap command, replace
        main_arena = read_variable("main_arena")
        arena_address = main_arena.address
        ar_ptr = malloc_state(arena_address, inferior=inferior)
        # 8 bytes into struct malloc_state on both 32/64bit
        fastbinsY = int(ar_ptr.address) + 8
        fb_base = fastbinsY

        # mchunkptr bins in struct malloc_state
        if ptm.SIZE_SZ == 4:
            bins_offset = 4 + 4 + 40 + 4 + 4  # 56
            sb_base = int(ar_ptr.address) + bins_offset
        elif ptm.SIZE_SZ == 8:
            bins_offset = 4 + 4 + 80 + 8 + 8  # 104
            sb_base = int(ar_ptr.address) + bins_offset

        # print_title("Heap Dump")

        for fb in range(0, ptm.NFASTBINS):
            print_once = True
            p = malloc_chunk(fb_base - (2 * ptm.SIZE_SZ) + fb * ptm.SIZE_SZ,
                             inuse=False)

            while (p.fd != 0):
                if p.fd is None:
                    break

                if print_once:
                    print_once = False
                    if fb > 0:
                        print("")
                    print_header("fast bin {}".format(fb), end="")
                    print(" @ ", end="")
                    print_value("{:#x}".format(p.fd), end="")

                print("\n\tfree chunk @ ", end="")
                print_value("{:#x} ".format(int(p.fd)))
                print("- size ", end="")
                p = malloc_chunk(p.fd, inuse=False)
                print("{:#x}".format(int(ptm.chunksize(p))), end="")

        for i in range(1, ptm.NBINS):
            print_once = True
            b = sb_base + i * 2 * ptm.SIZE_SZ - 4 * ptm.SIZE_SZ
            p = malloc_chunk(ptm.first(malloc_chunk(b, inuse=False)),
                             inuse=False)

            while p.address != int(b):
                if print_once:
                    print("")
                    print_once = False

                    if i == 1:
                        print_header("unsorted bin", end="")
                    else:
                        print_header("small bin {}".format(i))

                    print(" @ ", end="")
                    print_value("{:#x}".format(int(b) + 2 * ptm.SIZE_SZ),
                                end="")

                print("\n\tfree chunk @ ", end="")
                print_value("{:#x} ".format(int(p.address)))
                print("- size ", end="")
                print("{:#x}".format(int(ptm.chunksize(p))), end="")
                p = malloc_chunk(ptm.first(p), inuse=False)

        print("")
