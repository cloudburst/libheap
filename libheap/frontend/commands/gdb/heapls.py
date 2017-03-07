from __future__ import print_function

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    import sys
    sys.exit()

from libheap.printutils import print_title
from libheap.printutils import print_value

from libheap.ptmalloc.ptmalloc import ptmalloc

from libheap.ptmalloc.malloc_par import malloc_par
from libheap.ptmalloc.malloc_state import malloc_state
from libheap.ptmalloc.malloc_chunk import malloc_chunk

from libheap.debugger.pygdbpython import get_inferior
from libheap.debugger.pygdbpython import read_variable
from libheap.debugger.pygdbpython import get_heap_address


class heapls(gdb.Command):
    """Print a flat listing of an arena"""

    def __init__(self):
        super(heapls, self).__init__("heapls", gdb.COMMAND_USER,
                                     gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        """Inspired by jp's phrack print and arena.c"""

        ptm = ptmalloc()
        inferior = get_inferior()

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        # XXX: from old heap command, replace
        main_arena = read_variable("main_arena")
        arena_address = main_arena.address
        ar_ptr = malloc_state(arena_address, inferior=inferior)

        mp_ = read_variable("mp_")
        mp_address = mp_.address
        mp = malloc_par(mp_address)
        start, end = get_heap_address(mp)
        sbrk_base = start

        # print_title("{:>15}".format("flat heap listing"), end="\n")
        print_title("{:>15}{:>17}{:>18}".format("ADDR", "SIZE", "STATUS"),
                    end="\n")
        print("{:11}".format("sbrk_base"), end="")
        print_value("{:#x}".format(int(sbrk_base)), end="\n")

        p = malloc_chunk(sbrk_base, inuse=True, read_data=False)

        while(1):
            print("{:11}".format("chunk"), end="")
            print_value("{: <#17x}".format(int(p.address)), end="")
            print("{: <#16x}".format(int(ptm.chunksize(p))), end="")

            if p.address == ptm.top(ar_ptr):
                print("(top)")
                break
            elif p.size == (0 | ptm.PREV_INUSE):
                print("(fence)")
                break

            if ptm.inuse(p):
                print("(inuse)")
            else:
                p = malloc_chunk(p.address, inuse=False)
                print("(F) FD ", end="")
                print_value("{:#x} ".format(int(p.fd)))
                print("BK ", end="")
                print_value("{:#x} ".format(int(p.bk)))

                if ((p.fd == ar_ptr.last_remainder)
                   and (p.bk == ar_ptr.last_remainder)
                   and (ar_ptr.last_remainder != 0)):
                    print("(LR)")
                elif ((p.fd == p.bk) & ~ptm.inuse(p)):
                    print("(LC)")
                else:
                    print("")

            p = malloc_chunk(ptm.next_chunk(p), inuse=True, read_data=False)

        sbrk_end = int(sbrk_base + ar_ptr.max_system_mem)
        print("{:11}".format("sbrk_end"), end="")
        print_value("{:#x}".format(sbrk_end), end="")
        print("")
