from __future__ import print_function

import sys

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    sys.exit()

from libheap.frontend.printutils import print_title
from libheap.frontend.printutils import print_value
from libheap.frontend.printutils import print_error

from libheap.ptmalloc.ptmalloc import ptmalloc

from libheap.ptmalloc.malloc_par import malloc_par
from libheap.ptmalloc.malloc_state import malloc_state
from libheap.ptmalloc.malloc_chunk import malloc_chunk


class heapls(gdb.Command):
    """Print a flat listing of an arena"""

    def __init__(self, debugger=None, version=None):
        super(heapls, self).__init__("heapls", gdb.COMMAND_OBSCURE,
                                     gdb.COMPLETE_NONE)

        if debugger is not None:
            self.dbg = debugger
        else:
            print_error("Please specify a debugger")
            sys.exit()

        self.version = version

    def invoke(self, arg, from_tty):
        """Inspired by jp's phrack print and arena.c"""

        ptm = ptmalloc(debugger=self.dbg)

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        # XXX: from old heap command, replace
        main_arena = self.dbg.read_variable("main_arena")
        arena_address = self.dbg.format_address(main_arena.address)
        ar_ptr = malloc_state(arena_address, debugger=self.dbg,
                              version=self.version)

        # XXX: add mp_ address guessing via offset without symbols
        mp_ = self.dbg.read_variable("mp_")
        mp_address = mp_.address
        mp = malloc_par(mp_address, debugger=self.dbg, version=self.version)
        start, end = self.dbg.get_heap_address(mp)
        sbrk_base = start

        # print_title("{:>15}".format("flat heap listing"), end="\n")
        print_title("{:>15}{:>17}{:>18}".format("ADDR", "SIZE", "STATUS"),
                    end="\n")
        print("{:11}".format("sbrk_base"), end="")
        print_value("{:#x}".format(int(sbrk_base)), end="\n")

        p = malloc_chunk(sbrk_base, inuse=True, read_data=False,
                         debugger=self.dbg)

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
                p = malloc_chunk(p.address, inuse=False, debugger=self.dbg)
                print("(F) FD ", end="")
                print_value("{:#x} ".format(int(p.fd)))
                print("BK ", end="")
                print_value("{:#x} ".format(int(p.bk)))

                if ((p.fd == ar_ptr.last_remainder) and
                   (p.bk == ar_ptr.last_remainder) and
                   (ar_ptr.last_remainder != 0)):
                    print("(LR)")
                elif ((p.fd == p.bk) & ~ptm.inuse(p)):
                    print("(LC)")
                else:
                    print("")

            p = malloc_chunk(ptm.next_chunk(p), inuse=True, read_data=False,
                             debugger=self.dbg)

        sbrk_end = int(sbrk_base + ar_ptr.max_system_mem)
        print("{:11}".format("sbrk_end"), end="")
        print_value("{:#x}".format(sbrk_end), end="")
        print("")
