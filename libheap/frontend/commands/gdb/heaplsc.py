from __future__ import print_function

import sys

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    sys.exit()

from libheap.ptmalloc.ptmalloc import ptmalloc

from libheap.frontend.printutils import print_title
from libheap.frontend.printutils import print_error

from libheap.ptmalloc.malloc_par import malloc_par
from libheap.ptmalloc.malloc_state import malloc_state
from libheap.ptmalloc.malloc_chunk import malloc_chunk


class heaplsc(gdb.Command):
    """Print compact arena layout (all chunks)"""

    def __init__(self, debugger=None, version=None):
        super(heaplsc, self).__init__("heaplsc", gdb.COMMAND_OBSCURE,
                                      gdb.COMPLETE_NONE)

        if debugger is not None:
            self.dbg = debugger
        else:
            print_error("Please specify a debugger")
            sys.exit()

        self.version = version

    def invoke(self, arg, from_tty):
        """Inspired by jp's phrack print"""

        ptm = ptmalloc(debugger=self.dbg)

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        # XXX: from old heap command, replace
        main_arena = self.dbg.read_variable("main_arena")
        arena_addr = self.dbg.format_address(main_arena.address)
        ar_ptr = malloc_state(arena_addr, debugger=self.dbg,
                              version=self.version)

        # XXX: add mp_ address guessing via offset without symbols
        mp_ = self.dbg.read_variable("mp_")
        mp_address = mp_.address
        mp = malloc_par(mp_address, debugger=self.dbg, version=self.version)
        start, end = self.dbg.get_heap_address(mp)
        sbrk_base = start

        print_title("compact arena layout")
        p = malloc_chunk(sbrk_base, inuse=True, read_data=False,
                         debugger=self.dbg)

        while(1):
            if p.address == ptm.top(ar_ptr):
                print("|T|", end="")
                break

            if ptm.inuse(p):
                print("|A|", end="")
            else:
                p = malloc_chunk(p.address, inuse=False, debugger=self.dbg)

                if ((p.fd == ar_ptr.last_remainder) and
                   (p.bk == ar_ptr.last_remainder) and
                   (ar_ptr.last_remainder != 0)):
                    print("|L|", end="")
                else:
                    print("|%d|" % ptm.bin_index(p.size), end="")

            p = malloc_chunk(ptm.next_chunk(p), inuse=True, read_data=False,
                             debugger=self.dbg)

        print("")
