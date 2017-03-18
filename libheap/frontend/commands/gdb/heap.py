from __future__ import print_function

import sys

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    sys.exit()

from libheap.frontend.printutils import print_header
from libheap.frontend.printutils import print_error

from libheap.ptmalloc.ptmalloc import ptmalloc

from libheap.ptmalloc.malloc_state import malloc_state


class heap(gdb.Command):
    """libheap command help listing"""

    def __init__(self, debugger=None, version=None):
        super(heap, self).__init__("heap", gdb.COMMAND_OBSCURE,
                                   gdb.COMPLETE_NONE)

        if debugger is not None:
            self.dbg = debugger
        else:
            print_error("Please specify a debugger")
            sys.exit()

        self.version = version

    def invoke(self, arg, from_tty):
        # XXX: self.dbg.string_to_argv
        if arg.find("-h") != -1:
            # print_header("heap ", end="")
            # print("Options:", end="\n\n")
            # print_header("{:<15}".format("-a 0x1234"))
            # print("Specify an arena address")
            print_header("{:<15}".format("heapls"))
            print("Print a flat listing of all chunks in an arena")
            print_header("{:<15}".format("fastbins [#]"))
            print("Print all fast bins, or only a single fast bin")
            print_header("{:<15}".format("smallbins [#]"))
            print("Print all small bins, or only a single small bin")
            print_header("{:<15}".format("freebins"))
            print("Print compact bin listing (only free chunks)")
            print_header("{:<15}".format("heaplsc"))
            print("Print compact arena listing (all chunks)")
            print_header("{:<15}".format("mstats"), end="")
            print("Print memory alloc statistics similar to malloc_stats(3)")
            # print_header("{:<22}".format("print_bin_layout [#]"), end="")
            # print("Print the layout of a particular free bin")
            return

        ptm = ptmalloc(self.dbg)

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        # XXX: from old heap command, replace
        main_arena = self.dbg.read_variable("main_arena")
        # XXX: add arena address guessing via offset without symbols
        arena_address = self.dbg.format_address(main_arena.address)
        ar_ptr = malloc_state(arena_address, debugger=self.dbg,
                              version=self.version)

        # XXX: add arena address passing via arg (-a)
        if (len(arg) == 0) and (ar_ptr.next == 0):
            # struct malloc_state may be invalid size (wrong glibc version)
            print_error("No arenas could be found at {:#x}".format(
                        ar_ptr.address))
            return

        print("Arena(s) found:", end="\n")
        print("  arena @ ", end="")
        print_header("{:#x}".format(int(ar_ptr.address)), end="\n")

        if ar_ptr.address != ar_ptr.next:
            # we have more than one arena

            curr_arena = malloc_state(ar_ptr.next, debugger=self.dbg,
                                      version=self.version)

            while (ar_ptr.address != curr_arena.address):
                print("  arena @ ", end="")
                print_header("{:#x}".format(int(curr_arena.address)), end="\n")
                curr_arena = malloc_state(curr_arena.next, debugger=self.dbg,
                                          version=self.version)

                if curr_arena.address == 0:
                    print_error("No arenas could be correctly found.")
                    break  # breaking infinite loop
