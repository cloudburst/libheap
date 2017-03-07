from __future__ import print_function

import sys

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    sys.exit()

from functools import wraps

import libheap.ptmalloc.ptmalloc as ptmalloc

from libheap.ptmalloc.malloc_state import malloc_state

from libheap.debugger.pygdbpython import get_inferior

from libheap.printutils import print_error
from libheap.printutils import print_header

from libheap.prettyprinters import pretty_print_heap_lookup

from libheap.frontend.frontend_gdb import frontend_gdb

##############################################################################
# Temp ptmalloc compat layer
##############################################################################
ptm = ptmalloc.ptmalloc()


def has_inferior(f):
    "decorator to make sure we have an inferior to operate on"

    @wraps(f)
    def with_inferior(*args, **kwargs):
        inferior = get_inferior()
        if inferior != -1:
            if (inferior.pid != 0) and (inferior.pid is not None):
                return f(*args, **kwargs)
            else:
                print_error("No debugee could be found.  \
                            Attach or start a program.")
                sys.exit()
        else:
            sys.exit()
    return with_inferior


###############################################################################
# GDB COMMANDS
###############################################################################

class heap(gdb.Command):
    "print a comprehensive view of the heap"

    def __init__(self):
        super(heap, self).__init__("heap", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    @has_inferior
    def invoke(self, arg, from_tty):
        "Usage can be obtained via heap -h"

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        inferior = get_inferior()

        if arg.find("-h") != -1:
            # print_title("libheap help")
            print_header("\"heap\" ", end="")
            print("Options:", end="\n\n")
            print_header("{:<15}".format("-a 0x1234"))
            print("Specify an arena address")
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

        a_found = 0
        for item in arg.split():
            if a_found == 1:
                arena_address = int(item, 16)
                a_found = 0
                continue
            if item.find("-a") != -1:
                a_found = 1
                arena_address = 0

        if arg.find("-a") == -1:
            try:
                main_arena = gdb.selected_frame().read_var('main_arena')
                arena_address = main_arena.address
            except RuntimeError:
                print_error("No gdb frame is currently selected.")
                return
            except ValueError:
                try:
                    res = gdb.execute('x/x &main_arena', to_string=True)
                    arena_address = int(res.strip().split()[0], 16)
                except gdb.error:
                    print_error("Debug glibc was not found.")
                    print_error("Guessing main_arena address via offset \
                                from libc.")

                    # find heap by offset from end of libc in /proc
                    libc_end, heap_begin = read_proc_maps(inferior.pid)

                    if ptm.SIZE_SZ == 4:
                        # __malloc_initialize_hook + 0x20
                        # offset seems to be +0x380 on debug glibc,
                        # +0x3a0 otherwise
                        arena_address = libc_end + 0x3a0
                    elif ptm.SIZE_SZ == 8:
                        # offset seems to be +0xe80 on debug glibc,
                        # +0xea0 otherwise
                        arena_address = libc_end + 0xea0

                    if libc_end == -1:
                        print_error("Invalid address read via /proc")
                        return

        if arena_address == 0:
            print_error("Invalid arena address (0)")
            return

        ar_ptr = malloc_state(arena_address, inferior=inferior)

        if len(arg) == 0:
            if ar_ptr.next == 0:
                print_error("No arenas could be correctly guessed.")
                print_error("Nothing was found at {0:#x} or struct \
                            malloc_state has changed size".format(
                            ar_ptr.address))
                return

            # print_title("Heap Dump")
            print("Arena(s) found:", end="\n")

            try:
                # arena address obtained via read_var
                arena_type = gdb.lookup_type("unsigned long")
                arena_print = int(ar_ptr.address.cast(arena_type))
                print("  arena @ ", end="")
                print_header("{:#x}".format(arena_print), end="\n")
            except:
                # arena address obtained via -a
                print_header("\t arena @ {:#x}".format(
                             int(ar_ptr.address)), end="\n")

            if ar_ptr.address != ar_ptr.next:
                # we have more than one arena

                curr_arena = malloc_state(ar_ptr.next, inferior=inferior)
                while (ar_ptr.address != curr_arena.address):
                    print("\t arena @ {:#x}".format(
                          int(curr_arena.address)))
                    curr_arena = malloc_state(curr_arena.next,
                                              inferior=inferior)

                    if curr_arena.address == 0:
                        print_error("No arenas could be correctly found.")
                        break  # breaking infinite loop

            return


############################################################################
def read_proc_maps(pid):
    '''
    Locate the stack of a process using /proc/pid/maps.
    Will not work on hardened machines (grsec).
    '''

    filename = '/proc/%d/maps' % pid

    try:
        fd = open(filename)
    except IOError:
        print_error("Unable to open {0}".format(filename))
        return -1, -1

    libc_begin = libc_end = heap_begin = heap_end = 0
    for line in fd:
        if line.find("libc-") != -1:
            fields = line.split()

            libc_begin, libc_end = fields[0].split('-')
            libc_begin = int(libc_begin, 16)
            libc_end = int(libc_end, 16)
        elif line.find("heap") != -1:
            fields = line.split()

            heap_begin, heap_end = fields[0].split('-')
            heap_begin = int(heap_begin, 16)
            heap_end = int(heap_end, 16)

    fd.close()

    if libc_begin == 0 or libc_end == 0:
        print_error("Unable to read libc address information via /proc")
        return -1, -1

    if heap_begin == 0 or heap_end == 0:
        print_error("Unable to read heap address information via /proc")
        return -1, -1

    return libc_end, heap_begin

###############################################################################

# Register GDB Commands
heap()
frontend_gdb()

# Register GDB Pretty Printers
gdb.pretty_printers.append(pretty_print_heap_lookup)
