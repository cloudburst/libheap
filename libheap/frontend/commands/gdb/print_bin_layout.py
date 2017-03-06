from __future__ import print_function

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    import sys
    sys.exit()

from libheap.ptmalloc.malloc_chunk import malloc_chunk
from libheap.ptmalloc.malloc_state import malloc_state

from libheap.printutils import color_value
from libheap.printutils import print_error
from libheap.printutils import print_value

from libheap.ptmalloc.ptmalloc import ptmalloc


class print_bin_layout(gdb.Command):
    "dump the layout of a free bin"

    def __init__(self):
        super(print_bin_layout, self).__init__("print_bin_layout",
                                               gdb.COMMAND_USER,
                                               gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        "Specify an optional arena addr: print_bin_layout main_arena=0x12345"

        ptm = ptmalloc()

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        if len(arg) == 0:
            print_error("Please specify the free bin to dump")
            return

        try:
            if arg.find("main_arena") == -1:
                main_arena = gdb.selected_frame().read_var('main_arena')
                main_arena_address = main_arena.address
            else:
                arg = arg.split()
                for item in arg:
                    if item.find("main_arena") != -1:
                        if len(item) < 12:
                            print_error("Malformed main_arena parameter")
                            return
                        else:
                            main_arena_address = int(item[11:], 16)
        except RuntimeError:
            print_error("No frame is currently selected.")
            return
        except ValueError:
            print_error("Debug glibc was not found.")
            return

        if main_arena_address == 0:
            print_error("Invalid main_arena address (0)")
            return

        ar_ptr = malloc_state(main_arena_address)
        ptm.mutex_lock(ar_ptr)

        # print_title("Bin Layout")

        if int(arg) == 0:
            print_error("bin_at(0) does not exist")
            return

        b = ptm.bin_at(ar_ptr, int(arg))
        p = malloc_chunk(ptm.first(malloc_chunk(b, inuse=False)), inuse=False)
        print_once = True
        print_str = ""
        count = 0

        while p.address != int(b):
            if print_once:
                print_once = False
                print_str += "-->  "
                print_str += color_value("[bin {}]".format(int(arg)))
                count += 1

            print_str += "  <-->  "
            print_str += color_value("{:#x}".format(int(p.address)))
            count += 1
            p = malloc_chunk(ptm.first(p), inuse=False)

        if len(print_str) != 0:
            print_str += "  <--"
            print(print_str)
            print("|{}|".format(" " * (len(print_str) - 2 - count*12)))
            print("{}".format("-" * (len(print_str) - count*12)))
        else:
            print_value("Bin {} ".format(int(arg)), end="")
            print("empty")

        ptm.mutex_unlock(ar_ptr)
