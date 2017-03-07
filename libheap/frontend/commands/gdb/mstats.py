from __future__ import print_function

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    import sys
    sys.exit()

from libheap.ptmalloc.malloc_chunk import malloc_chunk
from libheap.ptmalloc.malloc_state import malloc_state

from libheap.debugger.pygdbpython import get_inferior
from libheap.debugger.pygdbpython import read_variable

from libheap.printutils import print_error
from libheap.printutils import print_value
from libheap.printutils import print_header

from libheap.ptmalloc.ptmalloc import ptmalloc


class mstats(gdb.Command):
    "print general malloc stats, adapted from malloc.c mSTATs()"

    def __init__(self):
        super(mstats, self).__init__("mstats", gdb.COMMAND_USER,
                                     gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        "Specify an optional arena addr: print_mstats main_arena=0x12345"

        ptm = ptmalloc()
        inferior = get_inferior()

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        try:
            # XXX: add mp_ address guessing via offset without symbols
            mp = read_variable("mp_")

            if arg.find("main_arena") == -1:
                main_arena = read_variable("main_arena")
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

        in_use_b = mp['mmapped_mem']
        system_b = in_use_b

        print("Malloc Stats", end="\n\n")

        arena = 0
        ar_ptr = malloc_state(main_arena_address, inferior=inferior)
        while(1):
            ptm.mutex_lock(ar_ptr)

            # account for top
            avail = ptm.chunksize(malloc_chunk(ptm.top(ar_ptr),
                                  inuse=True, read_data=False))
            nblocks = 1

            nfastblocks = 0
            fastavail = 0

            # traverse fastbins
            for i in range(ptm.NFASTBINS):
                p = ptm.fastbin(ar_ptr, i)
                while p != 0:
                    p = malloc_chunk(p, inuse=False)
                    nfastblocks += 1
                    fastavail += ptm.chunksize(p)
                    p = p.fd

            avail += fastavail

            # traverse regular bins
            for i in range(1, ptm.NBINS):
                b = ptm.bin_at(ar_ptr, i)
                p = malloc_chunk(ptm.first(malloc_chunk(b, inuse=False)),
                                 inuse=False)

                while p.address != int(b):
                    nblocks += 1
                    avail += ptm.chunksize(p)
                    p = malloc_chunk(ptm.first(p), inuse=False)

            print_header("Arena {}:".format(arena), end="\n")
            print("{:16} = ".format("system bytes"), end='')
            print_value("{}".format(ar_ptr.max_system_mem), end='\n')
            print("{:16} = ".format("in use bytes"), end='')
            print_value("{}".format(ar_ptr.max_system_mem - avail), end='\n')

            system_b += ar_ptr.max_system_mem
            in_use_b += (ar_ptr.max_system_mem - avail)

            ptm.mutex_unlock(ar_ptr)
            if ar_ptr.next == main_arena_address:
                break
            else:
                ar_ptr = malloc_state(ar_ptr.next, inferior=inferior)
                arena += 1

        print_header("\nTotal (including mmap):", end="\n")
        print("{:16} = ".format("system bytes"), end='')
        print_value("{}".format(system_b), end='\n')
        print("{:16} = ".format("in use bytes"), end='')
        print_value("{}".format(in_use_b), end='\n')
        print("{:16} = ".format("max system bytes"), end='')
        print_value("{}".format(mp['max_total_mem']), end='\n')
        print("{:16} = ".format("max mmap regions"), end='')
        print_value("{}".format(mp['max_n_mmaps']), end='\n')
        print("{:16} = ".format("max mmap bytes"), end='')
        print_value("{}".format(mp['max_mmapped_mem']), end='\n')
