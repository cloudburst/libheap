from __future__ import print_function

import sys

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    sys.exit()

import struct
from functools import wraps

import libheap.ptmalloc.ptmalloc as ptmalloc

from libheap.ptmalloc.malloc_par import malloc_par
from libheap.ptmalloc.malloc_chunk import malloc_chunk
from libheap.ptmalloc.malloc_state import malloc_state

from libheap.debugger.pygdbpython import get_inferior

from libheap.printutils import print_error
from libheap.printutils import print_title
from libheap.printutils import print_header
from libheap.printutils import print_value

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
            print_header("{:<14}".format("-a 0x1234"))
            print("Specify an arena address")
            print_header("{:<14}".format("-b"))
            print("Print compact bin listing (only free chunks)")
            print_header("{:<14}".format("-c"))
            print("Print compact arena listing (all chunks)")
            print_header("{:<14}".format("-l"))
            print("Print a flat listing of all chunks in an arena")
            print_header("{:<14}".format("-s [#]"))
            print("Print all small bins, or only a single small bin")
            print_header("{:<14}".format("fastbins [#]"))
            print("Print all fast bins, or only a single fast bin")
            print_header("{:<14}".format("mstats"), end="")
            print("Print memory alloc statistics similar to malloc_stats(3)")
            # print_header("{:<22}".format("print_bin_layout [#]"), end="")
            # print("Print the layout of a particular free bin")
            return

        a_found = s_found = p_sb = p_b = p_l = p_c = 0
        for item in arg.split():
            if a_found == 1:
                arena_address = int(item, 16)
                a_found = 0
                continue
            if s_found == 1:
                s_found = 0
                try:
                    sb_number = int(item)
                except:
                    pass
                continue
            if item.find("-a") != -1:
                a_found = 1
                arena_address = 0
            if item.find("s") != -1:
                s_found = 1
                sb_number = None
                p_sb = 1
            if item.find("b") != -1:
                p_b = 1
            if item.find("l") != -1:
                p_l = 1
            if item.find("c") != -1:
                p_c = 1

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

        try:
            fb_base = ar_ptr.address.cast(gdb.lookup_type("unsigned long")) + 8
        except:
            fb_base = ar_ptr.address + 8

        if ptm.SIZE_SZ == 4:
            try:
                sb_base = ar_ptr.address.cast(gdb.lookup_type(
                    "unsigned long"))+56
            except:
                sb_base = ar_ptr.address + 56
        elif ptm.SIZE_SZ == 8:
            try:
                sb_base = ar_ptr.address.cast(
                    gdb.lookup_type("unsigned long")) + 104
            except:
                sb_base = ar_ptr.address + 104

        try:
            mp_ = gdb.selected_frame().read_var('mp_')
            mp_address = mp_.address
        except RuntimeError:
            print_error("No gdb frame is currently selected.")
            return
        except ValueError:
            try:
                res = gdb.execute('x/x &mp_', to_string=True)
                mp_address = int(res.strip().split()[0], 16)
            except gdb.error:
                print_error("Debug glibc could not be found.")
                print_error("Guessing mp_ address via offset from main_arena.")

                if ptm.SIZE_SZ == 4:
                    try:
                        mp_address = ar_ptr.address.cast(
                            gdb.lookup_type("unsigned long")) + 0x460
                    except:
                        mp_address = ar_ptr.address + 0x460
                elif ptm.SIZE_SZ == 8:  # offset 0x880 untested on 64bit
                    try:
                        mp_address = ar_ptr.address.cast(
                            gdb.lookup_type("unsigned long")) + 0x880
                    except:
                        mp_address = ar_ptr.address + 0x460

        sbrk_base = malloc_par(mp_address).sbrk_base

        if p_sb:
            print_smallbins(inferior, sb_base, sb_number)
            print("")
        if p_b:
            print_bins(inferior, fb_base, sb_base)
            print("")
        if p_l:
            print_flat_listing(ar_ptr, sbrk_base)
            print("")
        if p_c:
            print_compact_listing(ar_ptr, sbrk_base)
            print("")


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
def print_fastbins(inferior, fb_base, fb_num):
    "walk and print the fast bins"

    if ptm.SIZE_SZ == 0:
        ptm.set_globals()

    print_title("fastbins", end="")

    if ptm.SIZE_SZ == 4:
        pad_width = 32
    elif ptm.SIZE_SZ == 8:
        pad_width = 29

    for fb in range(0, ptm.NFASTBINS):
        if fb_num is not None:
            fb = fb_num

        offset = int(fb_base + fb * ptm.SIZE_SZ)
        try:
            mem = inferior.read_memory(offset, ptm.SIZE_SZ)
            if ptm.SIZE_SZ == 4:
                fd = struct.unpack("<I", mem)[0]
            elif ptm.SIZE_SZ == 8:
                fd = struct.unpack("<Q", mem)[0]
        except RuntimeError:
            print_error("Invalid fastbin addr {0:#x}".format(offset))
            return

        print("")
        print("[ fb {} ] ".format(fb), end="")
        print("{:#x}{:>{width}}".format(offset, "-> ", width=5), end="")
        if fd == 0:
            print("[ {:#x} ] ".format(fd), end="")
        else:
            print_value("[ {:#x} ] ".format(fd))

        if fd != 0:  # fastbin is not empty
            fb_size = ((ptm.MIN_CHUNK_SIZE) + (ptm.MALLOC_ALIGNMENT) * fb)
            print("({})".format(int(fb_size)), end="")

            chunk = malloc_chunk(fd, inuse=False)
            while chunk.fd != 0:
                if chunk.fd is None:
                    # could not read memory section
                    break

                print_value("\n{:>{width}} {:#x} {} ".format("[", chunk.fd,
                                                             "]",
                                                             width=pad_width))
                print("({})".format(fb_size), end="")

                chunk = malloc_chunk(chunk.fd, inuse=False)

        if fb_num is not None:  # only print one fastbin
            return


###############################################################################
def print_smallbins(inferior, sb_base, sb_num):
    "walk and print the small bins"

    if ptm.SIZE_SZ == 0:
        ptm.set_globals()

    print_title("smallbins", end="")

    if ptm.SIZE_SZ == 4:
        pad_width = 33
    elif ptm.SIZE_SZ == 8:
        pad_width = 31

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
        print("{:#x}{:>{width}}".format(int(offset), "-> ", width=5), end="")
        print_value("[ {:#x} | {:#x} ] ".format(int(fd), int(bk)))

        while (1):
            if fd == (offset - 2 * ptm.SIZE_SZ):
                break

            chunk = malloc_chunk(fd, inuse=False)
            print("")
            print_value("{:>{width}}{:#x} | {:#x} ] ".format(
                        "[ ", int(chunk.fd), int(chunk.bk), width=pad_width))
            print("({})".format(int(ptm.chunksize(chunk))), end="")
            fd = chunk.fd

        if sb_num is not None:  # only print one smallbin
            return


###############################################################################
def print_bins(inferior, fb_base, sb_base):
    "walk and print the nonempty free bins, modified from jp"

    if ptm.SIZE_SZ == 0:
        ptm.set_globals()

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
        p = malloc_chunk(ptm.first(malloc_chunk(b, inuse=False)), inuse=False)

        while p.address != int(b):
            if print_once:
                print("")
                print_once = False
                if i == 1:
                    try:
                        print_header("unsorted bin", end="")
                        print(" @ ", end="")
                        cast_val = b.cast(gdb.lookup_type("unsigned long"))
                        print_value("{:#x}".format(int(cast_val + 2
                                    * ptm.SIZE_SZ)), end="")
                    except:
                        print_header("unsorted bin", end="")
                        print(" @ ", end="")
                        print_value("{:#x}".format(int(b + 2
                                    * ptm.SIZE_SZ)), end="")
                else:
                    try:
                        print_header("small bin {}".format(i))
                        print(" @ ", end="")
                        cast_val = b.cast(gdb.lookup_type("unsigned long"))
                        print_value("{:#x}".format(int(cast_val + 2
                                    * ptm.SIZE_SZ)), end="")
                    except:
                        print_header("small bin {}".format(i))
                        print(" @ ", end="")
                        print_value("{:#x}".format(int(b + 2
                                    * ptm.SIZE_SZ)), end="")

            print("\n\tfree chunk @ ", end="")
            print_value("{:#x} ".format(int(p.address)))
            print("- size ", end="")
            print("{:#x}".format(int(ptm.chunksize(p))), end="")
            p = malloc_chunk(ptm.first(p), inuse=False)


###############################################################################
def print_flat_listing(ar_ptr, sbrk_base):
    "print a flat listing of an arena, modified from jp and arena.c"

    if ptm.SIZE_SZ == 0:
        ptm.set_globals()

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


###############################################################################
def print_compact_listing(ar_ptr, sbrk_base):
    "print a compact layout of the heap, modified from jp"

    if ptm.SIZE_SZ == 0:
        ptm.set_globals()

    print_title("compact dump")
    p = malloc_chunk(sbrk_base, inuse=True, read_data=False)

    while(1):
        if p.address == ptm.top(ar_ptr):
            print("|T|", end="")
            break

        if ptm.inuse(p):
            print("|A|", end="")
        else:
            p = malloc_chunk(p.address, inuse=False)

            if ((p.fd == ar_ptr.last_remainder)
               and (p.bk == ar_ptr.last_remainder)
               and (ar_ptr.last_remainder != 0)):
                print("|L|", end="")
            else:
                print("|%d|" % ptm.bin_index(p.size), end="")

        p = malloc_chunk(ptm.next_chunk(p), inuse=True, read_data=False)


# Register GDB Commands
heap()
frontend_gdb()

# Register GDB Pretty Printers
gdb.pretty_printers.append(pretty_print_heap_lookup)
