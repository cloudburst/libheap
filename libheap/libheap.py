from __future__ import print_function

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    exit()

import sys
import struct
from functools import wraps

from libheap.ptmalloc.malloc_state import malloc_state
from libheap.ptmalloc.malloc_par import malloc_par
from libheap.ptmalloc.malloc_chunk import malloc_chunk
from libheap.debugger.pygdbpython import get_inferior, get_arch, get_size_sz

from libheap.printutils import print_error, print_title, print_header
from libheap.prettyprinters import malloc_par_printer
from libheap.prettyprinters import malloc_state_printer
from libheap.prettyprinters import malloc_chunk_printer
from libheap.prettyprinters import heap_info_printer

################################################################################
# MALLOC CONSTANTS AND MACROS
################################################################################

SIZE_SZ           = get_size_sz()
MIN_CHUNK_SIZE    = 4 * SIZE_SZ
MALLOC_ALIGNMENT  = 2 * SIZE_SZ
MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1
MINSIZE           = (MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK

def chunk2mem(p):
    "conversion from malloc header to user pointer"
    return (p.address + (2*SIZE_SZ))

def mem2chunk(mem):
    "conversion from user pointer to malloc header"
    return (mem - (2*SIZE_SZ))

def request2size(req):
    "pad request bytes into a usable size"

    if (req + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE):
        return MINSIZE
    else:
        return (int(req + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

PREV_INUSE     = 1
IS_MMAPPED     = 2
NON_MAIN_ARENA = 4
SIZE_BITS      = (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)

def prev_inuse(p):
    "extract inuse bit of previous chunk"
    return (p.size & PREV_INUSE)

def chunk_is_mmapped(p):
    "check for mmap()'ed chunk"
    return (p.size & IS_MMAPPED)

def chunk_non_main_arena(p):
    "check for chunk from non-main arena"
    return (p.size & NON_MAIN_ARENA)

def chunksize(p):
    "Get size, ignoring use bits"
    return (p.size & ~SIZE_BITS)

def next_chunk(p):
    "Ptr to next physical malloc_chunk."
    return (p.address + (p.size & ~SIZE_BITS))

def prev_chunk(p):
    "Ptr to previous physical malloc_chunk"
    return (p.address - p.prev_size)

def chunk_at_offset(p, s):
    "Treat space at ptr + offset as a chunk"
    return malloc_chunk(p.address + s, inuse=False)

def inuse(p):
    "extract p's inuse bit"
    return (malloc_chunk(p.address + \
            (p.size & ~SIZE_BITS), inuse=False).size & PREV_INUSE)

def set_inuse(p):
    "set chunk as being inuse without otherwise disturbing"
    chunk = malloc_chunk((p.address + (p.size & ~SIZE_BITS)), inuse=False)
    chunk.size |= PREV_INUSE
    chunk.write()

def clear_inuse(p):
    "clear chunk as being inuse without otherwise disturbing"
    chunk = malloc_chunk((p.address + (p.size & ~SIZE_BITS)), inuse=False)
    chunk.size &= ~PREV_INUSE
    chunk.write()

def inuse_bit_at_offset(p, s):
    "check inuse bits in known places"
    return (malloc_chunk((p.address + s), inuse=False).size & PREV_INUSE)

def set_inuse_bit_at_offset(p, s):
    "set inuse bits in known places"
    chunk = malloc_chunk((p.address + s), inuse=False)
    chunk.size |= PREV_INUSE
    chunk.write()

def clear_inuse_bit_at_offset(p, s):
    "clear inuse bits in known places"
    chunk = malloc_chunk((p.address + s), inuse=False)
    chunk.size &= ~PREV_INUSE
    chunk.write()

def bin_at(m, i):
    "addressing -- note that bin_at(0) does not exist"
    if SIZE_SZ == 4:
        offsetof_fd = 0x8
        cast_type = 'unsigned int'
    elif SIZE_SZ == 8:
        offsetof_fd = 0x10
        cast_type = 'unsigned long'

    return int(gdb.parse_and_eval("&((struct malloc_state *) 0x%x).bins[%d]" % \
            (int(m.address), int((i -1) * 2))).cast(gdb.lookup_type(cast_type)) \
            - offsetof_fd)

def next_bin(b):
    return (b + 1)

def first(b):
    return b.fd

def last(b):
    return b.bk

NBINS          = 128
NSMALLBINS     = 64
SMALLBIN_WIDTH = MALLOC_ALIGNMENT
MIN_LARGE_SIZE = (NSMALLBINS * SMALLBIN_WIDTH)

def in_smallbin_range(sz):
    "check if size is in smallbin range"
    return (sz < MIN_LARGE_SIZE)

def smallbin_index(sz):
    "return the smallbin index"

    if SMALLBIN_WIDTH == 16:
        return (sz >> 4)
    else:
        return (sz >> 3)

def largebin_index_32(sz):
    "return the 32bit largebin index"

    if (sz >> 6) <= 38:
        return (56 + (sz >> 6))
    elif (sz >> 9) <= 20:
        return (91 + (sz >> 9))
    elif (sz >> 12) <= 10:
        return (110 + (sz >> 12))
    elif (sz >> 15) <= 4:
        return (119 + (sz >> 15))
    elif (sz >> 18) <= 2:
        return (124 + (sz >> 18))
    else:
        return 126

def largebin_index_64(sz):
    "return the 64bit largebin index"

    if (sz >> 6) <= 48:
        return (48 + (sz >> 6))
    elif (sz >> 9) <= 20:
        return (91 + (sz >> 9))
    elif (sz >> 12) <= 10:
        return (110 + (sz >> 12))
    elif (sz >> 15) <= 4:
        return (119 + (sz >> 15))
    elif (sz >> 18) <= 2:
        return (124 + (sz >> 18))
    else:
        return 126

def largebin_index(sz):
    "return the largebin index"

    if SIZE_SZ == 8:
        return largebin_index_64(sz)
    else:
        return largebin_index_32(sz)

def bin_index(sz):
    "return the bin index"

    if in_smallbin_range(sz):
        return smallbin_index(sz)
    else:
        return largebin_index(sz)

BINMAPSHIFT = 5
BITSPERMAP  = 1 << BINMAPSHIFT
BINMAPSIZE  = (NBINS / BITSPERMAP)

def fastbin(ar_ptr, idx):
    return ar_ptr.fastbinsY[idx]

def fastbin_index(sz):
    "offset 2 to use otherwise unindexable first 2 bins"
    if SIZE_SZ == 8:
        return ((sz >> 4) - 2)
    else:
        return ((sz >> 3) - 2)

MAX_FAST_SIZE = (80 * SIZE_SZ / 4)
NFASTBINS     = (fastbin_index(request2size(MAX_FAST_SIZE)) + 1)

FASTCHUNKS_BIT = 0x1

def have_fastchunks(M):
    return ((M.flags & FASTCHUNKS_BIT) == 0)

def clear_fastchunks(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags |= FASTCHUNKS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

def set_fastchunks(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags &= ~FASTCHUNKS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

NONCONTIGUOUS_BIT = 0x2

def contiguous(M):
    return ((M.flags & NONCONTIGUOUS_BIT) == 0)

def noncontiguous(M):
    return ((M.flags & NONCONTIGUOUS_BIT) != 0)

def set_noncontiguous(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags |= NONCONTIGUOUS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

def set_contiguous(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags &= ~NONCONTIGUOUS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

def get_max_fast():
    return gdb.parse_and_eval("global_max_fast")

def mutex_lock(ar_ptr, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    ar_ptr.mutex = 1
    try:
        inferior.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))
    except gdb.MemoryError:
        pass

def mutex_unlock(ar_ptr, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    ar_ptr.mutex = 0
    try:
        inferior.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))
    except gdb.MemoryError:
        pass

def has_inferior(f):
    "decorator to make sure we have an inferior to operate on"

    @wraps(f)
    def with_inferior(*args, **kwargs):
        inferior = get_inferior()
        if inferior != -1:
            if (inferior.pid != 0) and (inferior.pid is not None):
                return f(*args, **kwargs)
            else:
                print_error("No debugee could be found.  Attach or start a program.")
                exit()
        else:
            exit()
    return with_inferior

def retrieve_sizesz():
    "Retrieve the SIZE_SZ after binary loading finished, this allows import within .gdbinit"
    global SIZE_SZ, MIN_CHUNK_SIZE, MALLOC_ALIGNMENT, MALLOC_ALIGN_MASK, MINSIZE, SMALLBIN_WIDTH, MIN_LARGE_SIZE, MAX_FAST_SIZE, NFASTBINS

    try:
        _machine = get_arch()[0]
    except IndexError:
        raise Exception("Retrieving the SIZE_SZ failed.")

    if "elf64" in _machine:
        SIZE_SZ = 8
    elif "elf32" in _machine:
        SIZE_SZ = 4
    else:
        raise Exception("Retrieving the SIZE_SZ failed.")

    MIN_CHUNK_SIZE    = 4 * SIZE_SZ
    MALLOC_ALIGNMENT  = 2 * SIZE_SZ
    MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1
    MINSIZE           = (MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK

    SMALLBIN_WIDTH = MALLOC_ALIGNMENT
    MIN_LARGE_SIZE = (NSMALLBINS * SMALLBIN_WIDTH)

    MAX_FAST_SIZE = (80 * SIZE_SZ / 4)
    NFASTBINS     = (fastbin_index(request2size(MAX_FAST_SIZE)) + 1)


################################################################################
# ARENA CONSTANTS AND MACROS
################################################################################

HEAP_MIN_SIZE     = 32 * 1024
HEAP_MAX_SIZE     = 1024 * 1024

def top(ar_ptr):
    return ar_ptr.top

def heap_for_ptr(ptr):
    "find the heap and corresponding arena for a given ptr"
    return (ptr & ~(HEAP_MAX_SIZE-1))


################################################################################
# GDB COMMANDS
################################################################################

class print_malloc_stats(gdb.Command):
    "print general malloc stats, adapted from malloc.c mSTATs()"

    def __init__(self):
        super(print_malloc_stats, self).__init__("print_mstats",
                                        gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        "Specify an optional arena addr: print_mstats main_arena=0x12345"

        if SIZE_SZ == 0:
            retrieve_sizesz()

        try:
            mp         = gdb.selected_frame().read_var('mp_')

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
                            main_arena_address = int(item[11:],16)
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

        print_title("Malloc Stats")

        arena = 0
        ar_ptr = malloc_state(main_arena_address)
        while(1):
            mutex_lock(ar_ptr)

            # account for top
            avail = chunksize(malloc_chunk(top(ar_ptr), inuse=True, \
                    read_data=False))
            nblocks = 1

            nfastblocks = 0
            fastavail = 0

            # traverse fastbins
            for i in range(NFASTBINS):
                p = fastbin(ar_ptr, i)
                while p!=0:
                    p = malloc_chunk(p, inuse=False)
                    nfastblocks += 1
                    fastavail += chunksize(p)
                    p = p.fd

            avail += fastavail

            # traverse regular bins
            for i in range(1, NBINS):
                b = bin_at(ar_ptr, i)
                p = malloc_chunk(first(malloc_chunk(b,inuse=False)),inuse=False)

                while p.address != int(b):
                    nblocks += 1
                    avail += chunksize(p)
                    p = malloc_chunk(first(p), inuse=False)

            print_header("Arena {}:\n".format(arena))
            print("{:16} = ".format("system bytes"), end='')
            print_value("{}".format(ar_ptr.max_system_mem), end='\n')
            print("{:16} = ".format("in use bytes"), end='')
            print_value("{}".format(ar_ptr.max_system_mem - avail), end='\n')

            system_b += ar_ptr.max_system_mem
            in_use_b += (ar_ptr.max_system_mem - avail)

            mutex_unlock(ar_ptr)
            if ar_ptr.next == main_arena_address:
                break
            else:
                ar_ptr = malloc_state(ar_ptr.next)
                arena += 1

        print_header("Total (including mmap):\n")
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


###############################################################################
class heap(gdb.Command):
    "print a comprehensive view of the heap"

    def __init__(self):
        super(heap, self).__init__("heap", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    @has_inferior
    def invoke(self, arg, from_tty):
        "Usage can be obtained via heap -h"

        if SIZE_SZ == 0:
            retrieve_sizesz()

        inferior = get_inferior()

        if arg.find("-h") != -1:
            print_title("Heap Dump Help")
            print("")
            print_header("Options:")
            print("\n")
            print_header("{:<12}".format("-a 0x1234"))
            print("Specify an arena address")
            print_header("{:<12}".format("-b"))
            print("Print compact bin listing (only free chunks)")
            print_header("{:<12}".format("-c"))
            print("Print compact arena listing (all chunks)")
            print_header("{:<12}".format("-l"))
            print("Print a flat listing of all chunks in an arena")
            print_header("{:<12}".format("-f [#]"))
            print("Print all fast bins, or only a single fast bin")
            print_header("{:<12}".format("-s [#]"))
            print("Print all small bins, or only a single small bin")
            return

        a_found = f_found = s_found = p_fb = p_sb = p_b = p_l = p_c = 0
        for item in arg.split():
            if a_found == 1:
                arena_address = int(item,16)
                a_found = 0
                continue
            if f_found == 1:
                f_found = 0
                try:
                    fb_number = int(item)
                except:
                    pass
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
            if item.find("f") != -1:
                f_found = 1
                fb_number = None
                p_fb = 1
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
                    print_error("Guessing main_arena address via offset from libc.")

                    #find heap by offset from end of libc in /proc
                    libc_end,heap_begin = read_proc_maps(inferior.pid)

                    if SIZE_SZ == 4:
                        #__malloc_initialize_hook + 0x20
                        #offset seems to be +0x380 on debug glibc,
                        #+0x3a0 otherwise
                        arena_address = libc_end + 0x3a0
                    elif SIZE_SZ == 8:
                        #offset seems to be +0xe80 on debug glibc,
                        #+0xea0 otherwise
                        arena_address = libc_end + 0xea0

                    if libc_end == -1:
                        print_error("Invalid address read via /proc")
                        return

        if arena_address == 0:
            print_error("Invalid arena address (0)")
            return

        ar_ptr = malloc_state(arena_address)

        if len(arg) == 0:
            if ar_ptr.next == 0:
                print_error("No arenas could be correctly guessed.")
                print_error("Nothing was found at {0:#x} or struct malloc_state has changed size".format(ar_ptr.address))
                return

            print_title("Heap Dump")
            print_header("\nArena(s) found:\n")

            try: 
                #arena address obtained via read_var
                print("\t arena @ {:#x}".format(
                        int(ar_ptr.address.cast(gdb.lookup_type("unsigned long")))))
            except: 
                #arena address obtained via -a
                print("\t arena @ {:#x}".format(int(ar_ptr.address)))

            if ar_ptr.address != ar_ptr.next:
                #we have more than one arena

                curr_arena = malloc_state(ar_ptr.next)
                while (ar_ptr.address != curr_arena.address):
                    print("\t arena @ {:#x}".format(int(curr_arena.address)))
                    curr_arena = malloc_state(curr_arena.next)

                    if curr_arena.address == 0:
                        print_error("No arenas could be correctly found.")
                        break #breaking infinite loop

            print("")
            return

        try:
            fb_base = ar_ptr.address.cast(gdb.lookup_type("unsigned long")) + 8
        except:
            fb_base = ar_ptr.address + 8
        if SIZE_SZ == 4:
            try:
                sb_base=ar_ptr.address.cast(gdb.lookup_type("unsigned long"))+56
            except:
                sb_base = ar_ptr.address + 56
        elif SIZE_SZ == 8:
            try:
                sb_base = ar_ptr.address.cast(gdb.lookup_type("unsigned long"))\
                        + 104
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

                if SIZE_SZ == 4:
                    try:
                        mp_address = ar_ptr.address.cast(
                            gdb.lookup_type("unsigned long")) + 0x460
                    except:
                        mp_address = ar_ptr.address + 0x460
                elif SIZE_SZ == 8: #offset 0x880 untested on 64bit
                    try:
                        mp_address = ar_ptr.address.cast(
                            gdb.lookup_type("unsigned long")) + 0x880
                    except:
                        mp_address = ar_ptr.address + 0x460

        sbrk_base = malloc_par(mp_address).sbrk_base

        if p_fb:
            print_fastbins(inferior, fb_base, fb_number)
            print("")
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
        return -1,-1

    found = libc_begin = libc_end = heap_begin = heap_end = 0
    for line in fd:
        if line.find("libc-") != -1:
            fields = line.split()

            libc_begin,libc_end = fields[0].split('-')
            libc_begin = int(libc_begin,16)
            libc_end = int(libc_end,16)
        elif line.find("heap") != -1:
            fields = line.split()

            heap_begin,heap_end= fields[0].split('-')
            heap_begin = int(heap_begin,16)
            heap_end = int(heap_end,16)

    fd.close()

    if libc_begin==0 or libc_end==0:
        print_error("Unable to read libc address information via /proc")
        return -1,-1

    if heap_begin==0 or heap_end==0:
        print_error("Unable to read heap address information via /proc")
        return -1,-1

    return libc_end,heap_begin


################################################################################
def print_fastbins(inferior, fb_base, fb_num):
    "walk and print the fast bins"

    print_title("Fastbins")

    pad_width = 32

    for fb in range(0,NFASTBINS):
        if fb_num != None:
            fb = fb_num

        offset = fb_base + fb*SIZE_SZ
        try:
            mem = inferior.read_memory(offset, SIZE_SZ)
            if SIZE_SZ == 4:
                fd = struct.unpack("<I", mem)[0]
            elif SIZE_SZ == 8:
                fd = struct.unpack("<Q", mem)[0]
        except RuntimeError:
            print_error("Invalid fastbin addr {0:#x}".format(offset))
            return

        print("")
        print_header("[ fb {} ] ".format(fb))
        print("{:#x}{:>{width}}".format(int(offset), "-> ", width=5), end="")
        print_value("[ {:#x} ] ".format(int(fd)))

        if fd != 0: #fastbin is not empty
            fb_size = ((MIN_CHUNK_SIZE) +(MALLOC_ALIGNMENT)*fb)
            print("({})".format(int(fb_size)))

            chunk = malloc_chunk(fd, inuse=False)
            while chunk.fd != 0:
                if chunk.fd is None:
                    # could not read memory section
                    break

                print_value("{:>{width}}{:#x}{}".format("[ ", int(chunk.fd), " ] ", width=pad_width))
                print("({})".format(int(fb_size)), end="")

                chunk = malloc_chunk(chunk.fd, inuse=False)

        if fb_num != None: #only print one fastbin
            return


################################################################################
def print_smallbins(inferior, sb_base, sb_num):
    "walk and print the small bins"

    print_title("Smallbins")

    pad_width = 33

    for sb in range(2,NBINS+2,2):
        if sb_num != None and sb_num!=0:
            sb = sb_num*2

        offset = sb_base + (sb-2)*SIZE_SZ
        try:
            mem = inferior.read_memory(offset, 2*SIZE_SZ)
            if SIZE_SZ == 4:
                fd,bk = struct.unpack("<II", mem)
            elif SIZE_SZ == 8:
                fd,bk = struct.unpack("<QQ", mem)
        except RuntimeError:
            print_error("Invalid smallbin addr {0:#x}".format(offset))
            return

        print("")
        print_header("[ sb {:02} ] ".format(int(sb/2)))
        print("{:#x}{:>{width}}".format(int(offset), "-> ", width=5), end="")
        print_value("[ {:#x} | {:#x} ] ".format(int(fd), int(bk)))

        while (1):
            if fd == (offset-2*SIZE_SZ):
                break

            chunk = malloc_chunk(fd, inuse=False)
            print("")
            print_value("{:>{width}}{:#x} | {:#x} ] ".format("[ ", int(chunk.fd), int(chunk.bk), width=pad_width))
            print("({})".format(int(chunksize(chunk))), end="")
            fd = chunk.fd

        if sb_num != None: #only print one smallbin
            return


################################################################################
def print_bins(inferior, fb_base, sb_base):
    "walk and print the nonempty free bins, modified from jp"

    print_title("Heap Dump")

    for fb in range(0,NFASTBINS):
        print_once = True
        p = malloc_chunk(fb_base-(2*SIZE_SZ)+fb*SIZE_SZ, inuse=False)

        while (p.fd != 0):
            if p.fd is None:
                break

            if print_once:
                print_once = False
                print_header("fast bin {} @ {:#x}".format(fb, int(p.fd)))
            print("\n\tfree chunk @ ", end="")
            print_value("{:#x} ".format(int(p.fd)))
            print("- size ", end="")
            p = malloc_chunk(p.fd, inuse=False)
            print_value("{:#x} ".format(int(chunksize(p))))

    for i in range(1, NBINS):
        print_once = True
        b = sb_base + i*2*SIZE_SZ - 4*SIZE_SZ
        p = malloc_chunk(first(malloc_chunk(b, inuse=False)), inuse=False)

        while p.address != int(b):
            print("")
            if print_once:
                print_once = False
                if i==1:
                    try:
                        print_header("unsorted bin @ ")
                        print_value("{:#x}".format(int(\
                                b.cast(gdb.lookup_type("unsigned long")) + 2*SIZE_SZ)))
                    except:
                        print_header("unsorted bin @ ")
                        print_value("{:#x}".format(int(b + 2*SIZE_SZ)))
                else:
                    try:
                        print_header("small bin {} @ ".format(i))
                        print_value("{:#x}".format(int(b.cast(gdb.lookup_type("unsigned long")) + 2*SIZE_SZ)))
                    except:
                        print_header("small bin {} @ ".format(i))
                        print_value("{:#x}".format(int(b + 2*SIZE_SZ)))

            print("\n\tfree chunk @ ",end="")
            print_value("{:#x} ".format(int(p.address)))
            print("- size ",end="")
            print_value("{:#x}".format(int(chunksize(p))))
            p = malloc_chunk(first(p), inuse=False)


###############################################################################
def print_flat_listing(ar_ptr, sbrk_base):
    "print a flat listing of an arena, modified from jp and arena.c"

    print_title("Heap Dump")
    print_header("\n{:>15}{:>17}{:>18}\n".format("ADDR", "SIZE", "STATUS"))
    print("{:11}{:#x}".format("sbrk_base", int(sbrk_base)))

    p = malloc_chunk(sbrk_base, inuse=True, read_data=False)

    while(1):
        print("{:11}{: <#17x}{: <#16x}".format("chunk", int(p.address),
              int(chunksize(p))), end="")

        if p.address == top(ar_ptr):
            print("(top)")
            break
        elif p.size == (0 | PREV_INUSE):
            print("(fence)")
            break

        if inuse(p):
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
            elif ((p.fd == p.bk) & ~inuse(p)):
                print("(LC)")
            else:
                print("")

        p = malloc_chunk(next_chunk(p), inuse=True, read_data=False)

    sbrk_end = int(sbrk_base + ar_ptr.max_system_mem)
    print("{:11}{:#x}".format("sbrk_end", sbrk_end), end="")


###############################################################################
def print_compact_listing(ar_ptr, sbrk_base):
    "print a compact layout of the heap, modified from jp"

    print_title("Heap Dump")
    p = malloc_chunk(sbrk_base, inuse=True, read_data=False)

    while(1):
        if p.address == top(ar_ptr):
            sys.stdout.write("|T|\n")
            break

        if inuse(p):
            sys.stdout.write("|A|")
        else:
            p = malloc_chunk(p.address, inuse=False)

            if ((p.fd == ar_ptr.last_remainder) \
            and (p.bk == ar_ptr.last_remainder) \
            and (ar_ptr.last_remainder != 0)):
                sys.stdout.write("|L|")
            else:
                sys.stdout.write("|%d|" % bin_index(p.size))

        p = malloc_chunk(next_chunk(p), inuse=True, read_data=False)


################################################################################
class print_bin_layout(gdb.Command):
    "dump the layout of a free bin"

    def __init__(self):
        super(print_bin_layout, self).__init__("print_bin_layout",
                                        gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        "Specify an optional arena addr: print_bin_layout main_arena=0x12345"

        if SIZE_SZ == 0:
            retrieve_sizesz()

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
                            main_arena_address = int(item[11:],16)
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
        mutex_lock(ar_ptr)

        print_title("Bin Layout")

        b = bin_at(ar_ptr, int(arg))
        p = malloc_chunk(first(malloc_chunk(b, inuse=False)), inuse=False)
        print_once = True
        print_str  = ""
        count      = 0

        while p.address != int(b):
            if print_once:
                print_once=False
                print_str += "-->  "
                print_str += color_value("[bin {}]".format(int(arg)))
                count += 1

            print_str += "  <-->  "
            print_str += color_value("{:#x}".format(int(p.address)))
            count += 1
            p = malloc_chunk(first(p), inuse=False)

        if len(print_str) != 0:
            print_str += "  <--"
            print(print_str)
            print("|{}|".format(" " * (len(print_str) - 2 - count*12)))
            print("{}".format("-" * (len(print_str) - count*12)))
        else:
            print("Bin {} empty.".format(int(arg)))

        mutex_unlock(ar_ptr)


def pretty_print_heap_lookup(val):
    "Look-up and return a pretty printer that can print val."

    val_type = val.type

    # If it points to a reference, get the reference.
    if val_type.code == gdb.TYPE_CODE_REF:
        val_type = val_type.target()

    # Get the unqualified type, stripped of typedefs.
    val_type = val_type.unqualified().strip_typedefs()

    # Get the type name.
    typename = val_type.tag
    if typename is None:
        return None
    elif typename == "malloc_par":
        print("calling malloc_par_printer")
        return malloc_par_printer(val)
    elif typename == "malloc_state":
        return malloc_state_printer(val)
    elif typename == "malloc_chunk":
        return malloc_chunk_printer(val)
    elif typename == "_heap_info":
        return heap_info_printer(val)
    else:
        print(typename)

    # Cannot find a pretty printer for type(val)
    return None


##############################################################################
# INITIALIZE CUSTOM GDB CODE
##############################################################################

heap()
print_malloc_stats()
print_bin_layout()
gdb.pretty_printers.append(pretty_print_heap_lookup)
