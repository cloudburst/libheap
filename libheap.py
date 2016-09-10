from __future__ import print_function

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    exit()

import sys
import struct
from printutils import *
from prettyprinters import *

################################################################################
# MALLOC CONSTANTS AND MACROS
################################################################################

def get_arch():
    return gdb.execute("maintenance info sections ?", to_string=True).strip().split()[-1:]

try:
    _machine = get_arch()[0]
except IndexError:
    _machine = ""
    SIZE_SZ = 0

if "elf64" in _machine:
    SIZE_SZ = 8
elif "elf32" in _machine:
    SIZE_SZ = 4
else:
    SIZE_SZ = 0

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
        return int(gdb.parse_and_eval("&main_arena.bins[%d]" % \
                int((i -1) * 2)).cast(gdb.lookup_type('unsigned int')) \
                - offsetof_fd)
    elif SIZE_SZ == 8:
        offsetof_fd = 0x10
        return int(gdb.parse_and_eval("&main_arena.bins[%d]" % \
                int((i -1) * 2)).cast(gdb.lookup_type('unsigned long')) \
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
    inferior.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))

def mutex_unlock(ar_ptr, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    ar_ptr.mutex = 0
    inferior.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))

def get_inferior():
    try:
        if len(gdb.inferiors()) == 0:
            print_error("No gdb inferior could be found.")
            return -1
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        print_error("This gdb's python support is too old.")
        exit()

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
class malloc_chunk:
    "python representation of a struct malloc_chunk"

    def __init__(self,addr=None,mem=None,size=None,inferior=None,inuse=False,read_data=True):
        self.prev_size   = 0
        self.size        = 0
        self.data        = None
        self.fd          = None
        self.bk          = None
        self.fd_nextsize = None
        self.bk_nextsize = None

        if addr == None or addr == 0:
            if mem == None:
                print_error("Please specify a valid struct malloc_chunk address.")
                return None

            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x8)
                elif SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x10)
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address 0x{0:x}".format(addr))
                return None
        else:
            # a string of raw memory was provided
            if inuse:
                if (len(mem)!=0x8) and (len(mem)<0x10):
                    print_error("Insufficient memory provided for a malloc_chunk.")
                    return None
                if len(mem)==0x8 or len(mem)==0x10:
                    #header only provided
                    read_data = False
            else:
                if (len(mem)!=0x18) and (len(mem)<0x30):
                    print_error("Insufficient memory provided for a free chunk.")
                    return None

        if SIZE_SZ == 4:
            (self.prev_size,
            self.size) = struct.unpack_from("<II", mem, 0x0)
        elif SIZE_SZ == 8:
            (self.prev_size,
            self.size) = struct.unpack_from("<QQ", mem, 0x0)

        if size == None:
            real_size = (self.size & ~SIZE_BITS)
        else:
            #a size was provided (for a malformed chunk with an invalid size)
            real_size = size & ~SIZE_BITS

        if inuse:
            if read_data:
                if self.address != None:
                    # a string of raw memory was not provided
                    try:
                        mem = inferior.read_memory(addr, real_size + SIZE_SZ)
                    except TypeError:
                        print_error("Invalid address specified.")
                        return None
                    except RuntimeError:
                        print_error("Could not read address 0x{0:x}".format(addr))
                        return None

                real_size = (real_size - SIZE_SZ) / SIZE_SZ
                if SIZE_SZ == 4:
                    self.data = struct.unpack_from("<%dI" % real_size, mem, 0x8)
                elif SIZE_SZ == 8:
                    self.data = struct.unpack_from("<%dQ" %real_size, mem, 0x10)

        if not inuse:
            if self.address != None:
                # a string of raw memory was not provided
                if inferior != None:
                    if SIZE_SZ == 4:
                        mem = inferior.read_memory(addr, 0x18)
                    elif SIZE_SZ == 8:
                        mem = inferior.read_memory(addr, 0x30)

            if SIZE_SZ == 4:
                (self.fd,         \
                self.bk,          \
                self.fd_nextsize, \
                self.bk_nextsize) = struct.unpack_from("<IIII", mem, 0x8)
            elif SIZE_SZ == 8:
                (self.fd,         \
                self.bk,          \
                self.fd_nextsize, \
                self.bk_nextsize) = struct.unpack_from("<QQQQ", mem, 0x10)

    def write(self, inferior=None):
        if self.fd == None and self.bk == None:
            inuse = True
        else:
            inuse = False

        if inferior == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if inuse:
            if SIZE_SZ == 4:
                mem = struct.pack("<II", self.prev_size, self.size)
                if self.data != None:
                    mem += struct.pack("<%dI" % len(self.data), *self.data)
            elif SIZE_SZ == 8:
                mem = struct.pack("<QQ", self.prev_size, self.size)
                if self.data != None:
                    mem += struct.pack("<%dQ" % len(self.data), *self.data)
        else:
            if SIZE_SZ == 4:
                mem = struct.pack("<IIIIII", self.prev_size, self.size, \
                        self.fd, self.bk, self.fd_nextsize, self.bk_nextsize)
            elif SIZE_SZ == 8:
                mem = struct.pack("<QQQQQQ", self.prev_size, self.size, \
                        self.fd, self.bk, self.fd_nextsize, self.bk_nextsize)

        inferior.write_memory(self.address, mem)

    def __str__(self):
        if self.prev_size == 0 and self.size == 0:
            return ""
        elif self.fd == None and self.bk == None:
            ret = color_title("struct malloc_chunk {")
            ret += "\n{:11} = ".format("prev_size")
            ret += color_value("0x{}".format(self.prev_size))
            ret += "\n{:11} = ".format("size")
            ret += color_value("0x{}".format(self.size))

            if self.data != None:
                if SIZE_SZ == 4:
                    ret += "\n{:11} = ".format("data")
                    ret += color_value("{}".format(self.data))
                    ret += "\n{:11} = ".format("raw")
                    ret += color_value("{}".format( \
                            struct.pack("<%dI"%len(self.data), *self.data)))
                elif SIZE_SZ == 8:
                    ret += "\n{:11} = ".format("data")
                    ret += color_value("{}".format(self.data))
                    ret += "\n{:11} = ".format("raw")
                    ret += color_value("{}".format( \
                            struct.pack("<%dQ"%len(self.data), *self.data)))
            return ret
        else:
            mc = color_title("struct malloc_chunk {")
            mc += "\n{:11} = ".format("prev_size")
            mc += color_value("0x{}".format(self.prev_size))
            mc += "\n{:11} = ".format("size")
            mc += color_value("0x{}".format(self.size))
            mc += "\n{:11} = ".format("fd")
            mc += color_value("0x{}".format(self.fd))
            mc += "\n{:11} = ".format("bk")
            mc += color_value("0x{}".format(self.bk))
            mc += "\n{:11} = ".format("fd_nextsize")
            mc += color_value("0x{}".format(self.fd_nextsize))
            mc += "\n{:11} = ".format("bk_nextsize")
            mc += color_value("0x{}".format(self.bk_nextsize))
            return mc


################################################################################
class malloc_state:
    "python representation of a struct malloc_state"

    def __init__(self, addr=None, mem=None, inferior=None):
        self.mutex          = 0
        self.flags          = 0
        self.fastbinsY      = 0
        self.top            = 0
        self.last_remainder = 0
        self.bins           = 0
        self.binmap         = 0
        self.next           = 0
        self.system_mem     = 0
        self.max_system_mem = 0

        if addr == None:
            if mem == None:
                print_error("Please specify a struct malloc_state address.")
                return None

            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x44c)
                elif SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x880)
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address 0x{0:x}".format(addr))
                return None

        if SIZE_SZ == 4:
            (self.mutex,         \
            self.flags)          = struct.unpack_from("<II", mem, 0x0)
            self.fastbinsY       = struct.unpack_from("<10I", mem, 0x8)
            (self.top,           \
            self.last_remainder) = struct.unpack_from("<II", mem, 0x30)

            self.bins            = struct.unpack_from("<254I", mem, 0x38)
            self.binmap          = struct.unpack_from("<IIII", mem, 0x430)
            (self.next,          \
            self.system_mem,     \
            self.max_system_mem) = struct.unpack_from("<III", mem, 0x440)
        elif SIZE_SZ == 8:
            (self.mutex,         \
            self.flags)          = struct.unpack_from("<II", mem, 0x0)
            self.fastbinsY       = struct.unpack_from("<10Q", mem, 0x8)
            (self.top,           \
            self.last_remainder) = struct.unpack_from("<QQ", mem, 0x58)
            self.bins            = struct.unpack_from("<254Q", mem, 0x68)
            self.binmap          = struct.unpack_from("<IIII", mem, 0x858)
            (self.next,          \
            self.system_mem,     \
            self.max_system_mem) = struct.unpack_from("<QQQ", mem, 0x868)

    def write(self, inferior=None):
        if inferior == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if SIZE_SZ == 4:
            mem = struct.pack("<275I", self.mutex, self.flags, self.fastbinsY, \
                    self.top, self.last_remainder, self.bins, self.binmap, \
                    self.next, self.system_mem, self.max_system_mem)
        elif SIZE_SZ == 8:
            mem = struct.pack("<II266QIIIIQQQ", self.mutex, self.flags, \
                    self.fastbinsY, self.top, self.last_remainder, self.bins, \
                    self.binmap, self.next, self.system_mem, \
                    self.max_system_mem)

        inferior.write_memory(self.address, mem)

    def __str__(self):
        ms = color_title("struct malloc_state {")
        ms += "\n{:14} = ".format("mutex")
        ms += color_value("0x{}".format(self.mutex))
        ms += "\n{:14} = ".format("flags")
        ms += color_value("0x{}".format(self.flags))
        ms += "\n{:14} = ".format("fastbinsY")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:14} = ".format("top")
        ms += color_value("0x{}".format(self.top))
        ms += "\n{:14} = ".format("last_remainder")
        ms += color_value("0x{}".format(self.last_remainder))
        ms += "\n{:14} = ".format("bins")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:14} = ".format("binmap")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:14} = ".format("next")
        ms += color_value("0x{}".format(self.next))
        ms += "\n{:14} = ".format("system_mem")
        ms += color_value("0x{}".format(self.system_mem))
        ms += "\n{:14} = ".format("max_system_mem")
        ms += color_value("0x{}".format(self.max_system_mem))
        return ms


################################################################################
class malloc_par:
    "python representation of a struct malloc_par"

    def __init__(self, addr=None, mem=None, inferior=None):
        self.trim_threshold   = 0
        self.top_pad          = 0
        self.mmap_threshold   = 0
        self.arena_test       = 0
        self.arena_max        = 0
        self.n_mmaps          = 0
        self.n_mmaps_max      = 0
        self.max_n_mmaps      = 0
        self.no_dyn_threshold = 0
        self.mmapped_mem      = 0
        self.max_mmapped_mem  = 0
        self.max_total_mem    = 0
        self.sbrk_base        = 0

        if addr == None:
            if mem == None:
                print_error("Please specify a struct malloc_par address.")
                return None

            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x34)
                elif SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x58)
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address 0x{0:x}".format(addr))
                return None

        if SIZE_SZ == 4:
            (self.trim_threshold, \
            self.top_pad,         \
            self.mmap_threshold,  \
            self.arena_text,      \
            self.arena_max,       \
            self.n_mmaps,         \
            self.n_mmaps_max,     \
            self.max_n_mmaps,     \
            self.no_dyn_threshold,\
            self.mmapped_mem,     \
            self.max_mmapped_mem, \
            self.max_total_mem,   \
            self.sbrk_base)       = struct.unpack("<13I", mem)
        elif SIZE_SZ == 8:
            (self.trim_threshold, \
            self.top_pad,         \
            self.mmap_threshold,  \
            self.arena_test,      \
            self.arena_max,       \
            self.n_mmaps,         \
            self.n_mmaps_max,     \
            self.max_n_mmaps,     \
            self.no_dyn_threshold,\
            self.mmapped_mem,     \
            self.max_mmapped_mem, \
            self.max_total_mem,   \
            self.sbrk_base)       = struct.unpack("<5Q4I4Q", mem)

        # work around for sbrk_base
        # if we cannot get sbrk_base from mp_, we can read the heap base from vmmap.
        if self.sbrk_base == 0:
            pid, task_id, thread_id = gdb.selected_thread().ptid
            maps_data = open("/proc/%d/task/%d/maps" % (pid, task_id)).readlines()
            for line in maps_data:
                if any(x.strip() == '[heap]' for x in line.split(' ')):
                    self.sbrk_base = int(line.split(' ')[0].split('-')[0], 16)
                    break

    def __str__(self):
        mp = color_title("struct malloc_par {")
        mp += "\n{:16} = ".format("trim_threshold")
        mp += color_value("0x{}".format(self.trim_threshold))
        mp += "\n{:16} = ".format("top_pad")
        mp += color_value("0x{}".format(self.top_pad))
        mp += "\n{:16} = ".format("mmap_threshold")
        mp += color_value("0x{}".format(self.mmap_threshold))
        mp += "\n{:16} = ".format("arena_test")
        mp += color_value("0x{}".format(self.arena_test))
        mp += "\n{:16} = ".format("arena_max")
        mp += color_value("0x{}".format(self.arena_max))
        mp += "\n{:16} = ".format("n_mmaps")
        mp += color_value("0x{}".format(self.n_mmaps))
        mp += "\n{:16} = ".format("n_mmaps_max")
        mp += color_value("0x{}".format(self.n_mmaps_max))
        mp += "\n{:16} = ".format("max_n_mmaps")
        mp += color_value("0x{}".format(self.max_n_mmaps))
        mp += "\n{:16} = ".format("no_dyn_threshold")
        mp += color_value("0x{}".format(self.no_dyn_threshold))
        mp += "\n{:16} = ".format("mmapped_mem")
        mp += color_value("0x{}".format(self.mmapped_mem))
        mp += "\n{:16} = ".format("max_mmapped_mem")
        mp += color_value("0x{}".format(self.max_mmapped_mem))
        mp += "\n{:16} = ".format("max_total_mem")
        mp += color_value("0x{}".format(self.max_total_mem))
        mp += "\n{:16} = ".format("sbrk_base")
        mp += color_value("0x{:x}".format(self.sbrk_base))
        return mp


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

        arena = 0
        while(1):
            ar_ptr = malloc_state(main_arena_address)
            mutex_lock(ar_ptr)

            print_title("Malloc Stats")

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
            print_value("0x{}".format(ar_ptr.max_system_mem))
            print("{:16} = ".format("in use bytes"), end='')
            print_value("0x{}".format(ar_ptr.max_system_mem - avail))

            system_b += ar_ptr.max_system_mem
            in_use_b += (ar_ptr.max_system_mem - avail)

            mutex_unlock(ar_ptr)
            if ar_ptr.next == main_arena_address:
                break
            else:
                ar_ptr = malloc_state(ar_ptr.next)
                arena += 1

        print_header("\nTotal (including mmap):\n")
        print("{:16} = ".format("system bytes"), end='')
        print_value("0x{}".format(system_b))
        print("{:16} = ".format("in use bytes"), end='')
        print_value("0x{}".format(in_use_b))
        print("{:16} = ".format("max system bytes"), end='')
        print_value("0x{}".format(mp['max_total_mem']))
        print("{:16} = ".format("max mmap regions"), end='')
        print_value("0x{}".format(mp['max_n_mmaps']))
        print("{:16} = ".format("max mmap bytes"), end='')
        print_value("0x{}".format(mp['max_mmapped_mem']))


################################################################################
class heap(gdb.Command):
    "print a comprehensive view of the heap"

    def __init__(self):
        super(heap, self).__init__("heap", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        "Usage can be obtained via heap -h"

        if SIZE_SZ == 0:
            retrieve_sizesz()

        inferior = get_inferior()
        if inferior == -1:
            return

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
                print_error("Nothing was found at 0x{0:x}".format(ar_ptr.address))
                return

            print_title("Heap Dump")
            print_header("\nArena(s) found:\n")

            try: 
                #arena address obtained via read_var
                print("\t arena @ 0x{}".format(
                        int(ar_ptr.address.cast(gdb.lookup_type("unsigned long")))))
            except: 
                #arena address obtained via -a
                print("\t arena @ 0x{}".format(int(ar_ptr.address)))

            if ar_ptr.address != ar_ptr.next:
                #we have more than one arena

                curr_arena = malloc_state(ar_ptr.next)
                while (ar_ptr.address != curr_arena.address):
                    print("\t arena @ 0x{}".format(int(curr_arena.address)))
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
            print_error("Invalid fastbin addr 0x{0:x}".format(offset))
            return

        print("")
        print_header("[ fb {} ] ".format(fb))
        print("{}{:x}{:>{width}}".format("0x", int(offset), "-> ", width=5), end="")
        print_value("[ 0x{:x} ] ".format(int(fd)))

        if fd != 0: #fastbin is not empty
            fb_size = ((MIN_CHUNK_SIZE) +(MALLOC_ALIGNMENT)*fb)
            print("({})".format(int(fb_size)))

            chunk = malloc_chunk(fd, inuse=False)
            while chunk.fd != 0:
                if chunk.fd is None:   
                    # could not read memory section
                    break

                print_value("{:>{width}}{:x}{}".format("[ 0x", int(chunk.fd), " ] ", width=pad_width))
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
            print_error("Invalid smallbin addr 0x{0:x}".format(offset))
            return

        print("")
        print_header("[ sb {:02} ] ".format(int(sb/2)))
        print("{}{:x}{:>{width}}".format("0x", int(offset), "-> ", width=5), end="")
        print_value("[ 0x{:x} | 0x{:x} ] ".format(int(fd), int(bk)))

        while (1):
            if fd == (offset-2*SIZE_SZ):
                break

            chunk = malloc_chunk(fd, inuse=False)
            print("")
            print_value("{:>{width}}{:x} | 0x{:x} ] ".format("[ 0x", int(chunk.fd), int(chunk.bk), width=pad_width))
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
                print_header("fast bin {} @ 0x{}".format(fb, int(p.fd)))
            print("\n\tfree chunk @ ", end="")
            print_value("0x{} ".format(int(p.fd)))
            print("- size ", end="")
            p = malloc_chunk(p.fd, inuse=False)
            print_value("0x{} ".format(int(chunksize(p))))

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
                        print_value("0x{}".format(int(\
                                b.cast(gdb.lookup_type("unsigned long")) + 2*SIZE_SZ)))
                    except:
                        print_header("unsorted bin @ ")
                        print_value("0x{}".format(int(b + 2*SIZE_SZ) + c_none))
                else:
                    try:
                        print_header("small bin {} @ ".format(i))
                        print_value("0x{}".format(int(b.cast(gdb.lookup_type("unsigned long")) + 2*SIZE_SZ)))
                    except:
                        print_header("small bin {} @ ".format(i))
                        print_value("0x{}".format(int(b + 2*SIZE_SZ)))

            print("\n\tfree chunk @ ",end="")
            print_value("0x{} ".format(int(p.address)))
            print("- size ",end="")
            print_value("0x{}".format(int(chunksize(p))))
            p = malloc_chunk(first(p), inuse=False)


################################################################################
def print_flat_listing(ar_ptr, sbrk_base):
    "print a flat listing of an arena, modified from jp and arena.c"

    print_title("Heap Dump")
    print_header("\n{:>14}{:>17}{:>15}\n".format("ADDR", "SIZE", "STATUS"))
    print("sbrk_base ", end="")
    print("0x{:x}".format(int(sbrk_base)))

    p = malloc_chunk(sbrk_base, inuse=True, read_data=False)

    while(1):
        print("chunk     0x{:x}{:>11}{:<8x}{:>3}".format(int(p.address),"0x",int(chunksize(p)),""),end="")

        if p.address == top(ar_ptr):
            print("(top)")
            break
        elif p.size == (0|PREV_INUSE):
            print("(fence)")
            break

        if inuse(p):
            print("(inuse)")
        else:
            p = malloc_chunk(p.address, inuse=False)
            print("(F) FD ", end="")
            print_value("0x{} ".format(int(p.fd)))
            print("BK ", end="")
            print_value("0x{} ".format(int(p.bk)))

            if ((p.fd == ar_ptr.last_remainder) \
            and (p.bk == ar_ptr.last_remainder) \
            and (ar_ptr.last_remainder != 0)):
                print("(LR)")
            elif ((p.fd == p.bk) & ~inuse(p)):
                print("(LC)")
            else:
                print("")

        p = malloc_chunk(next_chunk(p), inuse=True, read_data=False)

    print("sbrk_end  ", end="")
    print("0x{:x}".format(int(sbrk_base + ar_ptr.max_system_mem)), end="")


################################################################################
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
            print_str += color_value("0x{}".format(int(p.address)))
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


################################################################################
# INITIALIZE CUSTOM GDB CODE
################################################################################

heap()
print_malloc_stats()
print_bin_layout()
