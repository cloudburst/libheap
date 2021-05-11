import struct
import sys

from libheap.frontend.printutils import color_title
from libheap.frontend.printutils import color_value
from libheap.frontend.printutils import print_error

class malloc_par:
    "python representation of a struct malloc_par"

    CHUNK_ALIGNMENT = 16

    def __init__(self, addr=None, mem=None, debugger=None, version=None):
        self.trim_threshold = 0
        self.top_pad = 0
        self.mmap_threshold = 0
        self.arena_test = 0
        self.arena_max = 0
        self.n_mmaps = 0
        self.n_mmaps_max = 0
        self.max_n_mmaps = 0
        self.no_dyn_threshold = 0
        self.mmapped_mem = 0
        self.max_mmapped_mem = 0
        self.max_total_mem = 0
        self.sbrk_base = 0

        if addr is None:
            if mem is None:
                print_error("Please specify an address or raw memory.")
                return None

            self.address = None
        else:
            self.address = addr

        if debugger is not None:
            self.dbg = debugger
        else:
            print_error("Please specify a debugger")
            raise Exception("sys.exit()")

        # get architecture SIZE_SZ
        self.sz = self.dbg.get_size_sz()

        if version is None:
            print_error("Please specify a malloc_par version.")
            raise Exception("sys.exit()")
        else:
            self.version = version

        if mem is None:
            # a string of raw memory was not provided

            if self.version >= 2.15 and self.version <= 2.23:
                if self.sz == 4:
                    # sizeof(malloc_par) = 20 + 16 + 16
                    struct_malloc_par_size = 0x34
                elif self.sz == 8:
                    # sizeof(malloc_par) = 40 + 16 + 32
                    struct_malloc_par_size = 0x58
            elif self.version >= 2.24:
                # max_total_mem removed in 2.24
                if self.sz == 4:
                    struct_malloc_par_size = 0x30
                elif self.sz == 8:
                    struct_malloc_par_size = 0x50
            else:
                print("WARNING: Unexpected version encountered. See malloc_par.py")

            try:
                self.mem = self.dbg.read_memory(addr, struct_malloc_par_size)
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address {0:#x}".format(addr))
                return None
        else:
            self.mem = mem

        self.unpack_memory()

    def unpack_memory(self):
        if self.mem is None:
            print_error("No memory found")
            raise Exception("sys.exit()")

        if self.sz == 4:
            fmt = "<I"
        elif self.sz == 8:
            fmt = "<Q"

        self.trim_threshold = self.unpack_variable(fmt, 0)
        self.top_pad = self.unpack_variable(fmt, self.sz)
        self.mmap_threshold = self.unpack_variable(fmt, self.sz * 2)
        self.arena_text = self.unpack_variable(fmt, self.sz * 3)
        self.arena_max = self.unpack_variable(fmt, self.sz * 4)

        # size shared on both 32bit and 64bit Intel
        fmt = "<I"

        offset = self.sz * 5
        self.n_mmaps = self.unpack_variable(fmt, offset)

        offset = offset + 4
        self.n_mmaps_max = self.unpack_variable(fmt, offset)

        offset = offset + 4
        self.max_n_mmaps = self.unpack_variable(fmt, offset)

        offset = offset + 4
        self.no_dyn_threshold = self.unpack_variable(fmt, offset)

        if self.sz == 4:
            fmt = "<I"
        elif self.sz == 8:
            fmt = "<Q"

        offset = offset + 4
        self.mmapped_mem = self.unpack_variable(fmt, offset)

        offset = offset + self.sz
        self.max_mmapped_mem = self.unpack_variable(fmt, offset)

        # max_total_mem removed in 2.24
        if self.version <= 2.23:
            offset = offset + self.sz
            self.max_total_mem = self.unpack_variable(fmt, offset)

        offset = offset + self.sz

        self.sbrk_base = self.unpack_variable(fmt, offset)

        # Sometimes sbrk_base isn't
        self.sbrk_base = self.sbrk_base + (self.CHUNK_ALIGNMENT - 1)
        self.sbrk_base = self.sbrk_base & (~(self.CHUNK_ALIGNMENT - 1))
        # self.sbrk_base += 0x8

        # could not read sbrk_base from mp_, fall back to maps file
        if (self.sbrk_base == 0) or (self.sbrk_base is None):
            print("getting heap base from proc")
            self.sbrk_base, end = self.dbg.get_heap_address()

        # we can't read heap address from mp_ or from maps file, exit libheap
        if (self.sbrk_base == 0) or (self.sbrk_base is None):
            print_error("Could not find sbrk_base, this setup is unsupported.")
            exit()

    def unpack_variable(self, fmt, offset):
        return struct.unpack_from(fmt, self.mem, offset)[0]

    def write(self, inferior=None):
        # XXX: fixme
        print_error("malloc_par write() not yet implemented.")

    def __str__(self):
        txt = color_title("struct malloc_par {")
        txt += "\n{:16} = ".format("trim_threshold")
        txt += color_value("{:#x}".format(self.trim_threshold))
        txt += "\n{:16} = ".format("top_pad")
        txt += color_value("{:#x}".format(self.top_pad))
        txt += "\n{:16} = ".format("mmap_threshold")
        txt += color_value("{:#x}".format(self.mmap_threshold))
        txt += "\n{:16} = ".format("arena_test")
        txt += color_value("{:#x}".format(self.arena_test))
        txt += "\n{:16} = ".format("arena_max")
        txt += color_value("{:#x}".format(self.arena_max))
        txt += "\n{:16} = ".format("n_mmaps")
        txt += color_value("{:#x}".format(self.n_mmaps))
        txt += "\n{:16} = ".format("n_mmaps_max")
        txt += color_value("{:#x}".format(self.n_mmaps_max))
        txt += "\n{:16} = ".format("max_n_mmaps")
        txt += color_value("{:#x}".format(self.max_n_mmaps))
        txt += "\n{:16} = ".format("no_dyn_threshold")
        txt += color_value("{:#x}".format(self.no_dyn_threshold))
        txt += "\n{:16} = ".format("mmapped_mem")
        txt += color_value("{:#x}".format(self.mmapped_mem))
        txt += "\n{:16} = ".format("max_mmapped_mem")
        txt += color_value("{:#x}".format(self.max_mmapped_mem))

        if self.version <= 2.23:
            txt += "\n{:16} = ".format("max_total_mem")
            txt += color_value("{:#x}".format(self.max_total_mem))

        txt += "\n{:16} = ".format("sbrk_base")
        txt += color_value("{:#x}".format(self.sbrk_base))
        return txt
