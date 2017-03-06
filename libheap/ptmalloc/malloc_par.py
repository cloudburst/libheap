try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    exit()

import struct

from ..debugger.pygdbpython import get_inferior
from ..debugger.pygdbpython import get_size_sz

from ..printutils import color_title
from ..printutils import color_value
from ..printutils import print_error


class malloc_par:
    "python representation of a struct malloc_par"

    def __init__(self, addr=None, mem=None, inferior=None):
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
                print_error("Please specify a struct malloc_par address.")
                return None

            self.address = None
        else:
            self.address = addr

        if inferior is None and mem is None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        self.SIZE_SZ = get_size_sz()

        if mem is None:
            # a string of raw memory was not provided
            try:
                if self.SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x34)
                elif self.SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x58)
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address {0:#x}".format(addr))
                return None

        if self.SIZE_SZ == 4:
            (self.trim_threshold,
             self.top_pad,
             self.mmap_threshold,
             self.arena_text,
             self.arena_max,
             self.n_mmaps,
             self.n_mmaps_max,
             self.max_n_mmaps,
             self.no_dyn_threshold,
             self.mmapped_mem,
             self.max_mmapped_mem,
             self.max_total_mem,
             self.sbrk_base) = struct.unpack("<13I", mem)
        elif self.SIZE_SZ == 8:
            (self.trim_threshold,
             self.top_pad,
             self.mmap_threshold,
             self.arena_test,
             self.arena_max,
             self.n_mmaps,
             self.n_mmaps_max,
             self.max_n_mmaps,
             self.no_dyn_threshold,
             self.mmapped_mem,
             self.max_mmapped_mem,
             self.max_total_mem,
             self.sbrk_base) = struct.unpack("<5Q4I4Q", mem)

        # work around for sbrk_base: if we cannot get sbrk_base
        # from mp_, we can read the heap base from vmmap.
        if self.sbrk_base == 0:
            pid, task_id, thread_id = gdb.selected_thread().ptid
            maps_data = open("/proc/%d/task/%d/maps" % (pid, task_id)
                             ).readlines()
            for line in maps_data:
                if any(x.strip() == '[heap]' for x in line.split(' ')):
                    self.sbrk_base = int(line.split(' ')[0].split('-')[0], 16)
                    break

        # we can't read heap address from mp_ or from maps file, exit libheap
        if self.sbrk_base == 0:
            print_error("Could not find sbrk_base, this setup is \
                        unsupported.  Exiting.")
            exit()

    def __str__(self):
        mp = color_title("struct malloc_par {")
        mp += "\n{:16} = ".format("trim_threshold")
        mp += color_value("{:#x}".format(self.trim_threshold))
        mp += "\n{:16} = ".format("top_pad")
        mp += color_value("{:#x}".format(self.top_pad))
        mp += "\n{:16} = ".format("mmap_threshold")
        mp += color_value("{:#x}".format(self.mmap_threshold))
        mp += "\n{:16} = ".format("arena_test")
        mp += color_value("{:#x}".format(self.arena_test))
        mp += "\n{:16} = ".format("arena_max")
        mp += color_value("{:#x}".format(self.arena_max))
        mp += "\n{:16} = ".format("n_mmaps")
        mp += color_value("{:#x}".format(self.n_mmaps))
        mp += "\n{:16} = ".format("n_mmaps_max")
        mp += color_value("{:#x}".format(self.n_mmaps_max))
        mp += "\n{:16} = ".format("max_n_mmaps")
        mp += color_value("{:#x}".format(self.max_n_mmaps))
        mp += "\n{:16} = ".format("no_dyn_threshold")
        mp += color_value("{:#x}".format(self.no_dyn_threshold))
        mp += "\n{:16} = ".format("mmapped_mem")
        mp += color_value("{:#x}".format(self.mmapped_mem))
        mp += "\n{:16} = ".format("max_mmapped_mem")
        mp += color_value("{:#x}".format(self.max_mmapped_mem))
        mp += "\n{:16} = ".format("max_total_mem")
        mp += color_value("{:#x}".format(self.max_total_mem))
        mp += "\n{:16} = ".format("sbrk_base")
        mp += color_value("{:#x}".format(self.sbrk_base))
        return mp
