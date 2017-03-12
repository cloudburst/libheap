import sys
import struct

from libheap.frontend.printutils import color_title
from libheap.frontend.printutils import color_value
from libheap.frontend.printutils import print_error


class malloc_state:
    "python representation of a struct malloc_state"

    def __init__(self, addr=None, mem=None, debugger=None, version=None):
        self.mutex = 0
        self.flags = 0
        self.fastbinsY = 0
        self.top = 0
        self.last_remainder = 0
        self.bins = 0
        self.binmap = 0
        self.next = 0
        self.next_free = 0
        #self.attached_threads = 0
        self.system_mem = 0
        self.max_system_mem = 0

        if addr is None:
            if mem is None:
                print_error("Please specify a struct malloc_state address.")
                return None

            self.address = None
        else:
            self.address = addr

        if debugger is not None:
            self.dbg = debugger
        else:
            print_error("Please specify a debugger")
            sys.exit()

        self.sz = self.dbg.get_size_sz()

        if version is None:
            print_error("Please specify a malloc_state version.")
            sys.exit()
        else:
            self.version = version

        if mem is None:
            # a string of raw memory was not provided
            if self.version >= 2.15 and self.version < 2.23:
                if self.sz == 4:
                    # sizeof(malloc_state) = 4+4+40+4+4+(254*4)+16+4+4+4+4
                    struct_malloc_state_size = 0x450
                elif self.sz == 8:
                    # sizeof(malloc_state) = 4+4+80+8+8+(254*8)+16+8+8+8+8
                    struct_malloc_state_size = 0x888
            elif self.version >= 2.23 and self.version <= 2.25:
                # attached_threads added in 2.23
                if self.sz == 4:
                    struct_malloc_state_size = 0x454
                elif self.sz == 8:
                    struct_malloc_state_size = 0x890

            try:
                self.mem = self.dbg.read_memory(addr, struct_malloc_state_size)
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
            sys.exit()

        self.mutex = self.unpack_variable("<I", 0)
        self.flags = self.unpack_variable("<I", 4)

        if self.sz == 4:
            fmt = "<10I"
        elif self.sz == 8:
            fmt = "<10Q"
        self.fastbinsY = struct.unpack_from(fmt, self.mem, 8)

        if self.sz == 4:
            fmt = "<I"
        elif self.sz == 8:
            fmt = "<Q"
        offset = 8 + (10 * self.sz)
        self.top = self.unpack_variable(fmt, offset)
        offset = offset + self.sz
        self.last_remainder = self.unpack_variable(fmt, offset)

        if self.sz == 4:
            fmt = "<254I"
        elif self.sz == 8:
            fmt = "<254Q"
        offset = offset + self.sz
        self.bins = struct.unpack_from(fmt, self.mem, offset)

        offset = offset + (254 * self.sz)
        self.binmap = struct.unpack_from("<IIII", self.mem, offset)

        if self.sz == 4:
            fmt = "<I"
        elif self.sz == 8:
            fmt = "<Q"
        offset = offset + 16
        self.next = self.unpack_variable(fmt, offset)
        offset = offset + self.sz
        self.next_free = self.unpack_variable(fmt, offset)

        if self.version >= 2.23:
            offset = offset + self.sz
            self.attached_threads = self.unpack_variable(fmt, offset)

        offset = offset + self.sz
        self.system_mem = self.unpack_variable(fmt, offset)
        offset = offset + self.sz
        self.max_system_mem = self.unpack_variable(fmt, offset)

    def unpack_variable(self, fmt, offset):
        return struct.unpack_from(fmt, self.mem, offset)[0]

    def write(self, inferior=None):
        # XXX: fixme for new format
        if self.sz == 4:
            mem = struct.pack("<275I", self.mutex, self.flags, self.fastbinsY,
                              self.top, self.last_remainder, self.bins,
                              self.binmap, self.next, self.system_mem,
                              self.max_system_mem)
        elif self.sz == 8:
            mem = struct.pack("<II266QIIIIQQQ", self.mutex, self.flags,
                              self.fastbinsY, self.top, self.last_remainder,
                              self.bins, self.binmap, self.next,
                              self.system_mem, self.max_system_mem)

        if self.dbg is not None:
            self.dbg.write_memory(self.address, mem)
        elif inferior is not None:
            self.inferior.write_memory(self.address, mem)

    def __str__(self):
        ms = color_title("struct malloc_state {")
        ms += "\n{:16} = ".format("mutex")
        ms += color_value("{:#x}".format(self.mutex))
        ms += "\n{:16} = ".format("flags")
        ms += color_value("{:#x}".format(self.flags))
        ms += "\n{:16} = ".format("fastbinsY")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:16} = ".format("top")
        ms += color_value("{:#x}".format(self.top))
        ms += "\n{:16} = ".format("last_remainder")
        ms += color_value("{:#x}".format(self.last_remainder))
        ms += "\n{:16} = ".format("bins")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:16} = ".format("binmap")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:16} = ".format("next")
        ms += color_value("{:#x}".format(self.next))
        ms += "\n{:16} = ".format("next_free")
        ms += color_value("{:#x}".format(self.next_free))

        if self.version >= 2.23:
            ms += "\n{:16} = ".format("attached_threads")
            ms += color_value("{:#x}".format(self.attached_threads))

        ms += "\n{:16} = ".format("system_mem")
        ms += color_value("{:#x}".format(self.system_mem))
        ms += "\n{:16} = ".format("max_system_mem")
        ms += color_value("{:#x}".format(self.max_system_mem))
        return ms
