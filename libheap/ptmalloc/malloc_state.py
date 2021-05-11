import struct
import sys

from libheap.frontend.printutils import color_title
from libheap.frontend.printutils import color_value
from libheap.frontend.printutils import print_error

class malloc_state:
    "python representation of a struct malloc_state"

    def __init__(self, addr=None, mem=None, debugger=None, version=None):
        """XXX
        """

        self.size = 0
        self.mutex = 0
        self.flags = 0
        # self.have_fastchunks = 0
        self.fastbinsY = 0
        self.top = 0
        self.last_remainder = 0
        self.bins = 0
        self.binmap = 0
        self.next = 0
        self.next_free = 0
        # self.attached_threads = 0
        self.system_mem = 0
        self.max_system_mem = 0

        self.fastbins_offset = 0
        self.bins_offset = 0

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
            raise Exception('sys.exit()')

        self.size_sz = self.dbg.get_size_sz()

        if version is None:
            print_error("Please specify a malloc_state version.")
            raise Exception('sys.exit()')
        else:
            self.version = version

        if mem is None:
            # a string of raw memory was not provided
            if self.version >= 2.15 and self.version < 2.23:
                if self.size_sz == 4:
                    # sizeof(malloc_state) = 4+4+40+4+4+(254*4)+16+4+4+4+4
                    self.size = 0x450
                elif self.size_sz == 8:
                    # sizeof(malloc_state) = 4+4+80+8+8+(254*8)+16+8+8+8+8
                    self.size = 0x888

                self.fastbins_offset = 8
                self.bins_offset = self.fastbins_offset + 12 * self.size_sz
            elif self.version >= 2.23 and self.version <= 2.25:
                # attached_threads added in 2.23
                if self.size_sz == 4:
                    self.size = 0x454
                elif self.size_sz == 8:
                    self.size = 0x890

                self.fastbins_offset = 8
                self.bins_offset = self.fastbins_offset + 12 * self.size_sz
            elif self.version >= 2.27:
                # have_fastchunks added in 2.27
                if self.size_sz == 4:
                    self.size = 0x458
                    self.fastbins_offset = 0xC
                elif self.size_sz == 8:
                    self.size = 0x898
                    self.fastbins_offset = 0x10

                self.bins_offset = self.fastbins_offset + 12 * self.size_sz

            try:
                self.mem = self.dbg.read_memory(addr, self.size)
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address {0:#x}".format(addr))
                return None
        else:
            # XXX: fix class size
            # self.size = len(mem)
            self.mem = mem

        self.unpack_memory()

    def unpack_memory(self):
        if self.mem is None:
            print_error("No memory found")
            raise Exception('sys.exit()')

        self.mutex = self.unpack_variable("<I", 0)
        self.flags = self.unpack_variable("<I", 4)
        offset = 8
        if self.version >= 2.23:
            if self.size_sz == 4:
                fmt = "<I"
            elif self.size_sz == 8:
                fmt = "<Q"
            # this is padded on 64-bit despite being int
            self.have_fastchunks = self.unpack_variable(fmt, offset)
            offset = offset + self.size_sz

        if self.size_sz == 4:
            fmt = "<10I"
        elif self.size_sz == 8:
            fmt = "<10Q"
        self.fastbinsY = struct.unpack_from(fmt, self.mem, offset)
        offset = offset + 10 * self.size_sz

        if self.size_sz == 4:
            fmt = "<I"
        elif self.size_sz == 8:
            fmt = "<Q"
        self.top = self.unpack_variable(fmt, offset)
        offset += self.size_sz

        self.last_remainder = self.unpack_variable(fmt, offset)
        offset = offset + self.size_sz

        if self.size_sz == 4:
            fmt = "<254I"
        elif self.size_sz == 8:
            fmt = "<254Q"
        self.bins = struct.unpack_from(fmt, self.mem, offset)

        offset = offset + (254 * self.size_sz)
        self.binmap = struct.unpack_from("<IIII", self.mem, offset)

        if self.size_sz == 4:
            fmt = "<I"
        elif self.size_sz == 8:
            fmt = "<Q"
        offset = offset + 16
        self.next = self.unpack_variable(fmt, offset)
        offset = offset + self.size_sz
        self.next_free = self.unpack_variable(fmt, offset)

        if self.version >= 2.23:
            offset = offset + self.size_sz
            self.attached_threads = self.unpack_variable(fmt, offset)

        offset = offset + self.size_sz
        self.system_mem = self.unpack_variable(fmt, offset)
        offset = offset + self.size_sz
        self.max_system_mem = self.unpack_variable(fmt, offset)

    def unpack_variable(self, fmt, offset):
        return struct.unpack_from(fmt, self.mem, offset)[0]

    def write(self, inferior=None):
        # XXX: fixme for new format
        if self.size_sz == 4:
            mem = struct.pack(
                "<275I",
                self.mutex,
                self.flags,
                self.fastbinsY,
                self.top,
                self.last_remainder,
                self.bins,
                self.binmap,
                self.next,
                self.system_mem,
                self.max_system_mem,
            )
        elif self.size_sz == 8:
            mem = struct.pack(
                "<II266QIIIIQQQ",
                self.mutex,
                self.flags,
                self.fastbinsY,
                self.top,
                self.last_remainder,
                self.bins,
                self.binmap,
                self.next,
                self.system_mem,
                self.max_system_mem,
            )

        if self.dbg is not None:
            self.dbg.write_memory(self.address, mem)
        elif inferior is not None:
            self.inferior.write_memory(self.address, mem)

    def __str__(self):
        txt = color_title("struct malloc_state {")
        txt += "\n{:16} = ".format("mutex")
        txt += color_value("{:#x}".format(self.mutex))
        txt += "\n{:16} = ".format("flags")
        txt += color_value("{:#x}".format(self.flags))
        txt += "\n{:16} = ".format("fastbinsY")
        txt += color_value("{}".format("{...}"))
        txt += "\n{:16} = ".format("top")
        txt += color_value("{:#x}".format(self.top))
        txt += "\n{:16} = ".format("last_remainder")
        txt += color_value("{:#x}".format(self.last_remainder))
        txt += "\n{:16} = ".format("bins")
        txt += color_value("{}".format("{...}"))
        txt += "\n{:16} = ".format("binmap")
        txt += color_value("{}".format("{...}"))
        txt += "\n{:16} = ".format("next")
        txt += color_value("{:#x}".format(self.next))
        txt += "\n{:16} = ".format("next_free")
        txt += color_value("{:#x}".format(self.next_free))

        if self.version >= 2.23:
            txt += "\n{:16} = ".format("attached_threads")
            txt += color_value("{:#x}".format(self.attached_threads))

        txt += "\n{:16} = ".format("system_mem")
        txt += color_value("{:#x}".format(self.system_mem))
        txt += "\n{:16} = ".format("max_system_mem")
        txt += color_value("{:#x}".format(self.max_system_mem))
        return txt
