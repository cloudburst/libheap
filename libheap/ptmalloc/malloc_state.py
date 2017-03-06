import struct

from ..debugger.pygdbpython import get_inferior
from ..debugger.pygdbpython import get_size_sz

from ..printutils import color_title
from ..printutils import color_value
from ..printutils import print_error


class malloc_state:
    "python representation of a struct malloc_state"

    def __init__(self, addr=None, mem=None, inferior=None):
        self.mutex = 0
        self.flags = 0
        self.fastbinsY = 0
        self.top = 0
        self.last_remainder = 0
        self.bins = 0
        self.binmap = 0
        self.next = 0
        self.system_mem = 0
        self.max_system_mem = 0

        if addr is None:
            if mem is None:
                print_error("Please specify a struct malloc_state address.")
                return None

            self.address = None
        else:
            self.address = addr

        if inferior is None and mem is None:
            self.inferior = get_inferior()
            if self.inferior == -1:
                return None
        else:
            self.inferior = inferior

        self.SIZE_SZ = get_size_sz()

        if mem is None:
            # a string of raw memory was not provided
            try:
                if self.SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x44c)
                elif self.SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x880)
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address {0:#x}".format(addr))
                return None

        if self.SIZE_SZ == 4:
            (self.mutex, self.flags) = struct.unpack_from("<II", mem, 0x0)
            self.fastbinsY = struct.unpack_from("<10I", mem, 0x8)
            (self.top,
             self.last_remainder) = struct.unpack_from("<II", mem, 0x30)
            self.bins = struct.unpack_from("<254I", mem, 0x38)
            self.binmap = struct.unpack_from("<IIII", mem, 0x430)
            (self.next, self.system_mem,
             self.max_system_mem) = struct.unpack_from("<III", mem, 0x440)
        elif self.SIZE_SZ == 8:
            (self.mutex, self.flags) = struct.unpack_from("<II", mem, 0x0)
            self.fastbinsY = struct.unpack_from("<10Q", mem, 0x8)
            (self.top,
             self.last_remainder) = struct.unpack_from("<QQ", mem, 0x58)
            self.bins = struct.unpack_from("<254Q", mem, 0x68)
            self.binmap = struct.unpack_from("<IIII", mem, 0x858)
            (self.next, self.system_mem,
             self.max_system_mem) = struct.unpack_from("<QQQ", mem, 0x868)

    def write(self, inferior=None):
        if inferior is None:
            inferior = self.inferior
            if inferior == -1:
                return None

        if self.SIZE_SZ == 4:
            mem = struct.pack("<275I", self.mutex, self.flags, self.fastbinsY,
                              self.top, self.last_remainder, self.bins,
                              self.binmap, self.next, self.system_mem,
                              self.max_system_mem)
        elif self.SIZE_SZ == 8:
            mem = struct.pack("<II266QIIIIQQQ", self.mutex, self.flags,
                              self.fastbinsY, self.top, self.last_remainder,
                              self.bins, self.binmap, self.next,
                              self.system_mem, self.max_system_mem)

        inferior.write_memory(self.address, mem)

    def __str__(self):
        ms = color_title("struct malloc_state {")
        ms += "\n{:14} = ".format("mutex")
        ms += color_value("{:#x}".format(self.mutex))
        ms += "\n{:14} = ".format("flags")
        ms += color_value("{:#x}".format(self.flags))
        ms += "\n{:14} = ".format("fastbinsY")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:14} = ".format("top")
        ms += color_value("{:#x}".format(self.top))
        ms += "\n{:14} = ".format("last_remainder")
        ms += color_value("{:#x}".format(self.last_remainder))
        ms += "\n{:14} = ".format("bins")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:14} = ".format("binmap")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:14} = ".format("next")
        ms += color_value("{:#x}".format(self.next))
        ms += "\n{:14} = ".format("system_mem")
        ms += color_value("{:#x}".format(self.system_mem))
        ms += "\n{:14} = ".format("max_system_mem")
        ms += color_value("{:#x}".format(self.max_system_mem))
        return ms
