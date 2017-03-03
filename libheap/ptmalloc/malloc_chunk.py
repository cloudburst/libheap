import struct
from ..debugger.pygdbpython import get_inferior, get_size_sz
from ..printutils import color_title, color_value, print_error


PREV_INUSE     = 1
IS_MMAPPED     = 2
NON_MAIN_ARENA = 4
SIZE_BITS      = (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)


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

        SIZE_SZ = get_size_sz()

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
                print_error("Could not read address {0:#x}".format(addr))
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
                        print_error("Could not read address {0:#x}".format(addr))
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
            ret += color_value("{:#x}".format(self.prev_size))
            ret += "\n{:11} = ".format("size")
            ret += color_value("{:#x}".format(self.size))

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
            mc += color_value("{:#x}".format(self.prev_size))
            mc += "\n{:11} = ".format("size")
            mc += color_value("{:#x}".format(self.size))
            mc += "\n{:11} = ".format("fd")
            mc += color_value("{:#x}".format(self.fd))
            mc += "\n{:11} = ".format("bk")
            mc += color_value("{:#x}".format(self.bk))
            mc += "\n{:11} = ".format("fd_nextsize")
            mc += color_value("{:#x}".format(self.fd_nextsize))
            mc += "\n{:11} = ".format("bk_nextsize")
            mc += color_value("{:#x}".format(self.bk_nextsize))
            return mc
