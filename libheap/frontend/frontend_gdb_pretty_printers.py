from libheap.frontend.printutils import color_title
from libheap.frontend.printutils import color_value

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    exit()


def format_address(value):
    """Helper for printing gdb.Value on both python 2 and 3"""

    try:
        ret = int(value)
    except gdb.error:
        # python2 error: Cannot convert value to int
        try:
            ret = int(str(value), 16)
        except ValueError:
            # work around bug where val is 'sbrk_base ""'
            value = str(value).split()[0]
            ret = int(str(value), 16)

    return ret


class malloc_par_printer:
    "pretty printer for the malloc_par struct (mp_)"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        mp = color_title("struct malloc_par {")
        mp += "\n{:16} = ".format("trim_threshold")
        val = format_address(self.val['trim_threshold'])
        mp += color_value("{:#x}".format(val))
        mp += "\n{:16} = ".format("top_pad")
        val = format_address(self.val['top_pad'])
        mp += color_value("{:#x}".format(val))
        mp += "\n{:16} = ".format("mmap_threshold")
        val = format_address(self.val['mmap_threshold'])
        mp += color_value("{:#x}".format(val))
        mp += "\n{:16} = ".format("arena_test")
        val = format_address(self.val['arena_test'])
        mp += color_value("{:#x}".format(val))
        mp += "\n{:16} = ".format("arena_max")
        val = format_address(self.val['arena_max'])
        mp += color_value("{:#x}".format(val))
        mp += "\n{:16} = ".format("n_mmaps")
        val = format_address(self.val['n_mmaps'])
        mp += color_value("{:#x}".format(val))
        mp += "\n{:16} = ".format("n_mmaps_max")
        val = format_address(self.val['n_mmaps_max'])
        mp += color_value("{:#x}".format(val))
        mp += "\n{:16} = ".format("max_n_mmaps")
        val = format_address(self.val['max_n_mmaps'])
        mp += color_value("{:#x}".format(val))
        mp += "\n{:16} = ".format("no_dyn_threshold")
        val = format_address(self.val['no_dyn_threshold'])
        mp += color_value("{:#x}".format(val))
        mp += "\n{:16} = ".format("mmapped_mem")
        val = format_address(self.val['mmapped_mem'])
        mp += color_value("{:#x}".format(val))
        mp += "\n{:16} = ".format("max_mmapped_mem")
        val = format_address(self.val['max_mmapped_mem'])
        mp += color_value("{:#x}".format(val))

        # XXX: max_total_mem removed in glibc 2.24
        try:
            # compute val first so we force a gdb.error
            val = format_address(self.val['max_total_mem'])

            mp += "\n{:16} = ".format("max_total_mem")
            mp += color_value("{:#x}".format(val))
        except gdb.error:
            # not in this glibc version
            pass

        mp += "\n{:16} = ".format("sbrk_base")
        val = format_address(self.val['sbrk_base'])
        mp += color_value("{:#x}".format(val))
        return mp


class malloc_state_printer:
    "pretty printer for the malloc_state struct (ar_ptr/main_arena)"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        ms = color_title("struct malloc_state {")
        ms += "\n{:16} = ".format("mutex")
        val = format_address(self.val['mutex'])
        ms += color_value("{:#x}".format(val))
        ms += "\n{:16} = ".format("flags")
        val = format_address(self.val['flags'])
        ms += color_value("{:#x}".format(val))
        ms += "\n{:16} = ".format("fastbinsY")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:16} = ".format("top")
        val = format_address(self.val['top'])
        ms += color_value("{:#x}".format(val))
        ms += "\n{:16} = ".format("last_remainder")
        val = format_address(self.val['last_remainder'])
        ms += color_value("{:#x}".format(val))
        ms += "\n{:16} = ".format("bins")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:16} = ".format("binmap")
        ms += color_value("{}".format("{...}"))
        ms += "\n{:16} = ".format("next")
        val = format_address(self.val['next'])
        ms += color_value("{:#x}".format(val))
        ms += "\n{:16} = ".format("next_free")
        val = format_address(self.val['next_free'])
        ms += color_value("{:#x}".format(val))

        # XXX: attached_threads added in glibc 2.23
        try:
            # compute val first so we force a gdb.error
            val = format_address(self.val['attached_threads'])

            ms += "\n{:16} = ".format("attached_threads")
            ms += color_value("{:#x}".format(val))
        except gdb.error:
            # not in this glibc version
            pass

        ms += "\n{:16} = ".format("system_mem")
        val = format_address(self.val['system_mem'])
        ms += color_value("{:#x}".format(val))
        ms += "\n{:16} = ".format("max_system_mem")
        val = format_address(self.val['max_system_mem'])
        ms += color_value("{:#x}".format(val))
        return ms


class malloc_chunk_printer:
    "pretty printer for the malloc_chunk struct"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        mc = color_title("struct malloc_chunk {")
        mc += "\n{:11} = ".format("prev_size")
        val = format_address(self.val['prev_size'])
        mc += color_value("{:#x}".format(val))
        mc += "\n{:11} = ".format("size")
        val = format_address(self.val['size'])
        mc += color_value("{:#x}".format(val))
        mc += "\n{:11} = ".format("fd")
        val = format_address(self.val['fd'])
        mc += color_value("{:#x}".format(val))
        mc += "\n{:11} = ".format("bk")
        val = format_address(self.val['bk'])
        mc += color_value("{:#x}".format(val))
        mc += "\n{:11} = ".format("fd_nextsize")
        val = format_address(self.val['fd_nextsize'])
        mc += color_value("{:#x}".format(val))
        mc += "\n{:11} = ".format("bk_nextsize")
        val = format_address(self.val['bk_nextsize'])
        mc += color_value("{:#x}".format(val))
        return mc


class heap_info_printer:
    "pretty printer for the heap_info struct (_heap_info)"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        hi = color_title("struct heap_info {")
        hi += "\n{:13} = ".format("ar_ptr")
        val = format_address(self.val['ar_ptr'])
        hi += color_value("{:#x}".format(val))
        hi += "\n{:13} = ".format("prev")
        val = format_address(self.val['prev'])
        hi += color_value("{:#x}".format(val))
        hi += "\n{:13} = ".format("size")
        val = format_address(self.val['size'])
        hi += color_value("{:#x}".format(val))
        hi += "\n{:13} = ".format("mprotect_size")
        val = format_address(self.val['mprotect_size'])
        hi += color_value("{:#x}".format(val))
        return hi


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
