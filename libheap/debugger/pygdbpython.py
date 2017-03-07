import sys
from functools import wraps

from libheap.printutils import print_error

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    exit()


def gdb_is_running(f):
    "decorator to make sure gdb is running"

    @wraps(f)
    def _gdb_is_running(*args, **kwargs):
        if (gdb.selected_thread() is not None):
            return f(*args, **kwargs)
        else:
            print_error("GDB is not running.")
    return _gdb_is_running


@gdb_is_running
def get_arch():
    return gdb.execute("maintenance info sections ?",
                       to_string=True).strip().split()[-1:]


@gdb_is_running
def get_size_sz():
    try:
        _machine = get_arch()[0]
    except IndexError:
        _machine = ""
        SIZE_SZ = 0
        print_error("Retrieving SIZE_SZ failed.")
    except TypeError:  # gdb is not running
        _machine = ""
        SIZE_SZ = 0
        print_error("Retrieving SIZE_SZ failed.")

    if "elf64" in _machine:
        SIZE_SZ = 8
    elif "elf32" in _machine:
        SIZE_SZ = 4
    else:
        SIZE_SZ = 0
        print_error("Retrieving SIZE_SZ failed.")

    return SIZE_SZ


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
        sys.exit()


@gdb_is_running
def read_variable(variable=None):
    if variable is None:
        print_error("Please specify a variable to read")
        return None

    try:
        return gdb.selected_frame().read_var(variable)
    except RuntimeError:
        print_error("No gdb frame is currently selected.")
        return None


@gdb_is_running
def get_heap_address(mp=None):
    """Read heap address from glibc's mp_ structure if available,
    otherwise fall back to /proc/self/maps which is unreliable.
    """

    start, end = None, None

    if mp is not None:
        from libheap.ptmalloc.malloc_par import malloc_par
        if isinstance(mp, malloc_par):
            start = mp.sbrk_base
        else:
            print_error("Please specify a valid malloc_par variable")

        # XXX: add end from arena(s).system_mem ?
    else:
        pid, task_id, thread_id = gdb.selected_thread().ptid
        maps_data = open("/proc/%d/task/%d/maps" % (pid, task_id)).readlines()
        for line in maps_data:
            if any(x.strip() == '[heap]' for x in line.split(' ')):
                heap_range = line.split(' ')[0]
                start, end = [int(h, 16) for h in heap_range.split('-')]
                break

    return start, end
