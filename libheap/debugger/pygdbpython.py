import sys
from functools import wraps
from ..printutils import print_error

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
