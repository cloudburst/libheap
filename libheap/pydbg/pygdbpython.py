import sys

from functools import wraps

from libheap.frontend.printutils import print_error

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    sys.exit()


def gdb_is_running(f):
    "decorator to make sure gdb is running"

    @wraps(f)
    def _gdb_is_running(*args, **kwargs):
        if (gdb.selected_thread() is not None):
            return f(*args, **kwargs)
        else:
            print_error("GDB is not running.")
    return _gdb_is_running


class pygdbpython:
    def __init__(self):
        self.inferior = None

    @gdb_is_running
    def execute(self, cmd, to_string=True):
        return gdb.execute(cmd, to_string=to_string)

    @gdb_is_running
    def get_heap_address(self, mp=None):
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
            maps_file = "/proc/%d/task/%d/maps"
            maps_data = open(maps_file % (pid, task_id)).readlines()
            for line in maps_data:
                if any(x.strip() == '[heap]' for x in line.split(' ')):
                    heap_range = line.split(' ')[0]
                    start, end = [int(h, 16) for h in heap_range.split('-')]
                    break

        return start, end

    @gdb_is_running
    def get_arch(self):
        cmd = self.execute("maintenance info sections ?")
        return cmd.strip().split()[-1:]

    def get_inferior(self):
        try:
            if self.inferior is None:
                if len(gdb.inferiors()) == 0:
                    print_error("No gdb inferior could be found.")
                    return -1
                else:
                    self.inferior = gdb.inferiors()[0]
                    return self.inferior
            else:
                return self.inferior
        except AttributeError:
            print_error("This gdb's python support is too old.")
            sys.exit()

    @gdb_is_running
    def get_size_sz(self):
        try:
            _machine = self.get_arch()[0]
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

    @gdb_is_running
    def read_memory(self, address, length):
        if self.inferior is None:
            self.inferior = self.get_inferior()

        return self.inferior.read_memory(address, length)

    @gdb_is_running
    def read_variable(self, variable=None):
        if variable is None:
            print_error("Please specify a variable to read")
            return None

        try:
            return gdb.selected_frame().read_var(variable)
        except RuntimeError:
            # No idea why this works but sometimes the frame is not selected
            print_error("No gdb frame is currently selected.\n")
            return gdb.selected_frame().read_var(variable)

    @gdb_is_running
    def write_memory(self, address, buf, length=None):
        if self.inferior is None:
            self.inferior = self.get_inferior()

        try:
            if length is None:
                self.inferior.write_memory(address, buf)
            else:
                self.inferior.write_memory(address, buf, length)
        except MemoryError:
            print_error("GDB inferior write_memory error")
