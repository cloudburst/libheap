try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    import sys
    sys.exit()

from libheap.frontend import frontend_gdb
from libheap.frontend import frontend_gdb_pretty_printers

from libheap.pydbg.debugger import pydbg
from libheap.pydbg.pygdbpython import pygdbpython


class pyptmalloc:
    def __init__(self):
        # Setup debugger interface
        debugger = pygdbpython()
        self.debugger = pydbg(debugger)

        # Register GDB Commands
        frontend_gdb.frontend_gdb(self.debugger)

        # Register GDB Pretty Printers
        pp = frontend_gdb_pretty_printers.pretty_print_heap_lookup
        gdb.pretty_printers.append(pp)
