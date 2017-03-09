import os
import sys

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    sys.exit()

try:
    import configparser  # py3
except:
    import ConfigParser as configparser  # py2

from libheap.frontend import frontend_gdb
from libheap.frontend import frontend_gdb_pretty_printers

from libheap.pydbg.debugger import pydbg
from libheap.pydbg.pygdbpython import pygdbpython


class pyptmalloc:
    def __init__(self):
        # Setup debugger interface
        debugger = pygdbpython()
        self.debugger = pydbg(debugger)

        # Read User Config File
        config = configparser.SafeConfigParser()
        path = os.path.abspath(os.path.dirname(__file__))
        config.read(os.path.join(path, "libheap.cfg"))
        self.glibc_version = float(config.get("Glibc", "version"))

        # Register GDB Commands
        frontend_gdb.frontend_gdb(self.debugger, self.glibc_version)

        # Register GDB Pretty Printers
        pp = frontend_gdb_pretty_printers.pretty_print_heap_lookup
        gdb.pretty_printers.append(pp)
