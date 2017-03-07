try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    import sys
    sys.exit()

from libheap.prettyprinters import pretty_print_heap_lookup

from libheap.frontend.frontend_gdb import frontend_gdb

# Register GDB Commands
frontend_gdb()

# Register GDB Pretty Printers
gdb.pretty_printers.append(pretty_print_heap_lookup)
