from libheap.frontend.commands.gdb.print_bin_layout import print_bin_layout


class frontend_gdb:
    """Register commands with GDB"""

    def __init__(self):
        print_bin_layout()
