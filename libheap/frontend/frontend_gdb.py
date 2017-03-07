from libheap.frontend.commands.gdb.mstats import mstats
from libheap.frontend.commands.gdb.fastbins import fastbins
from libheap.frontend.commands.gdb.freebins import freebins
from libheap.frontend.commands.gdb.smallbins import smallbins
from libheap.frontend.commands.gdb.print_bin_layout import print_bin_layout


class frontend_gdb:
    """Register commands with GDB"""

    def __init__(self):
        mstats()
        fastbins()
        freebins()
        smallbins()
        print_bin_layout()
