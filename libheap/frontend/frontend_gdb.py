from libheap.frontend.commands.gdb.heap import heap
from libheap.frontend.commands.gdb.mstats import mstats
from libheap.frontend.commands.gdb.heapls import heapls
from libheap.frontend.commands.gdb.heaplsc import heaplsc
from libheap.frontend.commands.gdb.fastbins import fastbins
from libheap.frontend.commands.gdb.freebins import freebins
from libheap.frontend.commands.gdb.smallbins import smallbins
from libheap.frontend.commands.gdb.print_bin_layout import print_bin_layout


class frontend_gdb:
    """Register commands with GDB"""

    def __init__(self, debugger, version):
        heap(debugger, version)
        mstats(debugger, version)
        heapls(debugger, version)
        heaplsc(debugger, version)
        fastbins(debugger, version)
        freebins(debugger, version)
        smallbins(debugger, version)
        print_bin_layout(debugger, version)
