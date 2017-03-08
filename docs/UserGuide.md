# User Guide

## GDB Setup

Loading [`libheap`] is the same as any other Python library:

    $ gdb
    (gdb) python from libheap import *

This can also be added to your gdbinit to save a step:

    echo "python from libheap import *" >> ~/.gdbinit

## Overall Heap Status

A number of different functions exist to print the overall state of the heap as shown below:

#### heap -h
    (gdb) heap -h
    heapls         Print a flat listing of all chunks in an arena
    fastbins [#]   Print all fast bins, or only a single fast bin
    smallbins [#]  Print all small bins, or only a single small bin
    freebins       Print compact bin listing (only free chunks)
    heaplsc        Print compact arena listing (all chunks)
    mstats         Print memory alloc statistics similar to malloc_stats(3)

#### heap
    (gdb) heap
    Arena(s) found:
         arena @ 0xf2f3a0

#### freebins
    (gdb) freebins
    fast bin 0   @ 0x804b000
        free chunk @ 0x804b000 - size 0x10
    unsorted bin @ 0xf2f3d8
        free_chunk @ 0x804b010 - size 0x88

#### fastbins
    (gdb) fastbins
    fastbins
    [ fb  0 ] 0xf2f3a8 -> [ 0x0804b000 ] (16)
    [ fb  1 ] 0xf2f3ac -> [ 0x00000000 ]
    [ fb  2 ] 0xf2f3b0 -> [ 0x00000000 ]
    [ fb  3 ] 0xf2f3b4 -> [ 0x00000000 ]
    [ fb  4 ] 0xf2f3b8 -> [ 0x00000000 ]
    [ fb  5 ] 0xf2f3bc -> [ 0x00000000 ]
    [ fb  6 ] 0xf2f3c0 -> [ 0x00000000 ]
    [ fb  7 ] 0xf2f3c4 -> [ 0x00000000 ]
    [ fb  8 ] 0xf2f3c8 -> [ 0x00000000 ]
    [ fb  9 ] 0xf2f3cc -> [ 0x00000000 ]

#### smallbins
    (gdb) smallbins 1
    smallbins
    [ sb 01 ] 0xf2f3d8 -> [ 0x0804b010 | 0x0804b010 ]
                          [ 0x00f2f3d0 | 0x00f2f3d0 ]  (136)

#### heapls
    (gdb) heapls
               ADDR             SIZE         STATUS
    sbrk_base  0x602c00
    chunk      0x602c00         0x110        (inuse)
    chunk      0x602d10         0x110        (F) FD 75dea366deb8 BK 602f30
    chunk      0x602e20         0x110        (inuse)
    chunk      0x602f30         0x110        (F) FD 602d10 BK 75dea366deb8
    chunk      0x603040         0x110        (inuse)
    chunk      0x603150         0x20eb0      (top)
    sbrk_end   0x624008

#### heaplsc
    (gdb) heaplsc
    compact arena layout
    |A||11||A||11||A||T|

### Chunks

There are a number of ways to examine a malloc chunk using [`libheap`].  The library has a pretty printer for struct malloc_chunk so we can print any arbitrary address as if it was a valid chunk:

    (gdb) p *(mchunkptr) 0x608790
    struct malloc_chunk {
    prev_size   = 0x0
    size        = 0x21a81
    fd          = 0x0
    bk          = 0x0
    fd_nextsize = 0x0
    bk_nextsize = 0x0

To get more granular access to a chunk, [`libheap`] exposes a python class representation of a malloc chunk:

    (gdb) python print malloc_chunk(0x608790)
    struct malloc_chunk {
    prev_size   = 0x0
    size        = 0x21a81
    fd          = 0x0
    bk          = 0x0
    fd_nextsize = 0x0
    bk_nextsize = 0x0

By default an address is treated as a free chunk and reads all of the fields of struct malloc_chunk, however this can be changed by passing in the optional boolean flag named inuse.  If we only want to read the header of an allocated chunk we can also pass in an optional boolean flag named read_data.  By default the class will attempt to read whatever size is specified within the chunk.  Obviously this can be problematic within exploits where you are overwriting the size field with a bogus value so there is an optional size flag to the class that allows you to specify the real size of a chunk.  Putting this all together, let's see some examples of accessing and changing the individual fields of a chunk:

    (gdb) python chunk = malloc_chunk(0x608790, inuse=True, read_data=False)
    (gdb) python print chunk
    struct malloc_chunk {
    prev_size   = 0x0
    size        = 0x21a81

    (gdb) python chunk.size = 1
    (gdb) python chunk.write()
    (gdb) python print chunk
    struct malloc_chunk {
    prev_size   = 0x0
    size        = 0x1

    (gdb) python print malloc_chunk(0x608790, inuse=True, size=8)
    struct malloc_chunk {
    prev_size   = 0x0
    size        = 0x1
    data        = (0,)
    raw         = "\x00\x00\x00\x00"

Finally, if we are working on an exploit and want to prototype malloc chunks and see how they would appear within this heap implementation we can pass the class a string of raw memory and see how it would be interpreted:

    (gdb) python print malloc_chunk(mem='\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00', inuse=True)

    struct malloc_chunk {
    prev_size   = 0x1
    size        = 0x2

## Statistics

Memory allocation statistics similar to the ones printed by `malloc_stats(3)`
can be obtained:

    (gdb) mstats
    Malloc Stats

    Arena 0:
    system bytes     = 1867776
    in use bytes     = 1662880
    Arena 1:
    system bytes     = 5984256
    in use bytes     = 5140736
    Arena 2:
    system bytes     = 1589248
    in use bytes     = 955032
    Arena 3:
    system bytes     = 135168
    in use bytes     = 49168
    Arena 4:
    system bytes     = 770048
    in use bytes     = 664992
    Arena 5:
    system bytes     = 466944
    in use bytes     = 276984
    Arena 6:
    system bytes     = 720896
    in use bytes     = 593072
    Arena 7:
    system bytes     = 1871872
    in use bytes     = 1212952

    Total (including mmap):
    system bytes     = 13406208
    in use bytes     = 10555816
    max system bytes = 0
    max mmap regions = 1
    max mmap bytes   = 135168

## Glibc Structures

There are also included pretty printers for struct malloc_par and struct malloc_state.  These can be viewed by attempting to print out the global variables:

    (gdb) p mp_
    $1 = struct malloc_par {

    (gdb) p main_arena
    $2 = struct malloc_state {

Python classes also exist for these two important structures so you can examine arbitrary memory using them:

    (gdb) python p = pyptmalloc()
    (gdb) python ms = ptmalloc.malloc_state.malloc_state(0x6503d0b37e60, debugger=p.debugger)
    (gdb) python print(ms)
    struct malloc_state {
    mutex          = 0x0
    flags          = 0x1
    fastbinsY      = {...}
    top            = 0x608790
    last_remainder = 0x0
    bins           = {...}
    binmap         = {...}
    next           = 0x6503d0b37e60
    system_mem     = 0x21890
    max_system_mem = 0x21890


    (gdb) python p = pyptmalloc()
    (gdb) python mp = ptmalloc.malloc_par.malloc_par(0x6cb800, debugger=p.debugger)
    (gdb) python print(mp)
    struct malloc_par {
    trim_threshold   = 0x9e000
    top_pad          = 0x20000
    mmap_threshold   = 0x4f000
    n_mmaps          = 0x0
    n_mmaps_max      = 0x10000
    max_n_mmaps      = 0x1
    no_dyn_threshold = 0x0
    mmapped_mem      = 0x0
    max_mmapped_mem  = 0x4f000
    max_total_mem    = 0x0
    sbrk_base        = 0x809c000

## Convenience Functions

If you are looking to extend the library or use any of its functionality there are a number of Glibc functions reimplemented in Python.  A short list of the most useful ones is shown below:

    chunk2mem(p)
    mem2chunk(mem)
    request2size(req)
    prev_inuse(p)
    chunk_is_mmapped(p)
    chunk_non_main_arena(p)
    chunksize(p)
    next_chunk(p)
    prev_chunk(p)
    chunk_at_offset(p, s)
    inuse(p)
    set_inuse(p)
    clear_inuse(p)
    inuse_bit_at_offset(p, s)
    set_inuse_bit_at_offset(p, s)
    clear_inuse_bit_at_offset(p, s)
    bin_at(m, i)
    next_bin(b)
    first(b)
    last(b)
    in_smallbin_range(sz)
    smallbin_index(sz)
    largebin_index_32(sz)
    largebin_index_64(sz)
    largebin_index(sz)
    bin_index(sz)
    fastbin(ar_ptr, idx)
    fastbin_index(sz)
    have_fastchunks(M)
    clear_fastchunks(M)
    set_fastchunks(M)
    contiguous(M)
    noncontiguous(M)
    set_noncontiguous(M)
    set_contiguous(M)
    mutex_lock(ar_ptr [, inferior])
    mutex_unlock(ar_ptr [, inferior])
    top(ar_ptr)
    heap_for_ptr(ptr)
