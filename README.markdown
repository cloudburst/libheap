# Libheap

[`libheap`] is a GDB python library for examining the Glibc heap implementation on Linux.  It has been tested against Glibc 2.11 and 2.12 on 32bit/64bit systems.

# Installation

### Glibc Installation

Although [`libheap`] does not require a glibc compiled with gdb debugging support and symbols, it functions best if you do use one.  There are numerous guides to building Glibc manually, the best I have seen is:

[Devpit - Building GLIBC][1]

On Fedora, they have already done this for you so just simply type:

    debuginfo-install glibc

This will automatically install and setup a debug Glibc for you.

### GDB Installation

If you are using a modern Fedora, their GDB is bleeding edge enough to already have the latest python support added.  Otherwise you will likely have to build GDB from svn instead using the steps documented by [Tom Tromey][2]:

    $ sudo yum install python-devel git texinfo
    $ mkdir -p ~/archer/build ~/archer/install
    $ cd ~/archer

    $ git clone git://sourceware.org/git/archer.git
    $ cd archer
    $ git checkout --track -b python origin/archer-tromey-python

    $ cd ../build
    $ ../archer/configure --prefix=$(cd ../install && pwd)
    $ make all install

Once this is complete you should have a compiled version of GDB that can be run from archer/install/bin/gdb.

### Libheap Installation

The final and easiest step is to install the heap library.  All that is required is to move it to somewhere within your Python path (sys.path):

    $ mv libheap.py /usr/lib/python2.6

# Usage

Loading [`libheap`] is the same as any other Python library:

    $ gdb
    (gdb) python from libheap import *

### Overall Heap Status

A number of different functions exist to print the overall state of the heap as shown below:

#### heap -h
    (gdb) heap -h
    ============================== Heap Dump Help ==================================

    Options:

      -a 0x1234 Specify an arena address
      -b        Print compact bin listing (only free chunks)
      -c        Print compact arena listing (all chunks)
      -f [#]    Print all fast bins, or only a single fast bin
      -l        Print a flat listing of all chunks in an arena
      -s [#]    Print all small bins, or only a single small bin
        
    (gdb) heap
    ================================== Heap Dump ===================================

    Arena(s) found:
         arena @ 0xf2f3a0
        

    (gdb) heap -b
    ================================== Heap Dump ===================================

      fast bin 0   @ 0x804b000
        free chunk @ 0x804b000 - size 0x10
      unsorted bin @ 0xf2f3d8
        free_chunk @ 0x804b010 - size 0x88
        

    (gdb) heap -f
    =================================== Fastbins ===================================

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
        

    (gdb) heap -s 1
    =================================== Smallbins ==================================

    [ sb 01 ] 0xf2f3d8 -> [ 0x0804b010 | 0x0804b010 ] 
                          [ 0x00f2f3d0 | 0x00f2f3d0 ]  (136)
        

    (gdb) heap -l
    ================================== Heap Dump ===================================

              ADDR             SIZE         STATUS
    sbrk_base 0x602c00
    chunk     0x602c00         0x110        (inuse)
    chunk     0x602d10         0x110        (F) FD 75dea366deb8 BK 602f30 
    chunk     0x602e20         0x110        (inuse)
    chunk     0x602f30         0x110        (F) FD 602d10 BK 75dea366deb8 
    chunk     0x603040         0x110        (inuse)
    chunk     0x603150         0x20eb0      (top)
    sbrk_end  0x624008
        

    (gdb) heap -c
    ================================== Heap Dump ===================================
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

### Glibc Structures

There are also included pretty printers for struct malloc_par and struct malloc_state.  These can be viewed by attempting to print out the global variables:

    (gdb) p mp_
    $1 = struct malloc_par {

    (gdb) p main_arena
    $2 = struct malloc_state {

Python classes also exist for these two important structures so you can examine arbitrary memory using them:

    (gdb) python print malloc_state(0x6503d0b37e60)
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
        

    (gdb) python print malloc_par(0x6cb800)
    struct malloc_par {
    trim_threshold   = 0x9e000
    top_pad          = 0x20000
    mmap_threshold   = 0x4f000
    n_mmaps          = 0x0
    n_mmaps_max      = 0x10000
    max_n_mmaps      = 0x1
    no_dyn_threshold = 0x0
    pagesize         = 0x1000
    mmapped_mem      = 0x0
    max_mmapped_mem  = 0x4f000
    max_total_mem    = 0x0
    sbrk_base        = 0x809c000
        
### Convenience Functions

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

[1]:http://devpit.org/wiki/Gnu_Toolchain/GLIBC/Building_GLIBC
[2]:http://tromey.com/blog/?p=494
