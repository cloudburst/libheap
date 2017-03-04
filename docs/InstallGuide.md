# Installation

## Glibc Installation

Although [`libheap`] does not require a glibc compiled with gdb debugging support and symbols, it functions best if you do use one.  Without debug symbols you will need to supply the address of the main arena yourself.

#### On Ubuntu:

    apt-get install libc6-dbg

#### On Fedora:

    yum install yum-utils
    debuginfo-install glibc

Or:

    dnf install dnf-plugins-core
    dnf debuginfo-install glibc

## Libheap Installation

    $ git clone https://github.com/cloudburst/libheap
    $ pip3 install --user ./libheap/

You may need to add your pip user install location to your Python PATH afterwards so GDB can find it (depending on your setup).  Change the python version to match whatever your system is running (`pip3 show libheap` to find the location).

    echo "python import sys" >> ~/.gdbinit
    echo "python sys.path.append('~/.local/lib/python3.6/site-packages/')" >> ~/.gdbinit
