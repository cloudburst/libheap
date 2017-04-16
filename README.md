# Libheap

[`libheap`] is a python library to examine ptmalloc (the glibc userland heap implementation).

It is currently tested and known working on:

| glibc | distro |
| --- | --- |
| **2.15** | Ubuntu 12.04 LTS amd64 |
| **2.19** | Ubuntu 14.04 LTS i386, Ubuntu 14.04 LTS amd64
| **2.23** | Ubuntu 16.04 LTS i386, Ubuntu 16.04 LTS amd64
| **2.24** | Fedora 25 x86_64, Ubuntu 16.10 amd64, Ubuntu 17.04 amd64 |

# Installation

Please refer to the [Install Guide](docs/InstallGuide.md).

# Usage

Please refer to the [User Guide](docs/UserGuide.md).

# Design

```
-----------------------------------------------------------------------
                       debugger frontend (commands and prettyprinters)
                                                      libheap/frontend

                     +-----+
                     |     |
                     | gdb |
                     |     |
                     +--+--+
                        |
------------------------+----------------------------------------------
                        |               core logic (debugger-agnostic)
                        |                             libheap/ptmalloc
                   +----+-----+
                   |          |
                   | ptmalloc |
                   |          |
                   +----+-----+
                        |
------------------------+----------------------------------------------
                        |                      debugger-dependent APIs
                        |                                libheap/pydbg
   +--------------+-----+---------+-------------+
   |              |               |             |
+--+---+   +------+------+   +----+----+   +----+---+
|      |   |             |   |         |   |        |
| lldb |   | pygdbpython |   | pygdbmi |   | r2pipe |
| TODO |   |             |   |  TODO   |   |  TODO  |
|      |   |             |   |         |   |        |
+---+--+   +-------+-----+   +---+-----+   +----+---+
    |              |             |              |
    |              |             |    +---------+
    |              |             |    |
----+--------------+-------------+----+--------------------------------
    |              |             |    |      debugger-provided backend
    |              |             | +--+
    |              |    +--------+ |
 +--+---+       +--+--+ |   +------+-+
 |      |       |     | |   |        |
 | lldb |       | gdb +-+   | ptrace |
 |      |       |     |     |        |
 +------+       +-----+     +--------+
-----------------------------------------------------------------------
```
