# Libheap

[`libheap`] is a python library to examine ptmalloc (the glibc userland heap implementation).

It is currently tested and supported on glibc 2.19 only (Ubuntu 14.04 LTS).

If you try to use other glibc versions, the ptmalloc structures will be incorrectly sized and it won't work.  I'm refactoring the code to support multiple glibc versions but for now the structs have to be manually patched if you want to use a newer version.

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
