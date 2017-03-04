# Libheap

[`libheap`] is a GDB library that uses the python API to examine the glibc heap implementation (ptmalloc) on Linux.

It is currently tested and supported on glibc 2.19 only (Ubuntu 14.04 LTS).

If you try to use other glibc versions, the ptmalloc structures will be incorrectly sized and it won't work.  I'm refactoring the code to support multiple glibc versions but for now the structs have to be manually patched if you want to use a newer version.

# Installation

Please refer to the [Install Guide](docs/InstallGuide.md).

# Usage

Please refer to the [User Guide](docs/UserGuide.md).
