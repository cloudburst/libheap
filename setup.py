#!/usr/bin/env python

from distutils.core import setup

setup(name='libheap',
      version='0.1',
      description='gdb python library for examining the glibc heap (ptmalloc)',
      author='cloud',
      url='https://github.com/cloudburst/libheap',
      license="MIT",
      keywords="ptmalloc gdb python glibc",
      py_modules=['libheap', 'printutils', 'prettyprinters']
     )
