#!/usr/bin/env python

from distutils.core import setup

setup(
    name='libheap',
    packages=['libheap', 'libheap.pydbg', 'libheap.ptmalloc',
              'libheap.frontend', 'libheap.frontend.commands',
              'libheap.frontend.commands.gdb'],
    version='0.2',
    description='python library for examining ptmalloc (glibc userland heap)',
    author='cloud',
    url='https://github.com/cloudburst/libheap',
    license='MIT',
    keywords='ptmalloc gdb python glibc',
)
