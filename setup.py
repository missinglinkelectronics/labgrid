#!/usr/bin/env python3

from setuptools import setup, Extension

module_filsel = Extension('libfilsel',
                    sources = ['labgrid/clib/filsel.c'],
                    extra_compile_args=['-Wall', '-shared', '-fPIC'],
                    extra_link_args=['-ldl'])

module_hwsf = Extension('libhwsf',
                    sources = ['labgrid/clib/hwsf.c'],
                    extra_compile_args=['-Wall', '-shared', '-fPIC'],
                    extra_link_args=['-ldl'])

setup_args = dict(
    ext_modules=[module_filsel, module_hwsf],
)
setup(**setup_args)
