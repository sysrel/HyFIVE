#!/usr/bin/env python
"""
    Python package for the fuzzware pipeline.
"""
import os
from setuptools import setup

def get_packages(rel_dir):
    packages = [rel_dir]
    for x in os.walk(rel_dir):
        # break into parts
        base = list(os.path.split(x[0]))
        if base[0] == "":
            del base[0]

        for mod_name in x[1]:
            packages.append(".".join(base + [mod_name]))

    return packages

setup(name='hyfive_analysis',
    version='1.0',
    description='Python package for the fuzzware vulnerability detection component.',
    author='Tuba Yavuz',
    author_email='tuba@ece.ufl.edu',
    url='https://tuba.ece.ufl.edu/',
    packages=get_packages('hyfive_analysis'),
    entry_points = {
        'console_scripts': [
            'hyfive_symex = hyfive_analysis.GSYMEX:main',
            'hyfive_trace_guided_analysis = hyfive_analysis.TGA:main'  
        ]
    }
)
