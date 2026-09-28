#!/usr/bin/env python
import os
import logging
import signal
import traceback

import angr
import claripy
import archinfo

l = logging.getLogger("HYFIVE_ANA")

def analyze_window_and_filter(file_tuples):
    l.setLevel(logging.DEBUG)
    l.debug("Helloooooo")
    for a,b,c in file_tuples:
        if a == b:
           print(f"Unexpected equality")
        else:
           print(f"a {a} b {b} c {c}")
    return True
