#!/usr/bin/env python
import logging
import sys
from .traceAnalyzer import getFunctionInfo


if __name__ == "__main__":
    if len(sys.argv) < 5:
       print(f"Usage: {sys.argv[0]} command fimrware_elf out_file args")
       sys.exit(1) 
    if sys.argv[1] == "function_info":
       fw = sys.argv[2]
       with open(sys.argv[3], "w") as f:
          i = 4
          while i < len(sys.argv): 
                name = sys.argv[i]
                i += 1
                addr, size = getFunctionInfo(fw, name)
                if addr:
                   f.write(f"{name},{addr},{size}\n") 


