#!/usr/bin/env python
import logging
from .traceAnalyzer import *


if __name__ == "__main__":
    if len(sys.argv) != 5:
       print(f"Usage: {sys.argv[0]} fw_path copy_function_path")
       sys.exit(1) 
    fw_path = sys.argv[1]
    bin = sys.argv[2]
    analysis_type = ["find_copy_functions"]
    copy_functions_path = sys.argv[3]
    statistics_path = sys.argv[4]
    so = Tailor(config_path=None,
                fw_path=fw_path,
                bin=bin,
                analysis_type=analysis_type,
                copy_functions_path=copy_functions_path,
                statistics_path=statistics_path
         )
    so.runSingle()
 


