
import datetime
import os
from re import sub
import signal
import subprocess
import time
import uuid
from pathlib import Path
from multiprocessing import Pool, Value
from ..traceAnalyzer import *
import rq
from rq.worker import WorkerStatus

import logging

l = logging.getLogger(__name__)
#l.setLevel(logging.DEBUG)

test="Tainted addresses: 0x20001000 0x20001001 0x20001002 0x20001003 0x20001004 0x20001005 0x20001006 0x20001007 0x20001008 0x20001009 0x2000100a 0x2000100b 0x2000100c 0x2000100d 0x2000100e 0x2000100f 0x20001010 0x20001011 0x20001012 0x20001013 0x20001014 0x20001015 0x20001016 0x20001017 0x20001018 0x20001019 0x2000101a 0x2000101b 0x2000101c 0x2000101d 0x2000101e 0x2000101f 0x20001020 0x20001021 0x20001022 0x20001023 0x20001024 0x20001025 0x20001026 0x20001027 0x20001028 0x20001029 0x2000102a 0x2000102b 0x2000102c 0x2000102d 0x2000102e 0x2000102f 0x20001030 0x20001031 0x20001032 0x20001033 0x20001034 0x20001035 0x20001036 0x20001037 0x20001038 0x20001039 0x2000103a 0x2000103b 0x2000103c 0x2000103d 0x2000103e 0x2000103f 0x20001040 0x20001041 0x20001042 0x20001043 0x20001044 0x20001045 0x20001046 0x20000c6c 0x20000c70 0x20000c74 0x200053ac 0x200053b2 0x200053b3 0x20000f58 0x20000f59 0x20000f5a 0x20000f5b 0x20000f5c 0x20000f5d 0x20000f5e 0x20000f5f 0x20000f60 0x20000f61 0x20000f62 0x20000f63 0x20000f64 0x20000f65 0x20000f66 0x20000f67 0x20000f68 0x20000f69 0x20000f6a 0x20000f6b 0x20000f6c 0x20000f6d 0x20000f6e 0x20000f6f 0x20000f70 0x20000f71 0x20000f72 0x20000f73 0x20000f74 0x20000f75 0x20000f76 0x20000f77 0x20000f78 0x20000f79 0x20000f7a 0x20000f7b 0x20000f7c 0x20000f7d 0x20000f7e 0x20000f7f 0x20000f80 0x20000f81 0x20000f82 0x20000f83 0x20000f84 0x20000f85 0x20000f86 0x20000f87 0x20000f88 0x20000f89 0x20000f8a 0x20000f8b 0x20000f8c 0x20000f8d 0x20000f8e 0x20000f8f 0x20000f90 0x20000f91 0x20000f92 0x20000f93 0x20000f94 0x20000f95 0x20000f96 0x20000f97 0x20000f98 0x20000f99 0x20000f9a 0x20000f9b 0x20000f9c 0x20000f9d 0x20000f9e 0x20000f9f 0x20000fa0 0x20000fa1 0x20000fa2 0x20000fa3 0x20000fa4 0x20000fa5 0x20000fa6 0x20000fa7 0x20000fa8 0x20000fa9 0x20000faa 0x20000fab 0x20000fac 0x20000fad 0x20000fae 0x20000faf 0x20000fb0 0x20000fb1 0x20000fb2 0x20000fb3 0x20000fb4 0x20000fb5 0x20000fb6 0x20000fb7 0x20000fb8 0x20000fb9 0x20000fba 0x20000fbb 0x20000fbc 0x20000fbd 0x20000fbe 0x20000fbf 0x20000fc0 0x20000fc1 0x20000fc2 0x20000fc3 0x20000fc4 0x20000fc5 0x20000fc6 0x20000fc7 0x20000fc8 0x20000fc9 0x20000fca 0x20000fcb 0x20000fcc 0x20000fcd 0x20000fce 0x20000fcf 0x20000fd0 0x20000fd1 0x20000fd2 0x20000fd3 0x20000fd4 0x20000fd5 0x20000fd6 0x20000fd7 0x20000fd8 0x20000fd9 0x20000fda 0x20000fdb 0x20000fdc 0x20000fdd 0x20000fde 0x20000fdf 0x20000fe0 0x20000fe1 0x20000fe2 0x20000fe3 0x20000fe4 0x20000fe5 0x20000fe6 0x20000fe7 0x20000fe8 0x20000fe9 0x20000fea 0x20000feb 0x20000fec 0x20000fed 0x20000fee 0x20000fef 0x20000ff0 0x20000ff1 0x20000ff2 0x20000ff3 0x20000ff4 0x20000ff5 0x20000ff6 0x20000ff7 0x20000ff8 0x20000ff9 0x20000ffa 0x20000ffb 0x20000ffc 0x20000ffd 0x20000ffe 0x20000fff\n \
[UNIQUE ENTRY POINT]: 0x2058b0\n \
[UNIQUE ENTRY POINT]: 0x205920\n \
[UNIQUE ENTRY POINT]: 0x205942\n \
[UNIQUE ENTRY POINT]: 0x2058fe"


copy_functions = {}

def filter(trace_file_path, copy_functions_path, uniqueCopyFuncContexts_path):
    return filterGeneric(trace_file_path, uniqueCopyFuncContexts_path)
    # return filterCopyFuncBased(trace_file_path, copy_functions_path, uniqueCopyFuncContexts_path)

def filterCopyFuncBased(trace_file_path, copy_functions_path, uniqueCopyFuncContexts_path):
        uniqueCopyFuncContexts = set()
        # will create the first time
        with open(uniqueCopyFuncContexts_path, "a+") as ustream:
             ustream.seek(0)
             for line in ustream:
                 uniqueCopyFuncContexts.add(''.join(line.split()))
        if len(copy_functions) == 0:
           with open(copy_functions_path, 'r') as cstream:
             for line in cstream:
                 fn, fa, fs = line.split(',')
                 copy_functions[fa] = (fn, fs)
        #l.warning(f"Filtering for {trace_file_path} size of unique contexts {len(uniqueCopyFuncContexts)}\n")
        result = False
        for fa, ft in copy_functions.items():
            fn, fs = ft 
            cpstr = fn + " from"
            try:
                output = subprocess.check_output(["grep", cpstr, trace_file_path], text=True)
            except subprocess.CalledProcessError:
                continue
            for ln in output.splitlines():
                #l.warning(f"Grep result {ln} in {trace_file_path}")
                sln = ln.split(":")
                if len(sln) >= 2:
                   #l.warning(f"Checking context {sln[1]}")
                   tstr = ''.join(sln[1].split())
                   if not tstr in uniqueCopyFuncContexts and not tstr == "":
                      result = True
                      uniqueCopyFuncContexts.add(tstr)
                      l.warning(f"Unique context: {tstr}")
        with open(uniqueCopyFuncContexts_path, "w") as ustream:
             for line in uniqueCopyFuncContexts:
                 ustream.write(f"{line}\n")
        return result

def filterGeneric(trace_file_path, uniqueCopyFuncContexts_path):
        uniqueCopyFuncContexts = set()
        # will create the first time
        with open(uniqueCopyFuncContexts_path, "a+") as ustream:
             ustream.seek(0)
             for line in ustream:
                 uniqueCopyFuncContexts.add(''.join(line.split()))
        #l.warning(f"Filtering for {trace_file_path} size of unique contexts {len(uniqueCopyFuncContexts)}\n")
        result = False
        try:
            output = subprocess.check_output(["grep", "Calling", trace_file_path], text=True)
        except subprocess.CalledProcessError:
            l.warning("Unexpected case for not finding Calling keyword in a replay file!!!")
            return result
        for ln in output.splitlines():
            #l.warning(f"Grep result {ln} in {trace_file_path}")
            sln = ln.split(":")
            if len(sln) >= 2:
               #l.warning(f"Checking context {sln[1]}")
               tstr = ''.join(sln[1].split())
               if not tstr in uniqueCopyFuncContexts and not tstr == "":
                  result = True
                  uniqueCopyFuncContexts.add(tstr)
                  l.warning(f"Unique context: {tstr}")
        with open(uniqueCopyFuncContexts_path, "w") as ustream:
             for line in uniqueCopyFuncContexts:
                 ustream.write(f"{line}\n")
        return result

def find_entry_points(firmware_path, binary, MMIO_datareg, taint_pc, copy_functions_path, analysis_type, callchain_depth_bound, 
                      trace_index, temp_results_path, results_path, trace_path, statistics_path, uniqueCopyFuncContexts_path):
    # for testing
    #with open(results_path, 'w') as fstr:
    #     fstr.write(f"{test}")
    #     fstr.close()
    #     return True 
    #l.warning("Trace Guided Analysis in action...\n")
    #if not filter(trace_path, copy_functions_path, uniqueCopyFuncContexts_path):
    #   return True
    if isinstance(MMIO_datareg, str):
       MMIO_datareg = int(MMIO_datareg)
    #if isinstance(taint_pc, str):
    #   taint_pc = int(taint_pc)  
    #temp = results_path.replace("", "")
    try:   
          gp = subprocess.run(['wc', '-l', trace_path], stdout=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
          print(f"Error during grep: {e}")
          print(f"Stderr: {e.stderr}")
    print(f"Size {gp.stdout}")
    for line in gp.stdout.splitlines():
           tks = line.split()
           trace_index = int(''.join(tks[0].split())) 
           break
    print(f"Starting entry point analysis for {trace_path} using trace index {trace_index}\n")     
    so = Tailor(config_path=None,
                     fw_path=firmware_path,
                     bin=binary,
                     MMIO_datareg=MMIO_datareg,
                     #taint_pc=taint_pc,
                     copy_functions_path=copy_functions_path,
                     analysis_type=analysis_type,
                     callchain_depth_bound=callchain_depth_bound,
                     trace_index=trace_index,
                     results_path=temp_results_path,
                     trace_path=trace_path,
                     statistics_path=statistics_path,
                     return_value_tracking="True"
                )
    so.runSingle() 
    print(f"Copying temporary result to {results_path}\n")     
    sub = subprocess.Popen(["cp", temp_results_path, results_path], stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sub.wait() 
    return True

def find_entry_points_with_config(config):
    so = Tailor(config_path=config)
    so.run() 
    
#def find_entry_points(args):
#    print(f"num args {len(args)} ")
#    return True
