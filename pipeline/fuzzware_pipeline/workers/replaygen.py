import datetime
import os
from re import sub
import signal
import subprocess
import time
import uuid
from pathlib import Path
from multiprocessing import Pool, Value

import hashlib
import rq
from fuzzware_pipeline.logging_handler import logging_handler
from rq.worker import WorkerStatus

from .. import naming_conventions as nc
from ..run_target import gen_run_arglist, run_target
from ..util.config import load_extra_args, parse_extra_args

from fuzzware_harness.tracing.serialization import (parse_mmio_line,
                                                    parse_ram_line,
                                                    parse_bb_line)
logger = logging_handler().get_logger("replaygen")

mmioContextMap = {}

def recordMMIOs(input_path, input_file_name, parent_base_dir, session_name, fuzzer_instance_name, mmios):
    log_path = parent_base_dir + "/" + session_name + "/" + nc.SESS_DIRNAME_FUZZERS + "/" + fuzzer_instance_name + "/" + nc.SESS_DIRNAME_REPLAY_GEN + "/" + nc.PREFIX_MMIO_PC + "_" + input_file_name
    logstream = open(log_path, "w")
    for mmio, pc in mmios:
        logstream.write(f"{mmio},{pc}\n")
    logstream.close()

def replay(jobid, input_path, input_file_name, parent_base_dir, session_name, fuzzer_instance_name, target_func_addr, target_func_size):
    logger.info(f"Replay generator at work :)")
    templog_path = parent_base_dir + "/" + session_name + "/" + nc.SESS_DIRNAME_FUZZERS + "/" + fuzzer_instance_name + "/" + nc.SESS_DIRNAME_TEMPORARY_REPLAY_GEN + "/" + nc.PREFIX_REPLAY_GEN + "_" + input_file_name
    log_path = parent_base_dir + "/" + session_name + "/" + nc.SESS_DIRNAME_FUZZERS + "/" + fuzzer_instance_name + "/" + nc.SESS_DIRNAME_REPLAY_GEN + "/" + nc.PREFIX_REPLAY_GEN + "_" + input_file_name
    logstream = open(templog_path, "w")
    process = subprocess.Popen(["fuzzware", "replay", "--debug", "-M", "-t", input_path],  stdout=logstream, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return_code = process.wait()
    logger.info(f"Job {jobid} completed with return code {return_code}, moving {templog_path} to {log_path}")    
    subprocess.Popen(['mv', templog_path, log_path])
    logger.info(f"Replay work completed for job {jobid}!")
    return return_code

def readMMIOTrace(file, events, mmioIds):
    with open(file, "r") as fs:
         for line in fs: 
             if line == "" or line == None:
                continue
             try:
                 event_id, pc, lr, mode, orig_access_size, access_fuzz_ind, num_consumed_fuzz_bytes, address, val_text = parse_mmio_line(line)
             except AttributeError:
                 continue
             #if event_id in events:
             #   logger.info(f"WARNING: event id already exists {event_id}")
             #   continue
             mmioIds.add(event_id) 
             events[event_id] = (pc, lr, mode, orig_access_size, access_fuzz_ind, num_consumed_fuzz_bytes, address, val_text) 

def readRAMTrace(file, events, ramIds):
    with open(file, "r") as fs:
         for line in fs: 
             if line == "" or line == None:
                continue
             try: 
                 event_id, pc, lr, mode, size, address, val_text = parse_ram_line(line)
             except AttributeError:
                 continue
             if event_id in events:
                logger.info(f"WARNING: event id already exists {event_id}")
                continue
             ramIds.add(event_id) 
             events[event_id] = (pc, lr, mode, size, address, val_text) 

def readBBLTrace(file, events, bblIds):
    with open(file, "r") as fs:
         for line in fs: 
             if line == "" or line == None:
                continue
             try: 
                 event_id, pc, cnt = parse_bb_line(line)
             except AttributeError:
                 continue
             if event_id in events:
                logger.info(f"WARNING: event id already exists {event_id}")
                continue
             bblIds.add(event_id)
             events[event_id] = (pc, cnt) 

def getHash(events, id, bblIds):
    count = id - 1
    window = 0
    hstr = ""
    while window < 16 and count >= 0:
          if count in events.keys():
             if count in bblIds:
                pc, cnt = events[count]
                hstr += hex(pc)
                window += 1   
          count -= 1 
    hash_object = hashlib.sha256(hstr.encode())
    return hash_object.hexdigest()

def updateContextMap(events, mmioIds, ramIds, bblIds):
    mmiowithnewcontext = set()
    numnewcontexts = 0
    for id in mmioIds:
        ev = events[id]
        if ev[2] == "r":
           pc = ev[0]
           address = ev[6]
           hvalue = getHash(events, id, bblIds)
           # we want to update this one to include all relevant mmio accesses
           mmiowithnewcontext.add((address, pc))      
           if not address in mmioContextMap.keys():
              mmioContextMap[address] = set() 
           if not hvalue in mmioContextMap[address]:
              numnewcontexts += 1
              mmioContextMap[address].add(hvalue)
              logger.info(f"New context for MMIO address {hex(address)} access {hex(pc)}")
    return numnewcontexts, mmiowithnewcontext 

def accessesTarget(events, mmioIds, target_mmio_addr):
    for id in mmioIds:
        ev = events[id]
        if ev[2] == "r":
           pc = ev[0]
           address = ev[6]
           #logger.info(f"Checking for target MMIO {target_mmio_addr} vs {address}")
           if address == target_mmio_addr:
              return True
    return False

def checkUniqueness(input_path, target_mmio_addr=None):
    mmiotr, ramtr, bbltr = nc.window_trace_path_for_input(input_path)
    events = {}
    mmioIds = set()
    ramIds = set()
    bblIds = set()
    allexist = False
    while not allexist:
          me = os.path.exists(mmiotr)
          re = os.path.exists(ramtr)
          be = os.path.exists(bbltr)
          allexist = me and re and be
    readMMIOTrace(mmiotr, events, mmioIds) 
    if not target_mmio_addr == None:
       if not accessesTarget(events, mmioIds, target_mmio_addr):
          return False, None
    readRAMTrace(ramtr, events, ramIds) 
    readBBLTrace(bbltr, events, bblIds)
    unique, mmiowithunique = updateContextMap(events, mmioIds, ramIds, bblIds) 
    del events
    return unique, mmiowithunique 


def checkTargetRelevance(input_path, target_func_addr, target_func_size, explore_tainted_access_in_copy_func, copy_functions_path):
    mmiotr, ramtr, bbltr = nc.window_trace_path_for_input(input_path)
    logger.info(f"bbl trace path {bbltr} for input path {input_path}")
    #events = {}
    #mmioIds = set()
    #ramIds = set()
    #bblIds = set()
    #allexist = False
    #while not allexist:
    #      me = os.path.exists(mmiotr)
    #      re = os.path.exists(ramtr)
    #      be = os.path.exists(bbltr)
    #      allexist = me and re and be
    if not os.path.exists(bbltr):
       return False
    if explore_tainted_access_in_copy_func:
       cpfm = {}
       if not os.path.exists(copy_functions_path):
          return False
       with open(copy_functions_path) as cfs:
            for line in cfs:
                fn, fa, fs = line.split(',')
                cpfm[int(fa)] = int(fs)
       with open(bbltr, "r") as fs:
         for line in fs: 
             if line == "" or line == None:
                continue
             try: 
                 event_id, pc, cnt = parse_bb_line(line)
                 for cfa in cpfm.keys():
                     if pc >= cfa and pc < cfa + cpfm[cfa]:
                        return True
             except AttributeError:
                 continue
    if target_func_addr:
       with open(bbltr, "r") as fs:
         for line in fs: 
             if line == "" or line == None:
                continue
             try: 
                 event_id, pc, cnt = parse_bb_line(line)
                 if pc >= target_func_addr and pc < target_func_addr + target_func_size:
                    return True
             except AttributeError:
                 continue
    return False
 
class ReplayGenWorker(rq.Worker):


   def execute_job(self, job, queue):
      self.set_state(WorkerStatus.BUSY)
      job.started_at = datetime.datetime.utcnow()
      input_path, input_file_name, parent_base_dir, session_name, fuzzer_instance_name, target_mmio_addr, target_func_addr, target_func_size, explore_read_tainted, explore_tainted_access_in_copy_func, copy_functions_path = job.args
      #unique, mmiowithunique = checkUniqueness(input_path, target_mmio_addr)
      job.ended_at = datetime.datetime.utcnow()
      #if unique:  
      if explore_read_tainted or checkTargetRelevance(input_path, target_func_addr, target_func_size, explore_tainted_access_in_copy_func, copy_functions_path):
         #recordMMIOs(input_path, input_file_name, parent_base_dir, session_name, fuzzer_instance_name, mmiowithunique)
         return_code = replay(job.id, input_path, input_file_name, parent_base_dir, session_name, fuzzer_instance_name, target_func_addr, target_func_size)
      else:
         return_code = 0  
      if not return_code:
         # Job success
         job.set_status(rq.job.JobStatus.FINISHED)

         self.handle_job_success(job=job, queue=queue,
                started_job_registry=queue.started_job_registry)
      else:
         job.set_status(rq.job.JobStatus.FINISHED)
         # Job fail
         self.handle_job_failure(job=job, queue=queue,
                started_job_registry=queue.started_job_registry)

      self.set_state(WorkerStatus.IDLE)    
