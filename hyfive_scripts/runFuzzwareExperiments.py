import os
import sys
import subprocess
import glob
import logging
import signal
import time
import datetime
from pathlib import Path


log = None
#argv[1]: benchmark_dir
#argv[2]: output_dir
#argv[3]: timeout
#argv[4]: number of repetitions

def getElfFile(path):
       try:   
          gp = subprocess.run(['find', path, '-name', "*.elf"], stdout=subprocess.PIPE, text=True)
       except subprocess.CalledProcessError as e:
          print(f"Error during grep: {e}")
          print(f"Stderr: {e.stderr}")
       elffile = ""
       elfpath = "" 
       for line in gp.stdout.splitlines():
           if "fuzzware-project" in line:
              continue
           elffile = os.path.basename(line)
           elfpath = line
           break
       try:   
          gp = subprocess.run(['find', path, '-name', "*.bin"], stdout=subprocess.PIPE, text=True)
       except subprocess.CalledProcessError as e:
          print(f"Error during grep: {e}")
          print(f"Stderr: {e.stderr}")
       binfile = ""
       binpath = "" 
       for line in gp.stdout.splitlines():
           if "fuzzware-project" in line:
              continue
           binfile = os.path.basename(line)
           binpath = line
           break
       bench_dir = os.path.basename(path)
       print(f"path {path} bench dir {bench_dir}")
       return elffile, elfpath, binfile, binpath, bench_dir


if __name__ == "__main__":
  if len(sys.argv) >= 5:
     try:
       bench_path = sys.argv[1]
       print(f"benchmark path: {bench_path}")
       timeout = float(sys.argv[3])*3600
       repetition = int(sys.argv[4])
       elffile, elfpath, binfile, binpath, bench_dir = getElfFile(bench_path)
       output_path = sys.argv[2] + "/" + bench_dir
       print(f"output path: {output_path}")
       try:
           os.makedirs(output_path)
       except FileExistsError:
           print(f"WARNING: Directory {output_path} exists!")
           sys.exit(1)  
       logfile = output_path + '/runFuzwareExp.log'
       subprocess.run(['touch', logfile])
       logging.basicConfig(
                 filename= logfile,
                 level=logging.DEBUG,
                 format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                 filemode='w' # 'w' overwrites the file each time, 'a' (default) appends
       )
       # Get a log instance, conventionally using __name__
       log = logging.getLogger(__name__)
       log.info(f"[{datetime.datetime.now()}] Starting experiments for benchmark {bench_dir} for {timeout} seconds, benchmark path {bench_path} ")
       log.info(f"[{datetime.datetime.now()}] Sanity checking output path and its directories..")
       i = 1
       while i<=repetition:
             bench_round = output_path + "/round" + str(i) 
             if os.path.exists(bench_round):
                log(f"[{datetime.datetime.now()}] round path {bench_round} already exists!!!")
                exit(1)
             i += 1
       log.info(f"[{datetime.datetime.now()}] Output path {output_path} ready for experiments") 
       subproc = None
       i = 1
       while i<=repetition:
             bench_round = output_path + "/round" + str(i) 
             bench_output_path = bench_round 
             log.info(f"[{datetime.datetime.now()}] Round {i} path {bench_round}, output path {bench_output_path}")
             try:
                 os.makedirs(bench_round)
             except FileExistsError:
                 print(f"WARNING: Directory round {i} path {bench_round} exists!")
                 sys.exit(1)  
             #try:
             #    os.makedirs(bench_output_path)
             #except FileExistsError:
             #    print(f"WARNING: Directory bench output path {bench_output_path} exists!")
             #    sys.exit(1)  
             log.info(f"[{datetime.datetime.now()}] round {i}, starting fuzzware for benchmark {bench_dir} for {timeout} seconds ")
             subproc = subprocess.Popen(["fuzzware", "pipeline", "--skip-afl-cpufreq", bench_path]) 
             time.sleep(timeout)
             subproc.send_signal(signal.SIGINT)
             time.sleep(5)
             subproc = None
             subprocess.run(["cp", "-R", bench_path + "/fuzzware-project", bench_output_path]) 
             i += 1
     except KeyboardInterrupt:
        log.info(f"[{datetime.datetime.now()}] Received SIGINIT")
        if subproc:
           subproc.send_signal(signal.SIGINT)
           log.info(f"[{datetime.datetime.now()}] Killed fuzzer...")
        log.info(f"[{datetime.datetime.now()}] Terminating experiments")
        exit(1)
        
