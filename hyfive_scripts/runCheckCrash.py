import os
import sys
import subprocess
import glob
import logging
from pathlib import Path

logger = None
#argv[1]: benchmark path
#argv[2]: output path
#argv[2]: cutoff (last call N call sequence will be used to classify crashes)

entry_points = set()


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

def filesUnderDirectoryPattern(pattern):
    return set(glob.glob(pattern))

if __name__ == "__main__":
    if len(sys.argv) >= 5:
       bench_path = sys.argv[1]
       output_path = sys.argv[2]
       cutoff = int(sys.argv[3]) 
       if not cutoff > 1:
          print(f"Cutoff must be greater than 1!")
          sys.exit(1) 
       keyword = sys.argv[4]
       print(f"benchmark path: {bench_path}")
       main_dirs = glob.glob(bench_path + "/fuzzware-project/main*")
       elffile, elfpath, binfile, binpath, output_dir = getElfFile(bench_path)
       bench_output_path = output_path + "/" + output_dir
       try:
           os.makedirs(bench_output_path)
       except FileExistsError:
           print(f"WARNING: Directory bench output path {bench_output_path} exists!")
           sys.exit(1)  
       print(f"Crash analysis results will be available at {bench_output_path}")      
       logfile = bench_output_path + '/crashClassification.log'
       logging.basicConfig(
                 filename= logfile,
                 level=logging.DEBUG,
                 format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                 filemode='w' # 'w' overwrites the file each time, 'a' (default) appends
       )
       # Get a log instance, conventionally using __name__
       log = logging.getLogger(__name__)
       subprocess.run(['touch', logfile])
       crashcallseq = set()
       crashmap = {}
       for maindir in main_dirs:
           crash_dirs = glob.glob(maindir + "/fuzzers/fuzzer*/crashes")
           for crashdir in crash_dirs:
               crash_files = glob.glob(crashdir + "/id*")
               for crashfile in crash_files:
                   log.info(f"Emulating crash file {crashfile}\n")
                   emuproc = subprocess.run(["fuzzware", "emu", "-c", maindir + "/config.yml", "-d", "-v", "-M", "-t", crashfile],
                                  capture_output=True, text=True, check=True)
                   #print(f"Trace file contents {emuproc}")
                   log.info(f"Size of trace file: {len(emuproc.stdout)}")
                   found = False
                   foundIndex = -1
                   i = 0
                   clines = []
                   for line in emuproc.stdout.splitlines():
                       # print(f"{line}")
                       if "Calling" in line:
                           i += 1
                           if keyword in line:
                              found = True
                              foundIndex = i
                           clines.append(line)
                   rangestr = ""
                   if found:
                      start = i - 2*cutoff
                      end = i - 1
                      if foundIndex > cutoff:
                         start = foundIndex - cutoff
                      if end - foundIndex > cutoff:
                         end = foundIndex + cutoff 
                      rangestr = ""
                      j = end
                      while j >= start and j>=0:
                         rangestr = rangestr + clines[j] + "\n"
                         j -= 1  
                      if not rangestr in crashcallseq:  
                         log.info(f"Found a new crash category:\n{rangestr}")
                         crashcallseq.add(rangestr)
                   else:
                      j = len(clines) - 1
                      while j >= len(clines) - 1 - cutoff and j>=0:
                         rangestr = rangestr + clines[j] + "\n"
                         j -= 1                       
                   crashmap[crashfile] = rangestr
       log.info(f"Crash file -> crash category mapping\n") 
       for cf in crashmap.keys():
           log.info(f"{cf}\n\t\t\t{crashmap[cf]}\n")
       log.info(f"Number of unique crashes: {len(crashcallseq)}\n")
       i = 1
       for c in crashcallseq:
           log.info(f"Crash {i}:\n{c}\n")  
           i += 1      

