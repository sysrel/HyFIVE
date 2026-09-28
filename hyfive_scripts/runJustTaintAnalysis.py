import os
import sys
import subprocess
import glob
import logging
from pathlib import Path

fuzzware_path = os.environ['FUZZWARE_PATH']
hyfive_results = os.environ['HYFIVE_RESULTS']

logger = None
#argv[1]: benchmark_dir
#argv[2]: timeout

entry_points = set()

def genConfig(fw_path, binfile, MMIOaddr, max_trace_index, trace_dir, output_dir, desc, copy_functions_path):
    result = "{\n"
    result += "\"bin\": "
    result += "\"" + binfile + "\",\n"
    result += "\"fw_path\": " 
    result += "\"" + fw_path + "\",\n"
    result += "\"MMIO_base_addr\": " 
    result += "\"" + MMIOaddr + "\",\n"
    result += "\"data_reg_offset\": "
    result += "\"0x0\",\n"
    result += "\"status_reg_offset\": "
    result += "\"0x0\",\n"
    result += "\"handler_data_size\": "
    result += "512,\n"
    result += "\"callchain_depth_bound\": "
    result += "3,\n"
    result += "\"copy_functions_path\": "
    result += "\"" + copy_functions_path + "\",\n" 
    result += "\"analysis_type\": "
    result += "[\"read_copy_functions\",\"trace_guided_analysis\"],\n"
    result += "\"trace_index\": "
    result += max_trace_index + ",\n"
    result += "\"trace_dir\": "
    result += "\"" + trace_dir  + "\",\n"
    result += "\"output\": "
    result += "\"" + output_dir +"\",\n"
    result += "\"result_file_desc\": "
    result += "\"" + desc + "\",\n"
    result += "\"return_value_tracking\": \"True\"\n}"
    return result

def getMMIOAddr(path):
       try:   
          gp = subprocess.run(['grep', 'mmio_addr', path], stdout=subprocess.PIPE, text=True)
       except subprocess.CalledProcessError as e:
          print(f"Error during grep: {e}")
          print(f"Stderr: {e.stderr}")
       mmio = ""
       for line in gp.stdout.splitlines():
           tks = line.split(':')
           if len(tks) < 2:
              continue
           mmio = ''.join(tks[1].split())
       return mmio

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

def getMaxTraceIndex(path):
       try:   
          gp = subprocess.run(['wc', '-l', path], stdout=subprocess.PIPE, text=True)
       except subprocess.CalledProcessError as e:
          print(f"Error during grep: {e}")
          print(f"Stderr: {e.stderr}")
       print(f"Size {gp.stdout}")
       trace_index = 100000
       for line in gp.stdout.splitlines():
           tks = line.split()
           trace_index = ''.join(tks[0].split()) 
           break
       return trace_index

def initDirs(benchmark_path, output_path):
     elffile, elfpath, binfile, binpath, bench_dir = getElfFile(benchmark_path)
     states_path = output_path + "/" + bench_dir + "/entry_point_states" 
     handled_states_path = output_path + "/" + bench_dir + "/handled_entry_point_states" 
     tainted_path = output_path + "/" + bench_dir + "/tainted"
     symex_path = output_path + "/" + bench_dir + "/symex_results"
     empty_file = output_path + "/empty.txt"
     subprocess.run(['touch', empty_file])
     try:
         os.makedirs(tainted_path)
     except FileExistsError:
         print(f"WARNING: Directory {tainted_path} exists!")
         sys.exit(1)  
     try:
         os.makedirs(states_path)
     except FileExistsError:
         print(f"WARNING: Directory {states_path} exists!")
         sys.exit(1)  
     try:
         os.makedirs(handled_states_path)
     except FileExistsError:
         print(f"WARNING: Directory {states_path} exists!")
         sys.exit(1)  
     try:
         os.makedirs(symex_path)
     except FileExistsError:
         print(f"WARNING: Directory {symex_path} exists!")


def generateStatesForEntryFile(bench_path, prefix, mmio, dirs, states_path, tainted_path):
     eps = set()
     for dir in dirs:
         try:   
            gp = subprocess.run(['grep', '-n', 'UNIQUE', dir], stdout=subprocess.PIPE, text=True)
         except subprocess.CalledProcessError as e:
            print(f"Error during grep: {e}")
            print(f"Stderr: {e.stderr}")
         print(f"{gp.stdout}")
         logger.info(f"Unique locations in {dir}:\n{gp.stdout}")
         for line in gp.stdout.splitlines():
           tokens = line.split(':')
           entry_point = ''.join(tokens[-1].split())
           #if entry_point in entry_points:
           #   logger.info(f"Skipping seen entry point {entry_point}")
           #   continue
           entry_points.add(entry_point) 
           pos = line.find(":[")
           print(f"pos {pos}")
           if pos == None:
              print(f"Could not find :[")
              continue
           file = os.path.basename(dir)
           pos = file.find("id") 
           if pos == None:
              print(f"Could not find id")
              continue
           pos2 = file.find("results")
           if pos2 >= 0:
              input = file[pos:pos2 + 7]
           else:
              pos2 = file.find(".txt")
              input = file[pos:pos2]
           pos_num = input.find("cov_")
           if pos_num >= 0:
              input = input[:pos_num+3]
           pos = file.find("entry_points")
           if pos == None:
              print(f"Could not find entry_points")
              continue
           input_path = prefix + "/queue/" + input
           pos = prefix.find("fuzzers")
           if pos == None:
              print(f"Could not find fuzzers")
              continue        
           main_dir = prefix[:pos]
           #main_dir = os.path.dirname(dir)
           pos = file.find("_0x")
           if pos == None:
              print(f"Could not find _0x")
              continue
           #mmio = file[pos+3:pos+11]
           print(f"File {file} main dir {main_dir} input path {input_path} mmio {mmio} entry point {entry_point}")
           eps.add((dir, main_dir, input_path, mmio, entry_point))
     for f,m,i,mmio,e in eps:
           config = m + "/config.yml"
           #config = bench_path + "/fuzzware-project/data/config.yml"
           print(f"config: {config}, input: {i}, output dir: {sys.argv[2]}, entry: {e}")
           logger.info(f"Generating state: config: {config}, input: {i}, output dir: {sys.argv[2]}, entry: {e}")
           args = ["fuzzware", "state_gen"] 
           args.append(config)
           args.append(i)  
           args.append(states_path) 
           args.append(mmio) 
           args.append(e)
           try:
              subprocess.run(args, stdout=sys.stdout, stdin=subprocess.DEVNULL, stderr=sys.stderr)
           except subprocess.CalledProcessError as e:
              print(f"Error during grep: {e}")
              print(f"Stderr: {e.stderr}")
           print(f"Generated state files for mmio {mmio} pc {e}")
           logger.info(f"Generated state files for mmio {mmio} pc {e}")
     tip = set()
     for f,m,i,mmio,e in eps:
           if i in tip:
              continue
           tip.add(i)
           try:
               gp2 = subprocess.run(['grep', 'Tainted addresses:', f], stdout=subprocess.PIPE, text=True)
           except subprocess.CalledProcessError as e:
               print(f"Error during grep: {e}")
               continue
           pos = i.find('id') 
           input_file = i[pos:]
           tainted_file = tainted_path + "/tainted_" + input_file   
           subprocess.run(['touch', tainted_file])
           print(f"Tainted addr: {gp2.stdout}")
           logger.info(f"Tainted addr: {gp2.stdout}")
           for line in gp2.stdout.splitlines():
               tks = line.split(':')
               if len(tks) < 2:
                  continue
               with open(tainted_file, "w") as fs:
                    fs.write(tks[1])               
           print(f"Generated tainted address file {tainted_file}")
           logger.info(f"Generated tainted address file {tainted_file}")

def filesUnderDirectoryPattern(pattern):
    return set(glob.glob(pattern))


def executeSymex(benchmark_path, output_path, state_path, state_files, timeout):
    elffile, elfpath, binfile, binpath, bench_dir = getElfFile(benchmark_path)
    taint_path = output_path + "/" + bench_dir + "/tainted"
    symex_path = output_path + "/" + bench_dir + "/symex_results"
    for file in state_files:
        print(f"file: {file}")
        logger.info(f"State file for symex: {file}")
        if "entry_point_state_mmio_addr" in file:
           idx = file.find('id')
           id_str = file[idx:]
           tainted_file = taint_path + "/tainted_" + id_str 
           i = file.find("addr")
           desc = file[i+4:]
           args = ["fuzzware", "hyfive_symex", "-d", "-t", timeout] 
           #args = ["fuzzware", "hyfive_symex"] 
           args.append(file)
           args.append(benchmark_path + "/copy_functions.txt") 
           args.append(tainted_file) 
           outfile = symex_path + "/symex_" + desc + "_full_tainted_timeout_" + timeout + ".txt"
           subprocess.run(["touch", outfile])
           stdout_path = open(outfile, "w")
           print(f"Symex command: {args}")
           logger.info(f"Symex command: {args}")
           sub = subprocess.run(args, stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)
           print(f"Executed symex for {file} with tainted addresses storing output in {outfile}")
           logger.info(f"Executed symex for {file} with tainted addresses storing output in {outfile}")

def findCutPoints(file, mmio_addr):
    pos = mmio_addr.find("0x")
    if pos >= 0:
       mmio_addr = mmio_addr[pos+2:]
    search = "Read: addr= 0x00000000"
    try:
       gp = subprocess.run(["grep", "-n", search + mmio_addr, file], stdout=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
       print(f"Error during grep: {e}")
       return []
    results = []
    for line in gp.stdout.splitlines():
        ls = line.split(':')
        if len(ls) < 2:
           continue
        results.append(int(ls[0]))
    return results   

if __name__ == "__main__":
    if len(sys.argv) >= 3:
       bench_path = sys.argv[1]
       print(f"benchmark path: {bench_path}")
       copy_functions_path = bench_path + "/copy_functions.txt"
       timeout = sys.argv[2]
       elffile, elfpath, binfile, binpath, output_dir = getElfFile(bench_path)
       print(f"Elf file: {binfile} bench dir {output_dir}")
       mmio_addr = getMMIOAddr(sys.argv[1] + '/config.yml')
       print(f"MMIO addr: {mmio_addr}")
       TGA_path = fuzzware_path + "/fuzzware_hyfive/hyfive_analysis/traceAnalyzer.py"
       output_path = hyfive_results
       trace_dir = "traces"
       bench_output_path = output_path + "/" + output_dir

       entry_pattern = bench_output_path + "/all*.txt"
       trace_path = bench_output_path + "/" + trace_dir
       state_pattern = bench_output_path + "/entry_point_states" + "/entry_point_state*"
       state_path = bench_output_path + "/entry_point_states" 
       handled_state_path = bench_output_path + "/handled_entry_point_states" 
       tainted_path = bench_output_path + "/tainted" 
       try:
           os.makedirs(bench_output_path)
       except FileExistsError:
           print(f"WARNING: Directory bench output path {bench_output_path} exists!")
           sys.exit(1)  
       try:
           os.makedirs(trace_path)
       except FileExistsError:
           print(f"WARNING: Directory trace path {trace_path} exists!")
           sys.exit(1)  
       try:   
          subprocess.run(['cp', binpath, bench_output_path])
          subprocess.run(['cp', elfpath, bench_output_path])
       except subprocess.CalledProcessError as e:
          print(f"Error during grep: {e}")
          print(f"Stderr: {e.stderr}")
       cpf = bench_path + "/copy_functions.txt"
       if os.path.exists(cpf):
          subprocess.run(['cp', cpf, bench_output_path])
          subprocess.run(['cp', cpf, bench_output_path + "/copy_functions"])
       initDirs(bench_path, output_path)
       logfile = bench_output_path + '/hyfiveExp.log'
       subprocess.run(['touch', logfile])
       logging.basicConfig(
         filename= logfile,
         level=logging.DEBUG,
         format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
         filemode='w' # 'w' overwrites the file each time, 'a' (default) appends
       )

       # Get a logger instance, conventionally using __name__
       logger = logging.getLogger(__name__)

       dirs = glob.glob(sys.argv[1] + "/fuzzware-project/*/*/*/replay_gen/")
       print(f"{dirs}")
       # copies config.yml
       subprocess.run(["mkdir", bench_output_path + "/fuzzware-project"]) 
       subprocess.run(["cp", "-R", bench_path + "/fuzzware-project/data", bench_output_path + "/fuzzware-project"]) 
       for dir in dirs:
           logger.info(f"Replay directory {dir}")
           subprocess.run(["cp", bench_path + "/fuzzware-project/data/config.yml", bench_output_path + "/fuzzware-project/data"]) 
           pos = dir.find("replay_gen")
           prefix = dir[:pos]
           pos2 = dir.find("fuzzers")
           prefix2 = dir[:pos2]
           print(f"dir: {dir}")
           rfs = os.listdir(dir)
           for r in rfs:
               rp = dir + "/" + r 
               print(f"\t{rp}")
               max_trace_index = getMaxTraceIndex(rp)
               #if int(max_trace_index) < 1000:
               #   print(f"Skipping file for small size")
               #   logger.info(f"Skipping replay file {r} for small size (< 1000)")
               #   continue
               print(f"\t{max_trace_index}")
               logger.info(f"Replay file {rp} with max trace index {max_trace_index}")
               config = genConfig(output_dir, elffile, mmio_addr, max_trace_index, trace_dir, output_dir, r, copy_functions_path)
               config_path = output_path + "/" + output_dir + "/config.json" 
               with open(config_path, "w") as fstr:
                    fstr.write(config)
               print(f"Wrote config:\n {config}")
               logger.info(f"Wrote config:\n {config}")              
               args = ["fuzzware", "hyfive_trace_guided_analysis"] 
               args.append(config_path)
               subprocess.run(['cp', rp, trace_path + "/trace.txt"])
               entry_files_before = filesUnderDirectoryPattern(entry_pattern)
               logger.info(f"Starting trace guided analysis for {timeout} seconds")
               try:
                  subprocess.run(args, timeout=int(timeout), stdout=sys.stdout, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
               except subprocess.TimeoutExpired as e:
                  print(f"Timeout for trace guided analysis reached for {rp}!")
                  logger.info(f"Timeout for trace guided analysis reached for {rp}!")                 
               except subprocess.CalledProcessError as e:
                  print(f"Trace guided analysis failed with return code {e.returncode}")
                  print(f"Stderr: {e.stderr}")
                  logger.info(f"Trace guided analysis failed with return code {e.returncode}")
                  logger.info(f"Stderr: {e.stderr}")
