import os
import sys
import subprocess
import glob

#argv[1]: benchmark_dir
#argv[2]: output_dir

fuzzware_path = os.environ['FUZZWARE_PATH']
hyfive_results = os.environ['HYFIVE_RESULTS']

def genConfig(fw_path, binfile, MMIOaddr, max_trace_index, trace_dir, output_dir, desc):
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
       binfile = ""
       binpath = "" 
       for line in gp.stdout.splitlines():
           if "fuzzware-project" in line:
              continue
           binfile = os.path.basename(line)
           binpath = line
           break
       bench_dir = os.path.basename(path)
       return binfile, binpath, bench_dir

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



if __name__ == "__main__":
    if len(sys.argv) >= 3:
       bench_path = sys.argv[1]
       binfile, binpath, output_dir = getElfFile(bench_path)
       print(f"Elf file: {binfile}")
       mmio_addr = getMMIOAddr(sys.argv[1] + '/config.yml')
       print(f"MMIO addr: {mmio_addr}")
       TGA_path = fuzzware_path + "/fuzzware_hyfive/hyfive_analysis/traceAnalyzer.py"
       if len(sys.argv) == 4:
          output_path = sys.argv[3]
       else:
          output_path = hyfive_results
       trace_dir = "traces"
       bench_output_path = output_path + "/" + output_dir
       trace_path = bench_output_path + "/" + trace_dir
       try:
           os.makedirs(bench_output_path)
           os.makedirs(trace_path)
       except FileExistsError:
           print(f"WARNING: Directory {trace_path} exists!")
           sys.exit(1)  
       try:   
          subprocess.run(['cp', binpath, bench_output_path])
       except subprocess.CalledProcessError as e:
          print(f"Error during grep: {e}")
          print(f"Stderr: {e.stderr}")
       cpf = bench_path + "/copy_functions.txt"
       if os.path.exists(cpf):
          subprocess.run(['cp', cpf, bench_output_path])
          subprocess.run(['cp', cpf, bench_output_path + "/copy_functions"])
       dirs = glob.glob(sys.argv[1] + "/fuzzware-project/*/*/*/replay_gen/")
       print(f"{dirs}")
       for dir in dirs:
           print(f"dir: {dir}")
           rfs = os.listdir(dir)
           for r in rfs:
               rp = dir + "/" + r 
               print(f"\t{rp}")
               max_trace_index = getMaxTraceIndex(rp)
               if int(max_trace_index) < 1000:
                  print(f"Skipping file for small size")
                  continue
               print(f"\t{max_trace_index}")
               config = genConfig(output_dir, binfile, mmio_addr, max_trace_index, trace_dir, output_dir, r)
               config_path = output_path + "/" + output_dir + "/config.json" 
               with open(config_path, "w") as fstr:
                    fstr.write(config)
               print(f"Wrote config:\n {config}")
               args = ["fuzzware", "hyfive_trace_guided_analysis"] 
               args.append(config_path)
               subprocess.run(['cp', rp, trace_path + "/trace.txt"])
               subprocess.run(args, stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
