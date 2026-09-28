import os
import sys
import subprocess

# argv[1]: benchmark dir
# argv[2]: output dir
# argv[3]: timeout

# go through the state files in the current directory

fuzzware_path = os.environ['FUZZWARE_PATH']

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

if __name__ == "__main__":
    if len(sys.argv) >= 4:
           binfile, binpath, bench_dir = getElfFile(sys.argv[1])
           output_path = sys.argv[2]
           empty_file = output_path + "/empty.txt"
           subprocess.run(['touch', empty_file])
           state_path = output_path + "/" + bench_dir + "/entry_point_states" 
           taint_path = output_path + "/" + bench_dir + "/tainted"
           symex_path = output_path + "/" + bench_dir + "/symex_results"
           try:
              os.makedirs(symex_path)
           except FileExistsError:
              print(f"WARNING: Directory {symex_path} exists!")
              sys.exit(1)  
           for file in os.listdir(state_path):
               print(f"file: {file}")
               if "entry_point_state_mmio_addr" in file:
                    idx = file.find('id')
                    id_str = file[idx:]
                    tainted_file = taint_path + "/tainted_" + id_str 
                    i = file.find("addr")
                    desc = file[i+4:]
                    args = ["fuzzware", "hyfive_symex", "-t", sys.argv[3]] 
                    #args = ["fuzzware", "hyfive_symex"] 
                    args.append(state_path + "/" + file)
                    args.append(sys.argv[1] + "/copy_functions.txt") 
                    args.append(tainted_file) 
                    outfile = symex_path + "/symex_" + desc + "_full_tainted_timeout_" + sys.argv[3] + ".txt"
                    subprocess.run(["touch", outfile])
                    stdout_path = open(outfile, "w")
                    print(f"Command: {args}")
                    sub = subprocess.run(args, stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                    print(f"Executed symex for {file} with tainted addresses storing output in {outfile}")
                    if len(sys.argv) >= 5 and sys.argv[4] == "empty":
                       # try with empty_tainted.txt  
                       outfile = "symex_result" + desc + "_empty_tainted_timeout_" + sys.argv[3] + ".txt"
                       stdout_path = open(outfile, "w")
                       args = ["fuzzware", "hyfive_symex", "--timeout " + sys.argv[3]] 
                       args.append(state_path + "/" + file)
                       args.append(sys.argv[1] + "/copy_functions.txt") 
                       args.append(empty_file) 
                       outfile = symex_path + "/symex_" + desc + "_empty_tainted_timeout_" + sys.argv[2] + ".txt"
                       subprocess.run(["touch", outfile])
                       stdout_path = open(outfile, "w")
                       print(f"Command: {args}")
                       sub = subprocess.run(args, stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                       print(f"Executed symex for {file} without tainted addresses storing output in {outfile}")
                         
