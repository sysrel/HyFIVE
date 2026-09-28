import os
import sys
import subprocess

# argv[1]: benchmark
# argv[2]: timeout

# go through the state files in the current directory

fuzzware_path = os.environ['FUZZWARE_PATH']

if __name__ == "__main__":
    if len(sys.argv) >= 3:
           for file in os.listdir('.'):
               print(f"file: {file}")
               if "entry_point_state_mmio_addr" in file:
                    i = file.find("addr")
                    desc = file[i+4:]
                    #args = [fuzzware_path + "/run_docker.sh", fuzzware_path + "/examples", "fuzzware", "hyfive_symex", "--debug", "--timeout " + sys.argv[2]] 
                    args = [fuzzware_path + "/run_docker.sh", fuzzware_path + "/examples", "fuzzware", "hyfive_symex", "--timeout " + sys.argv[2]] 
                    args.append("temp/" + sys.argv[1] + "/" + file)
                    args.append(sys.argv[1] + "/copy_functions.txt") 
                    taintedfile = "temp/" + sys.argv[1] + "/tainted_poc.txt" 
                    args.append(taintedfile) 
                    outfile = "symex_result" + desc + "_full_tainted_timeout_" + sys.argv[2] + ".txt"
                    subprocess.run(["touch", outfile])
                    stdout_path = open(outfile, "w")
                    print(f"Command: {args}")
                    sub = subprocess.run(args, stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                    print(f"Executed symex for {file} storing output in {outfile}")
                    if sys.argv[3] == "empty":
                       # try with empty_tainted.txt  
                       outfile = "symex_result" + desc + "empty_tainted_timeout_" + sys.argv[2] + ".txt"
                       stdout_path = open(outfile, "w")
                       #args = [fuzzware_path + "/run_docker.sh", fuzzware_path + "/examples", "fuzzware", "hyfive_symex", "--debug", "--timeout " + sys.argv[2]] 
                       args = [fuzzware_path + "/run_docker.sh", fuzzware_path + "/examples", "fuzzware", "hyfive_symex", "--timeout " + sys.argv[2]] 
                       args.append("temp/" + sys.argv[1] + "/" + file)
                       args.append(sys.argv[1] + "/copy_functions.txt") 
                       taintedfile = "temp/" + sys.argv[1] + "/empty_tainted.txt" 
                       args.append(taintedfile) 
                       outfile = "symex_result" + desc + "_empty_tainted_timeout_" + sys.argv[2] + ".txt"
                       subprocess.run(["touch", outfile])
                       stdout_path = open(outfile, "w")
                       print(f"Command: {args}")
                       sub = subprocess.run(args, stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                       print(f"Executed symex for {file} storing output in {outfile}")
                         
