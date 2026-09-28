import os
import sys
import subprocess

# argv[1]: benchmark
# argv[2]: taint analysis
# argv[3]: mmio addr

fuzzware_path = os.environ['FUZZWARE_PATH']

if __name__ == "__main__":
    if len(sys.argv) >= 4:
       with open(sys.argv[2], 'r') as frs:
            while True:
                 line = frs.readline().strip()
                 if line == "":
                    break
                 if "UNIQUE" in line:
                    lst = line.split(':')
                    if not len(lst) == 2:
                       continue
                    args = [fuzzware_path + "/run_docker.sh", fuzzware_path + "/examples", "fuzzware", "state_gen"] 
                    args.append(sys.argv[1] + "/POC/config.yml")
                    args.append(sys.argv[1] + "/POC/crashing_input")  
                    args.append("temp/" + sys.argv[1]) 
                    args.append(sys.argv[3]) 
                    args.append(lst[1])
                    subprocess.run(args, stdout=sys.stdout, stdin=subprocess.DEVNULL, stderr=sys.stderr)
                    print(f"Generated state files for mmio {sys.argv[3]} pc {lst[1]}")
