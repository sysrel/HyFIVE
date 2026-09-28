import sys
import subprocess

# argv[1]: benchmark
# argv[2]: outdir
# argv[3]: timeout

# go through the state files in the current directory

if __name__ == "__main__":
    if len(sys.argv) >= 4:
           for file in os.listdir('.'):
               if "entry_point_state_mmio_addr" in file:
                    i = file.find("addr")
                    desc = file.substring[i+4:]
                    args = ["./run_docker.sh", "examples", "fuzzware", "hyfive_symex", "--debug", "--timeout " + sys.argv[3]] 
                    args.append("temp/" + sys.argv[1] + "/" + file)
                    args.append(sys.argv[1] + "/copy_functions.txt")  
                    args.append("temp/" + sys.argv[1] + "/tainted_poc.txt") 
                    outfile = sys.argv[2] + "/symex_result" + desc + ".txt"
                    stdout_path = open(outfile, "w")
                    print(f"Command: {args}")
                    subprocess.run(args, stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                    subprocess.wait()
                    print(f"Executed symex for {file} storing output {outfile}")
