import os
import sys
import subprocess
import glob

# argv[1]: benchmark_path
# argv[2]: output_path

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
  if len(sys.argv) >= 3:
     benchmark_path = sys.argv[1]
     binfile, binpath, bench_dir = getElfFile(benchmark_path)
     output_path = sys.argv[2]
     states_path = output_path + "/" + bench_dir + "/entry_point_states" 
     tainted_path = output_path + "/" + bench_dir + "/tainted"
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
        dirs = glob.glob(sys.argv[1] + "/fuzzware-project/*/*/*/entry_points/")          
     except OSError as e:
        entry_point_path = output_path + "/entry_points"
        dirs = [entry_point_path]
     eps = set()
     for dir in dirs:
         try:   
            gp = subprocess.run(['grep', '-r', 'UNIQUE', dir], stdout=subprocess.PIPE, text=True)
         except subprocess.CalledProcessError as e:
            print(f"Error during grep: {e}")
            print(f"Stderr: {e.stderr}")
         print(f"{gp.stdout}")
         for line in gp.stdout.splitlines():
           pos = line.find(":[")
           print(f"pos {pos}")
           if pos == None:
              print(f"Could not find :[")
              continue
           file = line[:pos]
           pos = file.find("id") 
           if pos == None:
              print(f"Could not find id")
              continue
           input = file[pos:]
           pos = file.find("entry_points")
           if pos == None:
              print(f"Could not find entry_points")
              continue
           prefix = file[:pos]
           input_path = prefix + "/queue/" + input
           tokens = line.split(':')
           entry_point = ''.join(tokens[-1].split())
           pos = file.find("fuzzers")
           if pos == None:
              print(f"Could not find fuzzers")
              continue        
           main_dir = file[:pos]
           pos = file.find("_0x")
           if pos == None:
              print(f"Could not find _0x")
              continue
           mmio = file[pos+3:pos+11]
           print(f"File {file} main dir {main_dir} input path {input_path} mmio {mmio} entry point {entry_point}")
           eps.add((file, main_dir, input_path, mmio, entry_point))
     for f,m,i,mmio,e in eps:
           config = m + "/config.yml"
           print(f"config: {config}, input: {i}, output dir: {sys.argv[2]}, entry: {e}")
           args = ["fuzzware", "state_gen"] 
           args.append(config)
           args.append(i)  
           args.append(states_path) 
           args.append(mmio) 
           args.append(e)
           subprocess.run(args, stdout=sys.stdout, stdin=subprocess.DEVNULL, stderr=sys.stderr)
           print(f"Generated state files for mmio {mmio} pc {e}")
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
           for line in gp2.stdout.splitlines():
               tks = line.split(':')
               if len(tks) < 2:
                  continue
               with open(tainted_file, "w") as fs:
                    fs.write(tks[1])               
           print(f"Generated tainted address file {tainted_file}")
