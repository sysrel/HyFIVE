import os
import sys
import subprocess
import glob
from pathlib import Path

#argv[1]: benchmark_dir
#argv[2]: output_dir
#argv[3]: timeout

if __name__ == "__main__":
    if len(sys.argv) >= 4:
       if 'FUZZWARE_PATH' in os.environ:
          fuzzware_path = os.environ['FUZZWARE_PATH']
       else:
          print(f"Please set FUZZWARE_PATH environment variable to the top source tree for fuzzware-hyfive!")
          sys.exit(1)
       if 'HYFIVE_RESULTS' in os.environ:
          hyfive_results = os.environ['HYFIVE_RESULTS']
       else:
          print(f"Please set HYFIVE_RESULTS environment variable to the output path!")
          sys.exit(1)
       script_path = Path(__file__).resolve()
       script_dir = os.path.dirname(script_path)
       print(f"{script_dir}")
       benchmark_path = sys.argv[1]
       output_path = sys.argv[2]
       timeout = sys.argv[3]
       e = subprocess.run(['python3', script_dir + '/generateEntryPoints.py', benchmark_path, output_path])
       s = subprocess.run(['python3', script_dir + '/generateStateFilesGeneric.py', benchmark_path, output_path])
       sym = subprocess.run(['python3', script_dir + '/executeSymexGeneric.py', benchmark_path, output_path, timeout])
    else:
       print(f"Usage: {sys.argv[0]} benchmark_path output_path timeout_for_symex")
