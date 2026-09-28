# HyFIVE

This tool implements directed fuzzing for embedded firmware. The idea is to use trace-guided static taint analysis 
to detect peripheral-sourced taints and to focus input generation on relavant accesses. It also leverages 
copy functions such as memcpy for both taint propagation and bug explanation using taint-aware symbolic execution.

We built HyFIVE on top of Fuzzware for targeted bug detection and explanation. It is compiled and executed in the same 
way. However, it generates additional output directories regarding full trace generation, trace-guided taint analysis, 
and taint-aware symbolic execution, which are integrated to fuzzware's pipeline. It also comes with some scripts for offline 
analysis.

Important note: We made HyFIVE self contained. Although it should build successfully, if you ever encounter a 
build issue it may be due to some components that Fuzzware imports. So, if the build process complains about 
some files, you should be able to copy from original Fuzzware.

You can either use Docker or install locally. The CVE benchmarks are located under examples/CVEs.

To reproduce experiments for targeted bug detection for CVE-2021-3322, for instance, use the following commands:

1) Using Docker (after building the docker image)

   $ ./run_docker.sh examples fuzzware pipeline --skip-afl-cpufreq --explore-read-tainted X CVEs/CVE-2021-3320


2) Using a local installation

   $ fuzzware pipeline --skip-afl-cpufreq --explore-read-tainted X examples/CVEs/CVE-2021-3320

where X can be a positive value and it denotes HyFIVE moving to its targeted exploration after detecting at least 
X unique program locations reading from tainted memory regions based on the mmio_address specified in the config.yml file. 

Note: If it stops compaining about one of the workers is not running anymore, please check the logs. 
Most probably you need to execute 'sudo sysctl vm.overcommit_memory=1' to avoid such issues.

You can exclude the --explore-read-tainted X option if you want to perform targeted exploration based on a 
 target_caller/target_callee pair or a target_function that leads to read accesses to tainted memory region.

You can use these different targets individually or in combination. If you want to use only  the --explore-read-tainted X option, 
make sure to comment out the target_caller/target_callee pair and the target_function within the config.yml file.

Check for "Pausing" (waiting for trace-guided taint analysis), "Time to move" (starting stage II, targeted analysis) 
within pipeline.log for 

Taint-aware symbolic execution is also integrated into the pipeline. We recommend using it via the scripts 
under the hyfive_scripts directory. When running the scripts, make sure to set two environment variables:
FUZZWARE_PATH should point to the source directory for HyFIVE
HYFIVE_RESULTS should point to the results directory you want to generate.

Once HyFIVE (or vanilla Fuzzware) finds a crash, generate the full trace using the emulator. However, you 
need to create a new directory mimicking the prefix of the path from the original fuzzware-project created for the benchmark.
Let the crashing input path be denoted as Some_path/CVE-2021-3320/fuzzware-project/prefix/crashes/id:XXXXXX_suffix and 
let's assume you are going to create Another_path and the relevant subdirectories implied below to include 
the crashing input and the full trace:

$ fuzzware emu -c <path to config.yml> -d -v -M -t Some_path/CVE-2021-3320/fuzzware-project/prefix/crashes/id:XXXXXX_suffix > ~/Another_path/fuzzware-project/prefix/replay_gen/replay_id:XXXXXX_suffix

Note that the relvant config.yml will be located under the same main00X directory that the crashing input resides.

Then you also need to create a data directory:

$ mkdir Some_path/fuzzware-project/main00X/data

Copy the contents from Some_path/CVE-2021-3320/fuzzware-project/main00X/data to Another_path/CVE-2021-3320/fuzzware-project/main00X/data

Finally, copy the crashing input to Another_path/CVE-2021-3320/fuzzware-project/prefix/queue

Now, you can use runOriginal.py under hyfive_scripts to perform trace-guided analysis followed by taint-aware 
symbolic execution. We used a timeout of 72000 seconds for trace-guided analysis in our experiments:

First create a virtual environment for fuzzware (assuming using a local installation):

$ workon fuzzware

$ python3 hyfive_scripts/runOriginal.py Another_path/CVE-2021-3320 72000

Check the $HYFIVE_RESULTS/CVE-2021-3320 directory for the trace guided analysis file that starts with all_* 

Check the entry points it identified:

$ grep UNIQUE all_*

Under $HYFIVE_RESULTS/CVE-2021-3320/symex you will see the symbolic execution results generated for different entry points.

To find out various categories of paths:

$ grep -r Stashes -A15 $HYFIVE_RESULTS/CVE-2021-3320/symex | grep SimState 

To find out copy receiving

$ grep -r Stashes -A15 $HYFIVE_RESULTS/CVE-2021-3320/symex | grep SimState | grep copyfunc_rec

To find out symbolic reads/writes

$ grep -r Stashes -A15 $HYFIVE_RESULTS/CVE-2021-3320/symex | grep SimState | grep symbolic

Finally, if you check config.json for each CVE benchmark you will see three fields introduced for HyFIVE:

mmio_addr:
  This is the data register address that is used as a taint source
target_callee:
target_caller:
  These together define a call graph edge and if this edge is found within a trace then trace-guided 
taint analysis gets started and you see the Pausing message in pipeline.log
  
We also provide an alternative if you would like to specify a single function for the target:

target_function: 

In case you would like to cite HyFIVE, you may use the following BibTex entry:
```
@inproceedings {YBB26,
title = {A Hybrid Approach to Detecting and Explaining Firmware Vulnerabilities},
booktitle = {The 14th IEEE Conference on Communications and Network Security (IEEE CNS) 2026},
year = {2026},
address = {Newark, DE},
publisher = {IEEE},
author={Yavuz, Tuba and Bai, Ken (Yihang), and Kevin Butler},
month = september,
}
```

Please refer to Fuzzware's README for installation instructions and using various utilities.

