import os
import signal
import random
import subprocess
import time
import hashlib
from math import ceil

import redis
import rq
from fuzzware_pipeline.logging_handler import logging_handler

from ..const import (RQ_JOB_FAILURE_TTL, RQ_JOB_TTL, RQ_MODELING_JOB_TIMEOUT,
                     RQ_RESULT_TTL, RQ_STATEGEN_JOB_TIMEOUT, RQ_ENTRY_POINT_STATEGEN_JOB_TIMEOUT,
                     RQ_TRACE_GUIDED_JOB_TIMEOUT)
from ..naming_conventions import (REDIS_QUEUE_NAME_MODELING,
                                  REDIS_QUEUE_NAME_STATE_GEN_JOBS,
                                  REDIS_QUEUE_NAME_TRACE_GEN_JOBS,
                                  # sysrel
                                  COPY_FUNCTIONS_JOB_LOG,
                                  FIRMWARE_PATH,
                                  REDIS_QUEUE_NAME_TRACES_FOR_FILTERING_JOBS,
                                  REDIS_QUEUE_NAME_REPLAY_GEN_JOBS,
                                  REDIS_QUEUE_NAME_TRACE_GUIDED_ANALYSIS_JOBS,
                                  REDIS_QUEUE_NAME_GUIDED_SYMEX_JOBS,
                                  REDIS_QUEUE_NAME_ENTRY_POINT_STATE_GEN_JOBS, 
                                  RQ_DUMP_FILE, SESS_FILENAME_CONFIG,
                                  class_path, find_modeling_venv,
                                  # sysrel
                                  PIPELINE_FILENAME_COPY_FUNCTIONS,
                                  PIPELINE_FILENAME_COPY_FUNCTIONS_STATS,
                                  find_replay_venv,
                                  find_trace_guided_analysis_venv,
                                  find_guided_symex_venv,
                                  get_input_path_components,
                                  get_input_path_from_entry_point,
                                  get_input_file_from_entry_point_state_file,
                                  get_tainted_file_from_entry_point,
                                  mmio_state_name_prefix_for_input_path,
                                  entry_point_state_name_prefix_for_input_path,
                                  trace_paths_for_input)
from .. import naming_conventions as nc
from ..util.eval_utils import add_job_timing_entries
from ..workers import stategen, tracegen, replaygen, entrypointstategen


logger = logging_handler().get_logger("pipeline")

WORKER_SHUTDOWN_TIMEOUT = 0.25
REDIS_SERVER_TIMEOUT = 5
REDIS_PORT_RANGE_START = 2048
REDIS_PORT_RANGE_END = 60000
REDIS_PORT_RETRIES = 100
MMIO_MODELING_INCLUDE_PATH = "fuzzware_modeling.analyze_mmio.analyze_mmio_and_store"
#TRACE_FILTER_INCLUDE_PATH = "hyfive_analysis.analyze_window.analyze_window_and_filter"
TRACE_GUIDED_ANALYSIS_INCLUDE_PATH = "hyfive_analysis.TGA.trace_guided_analysis.find_entry_points"
GUIDED_SYMEX_INCLUDE_PATH = "hyfive_analysis.GSYMEX.analyze_taint.analyze_vulnerability_at_entry_point"

class WorkerPool:
    parent: None # : Pipeline
    conn: redis.Redis
    redis_port: int
    db_proc: subprocess.Popen
    procs: dict # {}
    jobs: list
    write_logs: bool

    # sysrel
    entryPointMap: dict
    entryPointHashes: set
    replayed_paths = set()

    job_queue_trace_gen: rq.Queue
    job_queue_state_gen: rq.Queue
    job_queue_modeling: rq.Queue
    # sysrel
    job_queue_traces_for_filtering: rq.Queue
    job_queue_replay_gen: rq.Queue
    job_queue_guided_symex: rq.Queue
    job_queue_entry_point_state_gen: rq.Queue

    def __init__(self, parent, write_logs):
        self.worker_procs = {
            REDIS_QUEUE_NAME_TRACE_GEN_JOBS: [],
            REDIS_QUEUE_NAME_MODELING: [],
            # sysrel  
            REDIS_QUEUE_NAME_REPLAY_GEN_JOBS: [],
            REDIS_QUEUE_NAME_TRACES_FOR_FILTERING_JOBS: [],
            REDIS_QUEUE_NAME_TRACE_GUIDED_ANALYSIS_JOBS: [],
            REDIS_QUEUE_NAME_GUIDED_SYMEX_JOBS: [], 
            REDIS_QUEUE_NAME_ENTRY_POINT_STATE_GEN_JOBS: []
        }
        self.parent = parent
        self.jobs = []
        self.db_proc = None
        self.write_logs = write_logs

        # sysrel
        self.entryPointMap = {}
        self.entryPointHashes = set()

        self.start_redis()

        # After starting our own redis instance, make sure it is up
        redis_up = False
        for _ in range(5):
            if self.db_up():
                redis_up = True
                break
            time.sleep(0.1)

        if not redis_up:
            print(f"Got answer from redis-server ping: {redis_up}")
            raise(Exception("Redis server not up?"))

        self.job_queue_trace_gen = rq.Queue(REDIS_QUEUE_NAME_TRACE_GEN_JOBS, connection=self.conn)
        self.job_queue_state_gen = rq.Queue(REDIS_QUEUE_NAME_STATE_GEN_JOBS, connection=self.conn)
        self.job_queue_modeling = rq.Queue(REDIS_QUEUE_NAME_MODELING, connection=self.conn)
        # sysrel
        self.job_queue_replay_gen = rq.Queue(REDIS_QUEUE_NAME_REPLAY_GEN_JOBS, connection=self.conn)
        self.job_queue_traces_for_filtering = rq.Queue(REDIS_QUEUE_NAME_TRACES_FOR_FILTERING_JOBS, connection=self.conn)
        self.job_queue_trace_guided_analysis = rq.Queue(REDIS_QUEUE_NAME_TRACE_GUIDED_ANALYSIS_JOBS, connection=self.conn)
        self.job_queue_guided_symex = rq.Queue(REDIS_QUEUE_NAME_GUIDED_SYMEX_JOBS, connection=self.conn)
        self.job_queue_entry_point_state_gen = rq.Queue(REDIS_QUEUE_NAME_ENTRY_POINT_STATE_GEN_JOBS, connection=self.conn)

        self.uniqueCopyFuncContexts = set()
        self.spawn_workers(self.parent.num_main_fuzzer_procs)
        time.sleep(1)
        self.check_running_procs()


    def check_running_procs(self):
        for queue_name, procs in self.worker_procs.items():
            for proc in procs:
                if proc.poll() is not None:
                    raise Exception("'{}' worker spawned by WorkerPool is not running anymore".format(queue_name))

        if self.db_proc and self.db_proc.poll() is not None:
            raise Exception("database process spawned by WorkerPool is not running anymore")

    def db_up(self):
        try:
            res = self.conn.ping()
            if not res:
                self.conn.close()
                self.conn = redis.Redis(port=self.redis_port)
                logger.warning("Redis server up, but ping still errored.")
                return self.conn.ping()
            else:
                logger.warning(f"Redis ping returned: {res}")
            return res
        except redis.exceptions.ConnectionError:
            logger.info("Could not establish connection with redis (yet)")
            return False

    def worker_log_path(self, queue_name, noqueue=False):
        if noqueue:
           return self.parent.get_logfile_path("worker_{}".format(queue_name))
        else:
           return self.parent.get_logfile_path("worker_{}_{:02d}".format(queue_name, len(self.worker_procs[queue_name])))

    # sysrel

    def getHash(self, obj):
        hash_object = hashlib.sha256(str(obj).encode())
        logger.info(f"hash {hash_object.hexdigest()}") 
        return hash_object.hexdigest()

    def getHashForMap(self, mapobj):
        hstr = ""
        for k in mapobj.keys():
            hstr += str(mapobj[k])
        hash_object = hashlib.sha256(hstr.encode())
        return hash_object.hexdigest()

    def check_and_update_entry_points(self, entry_point_file_name):
        neweps = set()
        logger.info(f"Trying to open entry file {entry_point_file_name}")
        taintedaddrs = ""
        with open(entry_point_file_name, 'r') as eps:
             #logger.info(f"File opened succ")              
             for line in eps:
                 #logger.info(f"line: {line} ep? {ep}")              
                 if "[UNIQUE ENTRY POINT]:" in line:
                     logger.info(f"Entry point line: {line}")
                     hv = self.getHash(line)   
                     if hv in self.entryPointHashes:
                        continue
                     self.entryPointHashes.add(hv)
                     pc = line.strip().split(':')[1]
                     neweps.add(pc)
                 if "Tainted addresses:" in line:
                     taintedaddrs += line.split(':')[1] + " "
        return neweps, taintedaddrs


    # sysrel
    def spawn_replay_gen_worker(self):
        if self.write_logs:
            logger.info("[WorkerPool] enabling logging for replay gen worker!")
            stdout_path = open(self.worker_log_path(REDIS_QUEUE_NAME_REPLAY_GEN_JOBS), "w")
        else:
            logger.info("[WorkerPool] suppressing logging for replayer gen worker")
            stdout_path = subprocess.DEVNULL

        self.worker_procs[REDIS_QUEUE_NAME_REPLAY_GEN_JOBS].append(subprocess.Popen(["python3", "-m", "rq.cli", "worker", "--url", f"redis://localhost:{self.redis_port}", "-q", "-w",  class_path(replaygen.ReplayGenWorker), REDIS_QUEUE_NAME_REPLAY_GEN_JOBS], stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)) #pylint: disable=consider-using-with

        logger.info("[WorkerPool] Replay gen worker created successfully!")
         

    def spawn_traces_for_filtering_worker(self):
        #replay_venv_path = find_replay_venv()
        
        #venv_python_path = os.path.join(replay_venv_path, "bin", "python3")
        #if not os.path.exists(venv_python_path):
        #    raise Exception("python inside venv could not be found in replay venv")

        if self.write_logs:
            logger.info("[WorkerPool] enabling logging for traces for filtering worker!")
            stdout_path = open(self.worker_log_path(REDIS_QUEUE_NAME_TRACES_FOR_FILTERING_JOBS), "w")
        else:
            logger.info("[WorkerPool] suppressing logging for traces for filtering worker")
            stdout_path = subprocess.DEVNULL

        #popen_args = [venv_python_path, "-m", "hyfive_analysis.rq_worker", "--port", f"{self.redis_port:d}"]
        #popen_args += [ REDIS_QUEUE_NAME_WINDOW_REPLAYER_JOBS ]

        #worker_proc = subprocess.Popen(popen_args, stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT) #pylint: disable=consider-using-with

        #self.worker_procs[REDIS_QUEUE_NAME_WINDOW_REPLAYER_JOBS].append(worker_proc)


        self.worker_procs[REDIS_QUEUE_NAME_TRACES_FOR_FILTERING_JOBS].append(subprocess.Popen(["python3", "-m", "rq.cli", "worker", "--url", f"redis://localhost:{self.redis_port}", "-q", "-w",  class_path(tracegen.TraceGenWorker), REDIS_QUEUE_NAME_TRACES_FOR_FILTERING_JOBS], stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)) #pylint: disable=consider-using-with

        logger.info("[WorkerPool] Traces for filtering worker created successfully!")

    # sysrel
    def spawn_trace_guided_analysis_worker(self):
        trace_guided_analysis_venv_path = find_trace_guided_analysis_venv()
        
        venv_python_path = os.path.join(trace_guided_analysis_venv_path, "bin", "python3")
        if not os.path.exists(venv_python_path):
            raise Exception("python inside venv could not be found in trace guided analysis venv")

        if self.write_logs:
            logger.info("[WorkerPool] enabling logging for trace guided analysis worker!")
            stdout_path = open(self.worker_log_path(REDIS_QUEUE_NAME_TRACE_GUIDED_ANALYSIS_JOBS), "w")
        else:
            logger.info("[WorkerPool] suppressing logging for trace guided analysis worker")
            stdout_path = subprocess.DEVNULL


        popen_args = [venv_python_path, "-m", "hyfive_analysis.TGA.rq_worker", "--port", f"{self.redis_port:d}"]
        popen_args += [ REDIS_QUEUE_NAME_TRACE_GUIDED_ANALYSIS_JOBS ]

        worker_proc = subprocess.Popen(popen_args, stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT) #pylint: disable=consider-using-with

        self.worker_procs[REDIS_QUEUE_NAME_TRACE_GUIDED_ANALYSIS_JOBS].append(worker_proc)

        logger.info("[WorkerPool] Trace guided analysis worker created successfully!")

    def spawn_entry_point_state_gen_worker(self):
        if self.write_logs:
            logger.info("[WorkerPool] enabling logging for entry point state gen worker!")
            stdout_path = open(self.worker_log_path(REDIS_QUEUE_NAME_ENTRY_POINT_STATE_GEN_JOBS), "w")
        else:
            stdout_path = subprocess.DEVNULL

        self.worker_procs[REDIS_QUEUE_NAME_ENTRY_POINT_STATE_GEN_JOBS].append(subprocess.Popen(["python3", "-m", "rq.cli", "worker", "--url", f"redis://localhost:{self.redis_port}", "-q", "-w",  class_path(entrypointstategen.EntryPointStateGenWorker), REDIS_QUEUE_NAME_ENTRY_POINT_STATE_GEN_JOBS], stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)) #pylint: disable=consider-using-with


    # sysrel
    def spawn_guided_symex_worker(self):
        guided_symex_venv_path = find_guided_symex_venv()
        
        venv_python_path = os.path.join(guided_symex_venv_path, "bin", "python3")
        if not os.path.exists(venv_python_path):
            raise Exception("python inside venv could not be found in guided symex venv")

        if self.write_logs:
            logger.info("[WorkerPool] enabling logging for guided symex worker!")
            stdout_path = open(self.worker_log_path(REDIS_QUEUE_NAME_GUIDED_SYMEX_JOBS), "w")
        else:
            logger.info("[WorkerPool] suppressing logging for guided symex worker")
            stdout_path = subprocess.DEVNULL

        popen_args = [venv_python_path, "-m", "hyfive_analysis.GSYMEX.rq_worker", "--port", f"{self.redis_port:d}"]
        popen_args += [ REDIS_QUEUE_NAME_GUIDED_SYMEX_JOBS ]

        worker_proc = subprocess.Popen(popen_args, stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT) #pylint: disable=consider-using-with

        self.worker_procs[REDIS_QUEUE_NAME_GUIDED_SYMEX_JOBS].append(worker_proc)

        logger.info("[WorkerPool] Guided symex worker created successfully!")

    def spawn_gen_worker(self):
        if self.write_logs:
            logger.info("[WorkerPool] enabling logging for gen worker!")
            stdout_path = open(self.worker_log_path(REDIS_QUEUE_NAME_TRACE_GEN_JOBS), "w")
        else:
            stdout_path = subprocess.DEVNULL

        self.worker_procs[REDIS_QUEUE_NAME_TRACE_GEN_JOBS].append(subprocess.Popen(["python3", "-m", "rq.cli", "worker", "--url", f"redis://localhost:{self.redis_port}", "-q", "-w",  class_path(tracegen.TraceGenWorker), REDIS_QUEUE_NAME_STATE_GEN_JOBS, REDIS_QUEUE_NAME_TRACE_GEN_JOBS], stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)) #pylint: disable=consider-using-with

    def spawn_modeling_worker(self, burst=False):
        modeling_venv_path = find_modeling_venv()

        venv_python_path = os.path.join(modeling_venv_path, "bin", "python3")
        if not os.path.exists(venv_python_path):
            raise Exception("python inside venv could not be found in modeling venv")

        if self.write_logs:
            logger.info("[WorkerPool] enabling logging for modeling worker!")
            stdout_path = open(self.worker_log_path(REDIS_QUEUE_NAME_MODELING) + ("_burst" if burst else ""), "w")
        else:
            logger.info("[WorkerPool] suppressing logging for modeling worker")
            stdout_path = subprocess.DEVNULL

        popen_args = [venv_python_path, "-m", "fuzzware_modeling.rq_worker", "--port", f"{self.redis_port:d}"]
        if burst:
            popen_args += ["--burst"]
        popen_args += [ REDIS_QUEUE_NAME_MODELING ]

        worker_proc = subprocess.Popen(popen_args, stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT) #pylint: disable=consider-using-with

        if not burst:
            self.worker_procs[REDIS_QUEUE_NAME_MODELING].append(worker_proc)

    def start_redis(self):
        logger.info("[WorkerPool] Starting redis server")

        for i in range(1, REDIS_PORT_RETRIES+1):
            self.redis_port = random.randint(REDIS_PORT_RANGE_START, REDIS_PORT_RANGE_END)
            self.db_proc = subprocess.Popen(['redis-server', '--save', '', '--port', f'{self.redis_port:d}', '--logfile', os.path.join(self.parent.base_dir, nc.PIPELINE_DIRNAME_LOGS, 'redis.log') ], stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT) #pylint: disable=consider-using-with

            time.sleep(0.25)
            self.conn = redis.Redis(port=self.redis_port)
            if self.db_proc.poll() is not None:
                logger.warning(f"[Redis server starting try {i} / {REDIS_PORT_RETRIES}] Trying to start redis on port {self.redis_port} failed immediately. Retrying...")
                continue

            for _ in range(REDIS_SERVER_TIMEOUT):
                if self.db_up():
                    logger.info(f"Redis server successfully started on port {self.redis_port:d}")
                    return

                logger.info("Waiting for redis server to come up...")
                time.sleep(1)

            logger.warning(f"[Redis server starting try {i} / {REDIS_PORT_RETRIES}] Trying to start redis on port {self.redis_port} did not come up even after waiting. Retrying...")
            self.db_proc.kill()
            self.db_proc = None

        # If we were unable to start redis, give up
        raise Exception("Redis server did not come up")

    def spawn_workers(self, num_fuzzer_procs):
        num_running_modeling_workers = len(rq.Worker.all(queue=self.job_queue_modeling))
        num_req_modeling_workers = max(ceil(num_fuzzer_procs / 4), 1)
        if num_req_modeling_workers > num_running_modeling_workers:
            for _ in range(num_req_modeling_workers - num_running_modeling_workers):
                logger.info("[WorkerPool] Spawning additional modeling worker")
                self.spawn_modeling_worker()

        # All workers which listen to trace generation also listen to state generation, so we can count them from one of the queues
        num_running_gen_workers = len(rq.Worker.all(queue=self.job_queue_trace_gen))
        num_req_gen_workers = max(ceil(num_fuzzer_procs / 2), 1)
        if num_req_gen_workers > num_running_gen_workers:
            for _ in range(num_req_gen_workers - num_running_gen_workers):
                logger.info("[WorkerPool] Spawning additional gen worker")
                self.spawn_gen_worker()
       
        # sysrel
        num_running_traces_for_filtering_workers = len(rq.Worker.all(queue=self.job_queue_traces_for_filtering))
        num_req_traces_for_filtering_workers = max(ceil(num_fuzzer_procs / 4), 1)
        if num_req_traces_for_filtering_workers > num_running_traces_for_filtering_workers:
            for _ in range(num_req_traces_for_filtering_workers - num_running_traces_for_filtering_workers):
                logger.info("[WorkerPool] Spawning additional traces for filtering worker")
                self.spawn_traces_for_filtering_worker()

        # sysrel
        num_running_replay_gen_workers = len(rq.Worker.all(queue=self.job_queue_replay_gen))
        num_req_replay_gen_workers = max(ceil(num_fuzzer_procs / 4), 1)
        if num_req_replay_gen_workers > num_running_replay_gen_workers:
            for _ in range(num_req_replay_gen_workers - num_running_replay_gen_workers):
                logger.info("[WorkerPool] Spawning additional replay gen worker")
                self.spawn_replay_gen_worker()


        # sysrel
        num_running_trace_guided_analysis_workers = len(rq.Worker.all(queue=self.job_queue_trace_guided_analysis))
        num_req_trace_guided_analysis_workers = max(ceil(num_fuzzer_procs / 4), 1)
        if num_req_trace_guided_analysis_workers > num_running_trace_guided_analysis_workers:
            for _ in range(num_req_trace_guided_analysis_workers - num_running_trace_guided_analysis_workers):
                logger.info("[WorkerPool] Spawning additional trace guided analysis workers")
                self.spawn_trace_guided_analysis_worker()

        num_running_entry_point_state_gen_workers = len(rq.Worker.all(queue=self.job_queue_entry_point_state_gen))
        num_req_entry_point_state_gen_workers = max(ceil(num_fuzzer_procs / 4), 1)
        if num_req_entry_point_state_gen_workers > num_running_entry_point_state_gen_workers:
            for _ in range(num_req_entry_point_state_gen_workers - num_running_entry_point_state_gen_workers):
                logger.info("[WorkerPool] Spawning additional entry point state gen workers")
                self.spawn_entry_point_state_gen_worker()

        # sysrel
        num_running_guided_symex_workers = len(rq.Worker.all(queue=self.job_queue_guided_symex))
        num_req_guided_symex_workers = max(ceil(num_fuzzer_procs / 4), 1)
        if num_req_guided_symex_workers > num_running_guided_symex_workers:
            for _ in range(num_req_guided_symex_workers - num_running_guided_symex_workers):
                logger.info("[WorkerPool] Spawning additional guided symex worker")
                self.spawn_guided_symex_worker()
 

    def shutdown(self, hard=False):
        logger.info("[WorkerPool] Killing workers")

        if hard:
            for queue_name, procs in self.worker_procs.items():
                # RIP workers
                for proc in procs:
                    proc.kill()

            if self.db_proc:
                self.db_proc.kill()
                self.db_proc = None
        else:
            for queue_name, procs in self.worker_procs.items():
                # Give workers a graceful exit opportunity
                for proc in procs:
                    proc.terminate()

            for queue_name, procs in self.worker_procs.items():
                while procs:
                    proc = procs.pop()
                    if proc.poll() is None:
                        logger.info(f"Waiting for '{queue_name}' worker proc")
                        time.sleep(WORKER_SHUTDOWN_TIMEOUT)
                        proc.kill()

            if self.db_proc:
                self.db_proc.terminate()

    def pause(self, excludeSet):
        for queue_name, procs in self.worker_procs.items():
            if queue_name in excludeSet:
               continue
            logger.info(f"Pausing queue {queue_name}")
            for proc in procs:
                proc.send_signal(signal.SIGSTOP) 

    def resume(self, excludeSet):
        for queue_name, procs in self.worker_procs.items():
            if queue_name in excludeSet:
               continue
            logger.info(f"Resuming queue {queue_name}")
            for proc in procs:
                proc.send_signal(signal.SIGCONT) 
    # sysrel
    def enqueue_job_gen_trace_events(self, input_path, MMIOpc, MMIOaddress, window_trace_path):
        #input_path = os.path.abspath(input_path)
        #window_trace_path = os.path.abspath(window_trace_path)

        #outdir = self.parent.window_replay_dir
        #out_path = os.path.join(outdir, input_path)
        #logger.info(f"enqueing window replay")
        #self.jobs.append(self.job_queue_window_replayer.enqueue(
        #    WINDOW_REPLAY_INCLUDE_PATH, [(input_path, window_trace_path, out_path)]
        #))
        #input_path = os.path.abspath(input_path)
        #window_trace_path = os.path.abspath(window_trace_path)

        _, input_file_name = os.path.split(input_path)
        pipeline_name, session_name, fuzzer_instance_name, input_type, input_filename = get_input_path_components(input_path)

        bbl_trace_path, ram_trace_path, mmio_trace_path, bbl_set_path, mmio_set_path, window_set_path, _ = trace_paths_for_input(input_path)

        #if 'mmio_addr' in self.parent.default_config_map:
        #   target = self.parent.default_config_map['mmio_addr']
        #   target_hex_value = hex(target)
        #   target_hex_value = target_hex_value[2:]           

        #   found = False
        #   with open(mmio_set_path, 'r') as ms:
        #        for line in ms.readline():
        #            logger.info(f"{mmio_set_path}:{line}")
        #            if target_hex_value + " r" in line:
        #               found = True
        #               break
        #        logger.info(f"Read of target MMIO hex value {target_hex_value} in {mmio_set_path}? {found} input file {input_path}")

        #   if not found:
              #logger.info(f"Read of target MMIO hex value {target_hex_value} could not be found in {mmio_set_path}, not generating trace files for {input_path}")
        #      return  

        #logger.info(f"disecting input path {input_path} : pipeline_name {pipeline_name} session_name {session_name} fuzzer_instance_name {fuzzer_instance_name} input_type {input_type} input_filename {input_filename}")
        out_path = self.parent.base_dir + "/" + session_name + "/" + nc.SESS_DIRNAME_FUZZERS + "/" + fuzzer_instance_name + "/" + nc.SESS_DIRNAME_TRACES_FOR_FILTERING + "/" + "replay_" + input_file_name
        #logger.info(f"enqueing window replay at out path {out_path} input {input_path} parent base {self.parent.base_dir} session {session_name}")
        #bbl_trace_path, ram_trace_path, mmio_trace_path = out_path, out_path, out_path
        bbl_trace_path = self.parent.base_dir + "/" + session_name + "/" + nc.SESS_DIRNAME_FUZZERS + "/" + fuzzer_instance_name + "/" + nc.SESS_DIRNAME_TRACES_FOR_FILTERING + "/" + "window_bbl_" + input_file_name        
        ram_trace_path = self.parent.base_dir + "/" + session_name + "/" + nc.SESS_DIRNAME_FUZZERS + "/" + fuzzer_instance_name + "/" + nc.SESS_DIRNAME_TRACES_FOR_FILTERING + "/" + "window_ram_" + input_file_name        
        mmio_trace_path = self.parent.base_dir + "/" + session_name + "/" + nc.SESS_DIRNAME_FUZZERS + "/" + fuzzer_instance_name + "/" + nc.SESS_DIRNAME_TRACES_FOR_FILTERING + "/" + "window_mmio_" + input_file_name        
        bbl_set_path, mmio_set_path, window_set_path = None, None, None

        config_path = os.path.join(self.parent.base_dir, session_name, SESS_FILENAME_CONFIG)
        job = self.job_queue_trace_gen.enqueue(tracegen.gen_traces, config_path, input_path,
            bbl_trace_path=bbl_trace_path,
            ram_trace_path=ram_trace_path,
            mmio_trace_path=mmio_trace_path,
            bbl_set_path=bbl_set_path,
            mmio_set_path=mmio_set_path,
            window_set_path=window_set_path,
            extra_args=self.parent.curr_main_session.extra_runtime_args,
            result_ttl=RQ_RESULT_TTL, ttl=RQ_JOB_TTL, failure_ttl=RQ_JOB_FAILURE_TTL
        )
        logger.info(f"JOB: {job.func_name} {job.id} mmio state gen") 
        self.jobs.append(job)
        #log_path = self.parent.base_dir + "/" + session_name + "/" + nc.SESS_DIRNAME_FUZZERS + "/" + fuzzer_instance_name + "/" + nc.PIPELINE_DIRNAME_WINDOW_REPLAY + "/" + "replay_full_" + input_file_name        
        #logstream = open(log_path, "w")
        #subprocess.Popen(["fuzzware", "replay", "--debug", "-M", "-t", input_path],  stdout=logstream, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT) 

    def filter(self, trace_file_name):
        trace_file_path = os.path.abspath(trace_file_name)
        result = False
        logger.info(f"Filtering for {trace_file_path} file {trace_file_name}")
        for fn, ft in self.parent.copy_functions.items():
            cpstr = fn + " from"
            try:
               output = subprocess.check_output(["grep", cpstr, trace_file_path], text=True)
            except subprocess.CalledProcessError:
               continue
            for ln in output.splitlines():
                   #logger.info(f"Grep result {ln} in {trace_file_path}")
                   sln = ln.split(":")
                   if len(sln) >= 2:
                      #logger.info(f"Checking context {sln[1]}")
                      if not sln[1] in self.uniqueCopyFuncContexts:
                         result = True
                         self.uniqueCopyFuncContexts.add(sln[1])
            #output = subprocess.check_output(["cut", "-d:", "-f2"], stdin=p1.stdout, text=True)
            #p1.wait()
            #ol = output.splitlines()
            #logger.info(f"[REPLAY FILTER] Checking copy function {fn} using {str} contexts in {trace_file_name} output number of lines {len(ol)}")
            #for line in output.splitlines():
            #    logger.info(f"[REPLAY FILTER] Processing {line}")
            #    if not line in self.uniqueCopyFuncContexts:
            #       result = True
            #       self.uniqueCopyFuncContexts.add(line)
        return result

    # sysrel
    def enqueue_job_trace_guided_analysis(self, trace_file_name, MMIO_address, pc):
        #if not self.filter(trace_file_name):
        #   return
        #if 'mmio_addr' in self.parent.default_config_map:
        #   target = self.parent.default_config_map['mmio_addr']
        #   logger.info(f"Target MMIO address is {hex(target)}")
        #   if not MMIO_address == str(target):
        #      logger.info(f"Skipping non target address {hex(int(MMIO_address))}")
        #      return
        trace_index = 0
        #max = 0
        #for fn in self.parent.copy_functions.keys():
        #    sub = subprocess.Popen(["grep", "-n", fn, trace_file_name], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL, stderr=subprocess.PIPE)
        #    while True:
        #        ln = sub.stdout.readline()
        #        if not ln:
        #           break
        #        else:
        #           if not isinstance(ln, str):
        #              ln = ln.decode('utf-8', 'replace')
        #           sln = ln.split("Calling function")
        #           if sln:
        #              sln2 = sln[0].split(':')
        #              if len(sln2) >= 2:
        #                 lineno = int(sln2[-2])
        #                 if lineno > max:
        #                    max = lineno
        trace_index = 100000
        #if max > trace_index:
        #   trace_index = max
        base_dir, elf_file = os.path.split(self.parent.firmware_path)
        analysis_type = ["read_copy_functions","trace_guided_analysis"]
        #results_path = nc.entry_point_for_replay_path(trace_file_name, hex(int(MMIO_address)), hex(int(pc)))
        results_path = nc.entry_point_for_replay_path(trace_file_name)
        temp_results_path = nc.temp_for_entry_point_path(results_path)
        statistics_path = nc.stats_for_entry_point(results_path)
        job = self.job_queue_trace_guided_analysis.enqueue(
            TRACE_GUIDED_ANALYSIS_INCLUDE_PATH, 
            firmware_path=base_dir,
            binary=self.parent.firmware_path,
            MMIO_datareg=MMIO_address,
            taint_pc=pc,
            copy_functions_path=self.parent.copy_functions_path,
            analysis_type=analysis_type,
            #callchain_depth_bound=3,
            callchain_depth_bound=self.parent.tga_depth,
            trace_index=trace_index,
            temp_results_path=temp_results_path,
            results_path=results_path,
            trace_path=trace_file_name,
            statistics_path=statistics_path,
            uniqueCopyFuncContexts_path=self.parent.unique_contexts_path,
            result_ttl=RQ_RESULT_TTL, ttl=RQ_JOB_TTL, failure_ttl=RQ_JOB_FAILURE_TTL, job_timeout=RQ_TRACE_GUIDED_JOB_TIMEOUT
        )
        logger.info(f"JOB: {job.func_name} {job.id} enqueing trace {trace_file_name} and mmio {MMIO_address} pc {pc} trace index {trace_index} tga depth {self.parent.tga_depth } pair for guided analysis")
        self.jobs.append(job)

    # sysrel
    def enqueue_job_gen_guided_symex(self, entry_point_state_path):
        input_filename = get_input_file_from_entry_point_state_file(entry_point_state_path)
        entry_point_state_path = os.path.abspath(entry_point_state_path)

        tainted_addrs_path = os.path.join(self.parent.tainted_addrs_dir, get_tainted_file_from_entry_point(entry_point_state_path))
        outdir = self.parent.vulnerability_dir
        out_path = os.path.join(outdir, input_filename)
        job = self.job_queue_guided_symex.enqueue(
            GUIDED_SYMEX_INCLUDE_PATH, [entry_point_state_path], out_path, self.parent.copy_functions_path, tainted_addrs_path,
            # Give the modeling timeout mechanism time to react to an impending timeout
            RQ_ENTRY_POINT_STATEGEN_JOB_TIMEOUT - 60,
            result_ttl=RQ_RESULT_TTL, ttl=RQ_JOB_TTL, failure_ttl=RQ_JOB_FAILURE_TTL, job_timeout=RQ_ENTRY_POINT_STATEGEN_JOB_TIMEOUT
        )
        logger.info(f"JOB: {job.func_name} {job.id} enqueing for guided symex {entry_point_state_path}")
        self.jobs.append(job)

    def enqueue_job_trace_gen(self, input_path):
        input_path = os.path.abspath(input_path)

        _, session_name, _, _, _ = get_input_path_components(input_path)
        bbl_trace_path, ram_trace_path, mmio_trace_path, bbl_set_path, mmio_set_path, window_set_path, _ = trace_paths_for_input(input_path)
        if not self.parent.do_full_tracing:
            bbl_trace_path, ram_trace_path, mmio_trace_path = None, None, None

        config_path = os.path.join(self.parent.base_dir, session_name, SESS_FILENAME_CONFIG)
        job = self.job_queue_trace_gen.enqueue(tracegen.gen_traces, config_path, input_path,
            bbl_trace_path=bbl_trace_path,
            ram_trace_path=ram_trace_path,
            mmio_trace_path=mmio_trace_path,
            bbl_set_path=bbl_set_path,
            mmio_set_path=mmio_set_path,
            window_set_path=window_set_path,
            extra_args=self.parent.curr_main_session.extra_runtime_args,
            result_ttl=RQ_RESULT_TTL, ttl=RQ_JOB_TTL, failure_ttl=RQ_JOB_FAILURE_TTL
        )
        logger.info(f"JOB: {job.func_name} {job.id} enqueing trace gen job")        
        self.jobs.append(job)

    def enqueue_job_replay_gen(self, input_path):
        if input_path in self.replayed_paths:
           return
        self.replayed_paths.add(input_path)
        if 'mmio_addr' in self.parent.default_config_map:
           target = self.parent.default_config_map['mmio_addr']
        else:
            logger.info(f"No MMIO target set, skipping replay generation!!!")
            return
        logger.info(f"Adding input path {input_path} to the replay job queue")

        target_func_addr = None
        target_func_size = None
        if len(self.parent.target_function_info):
           if 'target_caller' in self.parent.default_config_map:
              target_func_addr, target_func_size = self.parent.target_function_info[self.parent.default_config_map['target_caller']] 
           elif 'target_function' in self.parent.default_config_map:
              target_func_addr, target_func_size = self.parent.target_function_info[self.parent.default_config_map['target_function']] 
        pipeline_name, session_name, fuzzer_instance_name, input_type, input_filename = get_input_path_components(input_path)
        job = self.job_queue_replay_gen.enqueue(replaygen.replay, 
            input_path, input_filename, self.parent.base_dir, session_name, fuzzer_instance_name, target, target_func_addr, target_func_size, self.parent.explore_read_tainted, self.parent.explore_tainted_access_in_copy_func, self.parent.copy_functions_path
        )
        logger.info(f"JOB: {job.func_name} {job.id} enqueing for replay gen")
        self.jobs.append(job)

    def enqueue_job_complete_trace(self, trace_file_name):
        logger.info(f"Adding trace file {trace_file_name} to the replay job queue")

        job = self.job_queue_complete_trace.enqueue(
            TRACE_GUIDED_ANALYSIS_INCLUDE_PATH, trace_file_name
        )
        logger.info(f"JOB: {job.func_name} {job.id} enqueing for complete trace")
        self.jobs.append(job) 

    def enqueue_job_entry_point(self, entry_point_file_name):
        neweps, taintedaddrs = self.check_and_update_entry_points(entry_point_file_name)
        if len(neweps) == 0:
           return
        l = ",".join([pc for pc in neweps])
        logger.info(f"Adding {len(neweps)} entry points tuple to the entry point queue {l}")
        input_file = get_input_path_from_entry_point(entry_point_file_name)
        input_path = os.path.abspath(input_file)

        _, session_name, _, _, _ = get_input_path_components(input_path)
        config_path = os.path.join(self.parent.base_dir, session_name, SESS_FILENAME_CONFIG)
        entry_point_state_name_prefix = entry_point_state_name_prefix_for_input_path(input_path)

        tainted_path = os.path.join(self.parent.tainted_addrs_dir, get_tainted_file_from_entry_point(entry_point_file_name))
        logger.info(f"Recording tainted addresses in {tainted_path}")
        with open(tainted_path, 'w') as tfs:
             tfs.write(f"{taintedaddrs}")
             tfs.close()

        target = ""
        if 'mmio_addr' in self.parent.default_config_map:
           target = self.parent.default_config_map['mmio_addr']

        job = self.job_queue_entry_point_state_gen.enqueue(entrypointstategen.gen_entry_point_states_at, config_path, input_path,
            self.parent.entry_point_states_dir,
            neweps,
            hex(target),
            name_prefix=entry_point_state_name_prefix,
            extra_args=self.parent.curr_main_session.extra_runtime_args,
            result_ttl=RQ_RESULT_TTL, ttl=RQ_JOB_TTL, failure_ttl=RQ_JOB_FAILURE_TTL, job_timeout=RQ_ENTRY_POINT_STATEGEN_JOB_TIMEOUT
        )
        logger.info(f"JOB: {job.func_name} {job.id} Entry point state generator job created") 
        self.jobs.append(job)


    #def enqueue_job_entry_point_state(self, ep_state_file_name):
    #    logger.info(f"Adding entry point tuple to the entry point queue")
    #    self.jobs.append(self.job_queue_entry_point.enqueue(
    #        GUIDED_SYMEX_INCLUDE_PATH, trace_file_name, entry_tuple
    #    ))

    def enqueue_job_gen_mmio_states(self, input_path, pc_mmio_address_pairs):
        input_path = os.path.abspath(input_path)

        _, session_name, _, _, _ = get_input_path_components(input_path)
        config_path = os.path.join(self.parent.base_dir, session_name, SESS_FILENAME_CONFIG)
        state_name_prefix = mmio_state_name_prefix_for_input_path(input_path)

        job = self.job_queue_state_gen.enqueue(stategen.gen_mmio_states_at, config_path, input_path,
            self.parent.mmio_states_dir,
            pc_mmio_address_pairs,
            name_prefix=state_name_prefix,
            extra_args=self.parent.curr_main_session.extra_runtime_args,
            result_ttl=RQ_RESULT_TTL, ttl=RQ_JOB_TTL, failure_ttl=RQ_JOB_FAILURE_TTL, job_timeout=RQ_STATEGEN_JOB_TIMEOUT
        )
        logger.info(f"JOB: {job.func_name} {job.id} mmio state gen") 
        self.jobs.append(job)

    def enqueue_job_analyze_model(self, input_filename, mmio_state_path):
        mmio_state_path = os.path.abspath(mmio_state_path)

        outdir = self.parent.config_snippets_dir
        out_path = os.path.join(outdir, input_filename)
        job = self.job_queue_modeling.enqueue(
            MMIO_MODELING_INCLUDE_PATH, [mmio_state_path], out_path, self.parent.default_config_map,
            # Give the modeling timeout mechanism time to react to an impending timeout
            RQ_MODELING_JOB_TIMEOUT - 30,
            result_ttl=RQ_RESULT_TTL, ttl=RQ_JOB_TTL, failure_ttl=RQ_JOB_FAILURE_TTL, job_timeout=RQ_MODELING_JOB_TIMEOUT
        )
        logger.info(f"JOB: {job.func_name} {job.id} analyze model") 
        self.jobs.append(job)  

    def clean_lost_jobs(self):
        to_delete = []
        for job in self.jobs:
            try:
                job.refresh()
            except rq.exceptions.NoSuchJobError:
                self.parent.add_warning_line("Cleaning up no longer existing job: {} [args: {}]".format(job, job.args))
                to_delete.append(job)

        for job in to_delete:
            self.jobs.remove(job)

    def collect_job_timings(self, max_jobs=-1):
        # do this at most every second or if we looped for quite a bit so we don't lose jobs
        new_job_timing_entries = []
        num_queried = 0
        for job in self.jobs:
            num_queried += 1
            try:
               job_status = job.get_status()
               if job_status in ('finished', 'failed'):
                  # Get timing data from db
                  try:
                      job.refresh()
                  except rq.exceptions.NoSuchJobError:
                    pass

                  if job_status == 'failed':
                     self.parent.add_warning_line("job failed: {}, started at: {}, args: {}, exc_info: {}".format(job.func_name, job.started_at, job.args, job.exc_info))
                     logger.debug(f"JOB FAILURE: {job.func_name} DUE TO {job.exc_info}")
                  self.jobs.remove(job)
                  new_job_timing_entries.append((job.func_name, job_status, job.enqueued_at, job.started_at, job.ended_at))
            except rq.exceptions.InvalidJobOperation:
               logger.info(f"WARNING: Failed to retrieve status of job {job.id}!")
               pass
           

            if max_jobs != -1 and num_queried > max_jobs:
                # If we are busy, don't spend too much time housekeeping
                break

        if new_job_timing_entries:
            add_job_timing_entries(self.parent.job_timings_file, new_job_timing_entries)
            self.parent.job_timings_file.flush()

    def check_lost_jobs(self):
        for i in range(min(len(self.jobs), 10)):
            try:
                job = self.jobs[i]
                job.refresh()
                logger.info("remaining job ({}, status: {}): {}".format(job.func_name, job.get_status(), repr(job)))
            except rq.exceptions.NoSuchJobError:
                logger.error("job no longer exists: {} [args: {}]".format(job.func_name, job.args))
                self.clean_lost_jobs()
                break
