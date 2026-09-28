from ..run_target import run_target
import subprocess
import rq
import sys
from rq.worker import WorkerStatus
from fuzzware_pipeline.logging_handler import logging_handler

logger = logging_handler().get_logger("entrypointstate")

def gen_entry_point_states_at(config_path, input_path, output_dir, pcs, mmio_addr, name_prefix=None, extra_args=None):
    if extra_args is None:
        extra_args = []

    if name_prefix is not None:
        extra_args += ["--dumped-entry-point-name-prefix", name_prefix]

    extra_args += ["--entry-point-state-out", output_dir]

    extra_args += ["--dumped-entry-point-contexts", ",".join([pc for pc in pcs])]

    extra_args += ["--target-mmio-addr", mmio_addr]

    logger.info(f"Running target for entry point state generation with config path {config_path} input path {input_path} extra args {extra_args}")

    #run_target(config_path, input_path, extra_args, stdout=subprocess.DEVNULL, silent=True)
    # 0 return means timeout
    return_code = run_target(config_path, input_path, extra_args, stdout=sys.stdout, silent=True)
    return not return_code == 0


class EntryPointStateGenWorker(rq.Worker):


   def execute_job(self, job, queue):
      self.set_state(WorkerStatus.BUSY)
      config_path, input_path, output_dir, pcs, mmio_addr = job.args
      name_prefix, extra_args = job.kwargs.get("name_prefix", None), job.kwargs.get("extra_args", None)
      return_code = gen_entry_point_states_at(config_path, input_path, output_dir, pcs, mmio_addr, name_prefix, extra_args)
      if return_code:
         # Job success
         job.set_status(rq.job.JobStatus.FINISHED)

         self.handle_job_success(job=job, queue=queue,
                started_job_registry=queue.started_job_registry)
      else:
         # Job fail
         self.handle_job_failure(job=job, queue=queue,
                started_job_registry=queue.started_job_registry)
      self.set_state(WorkerStatus.IDLE)
