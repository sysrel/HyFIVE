import argparse
import yaml

import os
import logging
import signal
import traceback

import angr
import claripy
import archinfo

from .angr_utils import CUSTOM_STASH_NAMES, insn_addr_from_SimIRSBNoDecodeError
from .base_state_snapshot import EntryPointBaseStateSnapshot
from .fuzzware_utils.config import update_config_file, TRACE_NAME_TOKENS
from .arch_specific.arm_thumb_quirks import try_handling_decode_error, model_arch_specific
from .arch_specific.arm_thumb_regs import REGULAR_REGISTER_NAMES
from .logging_utils import set_log_levels
from .liveness_plugin import LivenessPlugin
from .tainted_memory_plugin import TaintedMemoryPlugin
from .exploration_techniques import MMIOVarScoper, FunctionReturner, FirstStateSplitDetector, TimeoutDetector, LoopEscaper, StateExplosionDetector, CopyFunctionSizeTainting, SymbolicReadChecker, SymbolicWriteChecker, NullPtrChecker
from .inspect_breakpoints import inspect_bp_tainted_intercept_read_after, inspect_bp_track_newly_added_constraints, inspect_bp_trace_call, inspect_bp_trace_ret, inspect_bp_trace_liveness_reg, inspect_bp_trace_liveness_mem, inspect_cond_is_mmio_read, inspect_bp_mmio_intercept_read_after, inspect_bp_trace_reads, inspect_bp_trace_writes, inspect_bp_singleton_ensure_mmio, inspect_after_address_concretization, inspect_bp_mem_read, inspect_bp_mem_write, inspect_bp_tainted_intercept_write_before, inspect_bp_tainted_intercept_read_before
from .arch_specific.arm_thumb_quirks import try_handling_decode_error, model_arch_specific
from .arch_specific.arm_thumb_regs import REGULAR_REGISTER_NAMES
from .logging_utils import set_log_levels
from .analyze_taint import perform_analyses

# Hard timeout
DEFAULT_TIMEOUT = 600
# Part of time set aside for stepping
EXPLORATION_TIMEOUT_FACTOR = 0.75


def main():
    print(f"[Guided Symex] Just started!")  

    parser = argparse.ArgumentParser(description="State restauration and vulnerability exploration")
    parser.add_argument('statefile', help="Path to the file containing the base state to start symbolic execution from")
    parser.add_argument('copy_functions_path', help="Path to the file containing the copy functions")
    parser.add_argument('tainted_addrs_path', help="Path to the file containing the tainted addresses")
    parser.add_argument('-r', '--result_file_path', default=None, help="Path to text file to append the analysis results to")
    parser.add_argument('-t', '--timeout', type=int, default=600, help=f"Timeout (in seconds)")

    # Debugging and logging
    parser.add_argument('-i', '--interactive', default=False, action='store_true', help="Drop into interactive shell in specific spots")
    parser.add_argument('-m', '--manual-stepping', default=False, action='store_true', help="Step interactively")
    parser.add_argument('-d', '--debug', default=False, action='store_true', help="Enable debug level output")

    args = parser.parse_args()

    # Delay import to delay
    #from .analyze_taint import perform_analyses
    print(f"{args.statefile}") 
    #print(f"{args.result_file_path}") 
    print(f"{args.copy_functions_path}") 
    print(f"{args.tainted_addrs_path}")
    print(f"{args.debug}") 
    print(f"{args.timeout}") 

    perform_analyses([args.statefile], args.copy_functions_path, args.tainted_addrs_path, is_debug=args.debug, timeout=args.timeout,cli_version=True)

if __name__ == '__main__':
    main()

