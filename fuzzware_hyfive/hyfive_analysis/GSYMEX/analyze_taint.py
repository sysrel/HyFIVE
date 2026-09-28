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



# Hard timeout
DEFAULT_TIMEOUT = 600
# Part of time set aside for stepping
EXPLORATION_TIMEOUT_FACTOR = 0.75

l = logging.getLogger("VANA")


# _tainted_addr__ADDR_IN_HEX__id
def tokenize_tainted_addrs(statefile, tainted_addrs):
    s1 = statefile.split('tainted_addr__')
    print(f"s1 size: {len(s1)}\n")
    if len(s1) == 2:
       s2 = s1[1].split('__id')
       print(f"s2 size: {len(s2)}\n")
       if len(s2) == 2:
          addrstr = s2[0].split('__')
          for addr in addrstr:
              print(f"tainted addr: {addr}\n")
              tainted_addrs.add(int(addr, 16))

def get_mmio_addr(statefile):
    s1 = statefile.split('mmio_addr_')
    print(f"s1 size: {len(s1)}\n")
    if len(s1) == 2:
       s2 = s1[1].split('_pc')
       print(f"s2 size: {len(s2)}\n")
       if s2:
          return s2[0]   
    return 0

def get_pc(state):
    try:
        addr = state.solver.eval_one(state.addr)
    except Exception as e:
        return 0
    return addr

def perform_analyses(statefiles, copy_functions_path, tainted_addrs_path, is_debug=False, timeout=DEFAULT_TIMEOUT, cli_version=False):
    if is_debug:
        set_log_levels(logging.DEBUG)
        l.debug("debug logging enabled")

    copy_functions = set()
    with open(copy_functions_path, 'r') as fs:
         for line in fs:
             fname, faddr, fsize = line.split(',')
             copy_functions.add((fname, int(faddr, 16), int(fsize, 16)))
             l.debug(f"Recording copy function {fname} at {faddr}")

    tainted_str = ""
    if not tainted_addrs_path == None:
       with open(tainted_addrs_path, 'r') as tstrm:
            while True:
                  line = tstrm.readline().strip()
                  if line == "":
                     break
                  tainted_str +=  line + " "

    #l.info(f"Tainted str: {tainted_str}")
    tainted_set = set()
    tl = tainted_str.split(" ")
    for t in tl:
        if t == "":
           continue 
        ts = t.split(',')
        if len(ts) != 2:
           continue
        #l.info(f"tainted address: {ts[0]} pc: {ts[1]}")
        tainted_set.add((int(ts[0], 16), int(ts[1], 16)))

    for statefile in statefiles:
        if any(tok in os.path.basename(statefile) for tok in TRACE_NAME_TOKENS):
            l.warning(f"Skipping trace file {statefile}")
            continue
        l.info(f"Working on {statefile}")
        tainted_addrs = set()
        # parse tainted addresses from the statefile
        tokenize_tainted_addrs(statefile, tainted_addrs)
        mmio_addr = get_mmio_addr(statefile)
        for ta in tainted_set:
            tainted_addrs.add(ta)
        perform_analysis(statefile, mmio_addr, tainted_addrs, copy_functions, is_debug=is_debug, timeout=timeout, cli_version=cli_version)
    return 

def setup_analysis(statefile, tainted_addrs, copy_functions, cli_version=False):
    if not os.path.isfile(statefile):
        raise ValueError("State file does not exist: {}".format(statefile))

    # Load snapshot and pre-constrain state registers for tainting
    project, initial_state, base_snapshot = EntryPointBaseStateSnapshot.from_state_file(statefile, None, cli_version)

    #cfg = project.analyses.CFG(data_references=True, cross_references=True)
 
    for fn, fa, fs in copy_functions:
        base_snapshot.set_copy_function_size(fa, fs)
        l.info(f"Copy function {hex(fa)} size {fs}")


    # sysrel
    tainted_addr_map = {}
    l.debug(f"Number of tainted addresses: {len(tainted_addrs)}")
    for addr, pc in tainted_addrs:
        sym = claripy.BVS("tainted_addr{:08x}".format(addr), 32)
        if not addr in tainted_addr_map.keys():
           tainted_addr_map[addr] = set()
        tainted_addr_map[addr].add(pc)
        l.debug(f"Memory type: {type(initial_state.memory)}")
        ival = initial_state.memory.load(addr, 4)
        base_snapshot.mark_tainted(addr, sym, ival, pc)
        initial_state.memory.store(addr, sym, 4)
        l.debug(f"Recording tainted address {hex(addr)} sym value {sym} initial value {ival}")

    base_snapshot.set_copy_functions(copy_functions)

    # Breakpoints for inspecting parameters of copy functions

    # Breakpoints: MMIO handling
    initial_state.inspect.b('mem_read', when=angr.BP_AFTER, action=inspect_bp_mmio_intercept_read_after, condition=inspect_cond_is_mmio_read)

    # Tainted analysis
    initial_state.inspect.b('mem_read', when=angr.BP_AFTER, action=inspect_bp_tainted_intercept_read_after)
    initial_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=inspect_bp_tainted_intercept_read_before)

    # Breakpoints: Liveness
    initial_state.inspect.b('reg_write', when=angr.BP_BEFORE, action=inspect_bp_trace_liveness_reg)
    initial_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=inspect_bp_trace_liveness_mem)
    initial_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=inspect_bp_tainted_intercept_write_before)
    initial_state.inspect.b('exit', when=angr.BP_BEFORE, action=inspect_bp_trace_ret)
    initial_state.inspect.b('call', when=angr.BP_BEFORE, action=inspect_bp_trace_call)

    # Breakpoints: Constraints
    initial_state.inspect.b('address_concretization', when=angr.BP_AFTER, action=inspect_after_address_concretization)
    initial_state.inspect.b('constraints', when=angr.BP_AFTER, action=inspect_bp_track_newly_added_constraints)    
    initial_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=inspect_bp_mem_read)
    initial_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=inspect_bp_mem_write)

    # Set up state globals which are set by inspection breakpoints and exploration techniques
    initial_state.globals['dead_too_many_out_of_scope'] = False
    initial_state.globals['dead_write_to_env'] = False
    initial_state.globals['path_constrained'] = False
    initial_state.globals['meaningful_actions_while_constrained'] = False
    initial_state.globals['config_write_performed'] = False

    # Arch-specific reg constants
    initial_state.globals['regular_reg_offsets'] = frozenset([initial_state.arch.get_register_offset(name) for name in REGULAR_REGISTER_NAMES])

    initial_state.globals['symbolic_read'] = False
    initial_state.globals['symbolic_write'] = False
    initial_state.globals['NULL_ptr'] = False 
    initial_state.globals['return_address_corrupted'] = False

    # Make memory accesses show up in state histories
    initial_state.options.add(angr.options.TRACK_MEMORY_ACTIONS)
    initial_state.options.add(angr.options.BYPASS_UNSUPPORTED_SYSCALL)

    # Register plugin to track dynamic liveness
    initial_state.register_plugin('liveness', LivenessPlugin(base_snapshot))

    # Register plugin to track tainted address access
    initial_state.register_plugin('tainted', TaintedMemoryPlugin(base_snapshot, tainted_addr_map)) 

    return project, initial_state, base_snapshot

MAX_NODECODE_ERRORS = 5
def wrapped_explore(simulation, **kwargs):
    """
    Step while trying to handle decoding errors.
    """

    stash_name = kwargs.get('stash') or 'active'

    cnt = 0
    while cnt < MAX_NODECODE_ERRORS:
        cnt += 1
        try:
            simulation.explore(**kwargs)
        except angr.errors.SimIRSBNoDecodeError as e:
            l.warning(f"Got SimIRSBNoDecodeError error: {e}")
            addr = insn_addr_from_SimIRSBNoDecodeError(e)

            # Try recovering from things like breakpoints
            if not try_handling_decode_error(simulation, stash_name, addr):
                return False
        except angr.errors.SimEngineError as e:
            traceback.print_tb(e.__traceback__)
            return False
        except angr.errors.SimOperationError as e:
            traceback.print_tb(e.__traceback__)
            return False
        except (angr.errors.SimZeroDivisionException) as e:
            traceback.print_tb(e.__traceback__)
            return False
        except angr.errors.SimValueError as e:
            traceback.print_tb(e.__traceback__)
            return False             
        except angr.errors.SimError as e:
            traceback.print_tb(e.__traceback__)
            return False             
        #except AngrUnsupportedSyscallError as e:
        #    traceback.print_tb(e.__traceback__)
        #    return False               
        except TimeoutError:
            return False

    return True

def timeout_handler(signal_no, stack_frame):
    l.warning("Hard timeout triggered. Raising exception...")
    raise TimeoutError()

def get_return_address_corrupted(sim):
    result = []
    for state in sim.active:
        if state.globals['return_address_corrupted']:
           result.append(state)
    return result

def perform_analysis(statefile, mmio_addr, tainted_addrs, copy_functions, is_debug=False, timeout=DEFAULT_TIMEOUT, cli_version=False):
    project, initial_state, base_snapshot = setup_analysis(statefile, tainted_addrs, copy_functions, cli_version)
    start_pc = base_snapshot.initial_pc

    if is_debug:
        initial_state.inspect.b('mem_read', when=angr.BP_AFTER, action=inspect_bp_trace_reads)
        initial_state.inspect.b('mem_write', when=angr.BP_AFTER, action=inspect_bp_trace_writes)

    simulation = project.factory.simgr(initial_state, resilience=False)

    # Handle quirky arch-specific instruction modeling
    result_line, config_entry = model_arch_specific(project, initial_state, base_snapshot, simulation)
    if result_line is not None and config_entry is not None:
        return result_line, config_entry

    for stash_name in CUSTOM_STASH_NAMES:
        simulation.populate(stash_name, [])

    # Simulation techniques
    simulation.use_technique(angr.exploration_techniques.DFS())
    simulation.use_technique(NullPtrChecker())
    simulation.use_technique(SymbolicReadChecker()) 
    simulation.use_technique(CopyFunctionSizeTainting()) 
    timeout_detector_technique = simulation.use_technique(TimeoutDetector(EXPLORATION_TIMEOUT_FACTOR * timeout))
    state_explosion_detector_technique = simulation.use_technique(StateExplosionDetector())
    first_state_split_detector_technique = simulation.use_technique(FirstStateSplitDetector())
    simulation.use_technique(FunctionReturner())
    #simulation.use_technique(MMIOVarScoper())
    simulation.use_technique(LoopEscaper(debug=is_debug))

    # Set Hard timeout
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    l.warning("Starting simulation now...")

    MAX_STEPS = 750
    explore_failed = wrapped_explore(simulation, n=MAX_STEPS, num_find=0xffff, opt_level=0) is False

    for s in simulation.active:
        l.debug(f"Callstack for {s} {s.callstack}")
    for s in simulation.symbolic_read:
        l.debug(f"Callstack for {s} {s.callstack}")
    for s in simulation.symbolic_write:
        l.debug(f"Callstack for {s} {s.callstack}")
    for s in simulation.copyfunc_receives_tainted_size:
        l.debug(f"Callstack for {s} {s.callstack}")
    for s in simulation.loops:
        l.debug(f"Callstack for {s} {s.callstack}")
    for s in simulation.null_ptr:
        l.debug(f"Callstack for {s} {s.callstack}")
    

    l.critical("### Stashes (after stepping):\n" \
        + "active:        {}\n".format(simulation.active) \
        + "loops:         {}\n".format(simulation.loops) \
        + "too_many_out_of_scope: {}\n".format(simulation.too_many_out_of_scope) \
        + "deep_calls:    {}\n".format(simulation.deep_calls) \
        + "vars_dead_but_path_constrained: {}\n".format(simulation.vars_dead_but_path_constrained) \
        + "returning_val: {}\n".format(simulation.returning_val) \
        + "copyfunc_receives_tainted_size: {}\n".format(simulation.copyfunc_receives_tainted_size) \
        + "symbolic_read: {}\n".format(simulation.symbolic_read) \
        + "symbolic_write: {}\n".format(simulation.symbolic_write) \
        + "null_ptr: {}\n".format(simulation.null_ptr) \
        + "return_address_corrupted: {}\n".format(get_return_address_corrupted(simulation)) \
        + "errored:       {}\n".format(simulation.errored) \
        + "unsat:         {}\n".format(simulation.unsat) \
        + "found:         {}".format(simulation.found))
    simulation.move(from_stash="deferred", to_stash="active")


    #for state in simulation.active:
    #    l.critical("Active PC: {}\n".format(hex(get_pc(state)))) 
    # Check different error cases to trigger pre-fork state fallback
    if explore_failed:
        l.critical("Got exception during stepping. Skipping further execution...")
        timeout_detector_technique.timed_out = True
    #elif simulation.active or simulation.deep_calls:
    #    l.critical("Active / deep call states are present after first round of exploration, too complex processing. Skipping further execution...")
    #    timeout_detector_technique.timed_out = True
    #elif state_explosion_detector_technique.is_exploded:
    #    l.critical("State explosion detected. Skipping further execution...")
    #    timeout_detector_technique.timed_out = True
    elif timeout_detector_technique.timed_out:
        l.critical("Hit timeout")
    elif simulation.errored:
        l.critical("Errored states encountered")
        simulation.errored[0].reraise()

    # Collect finished states
    # If unfinished states (active / deep_calls) are present, we will be in timeout case

    if simulation.copyfunc_receives_tainted_size:
        l.critical("Number of vulnerable states due to passing a symbolic size to a copy function (pc: {:08x}): {}".format(start_pc, len(simulation.copyfunc_receives_tainted_size)))

    if simulation.symbolic_read:
        l.critical("Number of vulnerable states due to symbolic read (pc: {:08x}): {}".format(start_pc, len(simulation.symbolic_read)))

    if simulation.symbolic_write:
        l.critical("Number of vulnerable states due to symbolic write (pc: {:08x}): {}".format(start_pc, len(simulation.symbolic_write)))

    if simulation.errored:
        l.critical("Number of errored states (pc: {:08x}): {}".format(start_pc, len(simulation.errored)))

    return


def analyze_vulnerability_at_entry_point(statefiles, out_path, copy_functions_path, tainted_addrs_path, timeout=DEFAULT_TIMEOUT, is_debug=False):
    """
    The wrapper which is invoked by the pipeline's vulnerability analysis workers
    """
    perform_analyses(statefiles, copy_functions_path, tainted_addrs_path, is_debug=True, timeout=timeout)

    return True
