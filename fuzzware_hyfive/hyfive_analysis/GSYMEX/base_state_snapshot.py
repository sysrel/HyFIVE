from pathlib import Path
import sys
from io import BytesIO
import logging
import re

import angr, claripy

from .arch_specific import arm_thumb_quirks
from .arch_specific.arm_thumb_regs import STATE_SNAPSHOT_REG_LIST, translate_reg_name_to_vex_internal_name, leave_reg_untainted, REG_NAME_PC, REG_NAME_SP
from .arch_specific.arm_cortexm_mmio_ranges import DEFAULT_MMIO_RANGES, ARM_CORTEXM_MMIO_START, ARM_CORTEXM_MMIO_END
from .angr_utils import contains_var
#from .fuzzware_utils.config import load_traces_for_state, get_mmio_ranges

l = logging.getLogger("BASESTATE")

reg_regex = re.compile(r"^[^=]{2,4}=0x([0-9a-f]+)$")

class EntryPointBaseStateSnapshot:
    """
    Information about the concrete restored initial state from which we start
    symbolically executing.
    """

    def __init__(self, cfg):
        self.init_reg_constraints = []
        self.init_reg_bitvecs = []
        self.init_reg_bitvecvals = []
        self.init_reg_bitvecs_unconstrained = []
        self.init_mem_constraints = []
        self.init_mem_bitvecs = []
        self.init_mem_bitvecvals = []
        self.init_mem_bitvecs_unconstrained = []
        self.regvars_by_name = {}
        # sysrel
        self.tainted_addrs = {}
        self.tainted_addrs_vars = set()
        self.tainted_init_values = {}
        self.copy_functions = {} 
        self.copy_function_sizes = {} 
        self.target_mmio_addr = "" 
        self.bb_trace = None
        self.ram_trace = None
        self.mmio_trace = None

        self.access_pc = None
        self.mmio_addr = None
        self.mmio_access_size = None

        self.mmio_ranges = list(DEFAULT_MMIO_RANGES)

        self.initial_pc = None

        configured_mmio_ranges = []
        if cfg:
            configured_mmio_ranges = get_mmio_ranges(cfg)
            for start, end in configured_mmio_ranges:
                self.mmio_ranges.append((start, end))

        if not configured_mmio_ranges:
            self.mmio_ranges.append((ARM_CORTEXM_MMIO_START, ARM_CORTEXM_MMIO_END))

    @property
    def all_initial_bitvecs(self):
        return self.init_reg_bitvecs + self.init_mem_bitvecs

    @property
    def all_unconstrained_bitvecs(self):
        return self.init_reg_bitvecs_unconstrained + self.init_mem_bitvecs_unconstrained

    @property
    def all_initial_bitvecvals(self):
        return self.init_reg_bitvecvals + self.init_mem_bitvecvals

    def unconstrain(self, ast):
        """
        In AST, replace variables from initial state with their unconstrained versions
        """
        for reg_ast, reg_ast_unconstrained in zip(self.all_initial_bitvecs, self.all_unconstrained_bitvecs):
            if contains_var(ast, reg_ast):
                l.debug(f"ast to unconstrain contains initial register variable: '{ast}' -> {reg_ast}")
                ast = ast.replace(reg_ast, reg_ast_unconstrained)

        return ast

    # sysrel
    def mark_tainted(self, addr, varname, ival, pc):
        if not addr in self.tainted_addrs.keys():
           self.tainted_addrs[addr] = set()
        self.tainted_addrs[addr].add(pc)  
        self.tainted_addrs_vars.add((addr, varname))
        self.tainted_init_values[addr] = ival
        return ival

    def is_tainted_addr(self, addr):
        return addr in self.tainted_addrs.keys()

    def is_tainted_var(self, var):
        return any([v for a, v in self.tainted_addrs_vars if v == var])

    def get_tainted_var(self, addr):
        for a, v in self.tainted_addrs_vars:
            if a == addr:
               return v
        return None 

    def is_tainted_read_loc_any(self, loc):
        for a in self.tainted_addrs.keys():
            if loc in self.tainted_addrs[a]:
               return True 
        return False

    def is_tainted_read_at_loc(self, addr, loc):
        zero_case = False 
        if addr in self.tainted_addrs.keys():
           if loc in self.tainted_addrs[addr]:
               return True 
           if 0 in self.tainted_addrs[addr]:
              zero_case = True              
        return zero_case

    def set_copy_functions(self, copy_functions):
        for fn, fa, fs in copy_functions:
            self.copy_functions[fa] = fn 

    def set_copy_function_size(self, addr, size):
        l.info(f"Copy function {hex(addr)} size {size}")
        self.copy_function_sizes[addr] = size 

    def is_a_copy_function_instruction(self, addr):
        #l.info(f"[is_a_copy_function] addr {hex(addr)} map size {len(self.copy_function_sizes)}")
        for fa in self.copy_function_sizes.keys():
            #l.info(f"Addr {hex(addr)} vs copy function {hex(fa)} size {self.copy_function_sizes[fa]})")
            if addr >= fa and addr < fa + self.copy_function_sizes[fa]:
               return True
        return False

    def is_a_copy_function(self, addr):
        return addr in self.copy_functions.keys()

    def set_target_mmio_addr(self, mmio_addr):
        self.target_mmio_addr = mmio_addr 

    def concretize(self, target_ast):
        """
        In AST, replace variables with their actual value
        """
        for ast, bvv in zip(self.all_initial_bitvecs, self.all_initial_bitvecvals):
            target_ast = target_ast.replace(ast, bvv)
        return target_ast

    def contained_base_vars(self, ast):
        """
        Collect all base variables involved in ast
        """
        res = []

        for base_state_ast, base_state_bvv in zip(self.all_initial_bitvecs, self.all_initial_bitvecvals):
            if contains_var(ast, base_state_ast):
                res.append((base_state_ast, base_state_bvv))

        return res

    def is_mmio_addr(self, addr):
        for start, end in self.mmio_ranges:
            if start <= addr <= end:
                return True
        return False

    def add_custom_mmio_range(self, start, end):
        assert not (self.is_mmio_addr(start) or self.is_mmio_addr(end))
        self.mmio_ranges.append((start, end))

    @classmethod
    def from_state_file(cls, statefile, cfg, cli_version=False):
        base_snapshot = cls(cfg)
        #base_snapshot.bb_trace, base_snapshot.ram_trace, base_snapshot.mmio_trace = load_traces_for_state(statefile)

        l.info("Loading state file: {}".format(statefile))
        with open(statefile, "r") as state_file:
            regs = {}

            for name in STATE_SNAPSHOT_REG_LIST:
                line = state_file.readline()
                l.debug("Looking at line: '{}'".format(line.rstrip()))
                val = int(reg_regex.match(line).group(1), 16)
                l.info("Restoring reg val: 0x{:x}".format(val))
                name = translate_reg_name_to_vex_internal_name(name)
                regs[name] = val

            line = ""
            while line == "":
                line = state_file.readline()

            sio = BytesIO(line.encode()+state_file.read().encode())

        l.debug(f"Project module path {Path(sys.modules[angr.Project.__module__].__file__).resolve()}")
        project = angr.Project(sio, arch="ARMCortexM", main_opts={'backend': 'hex', 'entry_point': regs[REG_NAME_PC]|1})

        # We need the following option in order for CBZ to not screw us over
        project.factory.default_engine.default_strict_block_end = True

        #initial_state = project.factory.blank_state(addr=regs[REG_NAME_PC]|1)

        if cli_version:
           l.info(f"Initializing with explicit SYMBOL_FILL_UNCONSTRAINED_MEMORY initialization")
           initial_state = project.factory.entry_state(addr=regs[REG_NAME_PC]|1, 
                                                       remove_options={
                                                                       angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                                                       angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                                       angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                                                                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                                                                      },
                                                       add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC}
                                                      )
        else:
           initial_state = project.factory.entry_state(addr=regs[REG_NAME_PC]|1) 

        arm_thumb_quirks.add_special_initstate_reg_vals(initial_state, regs)

        for obj in project.loader.all_objects:
                l.info(f"obj min: {hex(obj.min_addr)} max: {hex(obj.max_addr)}\n")
        #        data = obj.load(obj.min_addr, obj.max_addr - obj.min_addr)
        #        state.memory.store(obj.min_addr, data)

        # apply registers to state
        initial_sp = None
        for name, val in regs.items():
            print(f"Setting register {name} to {hex(val)}")
            if name == REG_NAME_PC:
                base_snapshot.initial_pc = val
                val |= 1
                continue

            #if leave_reg_untainted(name):
            #    ast = claripy.BVV(val, 32)
            #else:
            # For initial registers, we taint them by applying an AST with a fixed value via constraints
            ast, ast_unconstrained = claripy.BVS(f"initstate_{name}", 32), claripy.BVS("{name}_unconstrained", 32)
            #    bitvecval = claripy.BVV(val, 32)
            #    constraint = ast == bitvecval

            #    initial_state.add_constraints(constraint)
            base_snapshot.regvars_by_name['{}'.format(name)] = ast
            #    base_snapshot.init_reg_bitvecs.append(ast)
            #    base_snapshot.init_reg_bitvecvals.append(bitvecval)
            #    base_snapshot.init_reg_bitvecs_unconstrained.append(ast_unconstrained)
            #    base_snapshot.init_reg_constraints.append(constraint)

            #    if name == REG_NAME_SP:
            #        initial_sp = val

            # sysrel (keep registers concrete values)
            ast = claripy.BVV(val, 32)
            if name == REG_NAME_SP:
               initial_sp = val 
            setattr(initial_state.regs, name, ast)

        # Taint stack memory by setting constraints on it, as we do for initial registers
        #stack_readsize = min(256, (2**32)-initial_sp)
        #stack_mem = initial_state.memory.load(initial_sp, stack_readsize)
        #stack_mem_ast, stack_mem_ast_unconstrained = ast = claripy.BVS(f"init_mem_sp", 8*stack_readsize), claripy.BVS(f"init_mem_sp_unconstrained", 8*stack_readsize)
        #constraint = stack_mem_ast == stack_mem
        #initial_state.add_constraints(constraint)
        #initial_state.memory.store(initial_sp, stack_mem_ast)
        #base_snapshot.init_mem_bitvecs.append(stack_mem_ast)
        #base_snapshot.init_mem_bitvecvals.append(stack_mem)
        #base_snapshot.init_mem_constraints.append(constraint)
        #base_snapshot.init_mem_bitvecs_unconstrained.append(stack_mem_ast_unconstrained)

        return project, initial_state, base_snapshot
