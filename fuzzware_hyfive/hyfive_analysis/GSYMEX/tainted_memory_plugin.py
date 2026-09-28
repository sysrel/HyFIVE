import angr
import claripy
import copy
import logging
from .base_state_snapshot import EntryPointBaseStateSnapshot

l = logging.getLogger("TAINTED")

class TaintedMemoryPlugin(angr.SimStatePlugin):
    base_snapshot: EntryPointBaseStateSnapshot

    tainted_var_init: dict
    tainted_vars: dict

    def __init__(self, base_snapshot, tainted_vars, tainted_var_init=None):
        super(TaintedMemoryPlugin, self).__init__()
        self.base_snapshot = base_snapshot        
        self.tainted_vars = tainted_vars
        if tainted_var_init == None:
           self.tainted_var_init = {}
           for ta in tainted_vars.keys():
               self.tainted_var_init[ta] = False
        else:
           self.tainted_var_init = tainted_var_init 

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return TaintedMemoryPlugin(self.base_snapshot, self.tainted_vars, copy.deepcopy(self.tainted_var_init))

    def is_tainted(self, addr):
        return addr in self.tainted_vars.keys()

    def is_tainted_read_loc(self, addr, loc):
       if addr in self.tainted_vars.keys():
          if loc in self.tainted_vars[addr]:
             return True
       return False

    def is_tainted_read_loc_possibly_none(self, addr, loc):
       if addr in self.tainted_vars.keys():
          if loc in self.tainted_vars[addr]:
             return True
          if 0 in self.tainted_vars[addr]:
             return True
       return False

    def is_tainted_addr_init(self, addr):
        if addr in self.tainted_var_init.keys():
           return self.tainted_var_init[addr]
        return True
  
    def mark_tainted_addr_init(self, addr):
        if addr in self.tainted_var_init.keys():
           self.tainted_var_init[addr] = True
  
         
