#from memory_profiler import profile
#from pympler import asizeof
from pathlib import Path
import hashlib
import time
import copy
import monkeyhex
import angr
from angr.code_location import CodeLocation
import pyvex
import sys
import re
from angr.state_plugins.callstack import CallStack
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType, OP_BEFORE, OP_AFTER
from angr.utils.constants import DEFAULT_STATEMENT
angr.loggers.disable_root_logger()


class HybridAnalyzer:
    def __init__(self, proj, cfg, minRAM, config, default_config, result_file_desc, defusecyclebound=1, taintListProcessingBound=4000):
       self._project = proj
       self._config = config
       self._default_config = default_config
       self._result_file_desc = result_file_desc
       self._current_cfg = cfg
       self._dyncallgraph = None
       self._initial_state = self._project.factory.entry_state()
       #self._initial_state = self._project.factory.entry_state(
       #                remove_options={
       #                    angr.options.LAZY_SOLVES
       #                },
       #                add_options = { angr.options.FAST_MEMORY,
       #                angr.options.FAST_REGISTERS}
                       #add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                       #angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}

       #            )
       self._minRAM = minRAM
       self._bbForCFG = {}
       self._func_bb_addr_range = {}
       self._functionAddressRange = {}
       self._cfgnodeStmtRange = {}
       # map f.addr -> map (bb.addr, stmt_idx, node) -> set of (bb.addr, stmt_idx, node)
       self._def_for_use_in_func = {}
       self._def_for_use_ultimate_in_func = {}
       self._localOffset = {}
       self._inferred_base_reg = set()
       self._HandlerCallbackAssignments = {}
       self._HandlerBufferAssignments = {}
       self._HALBoundaryAPI = {}
       self._defusecyclebound = defusecyclebound
       self._taintListProcessingBound = taintListProcessingBound
       self._imarkLength = {}
       self._defInCFGNodeForReg = {}
       self._argumentsForExplicitCalls = {} 
       # Performs path precise def use analysis when set, otherwise performs approximate
       self._comprehensiveDefUse = False
       self._optimizePreds = False
       self._optimizedMaxPred = 512
       self._predDepth = 1
       self._callerDepth = 3
       self._usesInFunction = {}
       self._allusesInFunction = {}
       self._tempdefs = {}
       self._regdefs = {}
       self._functionRetSources = {}
       self._functionRetDefs = {}
       self._functionRetUltimateDefs = {}
       self._returningFunctionTaints = {}
       self._lastNode = ""
       self._lastGetDefTuple = []
       self._instCFGNodeMap = {}
       self._TUPLEDELIMITER = ';'
       self._startTime = 0
       self._mmioAccessContextFindingTime = 0
       self._rxBufferFindingTime = 0
       self._rxBufferAccessFindingTime = 0
       self._explicitCalledFunctions = self.IRfindExplicitlyCalledFunctions()
       self._skipPredComputationForFunction = {}
       self._allsourcedepth = None
       self._allsourcedepthBound = 2
       self._defsfornodedepth = None
       self._defsfornodedepthBound = 20
       self._usesDepthBound = 20
       self._defusecallchaindepthBound = 1
       self._dynamiccallchainsearchBound = 5
       self._dynamiccallchaintaintsearchBound = 5
       self._defsfornodenumpaths = 0 
       self._allcallsites = None
       self._copyfunctions = set()
       self._statistics = {}
       self._numsteps = -1
       self._dynExplicitCalls = None
       self._returnValueFlowBasedOnLoadPc = {} 
       self._returnValueFlowBasedOnStorePc = {} 
       self._CFG = {}
       self._RCFG = {}
       self._reachingDefsBase = {}
       self._reachingDefsIn = {}
       self._reachingDefsOut = {}

    def showTime(self):
        return "%s" % (time.strftime("%Y-%m-%d %H:%M"))

    def IRprintConfig(self, fd):
        if fd == None:
           return
        fd.write(f"Explicit configuration begin:\n")
        for k, v in self._config.items():
            fd.write(f"{k}: {v}\n")
        fd.write(f"Explicit configuration end:\n")
        fd.write(f"Default configuration begin:\n")         
        for k, v in self._default_config.items():
            fd.write(f"{k}: {v}\n")
        fd.write(f"Default configuration end:\n")
         

    # inputdir refers to the directory that includes the copy function information
    # outputdir is the directory the statistics are written to
    def IRinitstats(self,inputdir="",outputdir=""):
        self._lastProcessingTime = time.time()
        self._outputdir = outputdir
        self._inputdir = inputdir

    def IRupdatestats(self, taskname):
        current = time.time()
        self._numsteps += 1
        delta = current - self._lastProcessingTime
        self._statistics[self._numsteps] = (taskname, delta)
        self._lastProcessingTime = current
        return delta 

    def IRprintStats(self, fname="statistics"):
        if not self._result_file_desc == "":
           fname += "_" + self._result_file_desc 
        self._default_config['statistics_results'] = fname
        if not self._outputdir == "":
           fname = self._outputdir + "/" + fname
        fd = open(fname, "w")
        self.IRprintConfig(fd)
        num = len(self._statistics)
        total = 0
        i = 0
        while i < num:
              print(f"{self._statistics[i][0]}={self._statistics[i][1]:.2f} secs")
              fd.write(f"{self._statistics[i][0]}={self._statistics[i][1]:.2f} secs\n")
              total += self._statistics[i][1] 
              i += 1
        print(f"Total={total:.2f} secs")
        fd.write(f"Total={total:.2f} secs\n")
        fd.close()

    """
    def DebugShowGlobalSizes(self):
        print(f"self._bbForCFG : {sys.getsizeof(self._bbForCFG)}")
        print(f"self._func_bb_addr_range : {asizeof.asizeof(self._func_bb_addr_range)}")
        print(f"self._functionAddressRange : {asizeof.asizeof(self._functionAddressRange)}")
        print(f"self._cfgnodeStmtRange : {asizeof.asizeof(self._cfgnodeStmtRange)}")
        print(f"self._cfgnodeStmtRange : {sys.getsizeof(self._cfgnodeStmtRange)}")
        print(f"self._def_for_use_in_func : {asizeof.asizeof(self._def_for_use_in_func)}")
        print(f"self._def_for_use_ultimate_in_func : {asizeof.asizeof(self._def_for_use_ultimate_in_func)}")
        print(f"self._localOffset : {asizeof.asizeof(self._localOffset)}")
        print(f"self._imarkLength : {asizeof.asizeof(self._imarkLength)}")
        print(f"self._defInCFGNodeForReg : {asizeof.asizeof(self._defInCFGNodeForReg)}")
        print(f"self._argumentsForExplicitCalls : {asizeof.asizeof(self._argumentsForExplicitCalls)}")
        print(f"self._usesInFunction : {asizeof.asizeof(self._usesInFunction)}")
        print(f"self._allusesInFunction : {asizeof.asizeof(self._allusesInFunction)}")
        print(f" self._tempdefs : {asizeof.asizeof(self._tempdefs)}")
        print(f"self._regdefs : {asizeof.asizeof(self._regdefs)}")
        print(f"self._skipPredComputationForFunction : {asizeof.asizeof(self._skipPredComputationForFunction)}")
    """
    
    def InitStartTime(self, start):
       self._startTime = start

    def InitSetDynamicCallGraph(self, dyncg): 
       self._dyncallgraph = dyncg  

       """
        MMIOPointers
          MMIObase -> {(pointer_address, depth (level of indirection), instruction_address, block_address, function_address)}

        HALTransferFunctions
          MMIObase ->  {(handler_receiving_function, handler_access_type, handler_source, buffer_source_type, buffer_source, transfer_type)}
          A receive IRQ handler typically copies from the receive buffer to a global buffer before transferring new data
          Therefore, a transfer function may have multiple tuples specifying different buffers it may taint 

          transfer_type:
              "receive"
              "transmit"
              "transreceive"
          handler_access_type 
              "arg": handler_source will have the argname
              "global": handler_source will have the address
          buffer_source_type
              "arg": buffer_source will have the argname
              "global": buffer_source will have the address
              "handler_field": buffer_source will have the offset relative

        HALCallbackAssignments
        MMIObase -> { (context, handler_access_type, handler_source, data_structure_offset, callback_function) }
          handler_access_type 
              "arg": handler_source will have the argname
              "global": handler_source will have the address                

        HALBufferAssignments
        MMIObase -> { (context, handler_access_type, handler_source, data_structure_offset, buffer_source_type, buffer_source, instr) }
          handler_access_type 
              "arg": handler_source will have the argname
              "global": handler_source will have the address                
          buffer_source_type
              "arg": buffer_source will have the argname
              "global": buffer_source will have the address                

        HALBoundaryAPI (will probably not be needed)
        MMIObase -> { (boundary_func,  buffer_source_type, buffer_source) }                 
       """
       self._callbackAssignments = {}  
       # print(f"Tailor created")

    def HALDetectBoundaryAPI(self, base):
       """
        Go through functions that perform handler buffer assignments and find callers in a recursive way to detect the boundary API
        In a context that 
            1) directly or indirectly calls the handler buffer assigning function hba
            2) callsite for hba receives the buffer parameter as follows
	       a) The argument of the context is passed to hba
               b) A local buffer is passed to hba and local buffer gets copied to the arg of the context
               c) A global buffer gets passed to hba
       """
       callers = set()
       for context, hatype, hs, dtoffset, buf_stype, buf_source in self._HandlerBufferAssignments[base]:
           if buf_stype ==  "argument":
              ccallers = self.IRfindCallers(hs, context, buf_source)
              for cc in ccallers:
                  callers.add(cc)
           else:
              # to do: find buffer size  
              callers.add((context,"global",buf_source,1))
       return callers     



    """
       Using angr analyses
    """
    def IRcreateMMIOPointerTaints(self, cfg, ddg, vfg, halF, halCtx):
        cl1 = CodeLocation(0x80027ab, ins_addr=0x80027b7, stmt_idx=20)
        in_edges_vfg = vfg.graph.in_edges([cl1], data=True)
        print(f"VFG: In edges for code location {cl1}: {in_edges_vfg}")
        in_edges_ddg = ddg.graph.in_edges([cl1], data=True)
        print(f"DDG: In edges for code location {cl1}: {in_edges_ddg}")
        return



    
    """
       Using angr analyses
    """
    def HALdependenceAnalysis(self, halF, halCtx):
        f_obj = self.IRgetFunctionAtAddress(0x80026e0)
        bb = self._project.factory.block(0x80027ab)
        #bb.vex.pp()
        #print(f"num st: {len(bb.vex.statements)}")
        statement = bb.vex.statements[19]
        cl = CodeLocation(0x80027ab, insn_addr=0x80027b7, stmt_idx=20)
        #op = [("insn", 0x80027b2, ObservationPointType.OP_BEFORE), ("insn", 0x80027b2, ObservationPointType.OP_AFTER)]
        #t1 = ("insn", 0x80027b2, ObservationPointType.OP_BEFORE)
        #t2 = ("insn", 0x80027b2, ObservationPointType.OP_AFTER)
        op = [("insn", 0x80027b7, ObservationPointType.OP_BEFORE)]
        t1 = ("insn", 0x80027b7, ObservationPointType.OP_BEFORE)
        try: 
            print(f"Performing reaching definitions for function {f_obj.name}") 
            rd = self._project.analyses.ReachingDefinitions(subject=f_obj,  observation_points=op)
            state = ReachingDefinitionsState(
                 CodeLocation(f_obj.addr, None), self._project.arch, rd.subject, True) # setting track_tmps to True
            rd.insn_observe(0x80027b7, statement, bb, state, ObservationPointType.OP_BEFORE)
            #rd.insn_observe(0x80027b2, statement, bb, state, ObservationPointType.OP_AFTER)
        except BaseException as e:
            print(f"Error for reaching definitions: {e}")
            return 
        print(f"Observed results: {rd.observed_results} items {rd.observed_results.items()}")
        print(f"Live definitions {state.live_definitions}")
        ird_b = rd.get_reaching_definitions_by_insn(0x80027b7, ObservationPointType.OP_BEFORE) 
        print(f"RD: for observation point {op}: {ird_b}") 
        print(f"Registers {ird_b.registers}")
        print(f"Tmps {ird_b.tmps}")
        for k in ird_b.tmps.keys():
            vs = ird_b.tmps[k]
            for v in vs:
                print(f"key {k} def {v}")
        au = rd.model.all_uses
        uc = au.get_uses_by_location(cl)
        print(f"All uses {au} Uses by codeloc {uc}") 
        #ird_a = rd.get_reaching_definitions_by_insn(0x80027b2, ObservationPointType.OP_AFTER) 
        #print(f"RD: for code location {cl1} after: {ird_a}")  
        start = time.time()
        self._accurate_cfg = self._project.analyses.CFGEmulated(
            context_sensitivity_level=0,
            keep_state=True,
            state_add_options=angr.sim_options.refs,
        )
        self._vfg = self._project.analyses.VFG(
            self._accurate_cfg,
            start=self._project.entry,
            context_sensitivity_level=4,
            interfunction_level=4,
            record_function_final_states=True,
        )
        end = time.time()
        print(f"VFG creation time: {end-start} seconds")
        start = time.time()
        self._ddg = self._project.analyses.DDG(
            self._accurate_cfg,
            start=self._project.entry,
        )
        end = time.time()
        print(f"DDG creation time: {end-start} seconds")
        halF = set()
        halCtx = set()
        self.IRcreateMMIOPointerTaints(self._accurate_cfg, self._ddg, self._vfg, halF, halCtx)
        #all_block_addresses = {n.addr for n in vfg.graph.nodes()}
        #assert vfg_1_addresses[arch].issubset(all_block_addresses)

        # return value for functions

        # function authenticate has only two possible return values: 0 and 1
        #authenticate = cfg.functions.function(name="authenticate")
        #assert authenticate.addr in vfg.function_final_states
        #authenticate_final_states = vfg.function_final_states[authenticate.addr]
        #assert len(authenticate_final_states) == 1
        #authenticate_final_state = next(iter(authenticate_final_states.values()))
        #assert authenticate_final_state is not None
        #assert authenticate_final_state.solver.eval_upto(authenticate_final_state.regs.rax, 3) == [0, 1]


    def HALfindHandlerReceivingFunctionCallers(self, initial_state, target_base_set, halCtx, halF):
        newEntries = set()
        change = False
        for hfa, reg in halF:
            for caller in self._current_cfg.functions.values():
                for ba in caller.block_addrs:
                    try:
                       bb = self._project.factory.block(ba)
                    except angr.errors.SimEngineError:
                       continue
                    if isinstance(bb.vex.next,pyvex.IRExpr.Const):
                       if bb.vex.next.con._value == hfa:
                          #print(f"Checking context {caller.name} address {hex(caller.addr)}")
                          #if caller.name == "HAL_UART_RxCpltCallback":
                          #   bb.vex.pp()
                          pft = self.IRfindPassingToArgFromSet(caller, target_base_set, initial_state)
                          for cf, a in pft:
                              #if caller.name == "HAL_UART_RxCpltCallback":
                              #   cfFunc = self.IRgetFunctionAtAddress(cf) 
                              #   print(f"cf {hex(cf)} name {cfFunc.name}") 
                              if not (cf, a) in halF:
                                 newEntries.add((cf,a))
                                 change = True
                          if pft and not caller.addr in halCtx:
                             change = True 
                             halCtx.add(caller.addr)
                          for arg2 in ['r0', 'r1', 'r2', 'r3']:
                              apnode = self.IRfindActualArgNodeForCall(caller, bb, arg2)
                              #if caller.name == "HAL_UART_RxCpltCallback":
                              #   print(f"apnode {apnode}")
                              if apnode == None:
                                 continue
                              value = self.IRdefinedbyReg(bb, apnode)
                              #if caller.name == "HAL_UART_RxCpltCallback":
                              #   print(f"value1 {value}")
                              if value == None:
                                 value, loff = self.IRgetsFromArgIndirect(bb, apnode)
                              #if caller.name == "HAL_UART_RxCpltCallback":
                              #   print(f"value2 {value}")
                              if value == reg:
                                 if not (caller.addr, arg2) in halF:
                                    newEntries.add((caller.addr, arg2))
                                    change = True
                                 if not caller.addr in halCtx:
                                    change = True
                                    halCtx.add(caller.addr)                                 
        for n in newEntries:
            halF.add(n) 
        return change

    def HALfindCallersCalleesOfHandlerReceiving(self, initial_state, target_base_set, halCtx, halF):
        for ba, d, ia, bb, fa in target_base_set:
            f = self.IRgetFunctionAtAddress(fa)
            if f == None:
               continue
            halCtx.add(f.addr)
        change = True
        while change:
              oldhalCtx = halCtx
              c1 = self.HALdetectHandlerReceiving(initial_state, target_base_set, halCtx, halF)
              for hfa, reg in halF:
                  halCtx.add(hfa)
              c2 = self.HALfindHandlerReceivingFunctionCallers(initial_state, target_base_set, halCtx, halF)
              for hfa, reg in halF:
                  halCtx.add(hfa)
              c3 = self.HALfindAllCalleeHandlerReceiving(halF)
              for hfa, reg in halF:
                  halCtx.add(hfa)
              change = c1 or c2 or c3 or len(oldhalCtx) != len(halCtx)
        calleehalF = set()
        #for fa, a in halF:
        #    f = self.IRgetFunctionAtAddress(fa)
        #    if f == None:
        #       continue
        #    nh = self.HALfindCalleeHandlerReceiving(f, a)
        #    for n in nh:
        #        calleehalF.add(n)
        #for nfa, narg in calleehalF:
        #   nf = self.IRgetFunctionAtAddress(nfa) 
        #   print(f"New handler receiving function: {nf.name} {hex(nfa)} {narg}")
        #   halF.add((nfa, narg)) 
        print(f"Handler receiving functions and args")
        for fa, a in halF:
            f = self.IRgetFunctionAtAddress(fa)
            print(f"Function {hex(fa)} name {f.name} arg {a}")

    def HALdetectHandlerReceiving(self, state, target_base_set, halCtx, halF):
        newEntries = set()
        change = False
        for fa in halCtx:
            f = self.IRgetFunctionAtAddress(fa)
            res = self.IRfindPassingToArgFromSet(f, target_base_set, state)
            for hf, arg in res: 
               if not arg == None and not hf == None:
                  argno = self.IRgetArgNo(arg)
                  if not (hf, argno) in halF:
                     newEntries.add((hf, argno))
                     change = True
        for hf, arg in halF:
            hfunc = self.IRgetFunctionAtAddress(hf)
            for ba in hfunc.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                #for each bb that ends with a function call
                if isinstance(bb.vex.next,pyvex.IRExpr.Const):
                   cf = self.IRgetFunctionAtAddress(bb.vex.next.con._value)
                   if cf == None:
                      continue
                   for arg2 in ['r0', 'r1', 'r2', 'r3']:
                      apnode = self.IRfindActualArgNodeForCall(hfunc, bb, arg2)
                      if apnode == None:
                         continue
                      # is apnode defined by arg?
                      # is apnode defined directly
                      value = self.IRdefinedbyReg(bb, apnode)
                      if value == None:                            
                         value, loff = self.IRgetsFromArgIndirect(bb, apnode)
                      if value == arg:
                         if not (cf.addr, arg2) in halF:
                            newEntries.add((cf.addr, arg2))
                            change = True
        for n in newEntries:
            halF.add(n)
        return change

    def HALfindCallbacks(self, halCtx, halF, halCB):
        tmp = set()
        rcb = set()
        rbuf = set()
        for ha, arg in halF: 
            hf = self.IRgetFunctionAtAddress(ha) 
            tcb, tbuf = self.HALextract(hf, arg)
            for ca, do, fa in tcb:
                rcb.add((ca, do, fa))
                print(f"FCB1 {fa}")
                print(f"FCB2 {ca}")
                halCtx.add(fa)
                halCtx.add(ca) 
            for t in tbuf:
                rbuf.add(t)
        for ha in halCtx:
            hf = self.IRgetFunctionAtAddress(ha)
            for ba in hf.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                if not isinstance(bb.vex.next,pyvex.IRExpr.Const):
                   args = [a for f, a in halF if f == ha]
                   for arg in args: 
                       do = self.IRmatchFindDataStructureOffset(bb, bb.vex.next, arg)
                       cbf = [fa for ca, o, fa in rcb if do == o]
                       for cb in cbf:
                           halCB.add((cb, do))
        for f in halCtx:
            func = self.IRgetFunctionAtAddress(f)
            print(f"HALCTX function {hex(f)} name {func.name}")   

    """
        Return candidate buffer offsets that may receive from the data register
    """
    def HALreceivesFromDR(self, cbf, MMIO_base, MMIO_datareg, depth=3):
        #find instructions that use MMIO_datareg as offset in load type accesses 
        datareg_offset = MMIO_datareg - MMIO_base
        baseregset = self.IRgetBaseRegSetForFunction(cbf)
        #print(f"Base register set {baseregset}")
        buffer_offsets = set()
        #print(f"Does function {hex(cbf.addr)} name {cbf.name} receive from DR offset {hex(datareg_offset)}")
        for ba in cbf.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            stores = [x for x in bb.vex.statements if x.tag == 'Ist_Store']
            #bb.vex.pp()
            for s in stores:
                # first loads the handler's pointer from local then loads the base address and then loads from the data register
                dtoff = self.IRgetFirstLoadOffsetForThirdLoadFromBaseReg(bb, s.data, baseregset, depth)
                if not dtoff == None and not isinstance(dtoff,int):
                   print(f"dtoff {dtoff}")
                   dtoff = int(dtoff,16)
                #print(f"Data structure offset for {s.data} is {dtoff} vs {datareg_offset}")
                if dtoff == datareg_offset:
                   # first loads the handler's pointer from local then loads the buffer address
                   boff = self.IRgetFirstLoadOffsetForSecondLoadFromBaseReg(bb, s.addr, baseregset, depth)
                   if not boff == None and not isinstance(boff,int):
                      boff = int(boff,16)
                   #print(f"Data structure offset for {s.addr} is {boff}")
                   if not boff == -1:
                      buffer_offsets.add(boff)
        return buffer_offsets

    """
        Return offsets of candidate transfer buffers that get copied from into the data register
    """
    def HALtransmitsToDR(self, cbf, MMIO_base, MMIO_datareg, depth=3):
        #find instructions that use MMIO_datareg as offset in load type accesses 
        datareg_offset = MMIO_datareg - MMIO_base
        baseregset = self.IRgetBaseRegSetForFunction(cbf)
        #print(f"Base register set {baseregset}")
        buffer_offsets = set()
        #print(f"Does function {hex(cbf.addr)} name {cbf.name} store to DR offset {hex(datareg_offset)}")
        for ba in cbf.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            stores = [x for x in bb.vex.statements if x.tag == 'Ist_Store']
            #bb.vex.pp()
            for s in stores:
                # first loads the handler's pointer from local then loads from the handler to compute the data register
                dtoff = self.IRgetOffsetBeforeFirstLoadForSecondLoadFromBaseReg(bb, s.addr, baseregset, depth)
                if not dtoff == None and not isinstance(dtoff,int):
                   print(f"dtoff {dtoff}")
                   dtoff = int(dtoff,16)
                #print(f"Data structure offset for {s.data} is {dtoff} vs {datareg_offset}")
                if dtoff == datareg_offset:
                   # first loads the handler's pointer from local then loads the buffer address and then loads from the buffer
                   boff = self.IRgetSecondLoadOffsetForThirdLoadFromBaseReg(bb, s.data, baseregset, depth)
                   if not boff == None and not isinstance(boff,int):
                      boff = int(boff,16)
                   #print(f"Data structure offset for {s.addr} is {boff}")
                   if not boff == -1:
                      buffer_offsets.add(boff)
        return buffer_offsets

    def IRprintPredsAndSuccs(self, addr):
        node = self._current_cfg.get_any_node(addr)
        preds = self._current_cfg.get_all_predecessors(node, self._predDepth) 
        succs = self._current_cfg.get_all_successors(node, self._predDepth)
        print(f"Predecessors:")
        for pred in preds:
            print(f"\t {hex(pred.addr)}")
        print(f"Successors:")
        for succ in succs:
            print(f"\t {hex(succ.addr)}")
        func = self.IRgetFunctionAtAddress(addr)
        if func == None:
           return
        print(f"Local CFG for {func.name}")
        for source, dest in func.graph.edges():
            print(f"Edge from {hex(source.addr)} to {hex(dest.addr)}")



    def IRargDefinedIn(self, bb, arg, beforeStmtIndex=None):
       argname = arg
       if isinstance(arg, int):
          argname = self._project.arch.register_names[arg]
       limit = len(bb.vex.statements)
       if not beforeStmtIndex == None:
          limit = beforeStmtIndex
       i = 0
       for st in bb.vex.statements:
           if i > limit:
              break
           if isinstance(st,pyvex.IRStmt.Put):
              if self._project.arch.register_names[st.offset] == argname:
                 return i
           i += 1
       return None 

    def IRgetUltimateArgDefinedBy(self, func, bb, node):
       argnode, stmt = self.IRdefinedbyRegGetNodeWStmt(bb, node)
       if argnode == None:
          return (None, stmt)
       if stmt == None:
          return (argnode, stmt)
       stindex = self.IRargDefinedIn(bb, argnode.offset, stmt.stmt_idx)
       while not stindex == None:
          stmt = bb.vex.statements[stindex]
          argnode = stmt.data 
          res, rstmt = self.IRdefinedbyRegGetNodeWStmt(bb, argnode)
          if res == None:
             break
          else: 
             argnode = res
             stmt = rstmt
             stindex = self.IRargDefinedIn(bb, argnode.offset, stmt.stmt_idx)
       return (argnode, stmt)     

    def IRgetDefinedByArgsInLocalCFG(self, func, bb, node):
       visited = set()
       res = self.IRgetDefinedByArgsInLocalCFGPriv(func, bb, node, visited)
       del visited
       return res

    def IRgetDefinedByArgsInLocalCFGPriv(self, func, bb, node, visited):
       result = set()
       if bb.addr in visited:
          result.add(node)
          return result
       visited.add(bb.addr)
       arg, sstmt = self.IRgetUltimateArgDefinedBy(func, bb, node)  
       for source, dest in func.graph.edges():
           if dest.addr == bb.addr:
              res = None
              if arg == None:
                 res = self.IRgetDefinedByArgsInLocalCFGPriv(func, source, node, visited)
              else:
                 res = self.IRgetDefinedByArgsInLocalCFGPriv(func, source, arg, visited)
              if not res == None:
                 for rn in res:
                     result.add(rn)
       return result


    def IRgetLocalOffsetOnEntryOverCFG(self, func, baseregset, bb, node, reg, visited, c=None):
       result = set()
       if bb.addr in visited:
          return result
       visited.add(bb.addr)
       for source, dest in func.graph.edges():
           if dest.addr == bb.addr:
              snode = self.IRgetBasicBlockForAddress(func, source.addr)
              rs = self.IRgetLocalOffsetOnEntryOverCFGNode(func, baseregset, snode, node, reg, visited, len(snode.vex.statements), c)
              for r in rs:
                  result.add(r)
       return result        


    def IRgetOffsetAndSubWrtBaseRegResetOnLoad(self, func, baseregset, bb, node, reg, c=0):
        print(f"Initial node {node} reg {reg} c {c}")
        if isinstance(node, pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if dnode == None:
              return (None, 0)
           node = dnode.data
           if isinstance(node, pyvex.IRExpr.Get):
              if self._project.arch.register_names[node.offset] in baseregset:
                 return (node.offset, c)  
        if isinstance(node, pyvex.IRExpr.Load) or isinstance(node, pyvex.IRStmt.LoadG):
           return self.IRgetOffsetAndSubWrtBaseRegResetOnLoad(func, baseregset, bb, node.addr, reg, 0)        
        print(f"Calling basic offset node {node} in bb {hex(bb.addr)}")
        n, o = self.IRgetOffsetAndSub(bb, node)
        if n == None:
           return (None, 0)
        if isinstance(n, pyvex.IRExpr.RdTmp):
           return self.IRgetOffsetAndSubWrtBaseRegResetOnLoad(func, baseregset, bb, n, reg, o + c)   
        print(f"Basic offset for node {n} offset {o} reg {reg}")
        if self._project.arch.register_names[n] == reg:
           return (n, o + c)
        return self.IRgetOffsetAndSubWrtBaseRegResetOnLoad(func, baseregset, bb, n, reg, o + c)
          

    def IRgetLocalOffsetOnEntryOverCFGNode(self, func, baseregset, bb, node, reg, visited, index, c=0):
       print(f"IRgetLocalOffsetOnEntryOverCFGNode Node {node} bb {hex(bb.addr)}")
       result = set()
       found = False
       if isinstance(node, pyvex.IRExpr.Get):
          node = node.offset
          reg = self._project.arch.register_names[node]
       if node in self._project.arch.register_names.keys():
          i = index - 1
          while i>=0:
              st = bb.vex.statements[i]
              if bb.addr == func.addr:
                 if isinstance(st, pyvex.IRStmt.Store) or nstance(st, pyvex.IRStmt.StoreG):
                    # addr defined wrt sp and data defined wrt node
                    asrc, o1 = self.IRgetsFromArg(bb, st.addr)
                    dsrc, o2 = self.IRgetsFromArg(bb, st.data)
                    if asrc == "sp" and dsrc == reg:
                       result.add(st)
              if isinstance(st, pyvex.IRStmt.Put):
                 if st.offset == node:
                    if bb.addr == func.addr:
                       n, o = self.IRgetOffsetAndSubWrtBaseRegResetOnLoad(func, baseregset, bb, st.data, reg, c)
                       print(f"Offset wrt baseregset node {n} offset {o}") 
                       if not n == None:
                          result.add(o)
                       return result
                    else:
                       found = True
                       res = self.IRgetLocalOffsetOnEntryOverCFGNode(func, baseregset, bb, st.data, reg, visited, i, c)
                       for r in res:
                           result.add(r)
              i = i - 1 
       else:
           if isinstance(node, pyvex.IRExpr.RdTmp):
              dnode = self.IRgetDefStmt(bb, node)
              if dnode == None:
                 return set()
              return self.IRgetLocalOffsetOnEntryOverCFGNode(func, baseregset, bb, dnode.data, reg, visited, index, c)
           else:
              for ce in node.child_expressions:
                  res = self.IRgetLocalOffsetOnEntryOverCFGNode(func, baseregset, bb, ce, reg, visited, index, c)
                  for r in res:
                      result.add(r)
       if not found and len(result) == 0:
          return self.IRgetLocalOffsetOnEntryOverCFG(func, baseregset, bb, node, reg, visited, c)
       return result

    def IRgetLocalOffsetOnEntry(self, func, baseregset, bb, node, reg):
        dnode = self.IRgetDefStmt(bb, node)
        print(f"IRgetLocalOffsetOnEntry dnode {dnode}")
        if dnode == None:
           return None
        if isinstance(dnode.data, pyvex.IRExpr.Get):
           if dnode.data.offset in self._project.arch.register_names.keys():
              v = set()
              return self.IRgetLocalOffsetOnEntryOverCFGNode(func, baseregset, bb, dnode.data.offset, reg, v, len(bb.vex.statements))
        res = set() 
        for ce in dnode.data.child_expressions:
           v = set()
           r = self.IRgetLocalOffsetOnEntryOverCFGNode(func, baseregset, bb, ce, reg, v, len(bb.vex.statements))
           for re in r:
               res.add(re) 
        return res

    def HALfindDirectReceiveTaints(self, hrfun, an, dataregOffset, depth=3):
        argname = an
        if isinstance(an,int):
           argname = self.IRgetArgName(an)
        baseregset = self.IRgetBaseRegSetForFunction(hrfun)
        if len(baseregset) == 0:
           baseregset.add("sp")
        #print(f"Base register set {baseregset} data register offset {dataregOffset}")
        taints = set()
        argname_alias = self.IRgetRegAliasFromFirstBasicBlock(hrfun, argname)
        #print(f"Alias of {an} ({argname}) is {argname_alias}")
        args = {'r0', 'r1', 'r2', 'r3'}
        aliases = {}
        for a in args:
            aliases[a] = self.IRgetRegAliasFromFirstBasicBlock(hrfun, a) 
            #print(f"Alias of {a} is {aliases[a]}") 
        #if hrfun.name == "HAL_UART_IRQHandler":
        #   self.IRprintPredsAndSuccs(hrfun.addr)
        for ba in hrfun.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            stores = [x for x in bb.vex.statements if x.tag == 'Ist_Store']
            #if hrfun.name == "HAL_UART_Receive_IT":
            #   bb.vex.pp()
            for s in stores:
                # check if the address is an arg or a global and data flows from the data register
                # check if load from handler
                cand = argname_alias
                cand.add(argname)
                soffset = self.IRgetOffsetBeforeLoadDirectlyFromReg(bb, s.data) 
                #print(f"(Direct Receive) {argname} and {argname_alias} soffset {soffset} statement {s} ba {hex(ba)}")
                droffset = None
                found = False
                for sr, so in soffset:
                    if sr in cand and so == dataregOffset:
                       found = True
                       break
                if not found:
                   for sr, so in soffset:
                       if sr in cand:
                          droffset = self.IRmatchFindDataStructureOffsetDirectFromArg(bb, s.data, sr)
                          if dataregOffset == droffset:
                             t, source = self.IRGetNodeSource(bb, s.addr)
                             #print(f"s.data type {t} source {source} statement {s} ba {hex(ba)}")
                             if not (t == "argument" and (source == argname or source in argname_alias)):
                                continue
                             found = True
                             break
                          else:  
                             continue
                if not found:
                   continue
                argreg = self.IRdefinedbyReg(bb, s.data)
                #print(f"(Direct Receive) Arg reg {argreg} vs {argname} and {argname_alias} droffset {droffset}")
                if argreg == argname or argreg in argname_alias:
                   t, source = self.IRGetNodeSource(bb, s.addr)
                   #print(f"type {t} source {source} statement {s} ba {hex(ba)}")
                   if t == "argument" and not source in args:
                      for a in args:
                          if source in aliases[a]:
                             source = a
                             break
                   #print(f"after type {t} source {source} statement {s} ba {hex(ba)}")
                   if not t == None and not source == None:
                      #print(f"[Direct Taint in Receive] function {hrfun.name} source type {t} source {source}")
                      if not source in args:
                         #print(f"Computing stack offset for {s.addr} in {hex(bb.addr)}")
                         stackoff = self.IRgetLocalOffsetOnEntry(hrfun, baseregset, bb, s.addr, source)
                         #print(f"Stack offset {stackoff} for {s.addr}")
                         if not stackoff == None:
                            for so in stackoff:
                                taints.add((hrfun, "stack", so))
                      else:
                         taints.add((hrfun, t, source)) 
        return taints

    def HALfindDirectTransmitTaints(self, hrfun, an, dataregOffset, depth=3):
        argname = an
        if isinstance(an,int):
           argname = self.IRgetArgName(an)
        baseregset = self.IRgetBaseRegSetForFunction(hrfun)
        if len(baseregset) == 0:
           baseregset.add("sp")
        #print(f"Base register set {baseregset}")
        taints = set()
        argname_alias = self.IRgetRegAliasFromFirstBasicBlock(hrfun, argname)
        args = {'r0', 'r1', 'r2', 'r3'}
        aliases = {}
        for a in args:
            aliases[a] = self.IRgetRegAliasFromFirstBasicBlock(hrfun, a) 
        #if hrfun.name == "HAL_UART_IRQHandler":
        #   self.IRprintPredsAndSuccs(hrfun.addr)
        for ba in hrfun.block_addrs:
            try:
               bb = self._project.factory.block(ba)
               gregs = self.IRgetRegistersinGet(bb)
               #print(f"Registers in get in bb {hex(bb.addr)} is {gregs}")
            except angr.errors.SimEngineError:
               continue
            stores = [x for x in bb.vex.statements if x.tag == 'Ist_Store']
            #if hrfun.name == "HAL_UART_Receive_IT":
            #   bb.vex.pp()
            for s in stores:
                # check if the address is an arg or a global and data flows from the data register
                # check if load from handler
                cand = argname_alias
                cand.add(argname)
                soffset = self.IRgetOffsetBeforeLoadDirectlyFromRegWoSecondLoad(bb, s.addr)
                #print(f"(Direct Transmit) {argname} and {argname_alias} soffset {soffset} statement {s} ba {hex(ba)}")
                droffset = None
                found = False
                for sr, so in soffset:
                    if sr in cand and so == dataregOffset:
                       found = True
                       break
                if not found:
                   for sr, so in soffset:
                       if sr in cand:
                          droffset = self.IRmatchFindDataStructureOffsetDirectFromArg(bb, s.addr, sr)
                          if dataregOffset == droffset:
                             t, source = self.IRgetLoadSource(bb, s.data)
                             #print(f"s.data type {t} source {source} statement {s} ba {hex(ba)}")
                             if not (t == "argument" and (source == argname or source in argname_alias)):
                                continue
                             found = True
                             break
                          else:
                             continue
                if not found:
                   continue
                argreg = self.IRdefinedbyReg(bb, s.addr)
                #print(f"(Direct Transmit) Arg reg {argreg} vs {argname} and {argname_alias} droffset {droffset}")
                if argreg == argname or argreg in argname_alias:
                   t, source = self.IRgetLoadSource(bb, s.data)
                   #print(f"type {t} source {source} statement {s} ba {hex(ba)}")
                   if t == "argument" and not source in args:
                      for a in args:
                          if source in aliases[a]:
                             source = a
                             break
                   #print(f"after type {t} source {source} statement {s} ba {hex(ba)}")
                   if not t == None and not source == None:
                      #print(f"[Direct Taint in Transmit] function {hrfun.name} source type {t} source {source}")
                      if not source in args:
                         #print(f"Computing stack offset for {s.addr} in {hex(bb.addr)}")
                         stackoff = self.IRgetLocalOffsetOnEntry(hrfun, baseregset, bb, s.data, source)
                         #print(f"Stack offset {stackoff} for {s.addr}")
                         if not stackoff == None:
                            for so in stackoff:
                                taints.add((hrfun, "stack", so))
                      else:
                         taints.add((hrfun, t, source))
        return taints

    def HALfindReceiveTaints(self, hrfun, an, receiveBuffers, depth=3):
        argname = an
        if isinstance(an,int):
           argname = self.IRgetArgName(an)
        for rb in receiveBuffers:
            print(f"Receive buffer offset: {hex(rb)}")
        # if argname is "", we will still track to the stack but will not be able to link to a register
        baseregset = self.IRgetBaseRegSetForFunction(hrfun)
        #print(f"Base register set {baseregset}")
        taints = set()
        #if hrfun.name == "HAL_UART_IRQHandler":
        #   self.IRprintPredsAndSuccs(hrfun.addr)
        for ba in hrfun.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            stores = [x for x in bb.vex.statements if x.tag == 'Ist_Store']
            #if hrfun.name == "HAL_UART_Receive_IT":
            #   bb.vex.pp()
            for s in stores:
                # first loads the handler's pointer from local then loads from the handler to compute the data register
                #dtoff = self.IRgetOffsetBeforeLoadFromBaseReg(bb, s.addr, baseregset, depth)
                dtoffset = self.IRgetOffsetFromLocalOrArg(hrfun, baseregset, bb, s.addr, depth)
                if not dtoffset == None:
                   for dtoff in dtoffset:
                       if not isinstance(dtoff,int):
                          #print(f"dtoff {dtoff}")
                          dtoff = int(dtoff,16)
                       #print(f"Data structure offset for {s.addr} is {dtoff} in function {hex(hrfun.addr)} name {hrfun.name} at basic block {hex(ba)}")
                       if dtoff in receiveBuffers:
                          #print(f"Found statement setting the receive buffer at {s} in function {hex(hrfun.addr)} name {hrfun.name}")
                          arg = self.IRgetArgMatchOffsetInFunction(hrfun, baseregset, bb, s.data, "Store", "rhs")
                          if not arg == None:
                             print(f"Arg {arg} flows into receive buffer at {s} with offset {dtoff} in function {hex(hrfun.addr)} name {hrfun.name}")
                             taints.add((hrfun, "argument", arg, dtoff))
                             # check if it receives something directly from args
                          sargs = self.IRgetDefinedByArgsInLocalCFG(hrfun,bb,s.data)
                          for sarg in sargs:
                              print(f"Arg {sarg} flows into receive buffer at {s} with offset {dtoff} in function {hex(hrfun.addr)} name {hrfun.name}") 
        return taints

    def HALfindTransmitTaints(self, hrfun, an, transmitBuffers, depth=3):
        argname = self.IRgetArgName(an)
        argname_alias = self.IRgetRegAliasFromFirstBasicBlock(hrfun, argname)
        args = {'r0', 'r1', 'r2', 'r3'}
        aliases = {}
        for a in args:
            aliases[a] = self.IRgetRegAliasFromFirstBasicBlock(hrfun, a)
        # if argname is "", we will still track to the stack but will not be able to link to a register
        baseregset = self.IRgetBaseRegSetForFunction(hrfun)
        #print(f"Base register set {baseregset}")
        taints = set()
        for ba in hrfun.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            stores = [x for x in bb.vex.statements if x.tag == 'Ist_Store']
            #if hrfun.name == "HAL_SPI_Transmit_IT" or hrfun.name == "HAL_SPI_TransmitReceive_IT":
            #   bb.vex.pp()
            for s in stores:
                # first loads the handler's pointer from local then loads from the handler to compute the data register
                dtoff = self.IRgetOffsetBeforeLoadFromBaseReg(bb, s.addr, baseregset, depth)
                if not dtoff == None and not isinstance(dtoff,int):
                   #print(f"dtoff {dtoff}")
                   dtoff = int(dtoff,16)
                #print(f"Data structure offset for {s.addr} is {dtoff} in function {hex(hrfun.addr)} name {hrfun.name} at basic block {hex(ba)}")
                if dtoff in transmitBuffers:
                   print(f"Found statement setting the transmit buffer at {s} in function {hex(hrfun.addr)} name {hrfun.name}")
                   arg = self.IRgetArgMatchOffsetInFunction(hrfun, baseregset, bb, s.data, "Store", "rhs")
                   if not arg == None:
                      print(f"Arg {arg} flows into transmit buffer at {s} with offset {dtoff} in function {hex(hrfun.addr)} name {hrfun.name}")
                      taints.add((hrfun, "argument", arg, dtoff))                    
        return taints

    def IRloadFromAddress(self, state, addr):
        if not isinstance(addr,int):
           addr = int(addr,16)
        valuebv = state.memory.load(addr,4)
        value = state.solver.eval(valuebv)
        value = int.from_bytes(value.to_bytes(4,byteorder='little'),byteorder='big')
        return value

    def IRgetLoadFromAddressBasedOnKnownAssignments(self, func, bb, apnode, target_base_set, state):
        if isinstance(apnode,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, apnode)
           if dnode == None:
              return None
           return self.IRgetLoadFromAddressBasedOnKnownAssignments(func, bb, dnode.data, target_base_set, state)
        else:
           if isinstance(apnode,pyvex.IRExpr.Load) or isinstance(apnode,pyvex.IRStmt.LoadG):
              a = apnode.addr
              #print(f"Load from {apnode.addr} at {hex(bb.addr)}")
              if isinstance(apnode.addr, pyvex.IRExpr.Const):
                 a = apnode.addr.con._value
                 #if any([e1 for e1, e2, e3, e4, e5 in target_base_set if e1 == hex(a)]):
                 #   print(f"Base relevant load address: {apnode.addr}")
                 v = self.IRloadFromAddress(state,a) 
                 if any([e1 for e1, e2, e3, e4, e5 in target_base_set if e1 == hex(v)]):
                    #print(f"Base relevant load address: {apnode.addr} due to loading {hex(v)}")
                    return v
                 #print(f"\tLoad from {apnode.addr} at {hex(bb.addr)} VALUE {hex(v)}")
                 #if func.name == "serialBegin":
                 #   bb.vex.pp()
              else:
                 return self.IRgetLoadFromAddressBasedOnKnownAssignments(func, bb, apnode.addr, target_base_set, state)
           
        return None 

    def IRfindPassingToArgFromSet(self, func, target_base_set, state):
        result = set()
        args = ["r0", "r1", "r2", "r3"] 
        for ba in func.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            if isinstance(bb.vex.next,pyvex.IRExpr.Const):
               cf = self.IRgetFunctionAtAddress(bb.vex.next.con._value)
               if cf == None:
                  continue
               for arg in args:
                   apnode = self.IRfindActualArgNodeForCall(func, bb, arg)
                   if apnode == None:
                      continue
                   value = self.IRgetLoadFromAddressBasedOnKnownAssignments(func, bb, apnode, target_base_set, state)
                   if not value == None:
                      result.add((cf.addr, arg))
        return result
    """
        Finds the node (actual parameter) assigned to argument arg before the function call
    """

    def IRisInCycle(self, f, bb, cfgnode):
        print(f"[IRisInCycle] bb {hex(bb.addr)} cfgn {hex(cfgnode.addr)}")
        bmina, bmaxa = self.IRgetBBAddressRange(bb)
        try:
            ipreds = self._current_cfg.get_all_predecessors(cfgnode, self._predDepth)
        except RecursionError:
            ipreds = set()
        for ipred in ipreds:
            #print(f"\t\t[1] Immediate pred {hex(ipred.addr)} of {hex(cfgnode.addr)}")
            if cfgnode.addr == ipred.addr or (ipred.addr >= bmina and ipred.addr <= bmaxa):
               return True
        pbb, min, max = self.IRgetStatementIndexRangeForCFGNode(f, cfgnode)
        st = pbb.vex.statements[max] 
        if isinstance(st, pyvex.IRStmt.Exit):
           #print(f"\t\t[2] Immediate pred {hex(st.dst.value)} of {hex(cfgnode.addr)}")           
           if cfgnode.addr == st.dst.value or bb.addr == st.dst.value:
              return True
        preds = self.IRfindAllPredsInFunction(f, cfgnode)
        for pred in preds:
            preds2 = self.IRfindAllPredsInFunction(f, pred)
            for pred2 in preds2:
                if pred2.addr == cfgnode.addr:
                   return True
        return False

    def IRisInCycleControlledByArg(self, f, bb, index, arg, filter=None):
        cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
        preds = self.IRfindAllPredsInFunction(f, cfgnode)
        st = bb.vex.statements[len(bb.vex.statements)-1]
        if isinstance(st, pyvex.IRStmt.Exit):
           # include self
           if cfgnode.addr == st.dst.value or bb.addr == st.dst.value:
              preds.add(cfgnode)
        #print(f"cfgnode {hex(cfgnode.addr)} at bb {hex(bb.addr)} index {index} num preds {len(preds)}")
        for pred in preds:
            pbb, min, max = self.IRgetStatementIndexRangeForCFGNode(f, pred)
            st = pbb.vex.statements[max]
            #print(f"Last statement of pred {hex(pred.addr)} {st} len {len(pbb.vex.statements)} max {max}")
            if isinstance(st, pyvex.IRStmt.Exit):
               #print(f"\texit statement: {st} in bb {hex(bb.addr)}")
               ev = ""
               vm = {}
               baseregset = self.IRgetBaseRegSetForFunction(f)
               srcs = self.IRfindAllSourcesofAddress(f, baseregset, pred, pbb, st, max, st.guard, vm, ev, filter, False)
               del vm
               argdep = False
               for src in srcs:
                   #print(f"guard source {src} controlled by {arg}?")
                   if src[0] == 'argument' and src[1] == arg:
                      argdep = True
                      #print(f"cfgnode {hex(cfgnode.addr)} is controlled by {arg} {st} of {hex(pred.addr)}")
                      break
               if not argdep:
                  continue
               if self.IRisInCycle(f, pbb, pred):
                  return True                 
               #print(f"NOT in cycle!!! bb {hex(pbb.addr)} {hex(pred.addr)}")
        return False  

    def IRreadCopyFunctions(self, lenargs=['r1','r2'], oper='add', coffset=4, filter=None):
        # ablation
        # res = set()
        # return res
        if not 'copy_functions_path' in self._config:
           print(f"CRITICAL: copy functions path not defined!\n")
           sys.exit(1)
        fname = self._config['copy_functions_path']
        print(f"Reading copy functions from {fname}\n")
        #if not self._inputdir == "":
        #   fname = self._inputdir + "/" + fname
        cf = Path(fname) 
        if not cf.exists():
           return self.IRfindCopyFunctions(lenargs, oper, coffset, filter)
        with open(fname, 'r') as file:
             for line in file:
                 lt = line.split(',')
                 self._copyfunctions.add((lt[0], int(lt[1],16), int(lt[2],16)))
        return self._copyfunctions      
                  

    def IRfindCopyFunctions(self, lenargs=['r1','r2'], oper='add', coffset=4, filter=None):
        # ablation
        # res = set()
        # return res
        if not 'copy_functions_path' in self._config:
           print(f"CRITICAL: copy functions path not defined!\n")
           sys.exit(1)
        fname = self._config['copy_functions_path']
        print(f"Reading copy functions from {fname}\n")           
        #if not self._inputdir == "":
        #   fname = self._inputdir + "/" + fname
        cf = Path(fname) 
        if cf.exists():
           print(f"Skipping computing {fname} as copy functions already computed/read size {len(self._copyfunctions)}!")
           return self._copyfunctions
        fd = open(fname, "w")  
        allcs = self.IRfindAllCallsites()
        for f in self._current_cfg.functions.values():
            if not any([callee for caller, ia, callee in allcs if callee == f.addr]):
               continue
            print(f"Is {f.name} a copy function?")
            iscpy, witness = self.IRisACopyFunction(f.addr, lenargs, oper, coffset, filter)
            if iscpy:
               for wr in witness.keys():
                   if len(witness[wr]) < 2:
                      continue
                   self._copyfunctions.add((f.name, f.addr, f.size))
                   #self.IRprintBBs(f)
                   print(f"Copy semantics:")
                   for w in witness[wr]:
                       if len(w) == 4:
                          f, bb, i, nc = w
                          st = bb.vex.statements[i]
                          print(f"\tFunction f {f.name} at {hex(f.addr)} {hex(bb.addr)} statement {st} node {nc}")
                       elif len(w) == 2:
                          print(f"\tFunction f {f.name} at {w[0]}: {w[1]}")
               del witness 
        for cfn, cfa, cfs in self._copyfunctions:
            fd.write(f"{cfn},{hex(cfa)},{cfs}\n") 
        fd.close() 
        return self._copyfunctions

    # Patterns checked
    # Pattern 1: Find store instructions where both the address and the source 
    #            result from arithmetic computations add/sub using a specific offset
    # Pattern 2: Find store instructions where either the address or the source 
    #            result from arithmetic computations add/sub using a specific offset
    # Pattern 3: Find store instructions where neither the address nor the source 
    #            result from arithmetic computations yet at least one of them is defined by the 
    #            non-constant term of an arithmetic computation add/sub using a specific offset
    # Also cycle may be controlled by r1 (e.g., strcpy) or r2 (e.g., memcpy)
    def IRisACopyFunction(self, fa, lenargs=['r1', 'r2'], oper='add', coffset=4, filter=None):
        f = self.IRgetFunctionAtAddress(fa)
        #self.IRprintBBs(f)
        baseregset = self.IRgetBaseRegSetForFunction(f)
        count = 0
        addNodesGlobal = {}
        storestmts = set()
        for ba in f.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            index = 0
            addNodes = set()
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.WrTmp):
                     node = st.data
                     if isinstance(node,pyvex.IRExpr.Binop):
                        if oper == 'add' and (node.op == 'Iop_Add64' or node.op == 'Iop_Add32' or node.op == 'Iop_Add16'):
                           nc = None
                           const = None
                           for ce in node.child_expressions:
                               if not isinstance(ce,pyvex.IRExpr.Const):
                                  nc = ce
                               else:
                                  if not ce.con._value == coffset:
                                     nc = None
                                     break
                                  else: 
                                     const = coffset              
                           if not nc == None and not const == None:
                              addNodes.add((f, bb, index, nc))
                              #print(f"\t add node {hex(bb.addr)} index {index} {nc}")
                        if oper == 'sub' and (node.op == 'Iop_Sub64' or node.op == 'Iop_Sub32' or node.op == 'Iop_Sub16'):
                           nc = None
                           const = None
                           for ce in node.child_expressions:
                               if not isinstance(ce,pyvex.IRExpr.Const):
                                  nc = ce
                               else:
                                  if not ce.con._value == coffset:
                                     nc = None
                                     break
                                  else: 
                                     const = coffset              
                           if not nc == None and not const == None:
                              addNodes.add((f, bb, index, nc))
                  index += 1
            if len(addNodes) >= 2:
               usedsts = {}
               for an in addNodes:
                   f, bb, i, nc = an
                   st = bb.vex.statements[i]
                   #print(f"finding cgnode for bb {hex(bb.addr)} and index {i}")
                   cfgnode = self.IRfindCFGNodeForStatement(f, bb, i)
                   if cfgnode == None:
                      #print(f"cfgnode not found for {st}")
                      continue
                   try:  
                       #print(f"add/sub : {st} {nc} i {i} cfgnode {hex(cfgnode.addr)} bb {hex(bb.addr)}")
                       v = set()
                       ev = "" 
                       uses = self.IRgetUsesInFunctionNode(f, cfgnode, bb, st, i, "t" + str(st.tmp), v, ev)
                       del v
                   except RecursionError:
                       #print(f"Recursion error in use")
                       uses = set()
                   #print(f"Num uses: {len(uses)}")
                   for use in uses:
                       ubba, ust, ui, nuse, nother, ev = use
                       #print(f"ubba {hex(ubba)} bb {hex(bb.addr)}")
                       if not ubba == bb.addr:
                          #print(f"Skipping use {ust} in {hex(ubba)}")
                          continue
                       #print(f"\tUse : {ust} in {hex(ubba)}")
                       tuple = (ubba,ui)
                       if not tuple in usedsts.keys():
                          usedsts[tuple] = set()
                       usedsts[tuple].add((an,use))
                   if len(uses) == 0:
                      # check if non-constant term of arithmetic op is used by a store as in strcpy
                      try:  
                          #print(f"checking non-constant term uses : {nc}")
                          v = set()
                          ev = "" 
                          ncuses = self.IRgetUsesInFunctionNode(f, cfgnode, bb, st, i, nc, v, ev)
                      except RecursionError:
                          ncuses = set()
                      for ncuse in ncuses:
                          ubba, ust, ui, nuse, nother, ev = ncuse
                          try:
                              ubb = self._project.factory.block(ba)
                          except angr.errors.SimEngineError:
                              continue
                          storestmts.add(((f,ubb,ui), ncuse))
               addsWithUse = set()
               for uk in usedsts.keys():
                   #print(f"Use key : {hex(uk[0])} {uk[1]}")
                   unodes = set()
                   for an, un in usedsts[uk]:
                       #print(f"\t{an[3]} {un[1]}")
                       unodes.add(un[3]) 
                   if len(unodes) >= 2:
                      rel = set()
                      for node in unodes:
                          for an, un in usedsts[uk]:
                              if str(un[3]) == str(node):
                                 #print(f"Comparing {str(un[3])} vs {str(node)}")
                                 rel.add(an)
                      if len(rel) > 0:
                         addNodesGlobal[count] = rel
                         count += 1
                   for node in unodes:
                       for an, un in usedsts[uk]:
                           if str(un[3]) == str(node):
                              ubba, ust, ui, nuse, nother, ev = un
                              try:
                                  ubb = self._project.factory.block(ba)
                              except angr.errors.SimEngineError:
                                  continue
                              storestmts.add(((f, ubb, ui), un))
        sources0 = set()
        sources1 = set()
        toberemovedkeys = set()
        nottoberemovedkeys = set()
        for ak in addNodesGlobal.keys():
            for an in addNodesGlobal[ak]:
                f, bb, i, nc = an
                st = bb.vex.statements[i]
                cfgnode = self.IRfindCFGNodeForStatement(f, bb, i)
                ev = ""
                vm = {}
                #print(f"Finding source of {nc} from {st} {hex(bb.addr)} {i}")
                src = self.IRfindAllSourcesofAddress(f, baseregset, cfgnode, bb, st, i, nc, vm, ev, filter, False) 
                del vm 
                for s in src:
                    #print(f"source {s[0]} {s[1]} {f.name} {i} {nc}")
                    if s[0] == 'argument' and s[1] == 'r0':
                       sources0.add(an)
                    if s[0] == 'argument' and s[1] == 'r1':
                       sources1.add(an)
            if len(sources0) > 0 and len(sources1) > 0: 
               for s0 in sources0:
                   # check if within a cycle controlled by r2
                   incycle = False
                   for lenarg in lenargs: 
                       if self.IRisInCycleControlledByArg(s0[0], s0[1], s0[2], lenarg, filter):
                          incycle = True
                          break
                   if not incycle:
                      toberemovedkeys.add(ak)
                   else:
                      nottoberemovedkeys.add(ak)
                      # optimization
                      break
            else:
               toberemovedkeys.add(ak)                         
        for rkey in toberemovedkeys:
            if not rkey in nottoberemovedkeys:
               del addNodesGlobal[rkey] 
        if len(addNodesGlobal) > 0:
           return (len(addNodesGlobal) > 0, addNodesGlobal)
        else:
           # accept those case where at least either the dest or src uses offset
           for an, use in storestmts:
               ubba, ust, ui, nuse, nother, ev = use
               #print(f"checking use {ust} bb {hex(ubba)} index {ui}")
               try:
                   ubb = self._project.factory.block(ubba)
               except angr.errors.SimEngineError:
                   continue
               #print(f"finding cfgnode for bba {hex(ubba)} bb.addr {hex(ubb.addr)} index {ui}")
               ucfgnode = self.IRfindCFGNodeForStatement(f, ubb, ui)
               #print(f"ucfgnode {hex(ucfgnode.addr)} for bb {hex(ubb.addr)} index {ui}")
               if str(nuse) == str(ust.addr):
                  dest = nuse
                  src = nother
               else:
                  dest = nother
                  src = nuse
               vm1 = {}
               src1 = self.IRfindAllSourcesofAddress(f, baseregset, ucfgnode, ubb, ust, ui, dest, vm1, "", filter, False)
               #for s1 in src1:
               #    print(f"\t source: {s1}")
               vm2 = {}
               src2 = self.IRfindAllSourcesofAddress(f, baseregset, ucfgnode, ubb, ust, ui, src, vm2, "", filter, False)
               #for s2 in src2:
               #    print(f"\t source: {s2}")                    
               r0dest = any([src[1] for src in src1 if src[0] == 'argument' and src[1] == 'r0'])
               r1src = any([src[1] for src in src2 if src[0] == 'argument' and src[1] == 'r1'])
               #print(f" r0dest {r0dest} r1src {r1src}")
               if r0dest and r1src:
                  incycle = False
                  for lenarg in lenargs: 
                      if self.IRisInCycleControlledByArg(an[0], an[1], an[2], lenarg, filter):
                         incycle = True
                         break 
                  if incycle: 
                     addNodesGlobal[0] = set()
                     addNodesGlobal[0].add(("r0",nuse))
                     addNodesGlobal[0].add(("r1",nother))
                     print(f"Copy from r1 to r0: {ust}") 
                     return (True, addNodesGlobal)
                  #else:
                  #   print(f"bb {hex(an[1].addr)} index {an[2]} ubb {hex(ubb.addr)} arg {lenarg}")
                  #   ubb.vex.pp()
               r1dest = any([src[1] for src in src1 if src[0] == 'argument' and src[1] == 'r1'])
               r0src = any([src[1] for src in src2 if src[0] == 'argument' and src[1] == 'r0'])
               print(f"r1dest {r1dest} r0src {r0src}")
               if r1dest and r0src:
                  incycle = False
                  for lenarg in lenargs:  
                      if self.IRisInCycleControlledByArg(an[0], an[1], an[2], lenarg, filter):
                         incycle = True
                         break
                  if incycle:
                     addNodesGlobal[0] = set()
                     addNodesGlobal[0].add(("r0",nother))
                     addNodesGlobal[0].add(("r1",nuse)) 
                     print(f"Copy from r0 to r1: {ust}") 
                     return (True, addNodesGlobal)               
                  #else:
                  #   print(f"bb {hex(an[1].addr)} index {an[2]} ubb {hex(ubb.addr)} arg {lenarg}")
                  #   ubb.vex.pp()
        return (False, {}) 

    # assumes that function call is the last action of the basic block bb
    def IRfindActualArgNodeForCall(self, func, bb, arg):
        argnode = None
        for s in bb.vex.statements:
           if isinstance(s,pyvex.IRStmt.Put):
              if self._project.arch.register_names[s.offset] == arg:
                 argnode = s.data
        return argnode

    def getLocalOffset(self, str):
        index = str.rfind("_")
        off = str[index+1:]
        return int(off)

    def IRlocalDefinedByArg(self, func, localoff, type):
        argregs = ['r0', 'r1', 'r2', 'r3']
        try:
           bb1 = self._project.factory.block(func.addr)
        except angr.errors.SimEngineError:
           return None
        for s in bb1.vex.statements:
            if isinstance(s,pyvex.IRStmt.Store) or instance(s, pyvex.IRStmt.StoreG):
               if isinstance(s.data,pyvex.IRExpr.Get):
                  if self._project.arch.register_names[s.data.offset] in argregs:
                     # compute the offset for the target address
                     coff, basereg = self.IRcomputeStackOffsetAtBasicBlock(func, bb1, s.addr, "Store", "lhs")
                     print(f"Offset for {s.addr} is {coff}")
                     if coff == localoff:
                        return self._project.arch.register_names[s.data.offset]
                     else:
                        if type == "receive":
                           if self.IRlocalTaints(func, localoff, coff):
                              return self._project.arch.register_names[s.data.offset]  
                        if type == "transmit":
                           if self.IRlocalTaints(func, coff, localoff):
                              return self._project.arch.register_names[s.data.offset]  
               if isinstance(s.data,pyvex.IRExpr.RdTmp):
                  dnode = self.IRgetDefStmt(bb1, s.data)
                  if not dnode == None:
                     if isinstance(dnode.data,pyvex.IRExpr.Get):
                        if self._project.arch.register_names[dnode.data.offset] in argregs:
                        # compute the offset for the target address
                           coff, basereg = self.IRcomputeStackOffsetAtBasicBlock(func, bb1, s.addr, "Store", "lhs")
                           print(f"Offset for {s.addr} is {coff}")
                           if coff == localoff:
                              return self._project.arch.register_names[dnode.data.offset]
                           else:
                              if type == "receive":
                                 if self.IRlocalTaints(func, localoff, coff):
                                    return self._project.arch.register_names[dnode.data.offset]  
                              if type == "transmit":
                                 if self.IRlocalTaints(func, coff, localoff):
                                    return self._project.arch.register_names[dnode.data.offset]  
        return None 
    
    def IRgetAddressLoadingFrom(self, func, bb, node):
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if dnode == None:
              return None
           else:
              return self.IRgetAddressLoadingFrom(self, func, bb, dnode)
        if isinstance(node,pyvex.IRExpr.Load) or isinstance(node,pyvex.IRStmt.LoadG):
           return node.addr
        for ce in node.child_expressions:
            if not isinstance(node,pyvex.IRExpr.Const):
               return self.IRgetAddressLoadingFrom(self, func, bb, ce)
        return None   

    """
       Does it flow from offset1 to offset2
    """
    def IRlocalTaints(self, func, offset1, offset2):
        print(f"Does it flow from offset {offset1} to offset {offset2} in function {func.name}?")
        for ba in func.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            for s in bb.vex.statements:
                if isinstance(s,pyvex.IRStmt.Store) or isinstance(s,pyvex.IRStmt.StoreG):
                   o2, br = self.IRcomputeStackOffsetAtBasicBlock(func, bb, s.addr, "Store", "lhs")
                   if o2 == offset2:
                      print(f"Destination offset {offset2} matches {s.addr}")
                      o1, br = self.IRcomputeStackOffsetAtBasicBlock(func, bb, s.data, "Store", "rhs")
                      if o1 == offset1:
                         #print(f"Source offset {offset1} matches {s.data}")
                         return True
        return False

    def HALanalyzeImplicitTaint(self, func, baseregset, bb, apnode, localoffstr, type):
        #spOffset = self.IRgetLocalOffsetForReg(func, "sp")
        localoff = self.getLocalOffset(localoffstr)
        #origoffset = localoff + spOffset
        print(f"Local offset {localoff} for {apnode}")
        arg = None
        if localoff < 0:
           # must be a local variable
           print(f"Checking if local variable is defined by an arg register")
           arg = self.IRlocalDefinedByArg(func, localoff, type)
        else:
           # must be an arg (no >=4) passed via the stack
           print(f"to do: implement")
           #arg = "arg_sp_offset_%d" % (offset)
        return arg

    def HALanalyzeCallingContextForTaint(self, func, arg, type):
        taints = set()
        baseregset = self.IRgetBaseRegSetForFunction(func)
        for caller in self._current_cfg.functions.values():
            for ba in caller.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                if isinstance(bb.vex.next,pyvex.IRExpr.Const):
                   if bb.vex.next.con._value == func.addr:
                      print(f"calling function {hex(func.addr)} name {func.name} within function {hex(caller.addr)} name {caller.name}")
                      apnode = self.IRfindActualArgNodeForCall(caller, bb, arg)
                      if not apnode == None:
                         print(f"Checking node {apnode} that gets set to {arg}")
                         argoff = self.IRgetArgMatchOffsetInFunction(caller, baseregset, bb, apnode, "Put", "rhs")
                         if self.IRisArgReg(argoff):
                            print(f"Adding taint for {argoff}")
                            taints.add((caller, "argument", argoff))
                         else:
                            #if caller.name == "SPI_WIFI_ReceiveData":
                            #   bb.pp()
                            #   bb.vex.pp()
                            argimp = self.HALanalyzeImplicitTaint(caller, baseregset, bb, apnode, argoff, type)
                            if self.IRisArgReg(argimp):
                               print(f"Adding taint for {argimp}")
                               taints.add((caller, "argument", argimp))
        return taints

    def HALisHandlerAddressSource(self, func, handler_argno, cfgnode, bb, st, index, node):
        return True

    # instance is assumed to be at a zero offset within the handler
    def HALisHandlerInstanceAddressSource(self, func, handler_argno, cfgnode, bb, st, index, node):
        return True

    # one possible offset is the data register offset
    def HALisHandlerInstancePointerOffsetDataSource(self, baseregset, argname, offset, func, cfgnode, bb, index, node, dtuples, filter=None):
        args = ['r0','r1','r2','r3'] 
        for dtuple in dtuples:
               t1, t2, t3, t4, t5 = dtuple
               print(f"Ultimate def {dtuple}: ({hex(t1)},{t2},{t3},{t4},{t5}) for {hex(bb.addr)} {index} {node}")
               #if not self.IRselfdef(func, bb, index, node, dtuple):
               #if this this sourced from handler_argno
               dba, dindex, dnode, c, ev = dtuple
               if isinstance(dnode, pyvex.IRExpr.Get):
                  if argname in args and self._project.arch.register_names[dnode.offset] == argname:
                     #print(f"isDefLoadLoadArgOffset {node} target offset {offset}")
                     (fr, er) = self.IRisDefLoadLoadArgOffset(func, cfgnode, bb, index, node, argname, offset, ev, filter)
                     if fr:
                        return (True, er)
                  elif self._project.arch.register_names[dnode.offset] in baseregset:
                     #print(f"isDefLoadLoadLoadBaseRegThenOffset {node} target offset {offset}")
                     (fr, er) = self.IRisDefLoadLoadLoadBaseRegThenOffset(baseregset, func, cfgnode, bb, index, node, argname, offset, ev, filter)
                     if fr: 
                        return (True, er)
        return (False,"")



    # one possible offset is the data register offset
    def HALisHandlerInstancePointerOffsetAddressSource(self, baseregset, argname, offset, func, cfgnode, bb, index, node, dtuples, filter=None):
        args = ['r0','r1','r2','r3'] 
        for dtuple in dtuples:
            t1, t2, t3, t4, t5 = dtuple
            if func.name == "HAL_UART_Transmit":
               print(f"Ultimate def {dtuple}: ({hex(t1)},{t2},{t3},{t4}) for {hex(bb.addr)} {index} {node}")
            #if not self.IRselfdef(func, bb, index, node, dtuple):
            #if this this sourced from handler_argno
            dba, dindex, dnode, c, ev = dtuple
            if isinstance(dnode, pyvex.IRExpr.Get):
               print(f"Handler source register: offset {dnode.offset} {self._project.arch.register_names[dnode.offset]}")
               if argname in args and self._project.arch.register_names[dnode.offset] == argname:
                  #print(f"isDefLoadArgOffset {node} target offset {offset}")
                  #(fr, er) = self.IRisDefLoadArgOffset(func, cfgnode, bb, index, node, argname, offset, ev)
                  #(fr, er) = self.IRisDefLoadLoadArgOffset(func, cfgnode, bb, index, node, argname, offset, ev)
                  #if fr:
                  #   return (True, er)
                  mev = ""
                  st = bb.vex.statements[index]
                  lus = self.IRgetLoadAddressWithOffset(func, cfgnode, bb, st, index, node, offset, mev, filter)
                  for lu in lus:
                      lbba, lindex, lnode, lc, lev = lu
                      print(f"Checking {lnode} in {hex(lbba)} with offset {lc} exp {lev}")
                      if lc == offset and (isinstance(lnode, pyvex.IRExpr.Load) or isinstance(lnode, pyvex.IRStmt.LoadG)):
                         return (True, lev)
               elif self._project.arch.register_names[dnode.offset] in baseregset:
                  #print(f"isDefLoadLoadBaseRegThenOffset {node} target offset {offset}")
                  (fr, er) = self.IRisDefLoadLoadBaseRegThenOffset(baseregset, func, cfgnode, bb, index, node, argname, offset, ev)
                  if fr:
                     return (True, er)
        return (False, "")

    # returns the source if true, None otherwise
    def HALfindReceiveBufferAddressSource(self, hrfun, handler_argno, droffset, filter=None):
        argname = handler_argno
        if isinstance(handler_argno,int):
           argname = self.IRgetArgName(handler_argno)
        baseregset = self.IRgetBaseRegSetForFunction(hrfun)
        baseregset.add("sp")
        #print(f"Base register set {baseregset} for function {hrfun.name}")
        taints = set()
        #if hrfun.name == "HAL_UART_IRQHandler":
        #   self.IRprintPredsAndSuccs(hrfun.addr)
        for ba in hrfun.block_addrs:
            # for testing 
            #if not ba == hrfun.addr:
            #   continue
            #if not (ba == 0x8002512 or ba == 0x8002513):
            #   continue
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               print(f"WARNING: Could not get bb for {ba}")
               continue
            index = 0
            if hrfun.name == "UART_Receive_IT":
               bb.vex.pp()
            while index < len(bb.vex.statements): 
                st = bb.vex.statements[index]
                if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                   if not isinstance(st.data, pyvex.IRExpr.Const):
                      cfgnode = self.IRfindCFGNodeForStatement(hrfun, bb, index)
                      print(f"<<<<<<<<<<<<<<<< {st} {cfgnode} >>>>>>>>>>>>>>>>>")
                      if not cfgnode == None:
                         # read from data register
                         halev = "\n(%s,%d,%s)\n" % (hex(bb.addr), index, st)
                         dtuples = self.IRgetLoadAddressDefUltimate(hrfun, cfgnode, bb, st, index, st.data, halev, None, filter)
                         print(f"Size of LoadAddressDefUltimate for {st.data}: {len(dtuples)}") 
                         (hf, he) = self.HALisHandlerInstancePointerOffsetDataSource(baseregset, argname, droffset, hrfun, cfgnode, bb, index, st.data, dtuples)
                         if hf:
                            print(f"HAL handler source detected for {st.data}")
                            print(f"========================= HAL Handler evidence begin==========================")
                            print(f"{halev}\n{he}")
                            print(f"=========================HAL Handler evidence end==========================")
                            visitedMap = {}
                            se = ""
                            #print(f"From [HALfindReceiveBufferAddressSource] {st.addr}")
                            rbufds = self.IRfindAllSourcesofAddress(hrfun, baseregset, cfgnode, bb, st, index, st.addr, visitedMap, se, filter)
                            del visitedMap 
                            for rbufd in rbufds:
                                if len(rbufd) == 3:
                                   t, o, e = rbufd
                                   print(f"Receive buffer source {t} {o}")
                                   taints.add((hrfun, t, o))
                                elif len(rbufd) == 4:
                                   t, o, dtsof, e = rbufd
                                   print(f"Receive buffer source {t} {o} {dtsof}")
                                   taints.add((hrfun, t, o, dtsof))
                                print(f"========================= Source Address evidence begin==========================")
                                print(f"{e}") 
                                print(f"========================= Source Address evidence end==========================")
                                # todo: make it configurable
                            if len(rbufds) > 0:
                               return taints 
                index += 1
        return taints 

    # returns the source if true, None otherwise
    def HALfindTransmitBufferAddressSource(self, hrfun, handler_argno, droffset, filter=None):
        argname = handler_argno
        if isinstance(handler_argno,int):
           argname = self.IRgetArgName(handler_argno)
        baseregset = self.IRgetBaseRegSetForFunction(hrfun) 
        baseregset.add("sp")
        #print(f"Base register set {baseregset} for function {hrfun.name}")
        taints = set()
        #if hrfun.name == "HAL_UART_IRQHandler":
        #   self.IRprintPredsAndSuccs(hrfun.addr)
        numbbs = 0
        for ba in hrfun.block_addrs:
            numbbs += 1
            # for testing 
            #if not ba == hrfun.addr:
            #   continue
            #if numbbs > 2:
            #   continue
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            index = 0
            if hrfun.name == "HAL_UART_Transmit" or hrfun.name == "HAL_I2C_Mem_Write":
               bb.vex.pp()
            while index < len(bb.vex.statements):
                st = bb.vex.statements[index]
                if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                   if not isinstance(st.data, pyvex.IRExpr.Const):
                      cfgnode = self.IRfindCFGNodeForStatement(hrfun, bb, index)
                      if not cfgnode == None:
                         print(f"<<<<<<<<<<<<<<<< {st} {cfgnode} >>>>>>>>>>>>>>>>>")
                         # write to data register
                         halev = "(%s,%d,%s)\n" % (hex(bb.addr), index, st) 
                         dtuples = self.IRgetDefUseUltimate(hrfun, cfgnode, bb, st, index, st.addr, halev, filter)
                         print(f"cfgnode {hex(cfgnode.addr)} st {st} index {index} def tuples {len(dtuples)}")
                         (hf, he) = self.HALisHandlerInstancePointerOffsetAddressSource(baseregset, argname, droffset, hrfun, cfgnode, bb, index, st.addr, dtuples)
                         if hf:
                            print(f"HAL handler source detected for {st.addr}")
                            print(f"========================= HAL Handler evidence begin==========================")
                            print(f"{halev}\n{he}") 
                            print(f"=========================HAL Handler evidence end==========================")
                            se = "" 
                            ua = self.IRgetLoadAddressDef(hrfun, cfgnode, bb, st, index, st.data, se, filter)
                            for uat in ua:
                                uabba, uai, uan, uac, uev = uat
                                uabb = self._project.factory.block(uabba)  
                                ucfgnode = self.IRfindCFGNodeForStatement(hrfun, uabb, uai)  
                                uast = uabb.vex.statements[uai] 
                                visitedMap = {}
                                tbufds = self.IRfindAllSourcesofAddress(hrfun, baseregset, ucfgnode, uabb, uast, uai, uan, visitedMap, uev, filter)
                                del visitedMap 
                                for tbufd in tbufds:
                                    if len(tbufd) == 3:
                                       t, o, e = tbufd
                                       print(f"Transmit buffer source {tbufd}")
                                       taints.add((hrfun, t, o))
                                    elif len(tbufd) == 4:
                                       t, o, dtsof, e = tbufd
                                       print(f"Transmit buffer source {tbufd}")
                                       taints.add((hrfun, t, o, dtsof))                                       
                                    print(f"========================= Source Address evidence begin==========================")
                                    print(f"{e}") 
                                    print(f"========================= Source Address evidence end==========================")
                                    # todo: make it configurable  
                                    return taints 
                index += 1
        return taints    


    def HALfindAllCalleeHandlerReceiving(self, halF):
        result = set()
        for fa, halArgNo in halF:
            hrfun = self.IRgetFunctionAtAddress(fa)
            res = self.HALfindCalleeHandlerReceiving(hrfun, halArgNo, halF)
            for r in res:
                result.add(r)
        for r in result:
            halF.add(r) 
        return result

    def HALisInHALReceiving(self, fa, arg, halF):
        if (fa, arg) in halF:
           return True
        for faddr, argno in halF:
            if faddr == fa:
               if isinstance(argno, int):
                  if argno == 0 and arg == 'r0':
                     return True
                  if argno == 1 and arg == 'r1':
                     return True
                  if argno == 2 and arg == 'r2':
                     return True
                  if argno == 3 and arg == 'r3':
                     return True
        return False      
                  

    def HALfindCalleeHandlerReceiving(self, hrfun, halArgNo, halF, filter=None):
        if isinstance(halArgNo, int):
           halArgNo = self.IRgetArgName(halArgNo)
        print(f"Finding handler receiving through argument passing from {hrfun.name} for {halArgNo}")
        result = set()
        baseregset = self.IRgetBaseRegSetForFunction(hrfun)
        baseregset.add('sp')
        for ba in hrfun.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            #if hrfun.name == "HAL_UART_IRQHandler":
            #   bb.vex.pp();       
            callees = set()
            index = 0
            while index < len(bb.vex.statements):
                st = bb.vex.statements[index]
                if isinstance(st, pyvex.IRStmt.Put):
                   if self._project.arch.register_names[st.offset] == 'pc':
                      #print(f"Setting pc: {st}") 
                      if isinstance(st.data, pyvex.IRExpr.Const):
                         fa = st.data.con._value
                         if fa in self._current_cfg.functions or fa + 1 in self._current_cfg.functions:
                            if fa + 1 in self._current_cfg.functions:
                               fa += 1
                            #print(f"Callee address : {hex(st.data.con._value)}")
                            if not self.IRisArgDefinedFrom(hrfun, bb, index, halArgNo):
                               if not self.HALisInHALReceiving(fa, halArgNo, halF):
                                  result.add((fa, halArgNo))
                                  break 
                            func = self._current_cfg.functions[fa]
                            callees.add(fa)
                            if any([f1 for f1, f2 in halF if f1 == fa]):
                               continue
                            res = self.IRfindArgSourceFrom(hrfun, baseregset, bb, index - 1, halArgNo, filter)
                            for r in res:
                                rfa, rargno = r
                                #print(f"Argument source {r}\n")
                                if not any([faddr for faddr, argno in halF if faddr == rfa and argno == rargno]):
                                   result.add((fa, r))   
                index += 1
            if isinstance(bb.vex.next,pyvex.IRExpr.Const):
               fa = bb.vex.next.con._value
               if not fa in self._current_cfg.functions:
                  if fa + 1 in self._current_cfg.functions:
                     fa += 1
                  else:
                     continue 
               if not self.IRisArgDefinedFrom(hrfun, bb, len(bb.vex.statements) - 1, halArgNo):
                  if not self.HALisInHALReceiving(fa, halArgNo, halF):
                     result.add((fa, halArgNo))
                     return result  
               func = self._current_cfg.functions[fa]
               #print(f"Callee address : {hex(fa)} name {func.name}")
               callees.add(fa)
               if any([f1 for f1, f2 in halF if f1 == fa]):
                  continue 
               res = self.IRfindArgSourceFrom(hrfun, baseregset, bb, len(bb.vex.statements) - 1, halArgNo, filter)
               for r in res:
                   rfa, rargno = r
                   #print(f"Argument source {r}\n")
                   if self.HALisInHALReceiving(rfa, rargno, halF):
                      continue
                   result.add((fa, r))                
        return result

    def HALfindBufferAliases(self, halF, tuples, filter=None):
        aliases = set()
        for tuple in tuples:
            if not len(tuple) == 4:
               continue
            f, type, source, dtoffset = tuple
            for fa, argno in halF:
                hrfun = self._current_cfg.functions[fa]
                baseregset = self.IRgetBaseRegSetForFunction(hrfun)
                print(f"Finding aliases in function {hex(fa)} name {hrfun.name} for offset {dtoffset}")
                candidates = self.IRgetBBsWithConstant(hrfun, dtoffset)
                for cbb in candidates:
                    #cbb.vex.pp()
                    index = 0
                    while index < len(cbb.vex.statements):
                          st = cbb.vex.statements[index]
                          if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                             visitedMap = {}
                             ev = ""
                             cfgnode = self.IRfindCFGNodeForStatement(hrfun, cbb, index)
                             if not cfgnode == None:
                                #print(f"Finding sources of address {st.addr}")
                                #tbufds = self.IRfindAllSourcesofAddress(hrfun, baseregset, cfgnode, cbb, st, index, st.addr, visitedMap, ev)
                                visited = set()
                                tdefs = self.IRgetDefForUse(hrfun, cfgnode, cbb, st, index, st.addr, filter, visited)
                                del visited
                                for td in tdefs:
                                    tba, ti, tn, tc, tev = td
                                    #print(f"Offset of def use {tc} vs {dtoffset}")
                                    if tc == dtoffset:
                                       evcpy = "" 
                                       vm = {}
                                       us = self.IRfindAllSourcesofAddress(hrfun, baseregset, cfgnode, cbb, st, index, st.addr, vm, evcpy, filter)
                                       del vm
                                       matched = False  
                                       for ud in us:
                                           if len(ud) == 3: 
                                              type2, source2, ev = ud
                                              if type2 == "argument" and type == type2 and source2 == source:
                                                 matched = True
                                                 break
                                           elif len(ud) == 4:
                                              type2, source2, dtoffset2, ev = ud
                                              print(f"Candidate for store {st} address {st.addr} {type2} {source2} {dtoffset2}")
                                              if type2 == "argument" and type == type2 and source2 == source:
                                                 matched = True
                                                 break
                                       if matched:
                                          vm2 = {}
                                          ev2 = ""
                                          taliases = self.IRfindAllSourcesofAddress(hrfun, baseregset, cfgnode, cbb, st, index, st.data, vm2, ev2, filter)
                                          del vm2  
                                          for talias in taliases:
                                              if len(talias) == 3:
                                                 t3, s3, e3 = talias
                                                 if t3 == "argument" and s3 == source:
                                                    continue
                                                 aliases.add((fa, type, source, dtoffset, t3, s3))
                                                 print(f"ALIAS: {hex(fa)} {type} {source} {dtoffset} {t3} {s3}")
                                              elif len(talias) == 4:
                                                 t3, s3, o3, e3 = talias
                                                 if t3 == "argument" and s3 == source:
                                                    continue
                                                 aliases.add((fa, type, source, dtoffset, t3, s3, o3))
                                                 print(f"ALIAS: {hex(fa)} {type} {source} {dtoffset} {t3} {s3} {o3}")
                          index += 1
        return aliases



    def HALgetFunctionsWithPeripheralRegisterAccess(self, dataRegOffset):
        result = self.IRgetFunctionsWithConstant(dataRegOffset)
        offsets = self.HALgetAdjacentRegisters(dataRegOffset)
        fmap = {}
        for f in result:
            #if not f.name == "spi_stm32_isr": 
            #if not f.name == "spi_sam_fast_rx": 
            #   continue          
            sat = 0
            satval = set()
            for can in offsets:
                if self.IRisFunctionWithConstant(f, can):
                   sat += 1
                   satval.add(can)
            if sat>0:
               satval.add(dataRegOffset)
               fmap[f] = satval
               print(f"Function {f.name} with {sat} additional constants {satval}")
        return fmap.keys()

        
    def HALgetAdjacentRegisters(self, regoffset):
        offsets = [8]
        return offsets 
        candidate = regoffset
        while candidate >= 0:
              candidate -= 4
              if candidate > 0:
                 offsets.append(candidate)
        candidate = regoffset
        index = 1
        num = 4
        while index <= 4:
              candidate += 4*index
              offsets.append(candidate)
              index += 1
        return offsets 

   
    def HALFindGlobalBufferAccessLocations(self,actualBufferAddresses, bufferInfo, snapshotInfo, filter=None):
        faddrs = set()
        directAccesses, indirectAccesses = self.IRfindAddressLoadLocations(actualBufferAddresses, filter)
        print(f"Direct load buffer accesses:")
        for da in directAccesses:
            print(f"Buffer direct load access in {da[0].name} bb {hex(da[1].addr)} instruction {hex(da[2])} buffer at {hex(da[3])}")
            faddrs.add(da[0].addr)
            bufferInfo.add((da[0].name,da[0].addr,da[1].addr,da[2],da[3]))
        print(f"Indirect load buffer accesses:")
        for da in indirectAccesses:
            print(f"Buffer indirect load access in {da[0].name} bb {hex(da[1].addr)} instruction {hex(da[2])} buffer at {hex(da[3])}") 
            faddrs.add(da[0].addr)
            bufferInfo.add((da[0].name,da[0].addr,da[1].addr,da[2],da[3]))
        for fn,fa,bba,ia,buf in bufferInfo:
           ff = self.IRgetFunctionAtAddress(fa)
           callers = self.IRfindImmediateCallersWithCallsite(ff)
           for ca, ba in callers:
               c = self.IRgetFunctionAtAddress(ca)
               snapshotInfo.add((c.name, ca, ba, fn, fa, buf))               
               print(f"Caller {c.name} {hex(ca)} of {fn} {hex(fa)} callsite {hex(ba)} buffer {hex(buf)}") 


    def DynisCalledExplicitly(self, trace, f, maxindex):
        if self._dynExplicitCalls == None:
           self._dynExplicitCalls  = set()
           for k, tuple in trace.items():
               if tuple[0] == 'enter': 
                  tf = self.IRgetFunctionOfInstruction(tuple[2]-1)
                  if not tf == None:
                     self._dynExplicitCalls.add(tf.addr)
        return (f.addr in self._dynExplicitCalls)   

    

    def DyngetReturnAddressInternal(self, trace, index, maxindex, current, fstream=None):
        #print(f"index={index} current {current.name} addr {hex(current.addr)}") 
        #if not trace[index][0] == 'enter':
        #   if trace[index][0] == 'write' or trace[index][0] == 'read' or trace[index][0] == 'readMMIO':
        #      f = self.IRgetFunctionOfInstruction(trace[index][3])
        #      if not f == None and not f.addr == current.addr:
        #         print(f"Need to adjust target function from {current.name} to {f.name}!!!")
        #         sys.stdin.read(1) 
        csseen = 0        
        i = index 
        while i >= 0:
              if i in trace.keys():
                 if trace[i][0] == 'enter':
                    csseen += 1
                    if csseen > 500:
                       print(f"Could not find a caller after checking {csseen} callsites, start index {index} now {i} current {hex(current.addr)} vs {hex(trace[i][1])}")
                       if not fstream == None:
                          fstream.write(f"Could not find a caller after checking {csseen} callsites, start index {index} now {i} current {hex(current.addr)} vs {hex(trace[i][1])}\n")
                       break
                    if trace[i][1] == current.addr or trace[i][1] + 1 == current.addr:
                       return trace[i][2]      
              i -= 1
        return None      

    def DyngetReturnAddress(self, trace, index, fstream=None, callee=None):
        #print(f"[DyngetReturnAddress] index {index}")
        current = None
        if index in trace.keys():
           if trace[index][0] == 'enter':
              print(f"Current function from address {hex(trace[index][2])} at index {index} type {trace[index][0]}")
              current = self.IRgetFunctionOfInstruction(trace[index][2]-1)
           else:
              print(f"Current function from address {hex(trace[index][3])} at index {index} type {trace[index][0]}")
              current = self.IRgetFunctionOfInstruction(trace[index][3])
           if current == None:
              return None, None, None, None, None, None  
           print(f"Current function {current.name}")
        else:
           return None, None, None, None, None, None  
        min, max = self.IRgetFunctionAddressRange(current)
        reta, cstrace_index, bbs, ti, callerf = self.DynfindCallsitesReturnAddress(trace, index, current, callee)
        if reta == None or not cstrace_index in trace.keys():
           return None, None, None, None, None, None               
        # adjust current in case lr's of consecutive netries match
        #if trace[index][0] == 'enter' and trace[cstrace_index][0] == 'enter':
        #   if trace[index][2] == trace[cstrace_index][2]:
        #      current = self.IRgetFunctionAtAddress(trace[cstrace_index][1])
        #      print(f"Current function adjusted to {current.name}")
        #      reta, cstrace_index, bbs, ti = self.DynfindCallsitesReturnAddress(trace, index, current, callee)        
        if bbs == None:
           return None, None, None, None, None, None
        print(f"finding instructions in function {hex(callerf.addr)}[{callerf.name}]")
        justbbs = set()
        for bbt in bbs:
            justbbs.add(bbt[1].addr)
        instset = self.IRgetInstructionsForBBsInFunction(callerf, justbbs)
        del justbbs
        print(f"instset length {len(instset)} instset length: {len(instset)}")
        #sys.stdin.read(1)
        return reta, instset, bbs, cstrace_index, callerf, ti         
        #if not reta == None:
        #   print(f"instset length: {len(instset)}")
        #   return reta, instset, cstrace_index 
        #if index in trace.keys():
        #   if trace[index][0] == 'enter':
        #      currents = self.IRgetFunctionsOfInstruction(trace[index][2])
        #   else:
        #      currents = self.IRgetFunctionsOfInstruction(trace[index][3])
        #for current in currents:
        #    reta, cstrace_index, bbs, ti = self.DynfindCallsitesReturnAddress(trace, index, current, callee)
        #    if not reta == None:
        #       tinstset = self.IRgetInstructionsForBBsInFunction(current, bbs)
        #       for tin in tinstset:
        #           instset.add(tin)  
        #       print(f"tinstset length {len(tinsetset)} instset length: {len(instset)}")
        #       return reta, instset, cstrace_index 
        #return None, None, None

    def DynfindCallChain(self, trace, index, maxindex, depthBound, fstream=None):
        depth = 0
        current = 0
        lastLR = 0
        firstaddr = 0 
        if index in trace.keys():
           if trace[index] == 'enter':
              current = self.IRgetFunctionOfInstruction(trace[index][2]-1)
              lastLR = trace[index][2]
              firstaddr = lastLR
           else:
              current = self.IRgetFunctionOfInstruction(trace[index][3])
              firstaddr = trace[index][3]
        str = "%s,%s" % (hex(current.addr), hex(firstaddr))      
        nstr = "%s,%s" % (current.name, hex(firstaddr))
        #print(f"index={index} depthBound {depthBound} current {current.name}") 
        csseen = 0        
        i = index 
        while i >= 0 and depth < depthBound:
              if i in trace.keys():
                 if trace[i][0] == 'enter':
                    csseen += 1
                    if csseen > 500:
                       #print(f"Could not find a caller after checking {csseen} callsites, start index {index} now {i} current {hex(current.addr)} vs {hex(trace[i][1])}")
                       if not fstream == None:
                          fstream.write(f"Could not find a caller after checking {csseen} callsites, start index {index} now {i} current {hex(current.addr)} vs {hex(trace[i][1])}\n")
                       break
                    if trace[i][1] == current.addr or trace[i][1] + 1 == current.addr:
                       #print(f"Handling explicitly called {current.name} so far {nstr}") 
                       depth += 1
                       current = self.IRgetFunctionOfInstruction(trace[i][2]-1)
                       if current == None:
                          break
                       lastLR = trace[i][2] 
                       str += ":%s,%s" % (hex(current.addr), hex(lastLR))      
                       nstr += ":%s,%s" % (current.name, hex(lastLR))      
                    else:
                       tf = self.IRgetFunctionOfInstruction(trace[i][2]-1)
                       #print(f"Finding function for {hex(trace[i][1])}")
                       cf = self.IRgetFunctionAtAddress(trace[i][1])
                       if not tf == None and not cf == None and tf.addr == current.addr and not self.DynisCalledExplicitly(trace, cf, maxindex) and lastLR == trace[i][2]:
                          #print(f"Handling implicitly called {cf.name} so far {nstr}")                         
                          depth += 1
                          tf = cf
                          tstr = str.split(':')
                          tnstr = nstr.split(':')
                          str = tstr[0] + ":%s,%s" % (hex(tf.addr), hex(lastLR)) + ":" + tstr[1]     
                          nstr = tnstr[0] + ":%s,%s" % (tf.name, hex(lastLR)) + ":" + tnstr[1]      
              i -= 1
        return str, nstr

    def DynfindTaintCallChains(self, fname, trace, taintList, retBasedTaintMap, maxindex, depthBound, MMIODataReg, taintcmap=None, taintnmap=None, fstream=None):
          single = (taintcmap == None)
          if taintcmap == None:
             taintcmap = {}
          if taintnmap == None:
             taintnmap = {}
          num = 0  
          i = len(taintList) - 1
          while i >= 0:
                if num > self._taintListProcessingBound:
                   break
                tindex, pc, taddr = taintList[i]
                if not (taddr <= MMIODataReg and taddr > MMIODataReg - 32):
                   cstr, nstr = self.DynfindCallChain(trace, tindex, maxindex, depthBound, fstream)
                   #print(f"Call chain found: {nstr}")
                   if not cstr == "":
                      if not cstr in taintcmap:
                         taintcmap[cstr] = set()
                      taintcmap[cstr].add((fname, tindex))
                   if not nstr in taintnmap:
                      taintnmap[nstr] = set()
                   taintnmap[nstr].add((fname, tindex))
                i -= 1
                num += 1
          for fa in retBasedTaintMap.keys():
              for rbt in retBasedTaintMap[fa]: 
                  cstr, nstr = self.DynfindCallChain(trace, rbt[2], maxindex, depthBound, fstream)
                  print(f"Call chain found regarding return value based taint: {nstr}")
                  if not cstr == "":
                     if not cstr in taintcmap:
                        taintcmap[cstr] = set()
                        taintcmap[cstr].add((fname, rbt[2]))
                     if not nstr in taintnmap:
                        taintnmap[nstr] = set()
                        taintnmap[nstr].add((fname, rbt[2]))
          #sys.stdin.read(1)           
          if single:
             print(f"Map size: {len(taintcmap)} covering {len(taintList)} tainted locations in the trace")
             if fstream: 
                fstream.write(f"Map size: {len(taintcmap)} covering {len(taintList)} tainted locations in the trace\n")
             for cstr in taintcmap.keys():
                 print(f"\t{cstr} -> size {len(taintcmap[cstr])}")
                 if fstream:
                    fstream.write(f"\t{cstr} -> size {len(taintcmap[cstr])}\n")
             print(f"Map size: {len(taintnmap)} covering {len(taintList)} tainted locations in the trace")
             if fstream:
                fstream.write(f"Map size: {len(taintnmap)} covering {len(taintList)} tainted locations in the trace\n")   
             for cstr in taintnmap.keys():
                 print(f"\t{cstr} -> size {len(taintnmap[cstr])}")
                 if fstream:
                    fstream.write(f"\t{cstr} -> size {len(taintnmap[cstr])}\n")

    def DynfindTaintCallChainsAcrossAllTraces(self, tracemap, depthBound,MMIODataReg, fstream=None, entry_point_limit=None):
        endpoints = set()
        taintcmap = {}
        taintnmap = {}
        totalTainted = 0
        for key, tmt in tracemap.items():
            print(f"Size of taint list {len(tmt[1])}, return based taint map size {len(tmt[2])} read tainted list {len(tmt[3])}")
            if not fstream == None:
               fstream.write(f"Size of taint list {len(tmt[1])}, return based taint map size {len(tmt[2])}\n")
            self.DynfindTaintCallChains(key, tmt[0], tmt[1], tmt[2], tmt[4], depthBound, MMIODataReg, taintcmap, taintnmap, fstream)
            totalTainted += len(tmt[1])
        print(f"Map size: {len(taintcmap)} covering {totalTainted} tainted locations in the trace") 
        if fstream: 
           fstream.write(f"Map size: {len(taintcmap)} covering {totalTainted} tainted locations across all traces\n")
        for cstr in taintcmap.keys():
            print(f"\t{cstr} -> size {len(taintcmap[cstr])}")
            if fstream:
               fstream.write(f"\t{cstr} -> size {len(taintcmap[cstr])}\n")
        print(f"Map size: {len(taintnmap)} covering {totalTainted} tainted locations across all traces")
        if fstream:
           fstream.write(f"Map size: {len(taintnmap)} covering {totalTainted} tainted locations across all traces\n")   
        for cstr in taintnmap.keys():
            print(f"\t{cstr} -> size {len(taintnmap[cstr])}")
            if fstream:
               fstream.write(f"\t{cstr} -> size {len(taintnmap[cstr])}\n")
        for key, tuples in taintcmap.items():
            # choose one
            chosentuple = None
            maxindex = 0
            for t in tuples:
                if t[1] > maxindex:
                   chosentuple = t
                   maxindex = t[1] 
                break
            print(f"Using trace from {chosentuple[0]} for {key} to find taint for trace index {chosentuple[1]}")
            if not fstream == None:
               fstream.write(f"Using trace from {chosentuple[0]} for {key} to find taint for trace index {chosentuple[1]}\n")
            trace, taintList, retBasedTaintMap, max = tracemap[chosentuple[0]]
            taintpc = 0
            taintaddress = 0
            for tt in taintList:
                if tt[0] == chosentuple[1]:
                   taintpc = tt[1]
                   taintaddress = tt[2] 
                   break
            # lets not restrict dynamic call chain exploration by the clustering bound!
            maxBound = self._dynamiccallchaintaintsearchBound
            if depthBound > maxBound:
               maxBound = depthBound
            eps = self.DynfindEntryPoint(endpoints, trace, chosentuple[1], taintpc, taintList, retBasedTaintMap, maxBound, fstream, entry_point_limit)  
            for ep in eps:
                epstr = self.prettyPrintEntryPoint(ep)
                endpoints.add((ep[0], taintaddress))
                print(f"[Entry Point] Tainted addr={hex(taintaddress)},{epstr}")
                if not fstream == None:
                   fstream.write(f"[Entry Point] Tainted addr={hex(taintaddress)},{epstr}\n")
                print(f"@@@@@@@@@@@@@@@@ Global number of entry points found: {len(endpoints)}")
                if not entry_point_limit == None and len(endpoints) > entry_point_limit:
                   print(f"Reached entry point limit {hex(entry_point_limit)}")
                   #sys.stdin.read(1) 
                   return endpoints
            #sys.stdin.read(1) 
        return endpoints

    def IRfindPCFromStatementIndex(self, f, bb, index):
        while index >=0:
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.IMark):
                 return st.addr
              index -= 1
        return None

    def IRfindLoadStatement(self, pc):
        f = self.IRgetFunctionOfInstruction(pc)
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            index = 0
            ia = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.IMark):
                     ia = st.addr
                  if ia == pc and isinstance(st, pyvex.IRStmt.WrTmp):
                     if isinstance(st.data, pyvex.IRExpr.Load):
                        return f, bb, index, "t" + str(st.tmp)
                  if ia == pc and isinstance(st, pyvex.IRStmt.LoadG):
                     return f, bb, index, "t" + str(st.dst)
                  index += 1
        return None, None, None, None 
        

    def IRfindUsesofLoadWithPC(self, pc):
        results = set()
        # find load statement
        f, bb, index, node = self.IRfindLoadStatement(pc)
        if f == None:
           print(f"WARNING: Function of load pc {hex(pc)} could not be found!")
           return results
        cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
        st = bb.vex.statements[index]
        #print(f"Finding uses of {node} of {st} in bb {hex(bb.addr)} of pc {hex(pc)}")
        uses = self.IRgetUsesInFunction(f, cfgnode, bb, st, index, node)
        for use in uses:
            ubba, ust, ui, nuse, nother, ev = use
            try:
                ubb = self._project.factory.block(ubba)
            except angr.errors.SimEngineError:
                continue
            upc = self.IRfindPCFromStatementIndex(f, ubb, ui)
            results.add((use, upc))
        #if len(uses) == 0 and f.name == "protocol_process":
        #   bb.vex.pp()
        #   print(f"index {index} node {node}") 
        return results

    def DYNprintTainted(self, taintedAddressesMap, lastSessionId):
        sid = lastSessionId
        while sid >= 0:
              if sid in taintedAddressesMap.keys():
                 print(f"sid {sid}")
                 for t in taintedAddressesMap[sid]:
                     print(f"\t {hex(t[0])}")  
              sid -= 1
        return None
 

    def DYNfindSIDForReadAddress(self, taintedAddressesMap, lastSessionId, rtuple):
        sid = lastSessionId
        while sid >= 0:
              if sid in taintedAddressesMap.keys():
                 for t in taintedAddressesMap[sid]:
                     if rtuple[1] == t[0]:
                        return sid
              sid -= 1
        return None

    def DYNfindAllSIDsForReadAddress(self, taintedAddressesMap, lastSessionId, rtuple):
        result = set()
        sid = lastSessionId
        while sid >= 0:
              if sid in taintedAddressesMap.keys():
                 for t in taintedAddressesMap[sid]:
                     if rtuple[1] == t[0]:
                        result.add(sid)
              sid -= 1
        return result

    def DYNfindSIDForUse(self, usesMap, lastSessionId, wtuple):
        sid = lastSessionId
        while sid >= 0:
              if sid in usesMap.keys(): 
                 for t, pc in usesMap[sid]:
                     if wtuple[3] == pc:
                        return sid, t
              sid -= 1
        return None, None

    def DYNfindAllSIDsForUse(self, usesMap, lastSessionId, wtuple):
        result = set()
        sid = lastSessionId
        while sid >= 0:
              if sid in usesMap.keys(): 
                 for t, pc in usesMap[sid]:
                     if wtuple[3] == pc:
                        result.add((sid, t))
              sid -= 1
        return result

    def IRisBBAccessingArgRegs(self, bb):
        args = ['r0', 'r1', 'r2', 'r3']
        index = 0
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.WrTmp):
                 if isinstance(st.data, pyvex.IRExpr.Get):
                    if self._project.arch.register_names[st.data.offset] in args:
                       return True
              index += 1
        return False  

    def IRisCFGNodeAccessingArgRegs(self, f, pred):
        bb, min, max = self.IRgetStatementIndexRangeForCFGNode(f, pred)
        return self.IRisBBAccessingArgRegs(bb)



    def IRfindArgLoads(self, f, filter=None):
        results = set()
        args = ['r0', 'r1', 'r2', 'r3']
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            cfgnode = self.IRfindCFGNodeForStatement(f, bb, 0)
            apreds = self.IRfindAllPredsInFunction(f, cfgnode, filter)
            found = False
            for apred in apreds:
                if self.IRisCFGNodeAccessingArgRegs(f, apred):
                   found = True
                   break
            if not found:
               print(f"None of preds of {hex(bb.addr)} access arg regs!!!")
               continue
            ia = 0
            index = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.IMark):
                     ia = st.addr
                  if isinstance(st, pyvex.IRStmt.WrTmp):
                     if isinstance(st.data, pyvex.IRExpr.Load):
                        ev = ""
                        print(f"[IRfindArgLoads] cfgnode {cfgnode.addr} st {st} node {st.data.addr}")
                        ures = self.IRgetDefUseUltimate(f, cfgnode, bb, st, index, st.data.addr, ev, filter) 
                        for u in ures:
                            ubba, ui, un, uc, uev = u
                            if isinstance(un, pyvex.IRExpr.Get):
                               if self._project.arch.register_names[un.offset] in args:
                                  print(f"found {hex(ia)} in {f.name}")
                                  results.add(ia)
                                  break
                  index += 1
        return results

    def DynupdateArgLoads(self, tracecallchain, argLoads, f, pointsTo, index):
        print(f"Updating arg loads for {f.name} bw from index {index}, filtering using minRAM {hex(self._minRAM)} num entries {len(argLoads)}")
        if f == None:
           return
        if not f.addr in argLoads.keys():
           argLoads[f.addr] = self.IRfindArgLoads(f)
        i = index
        while i>= 0:
              if i in tracecallchain.keys():
                 tuple = tracecallchain[i]
                 if tuple[0] == 'read':
                    if tuple[3] in argLoads[f.addr] or tuple[3] - 1 in argLoads[f.addr]:
                       if tuple[2] >= self._minRAM:
                          if not tuple[1] in pointsTo.keys():
                             pointsTo[tuple[1]] = set()
                          print(f"[Points to recording] pointer {hex(tuple[1])} to {hex(tuple[2])} at pc {hex(tuple[3])}")
                          pointsTo[tuple[1]].add((tuple[2], tuple[3])) 
              i -= 1

    def DynfindRelevantPointers(self, pointsTo, targetSet, bound=0):
        pointers = set()
        tset = targetSet
        while True:
              change = False
              temp = set()
              for key in pointsTo.keys():
                  for t in tset:
                      if t in pointsTo[key]:
                         if not key in pointers:
                            pointers.add(key)
                            change = True
                            temp.add(key)
                      if bound > 0: 
                         for pt in pointsTo[key]:
                             if  pt[0] >= t - bound and pt[0] <= t:
                                 change = True
                                 temp.add(key)                                  
                                 if not key in pointers:
                                    pointers.add(key)
                                    change = True
                                    temp.add(key)
              del tset
              tset = set()
              for t in temp:
                  tset.add(t)
              if not change:
                 break
        return pointers

    def DynfindAccessLocations(self, tracecallchain, maxIndex, targetSet, bound=0):
        locs = set()
        index = 0  
        while index < maxIndex:
              if index in tracecallchain.keys():
                 tuple = tracecallchain[index]
                 if tuple[0] == 'read':
                    if bound == 0:
                       if tuple[1] in targetSet:
                          locs.add((tuple[1], tuple[3]))
                    else:
                       for t in targetSet:
                           if tuple[1] >= t - bound and tuple[1] <= t:  
                              locs.add((tuple[1], tuple[3]))
              index += 1
        return locs

    def IRgetInstructionsForBBsInFunction(self, f, bbs):
        insts = set() 
        for bba in bbs:
            #print(f"bba {bba}")
            bbt = self.IRgetBBForInstruction(f, bba)
            if not bbt[0] == None:
               bb = bbt[0]
               index = 0
               while index < len(bb.vex.statements):
                     st = bb.vex.statements[index]
                     if isinstance(st, pyvex.IRStmt.IMark):
                        insts.add(st.addr)
                     index += 1
        return insts  

    def IRgetInstructionsForBBTuplesInFunction(self, f, bbs):
        insts = set() 
        for bba in bbs:
            #print(f"bba {bba}")
            bbt = self.IRgetBBForInstruction(f, bba[1].addr)
            if not bbt[0] == None:
               bb = bbt[0]
               index = 0
               while index < len(bb.vex.statements):
                     st = bb.vex.statements[index]
                     if isinstance(st, pyvex.IRStmt.IMark):
                        insts.add(st.addr)
                     index += 1
        return insts  

    def IRgetInstructionsForBBs(self, bbs):
        f = None
        for bba in bbs:
            f = self.IRgetFunctionOfInstruction(bba)
            if not f == None:
               print(f"Finding insts within {f.name} for nn address {hex(bba)}")
               break
        insts = set() 
        for bba in bbs:
            bbt = self.IRgetBBForInstruction(f, bba)
            if not bbt[0] == None:
               bb = bbt[0]
               index = 0
               while index < len(bb.vex.statements):
                     st = bb.vex.statements[index]
                     if isinstance(st, pyvex.IRStmt.IMark):
                        insts.add(st.addr)
                     index += 1
        return insts  

    def DynisRegDefinedInCallingContext(self, tracecallchain, trace_index, tf, reg):
        print(f"Checking arg def in calling context, trace index {trace_index} caller {tf.name} reg {reg}")
        print(f"Finding callsite bbs for return address {hex(tracecallchain[trace_index][2])}")
        retaddr, cstrace_index, bbs, ti, callerf = self.DynfindCallsitesReturnAddress(tracecallchain, trace_index, tf)
        if bbs == None:
           return False
        instset = self.IRgetInstructionsForBBTuplesInFunction(tf, bbs)
        csbbs = self.IRfindCallsiteBBsForReturnAddress(tracecallchain[trace_index][2])
        for cf, csbb, cscfnode in csbbs: 
            print(f"Checking reg {reg} definition from node {hex(cscfnode.addr)}")
            rds = self.IRgetRegDefiningNode(tf, cscfnode, csbb, reg, instset)
            for rd in rds:
                rcfgnode, rbb, ri, rnode = rd 
                if not rcfgnode == None:
                   return True
        return False  


    def DynRecordReturnValueTaintPropagation(self, tracecallchain, trace_index, retBasedTaintMap, entryPoints, callee, fstream=None):
        print(f"Is {callee.name}[{hex(callee.addr)}] in return based taint map (size {len(retBasedTaintMap)})? ")
        for k in retBasedTaintMap.keys():
            print(f"{hex(k)}")
        if not callee.addr in retBasedTaintMap.keys():
           return False
        caller = self.IRgetFunctionOfInstruction(tracecallchain[trace_index][2])
        if caller == None:
           callerinfo = ""
        else:
           callerinfo = self.IRgetFunctionInfo(caller)
        tep = (tracecallchain[trace_index][2], self.IRgetFunctionInfo(callee), "return", "r0", callerinfo, "", "")
        entryPoints.add(tep)
        #if not fstream == None:
        #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
        print(f"Entry point returning a value {hex(tracecallchain[trace_index][2])} callee {callee.name}")
        #sys.stdin.read(1)
        return True
          

    # return value based taint propagation by passing the relevant map and updating it along the way
    # if the current function is in the map and the cfgnode in the map is used on the current path when returning to the calling context
    # declare the callsite return address as the entry point and register r0 as the taint! 
    # if the caller returns r0 implicitly, mark the caller as return value tainted
    def DynhandleReturnValueTaintPropagation(self, tracecallchain, retBasedTaintMap, entryPoints, trace_index, callee, cstrace_index, caller, fstream=None):
        if not self.DynRecordReturnValueTaintPropagation(tracecallchain, trace_index, retBasedTaintMap, entryPoints, callee, fstream): 
           return
        # is the retbb what we have here?
        f, start_index, end_index, bbts, insts, retbb = self.DyngetSegment(tracecallchain, trace_index, False)
        if retbb == None:
           return
        for rt in  retBasedTaintMap[callee.addr]:
            print(f"[DynhandleReturnValueTaintPropagation] {callee.name} {caller.name} {rt}") 
            if rt[0].addr == retbb or rt[1].addr == retbb:
               f2, start_index2, end_index2, bbts2, insts2, retbb2 = self.DyngetSegment(tracecallchain, cstrace_index, False)
               defs = self.IRgetReturnValueDefForBB(caller, 0, retbb2, insts2)           
               for d in defs:
                   if isinstance(d[2], pyvex.IRExpr.Get):
                      if self._project.arch.register_names[d[2].offset] == 'r0':
                         if not caller.addr in retBasedTaintMap.keys():
                            retBasedTaintMap[caller.addr] = {}
                         retBasedTaintMap[caller.addr].add((d[0], d[1]))
                         print(f"{caller.name} is also return tainted value returned by {callee.name}")      

    def DynfindEntryPointMoveOneLevelUp(self, epsofar, tracecallchain, retBasedTaintMap, otrace_index, otf, depth, calldepth, reg, entry_point_limit, fstream=None):
        if tracecallchain[otrace_index][0] == 'enter':
           trace_index = otrace_index
           tf = otf
        else:
           tra, trace_index, tbbs, ti, callerf = self.DynfindCallsitesReturnAddress(tracecallchain, otrace_index, otf)
           tf = self.IRgetFunctionOfInstruction(tra)
           if tra == None or tf == None:
              return (set(), tracecallchain[otrace_index][2], otrace_index, set())
        print(f"[DynfindEntryPointMoveOneLevelUp] function {tf.name} trace index {trace_index} reg {reg}")
        entryPoints = set()
        if depth >= calldepth:
           print(f"Call depth reached!!! Using location {hex(tracecallchain[trace_index][2])} in the trace {trace_index} as the entry point!")
           tep = (tracecallchain[trace_index][2],"", "", "", "", "", "")
           entryPoints.add(tep)
           #if not fstream == None:
           #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
           print(f"@@@@@@@@@@@@@@@@ Number of entry points found: {len(entryPoints)}, global: {len(epsofar)}")
           if not entry_point_limit == None and len(entryPoints) + len(epsofar) > entry_point_limit:
              return (entryPoints, tracecallchain[trace_index][2], trace_index, set())
           print(f"\tEntry point defaulting to {hex(tracecallchain[trace_index][2])} trace index {trace_index}")
           return (entryPoints, tracecallchain[trace_index][2], trace_index, set())           
        newretaddr, cstrace_index, bbs, implicit, callerf2 = self.DynfindCallsitesReturnAddress(tracecallchain, trace_index, tf)
        if newretaddr == None:
           print(f"Calling context could not be found! Using location {hex(tracecallchain[trace_index][2])} in the trace {trace_index} as the entry point!")
           tep = (tracecallchain[trace_index][2], "", "", "", "", "", "")
           entryPoints.add(tep)
           #if not fstream == None:
           #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
           print(f"@@@@@@@@@@@@@@@@ Number of entry points found: {len(entryPoints)}, global: {len(epsofar)}")
           if not entry_point_limit == None and len(entryPoints) + len(epsofar) > entry_point_limit:
              return (entryPoints, tracecallchain[trace_index][2], trace_index, set())
           print(f"\tEntry point defaulting to {hex(tracecallchain[trace_index][2])} trace index {trace_index}")
           return (entryPoints, tracecallchain[trace_index][2], trace_index, set())                
        if implicit:
           tfi = self.IRgetFunctionAtAddress(tracecallchain[cstrace_index][1])
           csbbs = self.IRfindImplicitCalleeBBs(tfi)
           print(f"Instructions computed within {tfi.name}")
           instset2 = self.IRgetInstructionsForBBTuplesInFunction(tfi, bbs)
        else:
           if tracecallchain[otrace_index][0] == 'enter':  
              csbbs = self.IRfindCallsiteBBsForReturnAddress(tracecallchain[cstrace_index][2])
           else: 
              csbbs = self.IRfindCallsiteBBsForReturnAddress(tracecallchain[trace_index][2])
           print(f"Instructions computed within {tf.name}")
           instset2 = self.IRgetInstructionsForBBTuplesInFunction(tf, bbs)
        #instset = set()
        allsrcsreg = set()
        #for cf, csbb, cscfnode in csbbs:
        #    cbbs = set()
        #    cbbs.add(csbb.addr) 
        #    iset = self.IRgetInstructionsForBBsInFunction(cf, cbbs)
        #    for ins in iset:
         #       instset.add(ins) 
        sameregfound = False 
        if not reg == None:
            self.IRprintInstSet(instset2, "[WITHIN MOVING UP]")
            for cf, csbb, cscfnode in csbbs:
                srcsreg = self.IRgetSourceForRegDef(cf, cscfnode, reg, instset2)
                for src in srcsreg:
                    allsrcsreg.add(src)
                    if src[0] == 'argument' and src[1] == reg:
                       sameregfound = True
                    print(f"source {src}")
        print(f"allsrcsreg length {len(allsrcsreg)}")  
        if len(allsrcsreg) == 0 or (len(allsrcsreg) == 1 and sameregfound):
           print(f"Checking if reg is assigned by the caller of the next level..")
           # Let C(F) (IC(F)) denotes explicit (implicit) caller of F
           # Case 1:  F1 by F2, F2 by F3, F3 by F4
           #          check arg def for reg within F3 before moving one level up from F1 to F2
           # Case 2:  F1 by F2, IC(F1) by F2, F2 by F3
           #          check arg def for reg within F2 before moving one level up from F1 to IC(F1)
           tf2 = self.IRgetFunctionOfInstruction(newretaddr)
           if tf2 == None:
              return (entryPoints, tracecallchain[trace_index][2], trace_index, set())
           if implicit:
              #print(f"Function {tf2.name} num inst {len(instset)}")
              print(f"[Implicit] May move up to entry index at {cstrace_index}")
              if not tf2 == None and self.DynisRegDefinedInCallingContext(tracecallchain, cstrace_index, tf2, reg):
                 self.DynhandleReturnValueTaintPropagation(tracecallchain, retBasedTaintMap, entryPoints, trace_index, tfi, cstrace_index, tf2) 
                 print(f"[Implicit] Moving one level up for the same arg reg {reg} to trace index {cstrace_index} callee function {tfi.name}")
                 return (entryPoints, tracecallchain[cstrace_index][2], cstrace_index, allsrcsreg)                 
                 #return self.DynfindEntryPointMoveOneLevelUp(tracecallchain, cstrace_index, tf2, depth + 1, calldepth, reg)              
           else:
              # ensure calling context defines the reg
              nr, csti, tbbs, timplicit, callerf3 = self.DynfindCallsitesReturnAddress(tracecallchain, cstrace_index, tf2)
              #tinstset = self.IRgetInstructionsForBBs(tf2, tbbs)
              #print(f"Function {tf2.name} num bbs {len(tbbs)} num inst {len(tinstset)}")
              if not nr == None:
                 print(f"[Explicit] May move up to entry index at {cstrace_index} nret {hex(nr)}")
                 tf3 = self.IRgetFunctionOfInstruction(nr)
                 if not tf3 == None and self.DynisRegDefinedInCallingContext(tracecallchain, csti, tf3, reg):
                    self.DynhandleReturnValueTaintPropagation(tracecallchain, retBasedTaintMap, entryPoints, trace_index, tf2, cstrace_index, tf3) 
                    print(f"Moving one level up for the same arg reg {reg} to trace index {cstrace_index} function {tf2.name}")
                    return (entryPoints, tracecallchain[cstrace_index][2], cstrace_index, allsrcsreg)                 
                    #return self.DynfindEntryPointMoveOneLevelUp(tracecallchain, cstrace_index, tf2, depth + 1, calldepth, reg)
              #else:
              #   entryPoints.add((tracecallchain[trace_index][2]))
              #   print(f"\tEntry point defaulting to {hex(tracecallchain[trace_index][2])} trace index {trace_index}")
              #   return (entryPoints, tracecallchain[trace_index][2], trace_index, set())                
        print(f"\tReturning trace index {cstrace_index}")
        return (entryPoints, tracecallchain[trace_index][2], trace_index, allsrcsreg)


    def IRfindStoresInBB(self, bb):
        results = set()
        index = 0
        ia = 0
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.IMark):
                 ia = st.addr
              if isinstance(st, pyvex.IRStmt.Store) or  isinstance(st, pyvex.IRStmt.StoreG):
                 results.add((bb, index, ia)) 
              index += 1  
        return results 

    # Caller arg reg flowing into callee arg reg through one or more store instructions
    # Case 1: F1(.., arg1, ...)  { Store(A1) = arg1 ... F2(..., A1, ...) }
    # Case 2: F2(.., arg1, ...)  { Store(A1) = A2 ...Store(A2 + offset) = arg1  F2(..., A1, ...) }
    #   not to make any assumptions on the order of stores !!!
    def IRfindImplicitFlowBwCallerArgCalleeArg(self, tf, baseregset, taintpc, calleereg, filter, dataStructureOffsetBound):
        #print(f"[Implicit flow] {tf.name} taintpc {hex(taintpc)}")
        args = ['r0', 'r1', 'r2', 'r3']
        sources = set()
        storeAddrs = self.IRgetStoresAtAddressWithinFunction(tf, taintpc)
        for sa in storeAddrs:
            f, bb, index = sa
            #if tf.name == "rf2xx_iface_sram_read":
            #   bb.vex.pp()
            st = bb.vex.statements[index] 
            print(f"CFGNODE for {tf.name} bb {hex(bb.addr)} index {index} st {st}") 
            cfgnode = self.IRfindCFGNodeForStatement(tf, bb, index)
            vm = {}
            ev = "" 
            # CASE 1
            tsrcs = self.IRfindAllSourcesofAddress(tf, baseregset, cfgnode, bb, st, index, st.addr, vm, ev, filter)
            del vm
            for tsrc in tsrcs:
                if tsrc[0] == 'argument':
                   if tsrc[1] in args:   
                      #print(f"[CASE 1] Tainted caller argument found {tsrc[1]} using st {st}")
                      sources.add(tsrc)
            # CASE 2
            v = set() 
            tev = ""
            ds = self.IRgetDefUseUltimate(tf, cfgnode, bb, st, index, st.data, tev, filter, v)
            astores = self.IRfindStoresInBB(bb)
            for d in ds:
                dbba, di, dn, dc, ev = d
                for sa2 in astores:
                    bb2, index2, ia2 = sa2
                    st2 = bb2.vex.statements[index2]
                    if index == index2:
                       continue
                    cfgnode2 = self.IRfindCFGNodeForStatement(tf, bb2, index2)
                    v2 = set()
                    tev2 = ""
                    ds2 = self.IRgetDefUseUltimate(tf, cfgnode2, bb2, st2, index2, st2.addr, tev2, filter, v2)
                    commonSource = False
                    for d2 in ds2:
                        dbba2, di2, dn2, dc2, ev2 = d2
                        #print(f"dn {dn} vs dn2 {dn2} di {di} vs di2 {di2} dc {dc} vs {dc2} bound {dataStructureOffsetBound}")
                        if str(dn) == str(dn2) and dc2 >= dc and abs(dc - dc2) <= dataStructureOffsetBound:
                           vm2 = {}
                           ev2 = ""
                           asrcs = self.IRfindAllSourcesofAddress(tf, baseregset, cfgnode2, bb, st2, index2, st2.data, vm2, ev2, filter)
                           del vm2 
                           for asrc in asrcs:
                               if asrc[0] == 'argument':
                                  if asrc[1] in args:   
                                     print(f"[CASE 2] Tainted caller argument found {asrc[1]} based on store instr at {hex(ia2)}")
                                     sources.add(asrc)
        # todo: extend it with predecessors for the search
        return sources   
    
    # revise to remove assumptions about ordering bw store statements
    # Let ST(A1) = D1 such that callee tainted reg is defined from A1(exact match with offset)
    # for every other store in the same basic block  ST(A2) = D2 such that source of D1 and source of A2 match within a threashold offset, e.g., 64
    # find and add sources of D2   
    def DynfindImplicitFlows(self,  tracecallchain, trace_minindex, trace_maxindex, tf, taintList, calleereg, cfgnode, bb, filter, rxOffsetBound, dataStructureOffsetBound):
        #if tf.name == "rf2xx_iface_sram_read":
        print(f"Trace index range [{trace_minindex},{trace_maxindex}] reg {calleereg} cfgnode {hex(cfgnode.addr)}")
        #for taint in taintList:
        #    print(f"index {taint[0]} pc {hex(taint[1])} addr {hex(taint[2])}")
        baseregset = self.IRgetBaseRegSetForFunction(tf)
        pcs = set()
        index = trace_minindex + 1
        while index <= trace_maxindex:
              if index in tracecallchain.keys():
                 if  tracecallchain[index][0] == 'enter':
                     break
                 if  tracecallchain[index][0] == 'write':
                     for i, pc, addr in taintList:
                         if abs(addr - tracecallchain[index][2]) <= rxOffsetBound:
                            #print(f"Tainting pc {hex(pc)} taint address {hex(addr)} search to start at {hex(tracecallchain[index][3])} diff {abs(addr - tracecallchain[index][2])}")
                            pcs.add(tracecallchain[index][3])
              index += 1
        sources = set()
        #print(f"Finding defining node for reg {calleereg} starting from {hex(cfgnode.addr)}")
        for taintpc in pcs:
            #print(f"[[[ SEARCH starts for pc {hex(taintpc)}, reg {calleereg} ]]]")
            #if taintpc == 0x4022b0:
            #   self._stop = True  
            srcs = self.IRfindImplicitFlowBwCallerArgCalleeArg(tf, baseregset, taintpc, calleereg, filter, dataStructureOffsetBound)
            for src in srcs:
                sources.add(src)
        return sources  

    def DynfindImplicitFlowsOld(self,  tracecallchain, trace_minindex, trace_maxindex, tf, taintList, calleereg, cfgnode, bb, filter, rxOffsetBound, dataOffsetBound):
        #if tf.name == "rf2xx_iface_sram_read":
        print(f"Trace index range [{trace_minindex},{trace_maxindex}] reg {calleereg} cfgnode {hex(cfgnode.addr)}")
        #for taint in taintList:
        #    print(f"index {taint[0]} pc {hex(taint[1])} addr {hex(taint[2])}")
        baseregset = self.IRgetBaseRegSetForFunction(tf)
        pcs = set()
        index = trace_minindex + 1
        while index <= trace_maxindex:
              if  tracecallchain[index][0] == 'enter':
                  break
              if  tracecallchain[index][0] == 'write':
                  for i, pc, addr in taintList:
                      if abs(addr - tracecallchain[index][2]) <= rxOffsetBound:
                         #print(f"Tainting pc {hex(pc)} taint address {hex(addr)} search to start at {hex(tracecallchain[index][3])} diff {abs(addr - tracecallchain[index][2])}")
                         pcs.add(tracecallchain[index][3])
              index += 1
        sources = set()
        print(f"Finding defining node for reg {calleereg} starting from {hex(cfgnode.addr)}")
        dnodes = self.IRgetRegDefiningNode(tf, cfgnode, bb, calleereg, filter)
        for dnode in dnodes:
            tcn, tbb, ti, tn = dnode
            tst = tbb.vex.statements[ti]
            ev = ""    
            print(f"Finding callee reg defs from st {tst} node {tst.data} @ {ti} bb {hex(tbb.addr)}")
            #tbb.vex.pp()        
            calleeregdefs = self.IRgetDefUseUltimate(tf, tcn, tbb, tst, ti, tst.data, ev, filter)
            for taintpc in pcs:
                print(f"[[[ SEARCH starts for pc {hex(taintpc)} from cfgnode {hex(tcn.addr)} st {tst} ]]]")
                srcs = self.IRfindImplicitFlowBwCallerArgCalleeArg(tf, baseregset, taintpc, calleereg, calleeregdefs, filter)
                for src in srcs:
                    sources.add(src)
        #if tf.name == "rf2xx_iface_sram_read":
        #   print(f"Num sources found: {len(sources)}")
        #   sys.exit()                 
        return sources  

    def IRprintInstSet(self, instset, desc=""):
        inststr = " {desc} "
        for inst in instset:
            inststr += " %s" % (hex(inst))
        print(f"Instruction set [{desc}]: {inststr}")

    def IRgetFunctionInfo(self, f):
        return "%s[%s]" % (hex(f.addr), f.name)
          
    def IRgetInstructionsForBBTuplesInFunction(self, tf, bbts):
       bbs = set()
       for bbt in bbts:
           bbs.add(bbt[1].addr)
       return self.IRgetInstructionsForBBsInFunction(tf, bbs)

    def DynfindEntryPointInternal(self, visited, epsofar, tracecallchain, retBasedTaintMap, trace_index, tf, taintList, tcfgnode, tbb, tst, ti, tn, depth, calldepth, entry_point_limit, fstream, reg=None):
        #self.IRprintBBs(tf)
        #print(f"=======================================")
        #tbb.vex.pp()
        entryPoints = set()        
        self.DynRecordReturnValueTaintPropagation(tracecallchain, trace_index, retBasedTaintMap, entryPoints, tf, fstream)
        if depth > calldepth:
           print(f"CALL DEPTH REACHED {depth}")
           return set()
        hash = self.UtilgetHashList([trace_index, tbb.addr, tcfgnode.addr, tf.name])
        if hash in visited:
           return entryPoints
        visited.add(hash)
        print(f"===================================================================")
        print(f"[DynfindEntryPointInternal] tf {tf.name} tbb {hex(tbb.addr)} trace index {trace_index} tst {tst} tn {tn} depth {depth} [max {calldepth}] epsofar {len(epsofar)}")
        print(f"===================================================================")
        #sys.stdin.read(1)
        args = ['r0', 'r1', 'r2', 'r3']      
        vm = {}
        ev = ""
        baseregset = self.IRgetBaseRegSetForFunction(tf)
        newretaddr, cstrace_index, bbs, implicit, callerf = self.DynfindCallsitesReturnAddress(tracecallchain, trace_index, tf)
        if bbs == None:
           return set()
        instset = self.IRgetInstructionsForBBTuplesInFunction(tf, bbs)
        print(f"Number of instructions for filtering: {len(instset)} num bbs {len(bbs)}")
        str = ""
        for bbt in bbs:
            str += " %s" % (hex(bbt[1].addr))
        print(f"Filter bb addresses: {str}")
        self.IRprintInstSet(instset)
        print(f"Direct src search for reg {reg} from {hex(tcfgnode.addr)} tbb {hex(tbb.addr)} index {ti} tst {tst} tn {tn}") 
        #tbb.vex.pp()
        srcs = self.IRfindAllSourcesofAddress(tf, baseregset, tcfgnode, tbb, tst, ti, tn, vm, ev, instset, True)
        del vm
        print(f"Number of direct srcs {len(srcs)}, type {tracecallchain[trace_index][0]}")
        if tracecallchain[trace_index][0] == 'write':
           isrcs = self.DynfindBackwardSourceFromTaintLoc(tracecallchain, trace_index, tracecallchain[trace_index][3], instset)
           print(f"Number of indirect srcs {len(isrcs)}")
           for isrc in isrcs:
               srcs.add(isrc)
        for src in srcs:
            print(f"src: {src}")
            if src[0] == 'argument':
               #if src[1] == 'r0':
               #   continue
               print(f"Argument register {src[1]} is a source for taint in {tf.name} for st {tst} node {tn} in cgnode {hex(tcfgnode.addr)}")
               # move one or more levels up when argreg is passed directly from calling context 
               tempeps, retaddr, cstrace_index, allsrcsreg = self.DynfindEntryPointMoveOneLevelUp(epsofar, tracecallchain, retBasedTaintMap, trace_index, tf, depth, calldepth, src[1], entry_point_limit, fstream)
               #if retaddr < 128:
               #   continue
               updateddepth = depth
               if trace_index != cstrace_index:
                  updateddepth += 1
               #epstr = ""
               #for ep in tempeps:
               #    epstr += " %s" % (hex(ep))
               print(f"Ultimate moving up decision: trace index {cstrace_index} {len(tempeps)} endpoints")
               if len(tempeps) > 0:
                  for ep in tempeps:  
                      entryPoints.add(ep)
                      #if not fstream == None:
                      #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(ep)}\n")
                      print(f"@@@@@@@@@@@@@@@@ Number of entry points found: {len(entryPoints)}, global: {len(epsofar)}")
                      if not entry_point_limit == None and len(entryPoints) + len(epsofar) > entry_point_limit:
                         return entryPoints
                  continue
               ntf = self.IRgetFunctionOfInstruction(retaddr)
               if ntf == None:
                  print(f"WARNING: Could not find function for {hex(retaddr)}")
                  continue
               newretaddr2, cstrace_index2, bbs2, implicit, callerf2 = self.DynfindCallsitesReturnAddress(tracecallchain, cstrace_index, ntf)
               if bbs2 == None:
                  print(f"No bbs found for {ntf.name} at trace index {cstrace_index} return address {tracecallchain[cstrace_index][2]}")
                  continue
               if implicit:
                  tf2 = self.IRgetFunctionAtAddress(tracecallchain[cstrace_index][1])
                  print(f"Implicit callsite bbs found within {tf2.name}")                 
                  csbbs = self.IRfindImplicitCalleeBBs(tf2)
               else:
                  print(f"Explicit callsite bbs found for return address {hex(retaddr)}")
                  csbbs = self.IRfindCallsiteBBsForReturnAddress(retaddr)
               print(f"Finding instructions within {ntf.name}")
               instset2 = self.IRgetInstructionsForBBTuplesInFunction(ntf, bbs2)
               self.IRprintInstSet(instset2, "Before exploring callsite bbs")
               callee = self.IRgetFunctionAtAddress(tracecallchain[cstrace_index][1])
               caller = self.IRgetFunctionOfInstruction(tracecallchain[cstrace_index][2]-1)
               if callee == None or caller == None:
                  continue
               for cf, csbb, cscfnode in csbbs:
                   print(f"Callsite in {cf.name} addr {hex(cscfnode.addr)} for return address {hex(retaddr)} reg {src[1]} num inst {len(instset2)}")
                   #self._comprehensiveDefUse = True 
                   srcsreg = self.IRgetSourceForRegDef(cf, cscfnode, src[1], instset2)
                   rxBufferBound = 256
                   dataStructureOffsetBound = 32
                   self._stop = False
                   isrcsreg = self.DynfindImplicitFlows(tracecallchain, cstrace_index2, cstrace_index, cf, taintList, src[1], cscfnode, csbb, instset2, rxBufferBound, dataStructureOffsetBound)
                   #if src[1] == 'r3' and self._stop:
                   #   sys.exit()
                   for isrc in isrcsreg:
                       srcsreg.add(isrc) 
                       print(f"~~~ Implicit source {isrc[0]} {isrc[1]}")
                   #self._comprehensiveDefUse = False
                   #if cf.name == "rf2xx_iface_frame_read":
                   #   print(f"************************************************************")
                   #   csbb.vex.pp() 
                   #   print(f"************************************************************")
                   for asrc in srcsreg:
                       print(f"asrc {asrc} in {cf.name}")
                       if asrc[0] == 'stack' or (asrc[0] == 'argument' and asrc[1] == 'sp'):
                          print(f"Detected a local source for arg")
                          tep = (retaddr, self.IRgetFunctionInfo(callee), 'argument', src[1], self.IRgetFunctionInfo(caller), 'stack', asrc[1]) 
                          entryPoints.add(tep)
                          #if not fstream == None:
                          #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
                          print(f"@@@@@@@@@@@@@@@@ Number of entry points found: {len(entryPoints)}, global: {len(epsofar)}")
                          if not entry_point_limit == None and len(entryPoints) + len(epsofar) > entry_point_limit:
                             print(f"WARNING: Entry point limit reached!!!")
                             return entryPoints
                       if asrc[0] == 'argument' and asrc[1] in args:
                          #if asrc[1] == 'r0':
                          #   continue
                          if updateddepth == calldepth:
                             print(f"Call depth reached")
                             tep = (newretaddr2, self.IRgetFunctionInfo(callee), 'argument', src[1], self.IRgetFunctionInfo(caller), 'argument', asrc[1])
                             entryPoints.add(tep)
                             #if not fstream == None:
                             #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
                             print(f"@@@@@@@@@@@@@@@@ Number of entry points found: {len(entryPoints)}, global: {len(epsofar)}")
                             if not entry_point_limit == None and len(entryPoints) + len(epsofar) > entry_point_limit:
                                print(f"WARNING: Entry point limit reached!!!")
                                return entryPoints
                             continue  
                          ntf2 = self.IRgetFunctionOfInstruction(newretaddr2)
                          if ntf2 == None:
                             continue
                          newretaddr3, cstrace_index3, bbs3, implicit3, callerf3 = self.DynfindCallsitesReturnAddress(tracecallchain, cstrace_index2, ntf2)
                          if bbs3 == None:
                             print(f"No bbs found for {ntf2.name} at trace index {cstrace_index2} return address {tracecallchain[cstrace_index2][2]}")
                          if implicit3:
                             tf3 = self.IRgetFunctionAtAddress(tracecallchain[cstrace_index2][1])
                             print(f"Implicit callsite bbs found within {tf3.name}")                 
                             csbbs2 = self.IRfindImplicitCalleeBBs(tf3)
                          else:
                             print(f"Explicit callsite bbs found for return address {hex(newretaddr2)}")
                             csbbs2 = self.IRfindCallsiteBBsForReturnAddress(newretaddr2)
                          for cf2, csbb2, cscfnode2 in csbbs2:
                             # find most recent update to reg and keep searching calling contexts
                             print(f"Searching reg defining node from {hex(cscfnode2.addr)} reg {asrc[1]} function {cf2.name} from trace index {cstrace_index2}")  
                             rdns = self.IRgetRegDefiningNode(cf2, cscfnode2, csbb2, asrc[1])
                             for rdn in rdns:
                                 rcfgnode, rbb, ri, rnode = rdn
                                 rst = rbb.vex.statements[ri]
                                 self.DynhandleReturnValueTaintPropagation(tracecallchain, retBasedTaintMap, entryPoints, cstrace_index, cf, cstrace_index2, cf2) 
                                 if cf2.addr == tf.addr:
                                    eps = self.DynfindEntryPointInternal(visited, epsofar, tracecallchain, retBasedTaintMap, cstrace_index2, cf2, taintList, rcfgnode, rbb, rst, ri, rnode, updateddepth, calldepth, entry_point_limit, fstream, asrc[1])
                                 else: 
                                    eps = self.DynfindEntryPointInternal(visited, epsofar, tracecallchain, retBasedTaintMap, cstrace_index2, cf2, taintList, rcfgnode, rbb, rst, ri, rnode, updateddepth + 1, calldepth, entry_point_limit, fstream, asrc[1])
                                 for ep in eps:
                                     entryPoints.add(ep)
                                     #if not fstream == None:
                                     #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(ep)}\n") 
                                     print(f"@@@@@@@@@@@@@@@@ Number of entry points found: {len(entryPoints)}, global: {len(epsofar)}")
                                     if not entry_point_limit == None and len(entryPoints) + len(epsofar) > entry_point_limit:
                                        print(f"WARNING: Entry point limit reached!!!")
                                        return entryPoints
                       if asrc[0] == 'global':
                          print(f"Global source {hex(asrc[1])} for taint")
                          i = 0
                          td = depth
                          tindex = cstrace_index2
                          prevf = ntf
                          while td < calldepth:
                                if tracecallchain[tindex][0] == 'enter':
                                   callee2 = self.IRgetFunctionAtAddress(tracecallchain[tindex][1])
                                   caller2 = self.IRgetFunctionOfInstruction(tracecallchain[tindex][2]-1)
                                else:
                                   caller2 = self.IRgetFunctionOfInstruction(tracecallchain[tindex][3])                                 
                                if not caller2 == None and (not tracecallchain[tindex][0] == 'enter' or not callee2 == None):
                                   nra, tindex, tbbs, timplicit, callerf4 = self.DynfindCallsitesReturnAddress(tracecallchain, tindex, caller2)
                                   if nra == None:
                                      break
                                   if i == 0:
                                      if not reg == None:
                                         tep = (nra, self.IRgetFunctionInfo(callee2), 'argument', src[0], self.IRgetFunctionInfo(caller2), 'global', asrc[1])
                                         entryPoints.add(tep)
                                         #if not fstream == None:
                                         #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
                                      else: 
                                         tep = (nra, "", 'argument', "", self.IRgetFunctionInfo(caller2), 'global', asrc[1])
                                         entryPoints.add(tep)
                                         #if not fstream == None:
                                         #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
                                   else:
                                      if not reg == None:
                                         tep = (nra, self.IRgetFunctionInfo(callee2), 'global', asrc[1], self.IRgetFunctionInfo(caller2), 'global', asrc[1])
                                         entryPoints.add(tep)
                                         #if not fstream == None:
                                         #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
                                      else:  
                                         tep = (nra, "", 'global', asrc[1], self.IRgetFunctionInfo(caller2), 'global', asrc[1])
                                         entryPoints.add(tep)
                                         #if not fstream == None:
                                         #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
                                   print(f"@@@@@@@@@@@@@@@@ Number of entry points found: {len(entryPoints)}, global: {len(epsofar)}")
                                   if not entry_point_limit == None and len(entryPoints) + len(epsofar) > entry_point_limit:
                                      print(f"WARNING: Entry point limit reached!!!")
                                      return entryPoints
                                td += 1
                                i += 1 
                                prevf = caller2
            if src[0] == 'global':
               print(f"Global source {hex(src[1])} for taint")
               #entryPoints.add(tracecallchain[trace_index][2])               
               td = depth
               tindex = trace_index
               prevf = tf
               while td < calldepth:
                     if tracecallchain[tindex][0] == 'enter':
                        print(f"Callee at {hex(tracecallchain[tindex][1])} and caller of {hex(tracecallchain[tindex][2])} at index {tindex}")
                        callee2 = self.IRgetFunctionAtAddress(tracecallchain[tindex][1])
                        caller2 = self.IRgetFunctionOfInstruction(tracecallchain[tindex][2]-1)
                     else:
                        caller2 = self.IRgetFunctionOfInstruction(tracecallchain[tindex][3])
                     if not caller2 == None and (not tracecallchain[tindex][0] == 'enter' or not callee2 == None):
                        nra, tindex, tbbs, timplicit, callerf5 = self.DynfindCallsitesReturnAddress(tracecallchain, tindex, caller2)
                        if nra == None:
                           break
                        if not reg == None:
                           tep = (nra, self.IRgetFunctionInfo(callee2), 'argument', reg, self.IRgetFunctionInfo(caller2), 'global', src[1]) 
                           entryPoints.add(tep)
                           #if not fstream == None:
                           #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
                        else: 
                           tep = (nra, "", 'global', src[1], self.IRgetFunctionInfo(caller2), 'global', src[1])
                           entryPoints.add(tep)
                           #if not fstream == None:
                           #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
                        print(f"@@@@@@@@@@@@@@@@ Number of entry points found: {len(entryPoints)}, global: {len(epsofar)}")
                        if not entry_point_limit == None and len(entryPoints) + len(epsofar) > entry_point_limit:
                           print(f"WARNING: Entry point limit reached!!!")
                           return entryPoints
                     td += 1
                     prevf = caller2 
            if (src[0] == 'stack' or (src[0] == 'argument' and src[1] == 'sp')):             
               # check if implict flow is still happening
               print(f"Detected a local source for arg {src}")
               if tracecallchain[trace_index][0] == 'enter':
                  caller2 = self.IRgetFunctionOfInstruction(tracecallchain[trace_index][2]-1)
                  callee2 = self.IRgetFunctionAtAddress(tracecallchain[trace_index][1])
               else:
                  caller2 = self.IRgetFunctionOfInstruction(tracecallchain[trace_index][3])
               if not caller2 == None and (not tracecallchain[trace_index][0] == 'enter' or not callee2 == None):
                  if not reg == None:
                     tep = (tracecallchain[trace_index][2], self.IRgetFunctionInfo(callee2), 'argument', reg, self.IRgetFunctionInfo(caller2), 'stack', src[1])
                     entryPoints.add(tep)
                     #if not fstream == None:
                     #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
                  else:
                     tep = (tracecallchain[trace_index][3], "", 'argument', "", self.IRgetFunctionInfo(caller2), 'stack', src[1])
                     entryPoints.add(tep)
                     #if not fstream == None:
                     #   fstream.write(f"EARLY ENTRY POINT: {self.prettyPrintEntryPoint(tep)}\n") 
                  print(f"@@@@@@@@@@@@@@@@ Number of entry points found: {len(entryPoints)}, global: {len(epsofar)}")
                  if not entry_point_limit == None and len(entryPoints) + len(epsofar) > entry_point_limit:
                     print(f"WARNING: Entry point limit reached!!!")
                     return entryPoints
        for ep in entryPoints:
            print(f"Entry point {hex(ep[0])} full info {ep}")
        return entryPoints

    #  call before self._comprehensiveDefUse = True (and reset after)
    def DynfindEntryPoint(self, epsofar, tracecallchain, trace_index, taintpc, taintList, retBasedTaintMap, calldepth, fstream=None, entry_point_limit=None):
        results = set()
        if tracecallchain[trace_index][0] == 'enter':
           addr = tracecallchain[trace_index][1]
           tf = self.IRgetFunctionAtAddress(tracecallchain[trace_index][1])
           tfs = set()
           tfs.add(tf)
           if len(tfs) == 0:
              print(f"WARNING: Could not find function at {hex(tracecallchain[trace_index][1])}")
              if not fstream == None:
                 fstream.write(f"WARNING: Could not find function at {hex(tracecallchain[trace_index][1])}\n")
        else: 
           addr = tracecallchain[trace_index][3]
           tfs = self.IRgetFunctionsOfInstruction(tracecallchain[trace_index][3])
           if len(tfs) == 0:
              print(f"WARNING: Could not find function of {hex(tracecallchain[trace_index][3])}")
              if not fstream == None:
                 fstream.write(f"WARNING: Could not find function of {hex(tracecallchain[trace_index][3])}\n")
        storeAddrs = set() 
        for tf in tfs:
            print(f"Finding store addresses within {tf.name} for {hex(addr)}")
            sas = self.IRgetStoresAtAddressWithinFunction(tf, taintpc)
            for sa in sas:
                storeAddrs.add(sa)
        #storeAddrs = self.IRgetStoresAtAddress(taintpc)
        print(f"Number of store addresses at {hex(taintpc)}: {len(storeAddrs)}") 
        for sa in storeAddrs:
            f, bb, index = sa
            if bb == None:
               #print(f"Could not find basic block for taint loc {hex(taintpc)} from trace index {trace_index}")
               continue
            st = bb.vex.statements[index]
            cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
            print(f"<<< FINDING ENTRY POINT for trace index {trace_index} TAINT addr {hex(tracecallchain[trace_index][1])} at location {hex(taintpc)} >>>")
            visited = set()
            tres = self.DynfindEntryPointInternal(visited, results, tracecallchain, retBasedTaintMap, trace_index, f, taintList, cfgnode, bb, st, index, st.addr, 0, calldepth, entry_point_limit, fstream) 
            del visited
            for res in tres:
                results.add(res)
            print(f"@@@@@@@@@@@@@@@@ Global number of entry points found: {len(results) + len(epsofar)}")
            if not entry_point_limit == None and len(results) + len(epsofar) > entry_point_limit:
               print(f"WARNINGL Entry point limit {entry_point_limit} reached!!!")
               #sys.stdin.read(1)
               return results
            #sys.stdin.read(1)
        return results


    # for each taint address ta:
    #     scan backwards until function entry while considering absolute value differences of up to 256: [ta-256, ta + 256]
    #          find the first source of direct and indirect buffer reference
    #          to identify sources
    # Pre: trace_index represents a store instruction that either performs a direct TAINT or propagates the taint
    def DynfindBackwardSourceFromTaintLoc(self, tracecallchain, trace_index, taintpc, filter, address_bound=256):
        args = ['r0', 'r1', 'r2', 'r3']
        results = set()
        entryIndex = 0
        i = trace_index
        while i >= 0:
              if i in tracecallchain.keys():
                 if tracecallchain[i][0] == 'enter':
                    entryIndex = i
                    break
              i -= 1
        pointsTo = {}
        loads = set()
        taddrs = set()
        taddrs.add(tracecallchain[trace_index][1])
        i = trace_index
        while i >= entryIndex:
              if i in tracecallchain.keys():
                 if tracecallchain[i][0] == 'read':
                    newaddrs = set()
                    for ta in taddrs:
                        #print(f"read addr {hex(tracecallchain[i][2])} vs tainted addr {hex(ta)}")
                        if abs(tracecallchain[i][2] - ta) < address_bound:
                           newaddrs.add(tracecallchain[i][2])
                           if not tracecallchain[i][1] in pointsTo.keys():
                              pointsTo[tracecallchain[i][1]] = set()
                           pointsTo[tracecallchain[i][1]].add(tracecallchain[i][2])
                           loads.add(tracecallchain[i][3])
                           #print(f"Recording taint related points to {hex(tracecallchain[i][1])} -> {hex(tracecallchain[i][2])} @ {i} pc {hex(tracecallchain[i][3])}") 
                    for na in newaddrs:
                        taddrs.add(na)  
              i -= 1
        for la in loads:
            loadAddrs = self.IRgetLoadsAtAddress(la)
            for lt in loadAddrs:
                f, bb, index = lt
                if bb == None:
                    print(f"Could not find basic block for taint loc {hex(la)}")
                st = bb.vex.statements[index]
                cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
                vm = {}
                ev = ""
                baseregset = self.IRgetBaseRegSetForFunction(f)
                tlsrcs = self.IRfindAllSourcesofAddress(f, baseregset, cfgnode, bb, st, index, st.data.addr, vm, ev, filter)
                del vm
                for tlsrc in tlsrcs:
                    results.add(tlsrc)
                ra = set()
                for r in results:
                    if r[0] == 'argument':    
                       ra.add(r[1])
                if len(ra) == 4:
                   break
        return results

    def DynisImplicitCall(self, tracecallchain, trace_index, tf, bbscovered):
        stuple = tracecallchain[trace_index]
        index = trace_index - 1
        while index >= 0:
              if index in tracecallchain.keys():
                 tuple = tracecallchain[index]
                 if tuple[0] == 'enter':
                    if tuple[2] == stuple[2]:
                       return True, index, tuple[1], tuple[2], bbscovered
                    else:
                       return False, index, tuple[1], tuple[2], bbscovered
                 if tuple[0] == 'basicblock' and not tuple[1] == 0:
                    bbscovered.add(tuple[1])
                 if tuple[0] == 'basicblock' and tuple[1] == 0:
                    # derive pc from lr
                    bbscovered.add(tuple[2] - 1)
              index -= 1
        return False, None, None, None, None

    def DynisImplicitCallWrtEntry(self, trace, trace_index, refindex):
        if trace[trace_index][0] == 'enter' and trace[refindex][0] == 'enter':
           callee = self.IRgetFunctionAtAddress(trace[trace_index][1])
           caller = self.IRgetFunctionOfInstruction(trace[refindex][2]-1)
           first_callee = self.IRgetFunctionOfInstruction(trace[refindex][2]-1)
           #print(f"lr for {trace_index}: {hex(trace[trace_index][2])} lr for {refindex}: {hex(trace[refindex][2])} first_callee {first_callee.name}")
           if trace[trace_index][2] == trace[refindex][2]:
              return True, callee
           elif not first_callee == None:
              if first_callee.addr == trace[trace_index][1] or first_callee.addr == trace[trace_index][1] + 1:
                 return False, callee
        return None, None
 



    # caller is the caller executes between start_index and end_index 
    # returns the bss executed by the caller in this segment by the caller 
    def DyngetBBsOnPath(self, trace, start_index, end_index, caller):
        bbs = set()
        min, max = self.IRgetFunctionAddressRange(caller)
        i = start_index 
        while i <= end_index:
              if i in trace.keys():
                 if trace[i][0] == 'basicblock' and not trace[i][1] == 0:
                    if trace[i][1] >= min and trace[i][1] <= max:
                       bbs.add(trace[i][1])
                 if trace[i][0] == 'basicblock' and trace[i][1] == 0:
                    if trace[i][2] - 1 >= min and trace[i][2] - 1 <= max:
                       bbs.add(trace[i][2] - 1)
              i += 1
        if trace[start_index][0] == 'enter':
           bbs.add(trace[start_index][1]) 
        results = set()
        for bba in bbs:
            try:
               bb = self._project.factory.block(bba)
            except angr.errors.SimEngineError:
               continue
            cfgnode = self.IRfindCFGNodeForInstruction(caller, bb, bb.addr)
            if cfgnode == None:
               print(f"WARNING: Could not find cfgnode for {hex(bba)}!")
               continue
            results.add((caller, bb, cfgnode))           
        return results

    def DyngetFunction(self, trace, index):
        if not index in trace.keys():
           return None
        if trace[index][0] == 'enter':
           return self.IRgetFunctionOfInstruction(trace[index][2]-1)
        if trace[index][0] == 'basicblock' and not trace[index][1] == 0:
           return self.IRgetFunctionOfInstruction(trace[index][1])
        if trace[index][0] == 'basicblock' and trace[index][1] == 0:
           return self.IRgetFunctionOfInstruction(trace[index][2] - 1)
        if trace[index][0] == 'readMMIO' or trace[index][0] == 'read' or trace[index][0] == 'write':
           return self.IRgetFunctionOfInstruction(trace[index][3])    
        return None 

    def DynfindCallsitesReturnAddress(self, trace, trace_index, tf, callee=None):
        if callee == None:
           print(f"Finding callsite return address for function entry {tf.name} from index {trace_index}")
        else:
           print(f"Finding callsite return address for function entry {tf.name} from index {trace_index} callee {callee.name}")
        foundcs = False
        csindex = -1
        caller = None
        implicit = None  
        ref_index = None
        if trace[trace_index][0] == 'enter':    
           i = trace_index - 1
           ref_index = trace_index
        else:
           fc = self.DyngetFunction(trace, trace_index)
           ti = trace_index
           while ti >= 0:
                 if ti in trace.keys():
                    if trace[ti][0] == 'enter':
                       #print(f"fc {fc.name} {hex(fc.addr)} vs {hex(trace[ti][1])}")
                       if fc.addr == trace[ti][1] or fc.addr  == trace[ti][1] + 1:
                          ref_index = ti
                          i = ref_index - 1
                          break
                 ti -= 1
        if ref_index == None:
           return None, None, None, None, None
        print(f"Start index adjusted {i} ref_index {ref_index}")  
        while i >= 0:
              if i in trace.keys():
                 if trace[i][0] == 'enter': 
                    #print(f"i {i} ref_index {ref_index}")
                    iflag, f = self.DynisImplicitCallWrtEntry(trace, i, ref_index)
                    if not iflag == None and not f == None:
                       print(f"callsite found {i} caller {f.name}")
                       foundcs = True
                       csindex = i
                       caller = f
                       implicit = iflag  
                       break 
              i -= 1
        if foundcs:
           print(f"Found callsite at {csindex} caller {caller.name}")
           bbs = self.DyngetBBsOnPath(trace, csindex, ref_index, caller)  
           return (trace[csindex][2], csindex, bbs, implicit, caller)
        return None, None, None, None, None

    def DynfindCallsitesReturnAddressOld(self, tracecallchain, trace_index, tf, callee=None):
        if callee == None:
           print(f"Finding callsite return address for function entry {tf.name} from index {trace_index}")
        else:
           print(f"Finding callsite return address for function entry {tf.name} from index {trace_index} callee {callee.name}")
        if tracecallchain[trace_index][0] == 'enter': 
           ibbscovered = set()
           ibbs = set()
           ituple = self.DynisImplicitCall(tracecallchain, trace_index, tf, ibbscovered)
           if not ituple[2] == None:
              icaller = self.IRgetFunctionOfInstruction(ituple[2])
              if not callee == None:
                 # first check if this may be an explicit call
                 if ituple[0]:
                    ibbst = self.IRfindExplicitCalleeBBs(icaller, callee)
                 else:
                    ibbst = self.IRfindExplicitCalleeBBs(tf, callee)
                 for t in ibbst:
                    ibbs.add(t[1].addr)
                 if len(ibbs) > 0:
                    print(f"Length of explicitly found bbs {len(ibbs)} for caller {tf.name} callee {callee.name}")
                    return (ituple[3], ituple[1], ibbs, True)                  
              if ituple[0]:
                 ibbst = self.IRfindImplicitCalleeBBs(icaller)
                 for t in ibbst:
                     ibbs.add(t[1].addr)
                 if len(ibbs) > 0:
                    print(f"\tFound implicit call entry at trace index {ituple} caller {icaller.name} address {hex(icaller.addr)} num bss {len(ibbs)}")
                    return (ituple[3], ituple[1], ibbs, True)
                 else:
                    print(f"Could not find an implicit call entry at trace index {ituple} caller {icaller.name} address {hex(icaller.addr)}")
                    return None, None, None, None                    
        bbscovered = set()  
        index = trace_index
        while index >= 0:
              if index in tracecallchain.keys():
                 tuple = tracecallchain[index]
                 if tuple[0] == 'enter' and (tuple[1] == tf.addr or tuple[1] + 1 == tf.addr):
                    print(f"\tStopped at trace index {index}") 
                    return (tuple[2], index, bbscovered, False)
                 if tuple[0] == 'basicblock' and not tuple[1] == 0:
                    bbscovered.add(tuple[1])
                 if tuple[0] == 'basicblock' and tuple[1] == 0:
                    # derive pc from lr
                    bbscovered.add(tuple[2] - 1)
              index -= 1
        return None, None, None, None

    def IRgetRegDefiningNode(self, func, cfgnode, bb, reg, filter=None, depth=0):
        results = set()
        if depth > self._defsfornodedepthBound:
           return results
        baseregset = self.IRgetBaseRegSetForFunction(func)
        rbb, min, max = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(func, cfgnode, bb) 
        index = max
        while index >= min:
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.Put):
                 if self._project.arch.register_names[st.offset] == reg:
                    results.add((cfgnode, bb, index, st.data))
                    break
              index -= 1
        if len(results) == 0:
           preds = self.IRfindImmediatePredsInFunction(func, cfgnode, bb, filter)
           for predt in preds:
               pred, pbb, pmin, pmax = predt
               #pbb = self.IRgetBBForCFGNode(func, pred) 
               subres = self.IRgetRegDefiningNode(func, pred, pbb, reg, filter, depth + 1)
               for res in subres:
                   results.add(res)
        return results
                  

    def IRfindImplicitArgFlowsThroughLocal(self, func,  cfgnode, bb, reg, local_offset, filter=None):
        args = ['r0', 'r1', 'r2', 'r3']
        results = set()
        baseregset = self.IRgetBaseRegSetForFunction(func)
        tbb, min, max = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(func, cfgnode, bb)
        index = max
        argsrcs = set()
        while index >= min:
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.Put):
                 if self._project.arch.register_names[st.offset] == reg:
                    vm = {}
                    ev = ""  
                    argsrcs = self.IRfindAllSourcesofAddress(func, baseregset, cfgnode, bb, st, index, st.data, vm, ev, filter, True) 
                    del vm
                    break
              index -= 1
        if len(argsrcs) == 0:
           # check the same thing in predecessors
           preds = self.IRfindImmediatePredsInFunction(func, cfgnode, bb, filter)
           for predt in preds:
               pred, pbb, pmin, pmax = predt
               #pbb = self.IRgetBBForCFGNode(func, pred) 
               subres = self.IRfindImplicitArgFlowsThroughLocal(func, pred, pbb, reg, local_offset, filter)
               for res in subres:
                   results.add(res)
           return results
        else:
           allpreds = self.IRfindAllPredsInFunction(func, cfgnode, filter)
           for pred in allpreds:
               pbb = self.IRgetBBForCFGNode(func, pred)
               tbb, min, max = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(func, pred, pbb)
               index = min
               while index <= max:
                     st = pbb.vex.statements[index]
                     # check for stores ..
                     if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                        vm2 = {}
                        destsrcs = self.IRfindAllSourcesofAddress(func, baseregset, pred, pbb, st, index, st.addr, vm2, "", filter, True)
                        del vm2
                        for destsrc in destsrcs:
                            if destsrc in argdef:
                               vm3 = {}  
                               datasrcs = self.IRfindAllSourcesofAddress(func, baseregset, pred, pbb, st, index, st.data, vm3, "", filter, True)
                               del vm3
                               for datasrc in datasrcs:
                                   if datasrc[0] == "argument" and not datasrc[1] in args:
                                      results.add((pred, pbb, st, index, st.data, datasrc[1]))                  
                     index += 1
        return results      

    def prettyPrintEntryPoint(self, ep):
        res = ""
        res += "Entry point=%s," % (hex(ep[0]))
        res += "Callee=%s," % (ep[1])
        res += "type=%s," % (ep[2])
        if len(ep) >= 4:
           if isinstance(ep[3], int):
              res += "value=%s," % (hex(ep[3]))
           else: 
              res += "value=%s," % (ep[3]) 
        if len(ep) >= 5:
           res += "Caller=%s," % (ep[4])
        if len(ep) >= 6:
           res += "type=%s," % (ep[5])
        if len(ep) >= 7:
           if isinstance(ep[6], int):
              res += "value=%s," % (hex(ep[6]))
           else: 
              res += "value=%s," % (ep[6])
        return res 

    # setting calldepth to a large value increases the chance for finding a good entry point
    # A suggested value is the default value for self._dynamiccallchaintaintsearchBound!
    def IRfindTaintEntryPoints(self, tracecallchain, taintList, retBasedTaintMap, calldepth, last, taint_index=None, fstream=None, entry_point_limit=None):
        endpoints = set()
        taints = set()
        taintPCs = set()
        i = len(taintList) - 1
        while i >= 0:
              if last > 0 and len(taints) >= last:
                 break
              if not taintList[i][1] in taintPCs:
                 taints.add(taintList[i])
                 taintPCs.add(taintList[i][1])
              i -= 1
        print(f"Number of unique taints based on location: {len(taints)}")
        #for taint in taints:
        self.IRprintConfig(fstream)
        analyzed = set() 
        index = len(taintList) - 1
        while index >= 0:
        #for taint in taintList:
            #if not taint[2] == 0x200022ae:
            #   continue
            #if not taint[0] == 153017:
            #if not taint[0] == 170964:
            taint = taintList[index] 
            if not taint_index == None and not taint[0] == taint_index:
               index -= 1
               continue 
            if taint_index == None and taint[1] in analyzed:
               index -= 1
               continue
            analyzed.add(taint[1])
            print(f"Working on taint index {taint[0]} pc {hex(taint[1])}")
            if not fstream == None:
               fstream.write(f"Working on taint index {taint[0]} pc {hex(taint[1])}\n") 
            eps = self.DynfindEntryPoint(endpoints, tracecallchain, taint[0], taint[1], taintList, retBasedTaintMap, calldepth, fstream, entry_point_limit)  
            for ep in eps:
                epstr = self.prettyPrintEntryPoint(ep)
                endpoints.add((ep[0], taint[2]))
                print(f"[Entry Point] Tainted addr={hex(taint[2])},{epstr}")
                if not fstream == None:
                   fstream.write(f"[Entry Point] Tainted addr={hex(taint[2])},{epstr}\n")
                print(f"@@@@@@@@@@@@@@@@ Global number of entry points found: {len(endpoints)}")
                if not entry_point_limit == None and len(endpoints) > entry_point_limit:
                   return endpoints
            index -= 1
        return endpoints

    def IRfindAllSuccsInFunction(self, f, cfgnode, bb):
        result = set()  
        worklist = set()
        visited = set()
        succset = self.IRfindImmediateSuccsInFunction(f, cfgnode, bb)         
        for st in succset:
            worklist.add(st)
        while len(worklist) > 0:
            st = worklist.pop()
            curr, sbb, smin, smax = st
            result.add(st)
            visited.add(curr.addr)
            succset = self.IRfindImmediateSuccsInFunction(f, curr, sbb)         
            for st2 in succset:
                if not st2[0].addr in visited:
                   worklist.add(st2)
        return result          


    def IRgetDefWithinCFGNode(self, f, bb, cfgnode, index, st, node):
        #print(f"[IRgetDefWithinCFGNode] {f.name} {hex(bb.addr)} {st} {node} {index} {self.showTime()}")
        results = set()
        if isinstance(node, pyvex.IRExpr.Const):
           return results
        i = index 
        while i >= 0:
              cst = bb.vex.statements[i]
              #print(f"cst {cst} i {i}")
              if isinstance(cst, pyvex.IRStmt.Put):
                 if isinstance(node, pyvex.IRExpr.Get):
                    if node.offset == cst.offset: 
                       cn = self.IRfindCFGNodeForStatement(f, bb, i)
                       res = self.IRgetDefWithinCFGNode(f, bb, cn, i, cst, cst.data) 
                       for r in res:
                           results.add(r)                  
                       break 
              elif isinstance(cst, pyvex.IRStmt.WrTmp):
                 if isinstance(node, pyvex.IRExpr.RdTmp):
                    if node._tmp == cst.tmp:
                       if isinstance(cst.data, pyvex.IRExpr.Load) or isinstance(cst.data, pyvex.IRStmt.LoadG):
                          results.add((bb.addr, i, cst.data, 0, ""))
                          if not isinstance(cst.data.addr, pyvex.IRExpr.Const):
                             cn = self.IRfindCFGNodeForStatement(f, bb, i)
                             res = self.IRgetDefWithinCFGNode(f, bb, cn, i, cst, cst.data.addr) 
                             for r in res:
                                 results.add(r)                  
                          break
                       else:                          
                          if len(cst.data.child_expressions) == 0:
                             cn = self.IRfindCFGNodeForStatement(f, bb, i)
                             res = self.IRgetDefWithinCFGNode(f, bb, cn, i, cst, cst.data) 
                             for r in res:
                                 results.add(r)
                             break                
                          else: 
                             for ce in cst.data.child_expressions:
                                 cn = self.IRfindCFGNodeForStatement(f, bb, i)
                                 res = self.IRgetDefWithinCFGNode(f, bb, cn, i, cst, ce) 
                                 for r in res:
                                     results.add(r)                
                             break
              i -= 1
        if len(results) == 0:
           if index < 0:
              index = 0
           results.add((bb.addr, index, node, 0, ""))                                       
        return results 

    def RDgetReachingDefsForCFGNodeDefs(self, f, bb, cfgnode, index, st, node):
        print(f"[RDgetReachingDefsForCFGNodeDefs] {f.name} {hex(bb.addr)} {st} {node}")
        self.IRgenerateReachingDefs(f)
        results = {}
        cdefs = self.IRgetDefWithinCFGNode(f, bb, cfgnode, index, st, node)
        #print(f"Num defs: {len(cdefs)}") 
        for cdt in cdefs:
            dbba, dindex, dnode, dc, dev = cdt
            try:
                dbb = self._project.factory.block(dbba)
            except angr.errors.SimEngineError:
                print(f"DEBUG: Could not map bb address {hex(dbba)} to a bb {self.showTime()}")
                continue
            #print(f"Def within bb: {hex(dbba)} st {dbb.vex.statements[dindex]} {dnode}")
            dcfgnode = self.IRfindCFGNodeForStatement(f, dbb, dindex)
            if isinstance(dnode, pyvex.IRExpr.Get):
               # since r0 may hold the return value we record it as is also 
               if not dnode.offset in self._project.arch.register_names.keys():
                  continue
               if self._project.arch.register_names[dnode.offset] == 'r0':
                  if not dnode.offset in results.keys():
                     results[dnode.offset] = set()
                  dia = self.IRInstructionAddress(dbb, dindex)
                  results[dnode.offset].add((dbba, dcfgnode.addr, dia, dbb.vex.statements[dindex]))
               if dcfgnode.addr in self._reachingDefsIn[f.addr].keys():
                  #print(f"Is offset {dnode.offset} defined in RDIN {hex(dcfgnode.addr)}")
                  if dnode.offset in self._reachingDefsIn[f.addr][dcfgnode.addr].keys():
                     rdefs = self._reachingDefsIn[f.addr][dcfgnode.addr][dnode.offset]
                     if not dnode.offset in results.keys():
                        results[dnode.offset] = set()
                     for r in rdefs:  
                         results[dnode.offset].add(r)
                  else:
                     if not dnode.offset in results.keys():
                        results[dnode.offset] = set()
                     dia = self.IRInstructionAddress(dbb, dindex)
                     results[dnode.offset].add((dbba, dcfgnode.addr, dia, dbb.vex.statements[dindex]))                       
            elif isinstance(node, pyvex.IRExpr.Get):  
                 if not node.offset in results.keys():
                    results[node.offset] = set()
                 dia = self.IRInstructionAddress(dbb, dindex)
                 results[node.offset].add((dbba, dcfgnode.addr, dia, dbb.vex.statements[dindex]))                       
        return results


    def RDisLoadingFrom(self, f, bb, cfgnode, index, st, data, loadPC):
        self.IRgenerateReachingDefs(f)
        if data:
           node = st.data
        else:
           node = st.addr
        defs = self.IRgetDefWithinCFGNode(f, bb, cfgnode, index, st, node)
        for d in defs:
            dbba, dindex, dnode, dc, dev = d
            if isinstance(dnode, pyvex.IRExpr.Load) or isinstance(dnode, pyvex.IRStmt.LoadG):
               try:
                   dbb = self._project.factory.block(dbba)
               except angr.errors.SimEngineError:
                   print(f"DEBUG: Could not map bb address {hex(dbba)} to a bb {self.showTime()}")
                   continue
               iaddr = self.IRInstructionAddress(dbb, dindex)
               #print(f"iaddr {hex(iaddr)} vs loadPC {hex(loadPC)}")
               if iaddr == loadPC:
                  return True
        for d in defs:
            dbba, dindex, dnode, dc, dev = d
            try:
                dbb = self._project.factory.block(dbba)
            except angr.errors.SimEngineError:
                print(f"DEBUG: Could not map bb address {hex(dbba)} to a bb {self.showTime()}")
                continue
            dcfgnode = self.IRfindCFGNodeForStatement(f, dbb, dindex)
            if isinstance(dnode, pyvex.IRExpr.Get):
               if dcfgnode.addr in self._reachingDefsIn[f.addr].keys():
                  if dnode.offset in self._reachingDefsIn[f.addr][dcfgnode.addr].keys():
                     rdefs = self._reachingDefsIn[f.addr][dcfgnode.addr][dnode.offset]
                     for rdt in rdefs:
                         rbba, rcgnodea, ria, rst = rdt       
                         defs2 = self.IRgetDefWithinCFGNode(f, bb, cfgnode, index, st, node)
                         for d2 in defs2:
                             dbba2, dindex2, dnode2, dc2, dev2 = d2
                             try:
                                dbb2 = self._project.factory.block(dbba2)
                             except angr.errors.SimEngineError:
                                print(f"DEBUG: Could not map bb address {hex(dbba2)} to a bb {self.showTime()}")
                                continue
                             if isinstance(dnode2, pyvex.IRExpr.Load) or isinstance(dnode2, pyvex.IRStmt.LoadG):
                                iaddr2 = self.IRInstructionAddress(dbb2, dindex2)
                                if iaddr2 == loadPC:
                                   return True
        return False
    
    def IRcheckFlowOfReadIntoReturnValueRegister(self, trace, index, filter=None):
        print(f"Checking flow of read into return value register for index {index} {self.showTime()}")
        results = set()
        if not (trace[index][0] == 'read' or trace[index][0] == 'readMMIO'):
           return results
        loadPC = trace[index][3]
        if loadPC in self._returnValueFlowBasedOnLoadPc.keys():
           return self._returnValueFlowBasedOnLoadPc[loadPC]
        print(f"Finding function of instruction {self.showTime()}")
        f = self.IRgetFunctionOfInstruction(loadPC)
        if f == None:
           return False
        print(f"Generating reaching definitions for {f.name} {self.showTime()}")
        self.IRgenerateReachingDefs(f)
        #print(f"Printing reaching definitions for {f.name} {self.showTime()}")
        #self.IRprintReachingDefs(f)
        print(f"Finding bb of instruction {self.showTime()}")
        bb, sti = self.IRgetBBForInstruction(f, loadPC)          
        if bb == None:
           return False
        print(f"Finding cfgnode of instruction {self.showTime()}")
        cfgnode = self.IRfindCFGNodeForInstruction(f, bb, loadPC)
        if cfgnode == None:
           print(f"WARNING: Could not find cfgnode for {hex(bb.addr)}! {self.showTime()}")
           return False
        print(f"Finding all successors {self.showTime()}")
        st = self.IRfindAllSuccsInFunction(f, cfgnode, bb)
        sbbs = set() 
        sbbs.add(bb)
        for s in st:
            succ, sbb, smin, smax = s
            sbbs.add(sbb)
        for sbb in sbbs:
            sindex = 0
            sia = 0
            while sindex < len(sbb.vex.statements):
                  st = sbb.vex.statements[sindex]
                  if isinstance(st, pyvex.IRStmt.IMark):
                     sia = st.addr                                                
                  if isinstance(st, pyvex.IRStmt.Put):                                       
                     if self._project.arch.register_names[st.offset] == 'r0':
                        visited = set()
                        scfgnode = self.IRfindCFGNodeForInstruction(f, sbb, sia)
                        if scfgnode == None: 
                           print(f"WARNING: Could not find cfgnode for {hex(sbb.addr)} and {hex(sia)}! {self.showTime()}")
                           break
                        if self.RDisLoadingFrom(f, sbb, scfgnode, sindex, st, True, loadPC):
                           self._returnValueFlowBasedOnLoadPc[loadPC] = True
                           return True
                  sindex += 1
        print(f"Load at {hex(loadPC)} DOES NOT flow through return value! {self.showTime()}")
        self._returnValueFlowBasedOnLoadPc[loadPC] = False
        return False

    def IRcheckFlowOfReadIntoReturnValueRegisterOld(self, trace, index, filter=None):
        print(f"Checking flow of read into return value register for index {index} {self.showTime()}")
        results = set()
        if not (trace[index][0] == 'read' or trace[index][0] == 'readMMIO'):
           return results
        loadPC = trace[index][3]
        if loadPC in self._returnValueFlowBasedOnLoadPc.keys():
           return self._returnValueFlowBasedOnLoadPc[loadPC]
        print(f"Finding function of instruction {self.showTime()}")
        f = self.IRgetFunctionOfInstruction(loadPC)
        if f == None:
           return False
        print(f"Generating reaching definitions for {f.name} {self.showTime()}")
        self.IRgenerateReachingDefs(f)
        #print(f"Printing reaching definitions for {f.name} {self.showTime()}")
        #self.IRprintReachingDefs(f)
        print(f"Finding bb of instruction {self.showTime()}")
        bb, sti = self.IRgetBBForInstruction(f, loadPC)          
        if bb == None:
           return False
        print(f"Finding cfgnode of instruction {self.showTime()}")
        cfgnode = self.IRfindCFGNodeForInstruction(f, bb, loadPC)
        if cfgnode == None:
           print(f"WARNING: Could not find cfgnode for {hex(bb.addr)}! {self.showTime()}")
           return False
        print(f"Finding all successors {self.showTime()}")
        st = self.IRfindAllSuccsInFunction(f, cfgnode, bb)
        sbbs = set() 
        sbbs.add(bb)
        for s in st:
            succ, sbb, smin, smax = s
            sbbs.add(sbb)
        for sbb in sbbs:
            sindex = 0
            sia = 0
            while sindex < len(sbb.vex.statements):
                  st = sbb.vex.statements[sindex]
                  if isinstance(st, pyvex.IRStmt.IMark):
                     sia = st.addr                                                
                  if isinstance(st, pyvex.IRStmt.Put):                                       
                     if self._project.arch.register_names[st.offset] == 'r0':
                        visited = set()
                        scfgnode = self.IRfindCFGNodeForInstruction(f, sbb, sia)
                        if scfgnode == None: 
                           print(f"WARNING: Could not find cfgnode for {hex(sbb.addr)} and {hex(sia)}! {self.showTime()}")
                           self._returnValueFlowBasedOnLoadPc[loadPC] = False
                           return False
                        # to do may need to compute filter to lower overhead
                        print(f"Finding def for use for {st.data} instruction {hex(sia)} {self.showTime()} filter size {len(filter)}")
                        stdefs = self.IRgetDefForUse(f, scfgnode, sbb, st, sindex, st.data, filter, visited, "")
                        del visited
                        for std in stdefs:
                            dbba, dindex, dnode, dc, dev = std
                            #print(f"\t def at {hex(dbba)} by {dnode} used at pc {hex(sia)}")
                            try:
                               dbb = self._project.factory.block(dbba)
                            except angr.errors.SimEngineError:
                               print(f"DEBUG: Could not map bb address {hex(dbba)} to a bb {self.showTime()}")
                               continue
                            upc = sia
                            if isinstance(dnode, pyvex.IRExpr.Load) or isinstance(dnode,pyvex.IRStmt.LoadG):
                               iaddr = self.IRInstructionAddress(dbb, dindex)
                               if iaddr == loadPC:
                                  print(f"Load at {hex(loadPC)} flows through return value! {self.showTime()}")
                                  self._returnValueFlowBasedOnLoadPc[loadPC] = True
                                  return True
                  sindex += 1
        print(f"Load at {hex(loadPC)} DOES NOT flow through return value! {self.showTime()}")
        self._returnValueFlowBasedOnLoadPc[loadPC] = False
        return False

    def RDcommonDefs(self, rd1, rd2):
        for o in rd1.keys():
            if o in rd2.keys():
               for rd1t in rd1[o]:
                   for rd2t in rd2[o]:
                       if rd1t == rd2t:
                          return True, rd1t
        return False, None 

    def IRcheckFlowOfStoredDataIntoReturnValueRegister(self, returnBasedTaintMap, trace, index, fstream=None, filter=None):
        results = set()
        if not (trace[index][0] == 'write'):
           return results
        storePC = trace[index][3]
        print(f"Checking flow of stored data at {hex(storePC)} into return value {self.showTime()}")
        if storePC in self._returnValueFlowBasedOnStorePc.keys():
           return self._returnValueFlowBasedOnStorePc[storePC] 
        f = self.IRgetFunctionOfInstruction(storePC)
        if f == None:
           return False
        print(f"Generating reaching definitions for {f.name} {self.showTime()}")
        self.IRgenerateReachingDefs(f)
        #print(f"BBs in {f.name}")
        #self.IRprintBBs(f)
        print(f"Finding store instructions at {hex(storePC)}")
        storeInsts = self.IRgetStoresAtAddressWithinFunction(f, storePC)
        bb, sti = self.IRgetBBForInstruction(f, storePC)          
        if bb == None:
           return False
        cfgnode = self.IRfindCFGNodeForInstruction(f, bb, storePC)
        if cfgnode == None:
           print(f"WARNING: Could not find cfgnode for {hex(bb.addr)}!")
           return False
        sdefs = set()
        self._comprehensiveDefUse = True 
        rmap, retrds = self.IRgetReturnValueReachingDefs(f)
        if len(retrds) == 0:
           self._returnValueFlowBasedOnStorePc[storePC] = False
           print(f"No return value reaching defs for {f.name} index {index}!") 
           return False
        #for rdt in rdefs:
        #   print(f"\tReturn value def ev: {rdt[2][4]}") 
        for stt in storeInsts:
            sf, sbb, si = stt 
            #print(f"store bb:")
            #sbb.vex.pp()
            st = sbb.vex.statements[si]
            scfgnode = self.IRfindCFGNodeForStatement(f, sbb, si) 
            #visited = set()
            print(f"Finding def use for {st.data} {self.showTime()}\n")
            sd1 = self.RDgetReachingDefsForCFGNodeDefs(f, sbb, scfgnode, si, st, st.data)
            common1, sample1 = self.RDcommonDefs(retrds, sd1)
            if common1:
               self._returnValueFlowBasedOnStorePc[storePC] = True
               if not f.addr in returnBasedTaintMap.keys():
                  returnBasedTaintMap[f.addr] = set()
               for rkey in rmap.keys():
                   for rt in rmap[rkey]:
                       rbb, rcfgnode, rdef = rt
                       if rdef == sample1:
                          returnBasedTaintMap[f.addr].add((rbb, rcfgnode, index))   
               return True
            sd2 = self.RDgetReachingDefsForCFGNodeDefs(f, sbb, scfgnode, si, st, st.addr)
            common2, sample2 = self.RDcommonDefs(retrds, sd2)
            if common2:
               self._returnValueFlowBasedOnStorePc[storePC] = True
               if not f.addr in returnBasedTaintMap.keys():
                  returnBasedTaintMap[f.addr] = set()
               for rkey in rmap.keys():
                   for rt in rmap[rkey]:
                       rbb, rcfgnode, rdef = rt
                       if rdef == sample1:
                          returnBasedTaintMap[f.addr].add((rbb, rcfgnode, index))   
               return True
        print(f"Store at {hex(storePC)} DOES NOT flow through return value! ")
        self._returnValueFlowBasedOnStorePc[storePC] = False
        return False


    def IRcheckFlowOfStoredDataIntoReturnValueRegisterOld(self, returnBasedTaintMap, trace, index, fstream=None, filter=None):
        results = set()
        if not (trace[index][0] == 'write'):
           return results
        storePC = trace[index][3]
        print(f"Checking flow of stored data at {hex(storePC)} into return value {self.showTime()}")
        if storePC in self._returnValueFlowBasedOnStorePc.keys():
           return self._returnValueFlowBasedOnStorePc[storePC] 
        f = self.IRgetFunctionOfInstruction(storePC)
        if f == None:
           return False
        #print(f"BBs in {f.name}")
        #self.IRprintBBs(f)
        print(f"Finding store instructions at {hex(storePC)}")
        storeInsts = self.IRgetStoresAtAddressWithinFunction(f, storePC)
        bb, sti = self.IRgetBBForInstruction(f, storePC)          
        if bb == None:
           return False
        cfgnode = self.IRfindCFGNodeForInstruction(f, bb, storePC)
        if cfgnode == None:
           print(f"WARNING: Could not find cfgnode for {hex(bb.addr)}!")
           return False
        sdefs = set()
        self._comprehensiveDefUse = True 
        rdefs = self.IRgetReturnValueDefs(f, 1)
        if len(rdefs) == 0:
           self._returnValueFlowBasedOnStorePc[storePC] = False
           return False
        for rdt in rdefs:
           print(f"\tReturn value def ev: {rdt[2][4]}") 
        for stt in storeInsts:
            sf, sbb, si = stt 
            #print(f"store bb:")
            #sbb.vex.pp()
            st = sbb.vex.statements[si]
            scfgnode = self.IRfindCFGNodeForStatement(f, sbb, si) 
            #visited = set()
            print(f"Finding def use for {st.data} {self.showTime()}")
            sv = set()
            d1 = self.IRgetDefForUse(f, scfgnode, sbb, st, si, st.data, filter, sv)
            for d1t in d1:
                print(f"\tStore def ev: {d1t[4]}")
            del sv
            print(f"Finding def use ultimate for {st.data} {self.showTime()}")
            defs = self.IRgetDefUseUltimate(f, scfgnode, sbb, st, si, st.data, "", filter)
            #del visited
            for d in defs:
                sdefs.add(d)
                #print(f"candidate store data def at {hex(d[0])} {d[1]} {d[2]}")
            #visited = set() 
            print(f"Finding def use for {st.addr} {self.showTime()}")
            sv = set()
            d2 = self.IRgetDefForUse(f, scfgnode, sbb, st, si, st.addr, filter, sv)
            for d2t in d2:
                print(f"\tStore def ev: {d2t[4]}")
            del sv
            print(f"Finding def use ultimate for {st.addr} {self.showTime()}")
            defs = self.IRgetDefUseUltimate(f, scfgnode, sbb, st, si, st.addr, "", filter)
            #del visited
            for d in defs:
                sdefs.add(d)
                #print(f"candidate store addr def at {hex(d[0])} {d[1]} {d[2]}")
        self._comprehensiveDefUse = False 
        for rbb, rcfgnode, dt in rdefs:
            dbba, dindex, dnode, dc, dev = dt
            #print(f"\t def at {hex(dbba)} by {dnode} used at pc {hex(sia)}")
            print(f"return value def at {hex(dbba)} {dindex} {dnode} {self.showTime()}")
            for stt in sdefs:
                sbba, sindex, snode, sc, sdev = stt
                #print(f"store bb {hex(sbba)} vs {hex(dbba)} s index {sindex} vs {dindex} store def {snode} vs {dnode} s constant {sc} vs {dc}")
                if dbba == sbba and dindex == sindex and str(dnode) == str(snode) and dc == sc: 
                   print(f"Stored data/addr at {hex(storePC)} flows through return value! ")
                   if not f.addr in returnBasedTaintMap.keys():
                      returnBasedTaintMap[f.addr] = set()
                   returnBasedTaintMap[f.addr].add((rbb, rcfgnode, index))   
                   print(f"Recording return value tainted for {f.name} as a tainted return at bb {hex(rbb.addr)} cfgnode {hex(rcfgnode.addr)} index {index} {self.showTime()}")
                   if not fstream == None:
                      fstream.write(f"Recording return value tainted for {f.name} as a tainted return at bb {hex(rbb.addr)} cfgnode {hex(rcfgnode.addr)} {self.showTime()}\n")
                   #sys.stdin.read(1)
                   self._returnValueFlowBasedOnStorePc[storePC] = True
                   return True
        # check if any store defs about r0
        rbbs = self.IRgetReturnBBs(f)
        found = False
        for stt in sdefs:
            sbba, sindex, snode, sc, sdev = stt
            if isinstance(snode, pyvex.IRExpr.Get) and self._project.arch.register_names[snode.offset] == 'r0':
               found = True
               break
        if found:
           for rbb in rbbs:
               rcfgnode = self.IRfindCFGNodeForStatement(f, rbb, len(rbb.vex.statements) - 1) 
               print(f"Recording return value tainted for {f.name} as a tainted return at bb {hex(rbb.addr)} cfgnode {hex(rcfgnode.addr)} {self.showTime()}")
               if not fstream == None:
                  fstream.write(f"Recording return value tainted for {f.name} as a tainted return at bb {hex(rbb.addr)} cfgnode {hex(rcfgnode.addr)} {self.showTime()}\n")
               #sys.stdin.read(1)
               self._returnValueFlowBasedOnStorePc[storePC] = True
               return True        
        print(f"Store at {hex(storePC)} DOES NOT flow through return value! ")
        self._returnValueFlowBasedOnStorePc[storePC] = False
        return False

    def RDreduceAndCheckUse(self, f, sbb, sindex, sst, storeAddr, dbb, dcfgnode, dsia, dst, dnode, fbb, cbb, results, fstream=None):
        index = None
        if isinstance(dnode, pyvex.IRExpr.RdTmp):
           index = self.IRgetStatementIndexForInstructioninBB(dbb, dsia, dst)
           if index > 0:
              tdefs = self.IRgetDefWithinCFGNode(f, dbb, dcfgnode, index - 1, dst, dnode)
              for td in tdefs:
                  tdbba, tdindex, tdnode, tc, tev = td
                  try:
                      tdbb = self._project.factory.block(tdbba)
                  except angr.errors.SimEngineError:
                      print(f"DEBUG: Could not map bb address {hex(ddbba)} to a bb")
                      continue
                  tdst = tdbb.vex.statements[tdindex]
                  #print(f"tdindex {tdindex} tdst {tdst}") 
                  tcfgnode = self.IRfindCFGNodeForStatement(f, tdbb, tdindex)
                  tdsia = self.IRInstructionAddress(tdbb, tdindex) 
                  if tdindex > 0 and self.RDreduceAndCheckUse(f, sbb, sindex, sst, storeAddr, tdbb, tcfgnode, tdsia, tdst, tdnode, fbb, cbb, results, fstream):
                     print(f"Use of MMIO read through return value at {hex(sbb.addr)} {sst}")
                     if not fstream == None:
                        fstream.write(f"Use of MMIO read through return value at {hex(sbb.addr)} {sst}\n")
                     results.add(((sbb.addr, sst, sindex, sst.data, sst.addr, ""), storeAddr))
                     return True
           else:
                print(f"UNEXPECTED {dnode} at index {index}")  
        if isinstance(dnode, pyvex.IRExpr.Load) or isinstance(dnode,pyvex.IRStmt.LoadG):
           if not fbb == None and dbb.addr == fbb.addr:
              print(f"Use of MMIO read through return value at {hex(sbb.addr)} {sst}")
              if not fstream == None:
                 fstream.write(f"Use of MMIO read through return value at {hex(sbb.addr)} {sst}\n")
                 results.add(((sbb.addr, sst, sindex, sst.data, sst.addr, ""), storeAddr))
              return True
        if isinstance(dnode, pyvex.IRExpr.Get) and self._project.arch.register_names[dnode.offset] == 'r0':                          
           if (cbb.addr == dbb.addr or (not fbb == None and dbb.addr == fbb.addr)):
              print(f"Use of MMIO read through return value at {hex(sbb.addr)} {sst} in caller {hex(f.addr)} [{f.name}]")
              if not fstream == None:
                 fstream.write(f"Use of MMIO read through return value at {hex(sbb.addr)} {sst}  in caller {hex(f.addr)} [{f.name}]\n")
              results.add(((sbb.addr, sst, sindex, sst.data, sst.addr, ""), storeAddr))
              return True
           else:
              # an approximate sanity check by making sure no put(r0) in the same bb before this instruction
              possibleUse = True
              index = self.IRfindStatementIndex(dbb, dst)
              if index == None:
                 index = len(dbb.vex.statements) - 1
              while index >= 0:
                 cst = dbb.vex.statements[index]
                 if isinstance(cst, pyvex.IRStmt.Put):
                    if self._project.arch.register_names[cst.offset] == 'r0':
                       possibleUse = False
                       break
                 index -= 1
              if possibleUse:
                 print(f"Use of MMIO read through return value at {hex(sbb.addr)} {sst} in caller {hex(f.addr)} [{f.name}]")
                 if not fstream == None:
                    fstream.write(f"Use of MMIO read through return value at {hex(sbb.addr)} {sst} in caller {hex(f.addr)}[{f.name}]\n")
                 results.add(((sbb.addr, sst, sindex, sst.data, sst.addr, ""), storeAddr))
                 return True
        print(f"Reduced to {dnode} at {hex(dbb.addr)} inst {hex(dsia)} index {index}")
        #sys.stdin.read(1)
        return False


    def IRgetUsesofReturnValueThroughStores(self, returnBasedTraceMap, caller, caller_bbts, cbb, fbb, caller_filter=None, fstream=None):
           results = set()
           succset = set()
           bbs = set()
           for cfbb in caller_bbts:
               bbs.add(cfbb[1])
               st = self.IRfindAllSuccsInFunction(caller, cfbb[2], cfbb[1])
               for s in st:
                   if s[1] == None:
                      continue
                   succset.add(s)
           for st in succset:
               succ, sbb, smin, smax = st
               bbs.add(sbb)
               print(f"\t Successor {hex(succ.addr)}")
           del succset
           empty = True
           for sbb in bbs:
               stores = self.IRfindStoresInBB(sbb)
               #if len(stores) > 0:
               #   sbb.vex.pp()
               print(f"\tNum stores in {hex(sbb.addr)}: {len(stores)}")
               #sys.stdin.read(1) 
               for store in stores:
                   empty = False
                   sbb, sindex, sia = store
                   st = sbb.vex.statements[sindex]
                   print(f"Store {st} {hex(sbb.addr)} {sindex} instruction {hex(sia)} in {caller.name}")
                   scfgnode = self.IRfindCFGNodeForInstruction(caller, sbb, sia)
                   if scfgnode == None:
                      print(f"DEBUG: None cfgnode for {hex(sbb.addr)} {sindex} instruction {hex(sia)} in {caller.name}")
                      scfgnode = self.IRfindCFGNodeForStatement(caller, sbb, sindex)
                      if scfgnode == None:                     
                         sbb.vex.pp() 
                         print(f"DEBUG: None cfgnode for {hex(sbb.addr)} {sindex} in {caller.name}")
                         #sys.exit()
                         continue
                   print(f"Is store in {hex(sbb.addr)} at cfgnode {hex(scfgnode.addr)} {st} using return value?")
                   stdefs = self.RDgetReachingDefsForCFGNodeDefs(caller, sbb, scfgnode, sindex, st, st.data)    
                   print(f"Number of defs={len(stdefs)} for {st.data} in {caller.name} in bb {hex(sbb.addr)} cfgnode {hex(scfgnode.addr)} index {sindex}") 
                   found = False
                   for o in stdefs.keys():
                      for d in stdefs[o]:
                       dbba, dcfgnode, dsia, dst = d
                       dnode = dst.data 
                       print(f"\t def at {hex(dbba)} by {dnode} used at pc {hex(sia)}")
                       try:
                           dbb = self._project.factory.block(dbba)
                       except angr.errors.SimEngineError:
                           print(f"DEBUG: Could not map bb address {hex(dbba)} to a bb")
                           #sys.exit()
                           continue
                       #dbb.vex.pp()
                       #print(f"Reducing {dnode} at {hex(dbb.addr)}")
                       if self.RDreduceAndCheckUse(caller, sbb, sindex, st, sia, dbb, dcfgnode, dsia, dst, dnode, fbb, cbb, results, fstream):
                          found = True
                          break
                   #print(f"??? FOUND use for store {st} at {hex(sia)}: {found}")
                   del stdefs
               del stores
           return results

    def IRgetUsesofReturnValueThroughStoresOld(self, returnBasedTraceMap, caller, caller_bbts, cbb, fbb, caller_filter=None, fstream=None):
           results = set()
           succset = set()
           bbs = set()
           for cfbb in caller_bbts:
               bbs.add(cfbb[1])
               st = self.IRfindAllSuccsInFunction(caller, cfbb[2], cfbb[1])
               for s in st:
                   if s[1] == None:
                      continue
                   succset.add(s)
           for st in succset:
               succ, sbb, smin, smax = st
               bbs.add(sbb)
               print(f"\t Successor {hex(succ.addr)}")
           del succset
           empty = True
           for sbb in bbs:
               stores = self.IRfindStoresInBB(sbb)
               #if len(stores) > 0:
               #   sbb.vex.pp()
               print(f"\tNum stores in {hex(sbb.addr)}: {len(stores)}")
               #sys.stdin.read(1) 
               for store in stores:
                   empty = False
                   sbb, sindex, sia = store
                   st = sbb.vex.statements[sindex]
                   print(f"Store {st}")
                   scfgnode = self.IRfindCFGNodeForInstruction(caller, sbb, sia)
                   if scfgnode == None:
                      print(f"DEBUG: None cfgnode for {hex(sbb.addr)} {sindex} instruction {hex(sia)} in {caller.name}")
                      scfgnode = self.IRfindCFGNodeForStatement(caller, sbb, sindex)
                      if scfgnode == None:                     
                         sbb.vex.pp() 
                         print(f"DEBUG: None cfgnode for {hex(sbb.addr)} {sindex} in {caller.name}")
                         #sys.exit()
                         continue
                   print(f"Is store in {hex(sbb.addr)} at cfgnode {hex(scfgnode.addr)} {st} using return value?")
                   visited = set()
                   stdefs = self.IRgetDefForUse(caller, scfgnode, sbb, st, sindex, st.data, caller_filter, visited, "")
                   del visited
                   print(f"Number of defs={len(stdefs)} for {st.data} in {caller.name} in bb {hex(sbb.addr)} cfgnode {hex(scfgnode.addr)} index {sindex}") 
                   for std in stdefs:
                       dbba, dindex, dnode, dc, dev = std
                       print(f"\t def at {hex(dbba)} by {dnode} used at pc {hex(sia)}")
                       try:
                           dbb = self._project.factory.block(dbba)
                       except angr.errors.SimEngineError:
                           print(f"DEBUG: Could not map bb address {hex(dbba)} to a bb")
                           #sys.exit()
                           continue
                       upc = sia
                       if isinstance(dnode, pyvex.IRExpr.Load) or isinstance(dnode,pyvex.IRStmt.LoadG):
                          if not fbb == None and dbba == fbb.addr:
                             print(f"Use of MMIO read through return value at {hex(sbb.addr)} {st}")
                             if not fstream == None:
                                fstream.write(f"Use of MMIO read through return value at {hex(sbb.addr)} {st}\n")
                             results.add(((sbb.addr, st, sindex, st.data, st.addr, dev),upc))
                             break
                       if isinstance(dnode, pyvex.IRExpr.Get) and self._project.arch.register_names[dnode.offset] == 'r0':                          
                          if (cbb.addr == dbba or (not fbb == None and dbba == fbb.addr)):
                             print(f"Use of MMIO read through return value at {hex(sbb.addr)} {st} in caller {hex(caller.addr)} [{caller.name}]")
                             if not fstream == None:
                                fstream.write(f"Use of MMIO read through return value at {hex(sbb.addr)} {st}  in caller {hex(caller.addr)} [{caller.name}]\n")
                             results.add(((sbb.addr, st, sindex, st.data, st.addr, dev),upc))
                             break
                          else:
                             # an approximate sanity check by making sure no put(r0) in the same bb before this instruction
                             possibleUse = True
                             index = dindex
                             while index >= 0:
                                   cst = dbb.vex.statements[index]
                                   if isinstance(cst, pyvex.IRStmt.Put):
                                      if self._project.arch.register_names[cst.offset] == 'r0':
                                         possibleUse = False
                                         break
                                   index -= 1
                             if possibleUse:
                                print(f"Use of MMIO read through return value at {hex(sbb.addr)} {st} in caller {hex(caller.addr)} [{caller.name}]")
                                if not fstream == None:
                                   fstream.write(f"Use of MMIO read through return value at {hex(sbb.addr)} {st} in caller {hex(caller.addr)}[{caller.name}]\n")
                                results.add(((sbb.addr, st, sindex, st.data, st.addr, dev),upc))
                                break
                   del stdefs
               del stores
           return results


    def IRgetCFGNodeTupleForBB(self, f, bba):
        try:
            bb = self._project.factory.block(bba)
        except angr.errors.SimEngineError:
            return None, None, None  
        cfgnode = self.IRfindCFGNodeForInstruction(f, bb, bb.addr)
        return (f, bb, cfgnode)

    def DynBBsForFunctionFromIndex(self, caller, trace, index):
        print(f"[DynBBsForFunctionFromIndex] {caller.name} {index}")
        results = set()
        min, max = self.IRgetFunctionAddressRange(caller)
        f, bb, cfgnode = self.IRgetCFGNodeTupleForBB(caller, caller.addr)
        if not f == None and not bb == None and not cfgnode == None:  
           results.add((f, bb, cfgnode)) 
           lastbb = bb  
        retbbs = self.IRgetReturnBBAddresses(caller)
        print(f"Return bb addresses for {caller.name}")
        for rbb in retbbs:
            print(f"rbb {hex(rbb)}")
        lr = trace[index][2]
        othercalls = []
        retbb = None
        lastbb = None
        i = index + 1
        while i < len(trace):
           if i in trace.keys():
              if trace[i][0] == 'basicblock':
                 if trace[i][1] == 0:
                    ba = trace[i][2] - 1
                 else:
                    ba = trace[i][1]
                 #print(f"Trace entry {trace[i]} Checking ba {hex(ba)} at {i}")
                 if ba in retbbs or ba + 1 in retbbs:
                    print(f"A return bb {hex(trace[i][1])} len of othercalls of the same {len(othercalls)} index {i}")
                    if len(othercalls) == 0:
                       f, bb, cfgnode = self.IRgetCFGNodeTupleForBB(caller, ba)
                       if not f == None and not bb == None and not cfgnode == None:  
                          results.add((f, bb, cfgnode)) 
                          lastbb = bb 
                       retbb = ba
                       break  
                    else:
                       othercalls.pop()
                 else:
                    if len(othercalls) == 0:
                       if ba >= min and ba <= max:
                          f, bb, cfgnode = self.IRgetCFGNodeTupleForBB(caller, ba)
                          if not f == None and not bb == None and not cfgnode == None:  
                             results.add((f, bb, cfgnode))
                             lastbb = bb
                 if ba == lr or ba + 1 == lr:
                    print(f"num other calls of same {len(othercalls)}")
                    if not lastbb == None:
                          retbb = lastbb.addr
                    break 
              if trace[i][0] == 'enter':
                 if trace[i][1] == caller.addr or trace[i][1] + 1 == caller.addr:
                    othercalls.append(i)
           i += 1
        print(f"Exited at {i}")
        return (results, i, retbb)  

    def DyngetSegment(self, trace, index, immediate):
        print(f"[DyngetSegment] index {index}")
        f = None
        start_index = index
        if trace[index][0] == 'enter':
           if immediate:
              f = self.IRgetFunctionOfInstruction(trace[index][2]-1)
              if f == None:
                 return (None, None, None, None, None, None)                 
              i = index
              while i >= 0:
                    if i in trace.keys():
                       if trace[i][0] == 'enter':
                          if trace[i][1] == f.addr or trace[i][1] + 1 == f.addr:
                             start_index = i
                             break
                    i -= 1
           else:
              f = self.IRgetFunctionAtAddress(trace[index][1])
              if f == None:
                 return (None, None, None, None, None, None)                 
        else: 
           if trace[index][0] == 'basicblock':
              f = self.IRgetFunctionOfInstruction(trace[index][1])
           if trace[index][0] == 'read' or trace[index][0] == 'readMMIO' or trace[index][0] == 'write':
              f = self.IRgetFunctionOfInstruction(trace[index][3])
           i = index
           while i >= 0:
                 if i in trace.keys():
                    if trace[i][0] == 'enter':
                       if trace[i][1] == f.addr or trace[i][1] + 1 == f.addr:
                          start_index = i
                          break
                 i -= 1
        if f == None:
           return (None, None, None, None, None, None)
        print(f"Finding segment including index {index} for function {f.name}")
        # find start index
        bbts, end_index, retbb = self.DynBBsForFunctionFromIndex(f, trace, start_index)
        bbs = set()
        for bbt in bbts:
            #print(f"bbt {bbt}")
            bbs.add(bbt[1].addr)
        insts = self.IRgetInstructionsForBBsInFunction(f, bbs)
        print(f"Function segment start-end: {start_index}-{end_index} num bbs {len(bbs)} num insts {len(insts)}")
        return (f, start_index, end_index, bbts, insts, retbb)

    # cbb is either the callsite bb or bb that includes the loadpc 
    def DyngetReturnValueUsesForSegment(self, returnBasedTraceMap, f, start_index, end_index, bbs, insts, retbb, cbb, loadpc, fstream=None):
        rbba = None 
        results = None
        if not loadpc == None and cbb == None:
           cbb = self.IRgetBBForAddress(f, loadpc)
        if loadpc == None:   
           print(f"[DyngetReturnValueUsesForSegment] {f.name} cbb {hex(cbb.addr)}")
        else:
           print(f"[DyngetReturnValueUsesForSegment] {f.name} cbb {hex(cbb.addr)} loadpc {hex(loadpc)}")
        self._comprehensiveDefUse = True
        print(f"insts:")
        self.IRprintInstSet(insts)
        rmap, retvaldefs = self.IRgetReturnValueReachingDefs(f)
        fbb = None 
        found = False
        print(f"retvaldefs {retvaldefs}")
        if not loadpc == None:
           for rkey in retvaldefs.keys():
            for rd in retvaldefs[rkey]:
               rbba, rc, raddr, rst = rd
               rn = rst.data  
               print(f"rbba {hex(rbba)} cn {hex(rc)} inst {hex(raddr)} node {rn}")
               print(f"Return value defs {hex(rbba)} {hex(raddr)} (vs loadPC {hex(loadpc)}) {rn} start index {start_index} end index {end_index}")
               try:
                  rbb = self._project.factory.block(rbba)
               except angr.errors.SimEngineError:
                  continue
               if isinstance(rn, pyvex.IRExpr.Load):
                  #raddr = self.IRInstructionAddress(rbb, ri)
                  print(f"Instruction address {hex(raddr)} for {rn}")
                  if raddr == loadpc:
                     found = True
                     fbb = rbb 
                     print(f"Basic block {hex(fbb.addr)} with load that flows into return value") 
                     if not fstream == None:
                        fstream.write(f"Basic block {hex(fbb.addr)} with load that flows into return value\n")
                     break
        print(f"Return value defs completed!")
        del retvaldefs
        results = self.IRgetUsesofReturnValueThroughStores(returnBasedTraceMap, f, bbs, cbb, fbb, insts, fstream)   
        self._comprehensiveDefUse = False
        if results == None:
           return set()
        else:
           return results


    # function of pc returns the result of a load for a tainted address at pc (csindex is a Read or Read MMIO type entry) and 
    # or emanating from such read (csindex is an entry type record) in a transitive way searching for a context that stores the 
    # returned value , from which the store relevant uses are found, which will ultimately passed and leveraged in identifying new 
    # taint locations
    # Note that we may need to se arch backward several callsites before we are able to find a use as sometimes the return value (r0)
    # is simply passed to the caller without storing it to a memory location
    # In summary, this function returns the uses of the return value 
    def IRfindUsesofLoadThroughReturnValue(self, trace, returnBasedTraceMap, pc, filter, lr, index, fstream=None, depth=0):
        if not index in trace.keys():
           return set() 
        print(f"Finding taints through return value pc={hex(pc)} lr={hex(lr)} index={index} depth={depth} {self.showTime()}")
        if not fstream == None:
           fstream.write(f"Finding taints through return value pc={hex(pc)} lr={hex(lr)} index={index} depth={depth}\n")
        hash = self.UtilgetHashList([pc, lr])
        if hash in self._returningFunctionTaints.keys():
           return self._returningFunctionTaints[hash]
        results = set()
        if depth > self._dynamiccallchainsearchBound:
           self._returningFunctionTaints[hash] = results
           return results
        callee, si1, ei1, bbs1, insts1, retbb1 = self.DyngetSegment(trace, index, False)
        callerreta, caller_filter, caller_bbts, csindex, caller, implicit_call = self.DyngetReturnAddress(trace, index, fstream)
        print(f"Return address 1: {csindex}, {caller.name} lr {hex(callerreta)} {self.showTime()}")
        if not fstream == None:
           fstream.write(f"Return address 1: {csindex}, {caller.name} lr {hex(callerreta)}\n")
        if caller == None or csindex == None:
           self._returningFunctionTaints[hash] = results
           print(f"Could not find callers of index {index}")
           #sys.stdin.read(1)
           return results
        loadpc1 = pc
        cbb1 = None
        res1 = self.DyngetReturnValueUsesForSegment(returnBasedTraceMap, callee, si1, ei1, bbs1, insts1, retbb1, cbb1, loadpc1, fstream)
        for r in res1:
            results.add(r)
        if retbb1 == None:
           print(f"Segment 1: {callee.name} [{si1}-{ei1}] return bb NONE num return value uses={len(res1)} {self.showTime()}")
        else:
           print(f"Segment 1: {callee.name} [{si1}-{ei1}] return bb {hex(retbb1)} num return value uses={len(res1)} {self.showTime()}")
        #sys.stdin.read(1)
        tempf, si2, ei2, bbs2, insts2, retbb2 = self.DyngetSegment(trace, csindex, False)
        if tempf == None:
           print(f"Could not find return function for {csindex}")
           self._returningFunctionTaints[hash] = results
           return results
        cbbs = set()
        ecbbt = self.IRfindExplicitCalleeBBs(caller, callee)
        for et in ecbbt:
            cbbs.add(et[1])
        icbbt = self.IRfindImplicitCalleeBBs(caller)
        for it in icbbt:
            cbbs.add(it[1])
        #cbb2 = self.IRgetBBForAddress(caller, callerreta)
        for cbb2 in cbbs:
           res2 = self.DyngetReturnValueUsesForSegment(returnBasedTraceMap, caller, si2, ei2, bbs2, insts2, retbb2, cbb2, None, fstream)
           for r in res2:
               results.add(r) 
           if retbb2 == None:
              print(f"Segment 2: {tempf.name} [{si2}-{ei2}] return bb NONE num return value uses={len(res2)} {self.showTime()}")
           else:
              print(f"Segment 2: {tempf.name} [{si2}-{ei2}] return bb {hex(retbb2)} num return value uses={len(res2)} {self.showTime()}")
        #sys.stdin.read(1)
        if len(cbbs) == 0:
           print(f"Could not find callsite bbs for callee {callee.name} from {caller.name} {self.showTime()}")
           #sys.stdin.read(1)
        callerreta2, caller_filter2, caller_bbts2, csindex2, caller2, implicit_call2 = self.DyngetReturnAddress(trace, csindex, fstream)
        if caller2 == None or csindex2 == None:
           print(f"Could not find return address for {csindex} {self.showTime()}")
           self._returningFunctionTaints[hash] = results
           return results
        print(f"Return address 3: {csindex2}, {caller2.name} lr {hex(callerreta2)} {self.showTime()}")
        tempf2, si3, ei3, bbs3, insts3, retbb3 = self.DyngetSegment(trace, csindex2, True)
        if tempf2 == None:
           print(f"Could not find return function for {csindex2} {self.showTime()}")
           self._returningFunctionTaints[hash] = results
           return results
        cbb3 = self.IRgetBBForAddress(tempf2, callerreta2)
        if not cbb3 == None:
           res3 = self.DyngetReturnValueUsesForSegment(returnBasedTraceMap, tempf2, si3, ei3, bbs3, insts3, retbb3, cbb3, None, fstream)
           for r in res3:
               results.add(r)
           if retbb3 == None:
              print(f"Segment 3: {tempf2.name} [{si3}-{ei3}] return bb NONE num return value uses={len(res3)} {self.showTime()}")
           else:
              print(f"Segment 3: {tempf2.name} [{si3}-{ei3}] return bb {hex(retbb3)} num return value uses={len(res3)} {self.showTime()}")
           #sys.stdin.read(1)
        else:
           print(f"Could not find bb in {tempf2.name} for {hex(callerreta2)} {self.showTime()}") 
           #sys.stdin.read(1)
           #bbs = set()
           #succset = set()      
           #ecbbt = self.IRfindExplicitCalleeBBs(caller, callee)
           #icbbt = self.IRfindImplicitCalleeBBs(caller)
           #for et in ecbbt:
           #    bbs.add(et[1])
           #    st = self.IRfindAllSuccsInFunction(caller, et[2].addr, et[1])
           #    for s in st:
           #        succset.add(s)
           #for it in icbbt:
           #    bbs.add(it[1])    
           #    st = self.IRfindAllSuccsInFunction(caller, it[2], it[1])
           #    for s in st:
           #        succset.add(s)
           #sys.stdin.read(1) 
        res4 = self.IRfindUsesofLoadThroughReturnValue(trace, returnBasedTraceMap, trace[csindex][1], caller_filter2, trace[csindex][2], csindex, fstream, depth + 1)
        for r in res4:
            results.add(r)
        print(f"Number of return values from recursive step={len(res4)} {self.showTime()}")
        self._returningFunctionTaints[hash] = results
        print(f"Total number of return value uses found at {index}={len(results)} {self.showTime()}")
        #sys.stdin.read(1)
        return results 


    def IRFindDataFlowsUsingTraceInfoForLastInstanceMMIOAccessAtPC(self, tracecallchain, maxIndex, oneHopTaint, pc, returnValue=False, fstream=None, mostRecentSID=True):
        i = maxIndex
        while i >= 0:
              if i in tracecallchain.keys():
                 tuple = tracecallchain[i]
                 if tuple[0] == 'readMMIO':
                    print(f"Candidate MMIO access of {hex(tuple[1])} at {hex(tuple[3])} vs {hex(pc)}")
                    if tuple[3] == pc:
                       break   
              i -= 1 
        print(f"Selected MMIO index {i}") 
        return self.IRFindDataFlowsUsingTraceInfo(tracecallchain, maxIndex, oneHopTaint, returnValue, fstream, mostRecentSID, i)


    def DyngetCallsiteForReturnAddress(self, trace, calleeaddr, returnaddr, targetFunc, endindex):
        seen = False
        index = endindex
        while index >= 0:
              if index in trace.keys():
                 tuple = trace[index]
                 if tuple[0] == 'enter':
                    lastfunc = self.IRgetFunctionAtAddress(tuple[1])
                    if lastfunc == None:
                       lastfunc = self.IRgetFunctionOfInstruction(tuple[1])
                       if lastfunc == None:
                          print(f"Undefined func for {hex(tuple[1])}") 
                    if not seen: 
                       if not lastfunc == None and lastfunc.addr == calleeaddr and tuple[2] == returnaddr:
                          seen = True
                          #print(f"Seen calleeaddr {hex(calleeaddr)} returnaddr {hex(returnaddr)} at index {index}")
                 if seen and tuple[0] == 'basicblock':
                    if tuple[1] == 0:
                       f = self.IRgetFunctionOfInstruction(tuple[2])
                       addr = tuple[2]
                       #print(f"function of bb {hex(tuple[2])} none? {f == None}")
                    else:
                       f = self.IRgetFunctionOfInstruction(tuple[1])
                       addr = tuple[1]
                       #print(f"function of bb {hex(tuple[1])} none? {f == None}")
                    if not f == None and f.addr == targetFunc.addr:
                       return addr
              index -= 1
        print(f"Not Seen calleeaddr {hex(calleeaddr)} returnaddr {hex(returnaddr)} targetFunc {targetFunc.name} starting at index {endindex}")
        return None
 
    def DyngetTopCallerInfo(self, str):
        al = str.split(':')    
        index = len(al) - 1
        while index >= 0:
              if al[index]:
                 l2 = al[index].split(',')
                 if len(l2) == 2:
                    return l2[0], l2[1]
              index -= 1
        return None, None

    def DyngetTopCallerCalleeInfo(self, str):
        calleeaddr = None
        calleraddr = None
        returnaddr = None
        al = str.split(':')    
        index = len(al) - 1
        while index >= 0:
              if al[index]:
                 l2 = al[index].split(',')
                 if len(l2) == 2:
                    if calleraddr == None:
                       calleraddr, returnaddr = l2[0], l2[1]
                    else:
                       calleeaddr = l2[0]
                       break   
              index -= 1
        return calleeaddr, calleraddr, returnaddr

    def DyngetBottomCallerCalleeInfo(self, str):
        calleeaddr = None
        calleraddr = None
        returnaddr = None
        al = str.split(':')    
        index = 0
        while index < len(al) - 1:
              if al[index]:
                 l2 = al[index].split(',')
                 if len(l2) == 2:
                    if calleeaddr == None:
                       calleeaddr = l2[0]
                    else:
                       calleraddr, returnaddr = l2[0], l2[1]
                       break   
              index += 1
        return calleeaddr, calleraddr, returnaddr


    def DynfindCallingContextsForIndex(self, trace, maxindex, endindex, depthBound, fstream=None):
        str, nstr = self.DynfindCallChain(trace, endindex, maxindex, depthBound, fstream=None)
        while True:
              calleestr, callerstr, rastr = self.DyngetBottomCallerCalleeInfo(str)
              if calleestr == None or callerstr == None or rastr == None:
                 break
              #print(f"str: {str} nstr: {nstr} callee: {calleestr} callerstr: {callerstr} rastr: {rastr}")
              callee = int(calleestr, 16)
              ra = int(rastr, 16)
              caller = self.IRgetFunctionOfInstruction(ra)
              if not caller == None: 
                 ep = self.DyngetCallsiteForReturnAddress(trace, callee, ra, caller, endindex)
                 if not ep == None:
                    return ep
              i1 = str.rfind(':')
              #print(f"cut index {i1}")
              if i1 > 1:
                 str = str[:i1]
              else:
                 break   
        return None

    def DyngetReadLocsForAddress(self, accesslist, targetaddr, maxindex):
        result = set()
        for tuple in accesslist:
            index = tuple[0]
            pc = tuple[1]
            addr = tuple[2]
            if index <= maxindex and targetaddr == addr:
               result.add(pc)
        return result       
       

    def DynfindTaintedAddressesUpToIndex(self, taintlist, readtaintlist, maxindex):
        tainted = set()
        for tuple in taintlist:
            index = tuple[0]
            pc = tuple[1]
            addr = tuple[2]
            if index <= maxindex:
               locs = self.DyngetReadLocsForAddress(readtaintlist, addr, maxindex)
               if len(locs) == 0:
                   tainted.add((addr, 0x0))
               else: 
                   for loc in locs:
                       tainted.add((addr, loc))
        return tainted        

    def DynfindCallingContextsForTaintPropagatingCopyFunctionsAcrossTraces(self, tracemap, depthBound, fstream=None):
        for key, tuple in tracemap.items():
            print(f"Size of taint list {len(tuple[1])}, return based taint map size {len(tuple[2])} read tainted list {len(tuple[3])}")
            self.DynfindCallingContextsForTaintPropagatingCopyFunctions(tuple[0], tuple[1], tuple[3], tuple[4], depthBound, fstream)

    def DynfindCallingContextsForTaintPropagatingCopyFunctions(self, trace, taintlist, readtaintlist, maxindex, depthBound, fstream=None):
        print(f"Dynamic calling contexts\n")
        copyFuncs = self.IRfindCopyFunctions(['r1','r2'], 'add', 1)
        if fstream:
           fstream.write(f"Copy functions:\n")
           for cfn, cfa, cfs in self._copyfunctions:
               fstream.write(f"{cfn},{hex(cfa)},{cfs}\n") 
        cfas = set()
        for cfn, cfa, cfs in copyFuncs:
            print(f"\tCopy function: {cfn} {hex(cfa)}")
            cfas.add(cfa)
        maxindex = 0
        uniqueeps = set()
        epscfa = set()
        for tuple in taintlist:
            index = tuple[0]
            pc = tuple[1]
            addr = tuple[2]
            caller = self.IRgetFunctionOfInstruction(pc)
            if caller == None:
               caller = self.IRgetFunctionAtAddress(pc)  
               if caller == None:
                  continue 
            if caller.addr in cfas:
               ep = self.DynfindCallingContextsForIndex(trace, maxindex, index, depthBound, fstream)
               if not ep == None:  
                  epscfa.add((ep, caller.name))
                  uniqueeps.add(ep)
               if index > maxindex:
                  maxindex = index
        epsrf = set()
        for tuple in readtaintlist:
            index = tuple[0]
            pc = tuple[1]
            addr = tuple[2]
            caller = self.IRgetFunctionOfInstruction(pc)
            if caller == None:
               caller = self.IRgetFunctionAtAddress(pc)  
               if caller == None:
                  continue 
            ep = self.DynfindCallingContextsForIndex(trace, maxindex, index, depthBound, fstream) 
            if not ep == None:  
               epsrf.add((ep, caller.name))
               uniqueeps.add(ep)
            if index > maxindex:
               maxindex = index
        tainted = self.DynfindTaintedAddressesUpToIndex(taintlist, readtaintlist, maxindex) 
        if fstream:
           fstream.write(f"Copy functions:\n")
           for cfn, cfa, cfs in self._copyfunctions:
               fstream.write(f"{cfn},{hex(cfa)},{cfs}\n") 
        tstr = "" 
        for ta, loc in tainted:
            tstr += hex(ta) + "," + hex(loc) + " "
        print(f"Found {len(epscfa)} entry points leading to a tainting copy functions, {len(epsrf)} entry points leading to taint reading functions up to depth {depthBound} with {len(tainted)} tainted addresses")
        if fstream:
           fstream.write(f"Found {len(epscfa)} entry points leading to a tainting copy functions, {len(epsrf)} entry points leading to taint reading functions up to depth {depthBound} with {len(tainted)} tainted addresses\n")
        print(f"Tainted addresses: {tstr}")
        if fstream:
           fstream.write(f"Tainted addresses: {tstr}\n")
        print(f"Entry points leading to tainting copy functions:")
        if fstream:
           fstream.write(f"Entry points leading to tainting copy functions:\n")
        for ep in epscfa:
            print(f"[TAINTING COPY FUNCTION ENTRY POINT]: {hex(ep[0])} leading to {ep[1]}")
            if fstream:
               fstream.write(f"[TAINTING COPY FUNCTION ENTRY POINT]: {hex(ep[0])} leading to {ep[1]}\n")
        print(f"Entry points leading to tainted reads:\n")
        if fstream:
           fstream.write(f"Entry points leading to tainted reads:\n")
        for ep in epsrf:
            print(f"[TAINTED READING ENTRY POINT]: {hex(ep[0])} leading to {ep[1]}")
            if fstream:
               fstream.write(f"[TAINTED READING ENTRY POINT]: {hex(ep[0])} leading to {ep[1]}\n")
        for ep in uniqueeps:
            print(f"[UNIQUE ENTRY POINT]: {hex(ep)}")
            if fstream:
               fstream.write(f"[UNIQUE ENTRY POINT]: {hex(ep)}\n")
            

    # a dictionary of MMIO read propagations, mapping each propagation session to the propagation
    # session id -> [(source_addr,source_data,dest_addr, dest_data, pc),...]
    # The goal is to capture global sinks
    def IRFindDataFlowsUsingTraceInfo(self, tracecallchain, maxIndex, oneHopTaint, returnValue=False, fstream=None, mostRecentSID=True, startIndex=0):
        self._comprehensiveDefUse = True
        copyFuncs = self.IRfindCopyFunctions(['r1','r2'], 'add', 1)
        cfas = set()
        print(f"Using copy functions:")
        if fstream:
           fstream.write(f"[IRFindDataFlowsUsingTraceInfo] Using return value tracking? {returnValue}\nUsing copy functions:\n")
        for cfn, cfa, cfs in copyFuncs:
            cf = self.IRgetFunctionAtAddress(cfa)
            print(f"\tCopy function: {cf.name} {hex(cf.addr)}")
            if fstream:
               fstream.write(f"\tCopy function: {cf.name} {hex(cf.addr)}\n")
            cfas.add(cfa)
        # track flow of mmio data register reads
        lastfunc = None
        lastEnterPc = 0
        # different MMIO reads may propagate in a different way
        # By storing the memory addresses specific to a session of MMIO read
        # we can avoid assuming a specific timing period for the propagation
        # For memory addresses that get tainted in more than one session, 
        # we should assume the most recent one the memory appears
        lastSessionId = 0
        dependencyMap = {}
        useMap = {}
        taintedAddressesMap = {}
        argLoads = {}
        pointsTo = {}
        mmioLoads = set()
        lastRead = -1
        lastReadTuple = None
        index = 0
        callchain = []
        taintList = []
        readtaintList = []
        returnBasedTaintMap = {}
        # record those that do not have return value uses to avoid computing at similar trace segments
        noreturnValueUses = set()
        #inisr = False
        while index < maxIndex:
              if index in tracecallchain.keys():
                 tuple = tracecallchain[index]                  
                 #if tuple[0] == 'enter' and tuple[2] >= self._minRAM:
                 #   inisr = True 
                 if tuple[0] == 'enter': 
                    # todo: check if legit text address
                    lastEnterPc = tuple[1]
                    lastfunc = self.IRgetFunctionAtAddress(lastEnterPc)
                    callchain.append((tuple[1],tuple[2], index))
                 if tuple[0] == 'basicblock' and tuple[1] == 0:
                    nomatch = True
                    # for some functions return indicator may not exist in the trace, so this is a best effort approach
                    temp = []
                    while len(callchain) > 0:
                          lastTuple = callchain.pop()
                          if tuple[2] == lastTuple[1]:
                             nomatch = False
                             break
                          else:
                             temp.append(lastTuple)
                    while len(temp) > 0:
                          lt = temp.pop()
                          callchain.append(lt)   
                    if nomatch:
                       print(f"[WARNING] Broken callchain at index {index}: returning to {hex(tuple[2])}") 
                    #   return
                 #if tuple[0] == 'basicblock' and tuple[1] == 0 and tuple[2] >= self._minRAM:
                 #   inisr = False
                 # selective taint tracking, e.g., track taint propagation from the last MMIO access 
                 if tuple[0] == 'readMMIO' and (startIndex == 0 or index == startIndex):
                    mmioLoads.add(tuple[1])
                    dependencyMap[lastSessionId] = []
                    ta = set()
                    ta.add((tuple[1],tuple[2], tuple[3]))
                    taintedAddressesMap[lastSessionId] = ta
                    useMap[lastSessionId] = set()
                    uses = self.IRfindUsesofLoadWithPC(tuple[3])
                    print(f"[READ MMIO, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])} {self.showTime()}")
                    if not fstream == None:
                       fstream.write(f"[READ MMIO, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])} {self.showTime()}\n")
                    for use, pc in uses:
                        useMap[lastSessionId].add((tuple, pc))
                        print(f"[USE, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)}")
                        if not fstream == None:
                           fstream.write(f"[USE, index: {index}]  of load from {hex(tuple[1])} at pc {hex(pc)}\n")
                    if len(uses) == 0:
                       print(f"\tindex: {index} NO USES of MMIO read addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])}") 
                       if not fstream == None:
                          fstream.write(f"\tindex: {index} NO USES of MMIO read addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])}\n")
                       # check if the read MMIO data register flows as a return value, i.e., to reg r0, and
                       # whether the callsite r0 flows into a store and record the use in the usemap
                       # find r0 defs from return cfgnodes using IRgetRegDefiningNode
                       # find defs for the data part of r0 defs
                       # filter those that load from this read pc
                       # if any then find the use of r0 based on lr and update useMap
                       # this must be repeated for multi hop taint tracking
                    lastEnterLr, filter, caller_bbts, csindex, callerf, implicit_call = self.DyngetReturnAddress(tracecallchain, index, fstream)
                    if returnValue and not tuple[3] in noreturnValueUses:
                       fs, start_index, end_index, bbts, insts, retbb = self.DyngetSegment(tracecallchain, index, False)
                       if not lastEnterLr == None and self.IRcheckFlowOfReadIntoReturnValueRegister(tracecallchain, index, insts):
                          if not tuple[3] in noreturnValueUses:
                             uses = self.IRfindUsesofLoadThroughReturnValue(tracecallchain, returnBasedTaintMap, tuple[3], filter, lastEnterLr, index, fstream) 
                             for use, pc in uses:
                                 useMap[lastSessionId].add((tuple, pc))
                                 print(f"[USE through return value, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)} {self.showTime()}")
                                 if not fstream == None:
                                    fstream.write(f"[USE through return value, index: {index}]  of load from {hex(tuple[1])} at pc {hex(pc)} {self.showTime()}\n")
                                 #sys.stdin.read(1)
                             if len(uses) == 0:
                                noreturnValueUses.add(tuple[3])
                             del uses
                       elif not lastEnterLr == None:
                            noreturnValueUses.add(tuple[3])                               
                    f = self.IRgetFunctionOfInstruction(tuple[3]) 
                    #self.DynupdateArgLoads(tracecallchain, argLoads, f, pointsTo, index)             
                    lastSessionId += 1
                 # handle if we want to track indirect taints as well
                 if tuple[0] == 'read' and not oneHopTaint:
                    lastRead = index
                    lastReadTuple = tuple
                    #print(f"Processing read last {lastSessionId} index: {index} addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])}")
                    if mostRecentSID:
                       sid = self.DYNfindSIDForReadAddress(taintedAddressesMap, lastSessionId, tuple)
                       if not sid == None:
                          readtaintList.append((index, tuple[3], tuple[1]))
                          print(f"[READ TAINTED, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])} {self.showTime()}")
                          if not fstream == None:                       
                             fstream.write(f"[READ TAINTED, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])} {self.showTime()}\n")
                          uses = self.IRfindUsesofLoadWithPC(tuple[3])
                          for use, pc in uses:
                              useMap[sid].add((tuple,pc))
                              print(f"[USE, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)}")
                              if not fstream == None:                       
                                 fstream.write(f"[USE, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)}\n")
                          if len(uses) == 0:
                             print(f"\tindex: {index} NO USES of read from tainted addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])}") 
                             if not fstream == None:                       
                                fstream.write(f"\tindex: {index} NO USES of read from tainted addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])}\n") 
                          del uses
                          lastEnterLr, filter, caller_bbts, csindex, callerf, implicit_call = self.DyngetReturnAddress(tracecallchain, index, fstream)
                          if returnValue and not tuple[3] in noreturnValueUses:
                             fs, start_index, end_index, bbts, insts, retbb = self.DyngetSegment(tracecallchain, index, False)
                             if not lastEnterLr == None and self.IRcheckFlowOfReadIntoReturnValueRegister(tracecallchain, index, insts):
                                if not tuple[3] in noreturnValueUses:
                                   uses = self.IRfindUsesofLoadThroughReturnValue(tracecallchain, returnBasedTaintMap, tuple[3], filter, lastEnterLr, index, fstream) 
                                   for use, pc in uses:
                                       useMap[sid].add((tuple, pc))
                                       print(f"[USE through return value, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)} {self.showTime()}")
                                       if not fstream == None:
                                          fstream.write(f"[USE through return value, index: {index}]  of load from {hex(tuple[1])} at pc {hex(pc)} {self.showTime()}\n")
                                   #sys.stdin.read(1)
                                   if len(uses) == 0:
                                      noreturnValueUses.add(tuple[3])
                                   del uses
                             elif not lastEnterLr == None:
                                  noreturnValueUses.add(tuple[3])                               
                    else:
                       sids = self.DYNfindAllSIDsForReadAddress(taintedAddressesMap, lastSessionId, tuple)
                       for sid in sids:
                           readtaintList.append((index, tuple[3], tuple[1]))
                           print(f"[READ TAINTED, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])} {self.showTime()}")
                           if not fstream == None:                       
                              fstream.write(f"[READ TAINTED, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])} {self.showTime()}\n")
                           uses = self.IRfindUsesofLoadWithPC(tuple[3])
                           for use, pc in uses:
                               useMap[sid].add((tuple,pc))
                               print(f"[USE, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)}")
                               if not fstream == None:                       
                                  fstream.write(f"[USE, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)}\n")
                           if len(uses) == 0:
                              print(f"\tindex: {index} NO USES of read from tainted addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])}") 
                              if not fstream == None:                       
                                 fstream.write(f"\tindex: {index} NO USES of read from tainted addr {hex(tuple[1])} value {hex(tuple[2])} pc {hex(tuple[3])}\n") 
                           del uses
                           lastEnterLr, filter, caller_bbts, csindex, callerf, implicit_call = self.DyngetReturnAddress(tracecallchain, index, fstream)
                           if returnValue and not tuple[3] in noreturnValueUses:
                              fs, start_index, end_index, bbts, insts, retbb = self.DyngetSegment(tracecallchain, index, False)
                              if not lastEnterLr == None and self.IRcheckFlowOfReadIntoReturnValueRegister(tracecallchain, index, insts):
                                 if not tuple[3] in noreturnValueUses:
                                    uses = self.IRfindUsesofLoadThroughReturnValue(tracecallchain, returnBasedTaintMap, tuple[3], filter, lastEnterLr, index, fstream) 
                                    for use, pc in uses:
                                        useMap[sid].add((tuple, pc))
                                        print(f"[USE through return value, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)} {self.showTime()}")
                                        if not fstream == None:
                                           fstream.write(f"[USE through return value, index: {index}]  of load from {hex(tuple[1])} at pc {hex(pc)} {self.showTime()}\n")
                                    #sys.stdin.read(1)
                                    if len(uses) == 0:
                                       noreturnValueUses.add(tuple[3])
                                    del uses
                                 elif not lastEnterLr == None:
                                      noreturnValueUses.add(tuple[3])                               
                 if tuple[0] == 'write':
                    # check if the tainted value is returned by the current function without any loads
                    # in case no read tainted event is issued for this
                    if mostRecentSID:
                       sid, usetuple = self.DYNfindSIDForUse(useMap, lastSessionId, tuple)
                       if not sid == None:
                           dependencyMap[sid].append((usetuple[1], usetuple[2], tuple[1], tuple[2], usetuple[1]))
                           taintedAddressesMap[sid].add((tuple[1],tuple[2], tuple[3])) 
                           print(f"[TAINT, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} from addr {hex(usetuple[1])} orig value {hex(usetuple[2])} pc {hex(tuple[3])} {self.showTime()}")
                           if not fstream == None:                       
                              fstream.write(f"[TAINT, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} from addr {hex(usetuple[1])} orig value {hex(usetuple[2])} pc {hex(tuple[3])} {self.showTime()}\n")
                           taintList.append((index, tuple[3], tuple[1])) 
                           lastEnterLr, filter, caller_bbts, csindex, callerf, implicit_call = self.DyngetReturnAddress(tracecallchain, index, fstream)
                           print(f"START check return value flow through store for {index}")
                           if returnValue and not tuple[3] in noreturnValueUses:
                              fs, start_index, end_index, bbts, insts, retbb = self.DyngetSegment(tracecallchain, index, False)
                              if not lastEnterLr == None and self.IRcheckFlowOfStoredDataIntoReturnValueRegister(returnBasedTaintMap, tracecallchain, index, fstream, insts):
                                 if not tuple[3] in noreturnValueUses:
                                    uses = self.IRfindUsesofLoadThroughReturnValue(tracecallchain, returnBasedTaintMap, tuple[3], filter, lastEnterLr, index, fstream) 
                                    for use, pc in uses:
                                        useMap[sid].add((tuple, pc))
                                        print(f"[USE (of write) through return value, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)}")
                                        if not fstream == None:
                                           fstream.write(f"[USE (of write) through return value, index: {index}]  of load from {hex(tuple[1])} at pc {hex(pc)}\n")     
                                    if len(uses) == 0:
                                       noreturnValueUses.add(tuple[3])
                                    del uses
                              elif not lastEnterLr == None:
                                   noreturnValueUses.add(tuple[3])                               
                           else: 
                               print(f"Stored data not flowing through retirn value")                        
                               #sys.stdin.read(1)
                           print(f"END check return value flow through store for {index}")
                       if not lastfunc == None and lastfunc.addr in cfas:
                          #print(f"Copy function detected: {hex(lastfunc.addr)} lastRead {lastRead} index {index} lasst raed value {lastReadTuple[2]} vs {tuple[2]}")
                          if lastRead == index - 1 and lastReadTuple[2] == tuple[2]:
                             sid = self.DYNfindSIDForReadAddress(taintedAddressesMap, lastSessionId, lastReadTuple)
                             if not sid == None:
                                dependencyMap[sid].append((lastReadTuple[1], lastReadTuple[2], tuple[1], tuple[2], tuple[3]))
                                taintedAddressesMap[sid].add((tuple[1],tuple[2], tuple[3])) 
                                print(f"[TAINT VIA COPY, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} from addr {hex(lastReadTuple[1])} orig value {hex(lastReadTuple[2])} pc {hex(tuple[3])} {self.showTime()}")
                                if not fstream == None:                       
                                   fstream.write(f"[TAINT VIA COPY, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} from addr {hex(lastReadTuple[1])} orig value {hex(lastReadTuple[2])} pc {hex(tuple[3])} {self.showTime()}\n")
                                taintList.append((index, tuple[3], tuple[1])) 
                                lastEnterLr, filter, caller_bbts, csindex, callerf, implicit_call = self.DyngetReturnAddress(tracecallchain, index, fstream)
                                if returnValue:
                                   fs, start_index, end_index, bbts, insts, retbb = self.DyngetSegment(tracecallchain, index, False)
                                   if not lastEnterLr == None and self.IRcheckFlowOfStoredDataIntoReturnValueRegister(returnBasedTaintMap, tracecallchain, index, fstream, insts):
                                      if not tuple[3] in noreturnValueUses:
                                         uses = self.IRfindUsesofLoadThroughReturnValue(tracecallchain, returnBasedTaintMap, tuple[3], filter, lastEnterLr, index, fstream) 
                                         for use, pc in uses:
                                             useMap[sid].add((tuple, pc))
                                             print(f"[USE (of write) through return value, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)} {self.showTime()}")
                                             if not fstream == None:
                                                fstream.write(f"[USE t(of write) hrough return value, index: {index}]  of load from {hex(tuple[1])} at pc {hex(pc)} {self.showTime()}\n")                              
                                         if len(uses) == 0:
                                            noreturnValueUses.add(tuple[3])
                                         del uses
                                   elif not lastEnterLr == None:
                                        noreturnValueUses.add(tuple[3])                               
                                else:                         
                                     print(f"Stored data not flowing through retirn value")
                                     #sys.stdin.read(1)
                                print(f"END check return value flow through store for {index}")
                    else:
                       sids = self.DYNfindAllSIDsForUse(useMap, lastSessionId, tuple)
                       for sid, usetuple in sids:
                           dependencyMap[sid].append((usetuple[1], usetuple[2], tuple[1], tuple[2], usetuple[1]))
                           taintedAddressesMap[sid].add((tuple[1],tuple[2], tuple[3])) 
                           print(f"[TAINT, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} from addr {hex(usetuple[1])} orig value {hex(usetuple[2])} pc {hex(tuple[3])} {self.showTime()}")
                           if not fstream == None:                       
                              fstream.write(f"[TAINT, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} from addr {hex(usetuple[1])} orig value {hex(usetuple[2])} pc {hex(tuple[3])} {self.showTime()}\n")
                           taintList.append((index, tuple[3], tuple[1])) 
                           lastEnterLr, filter, caller_bbts, csindex, callerf, implicit_call = self.DyngetReturnAddress(tracecallchain, index, fstream)
                           print(f"START check return value flow through store for {index}")
                           if returnValue and not tuple[3] in noreturnValueUses:
                              fs, start_index, end_index, bbts, insts, retbb = self.DyngetSegment(tracecallchain, index, False)
                              if not lastEnterLr == None and self.IRcheckFlowOfStoredDataIntoReturnValueRegister(returnBasedTaintMap, tracecallchain, index, fstream, insts):
                                 if not tuple[3] in noreturnValueUses:
                                    uses = self.IRfindUsesofLoadThroughReturnValue(tracecallchain, returnBasedTaintMap, tuple[3], filter, lastEnterLr, index, fstream) 
                                    for use, pc in uses:
                                        useMap[sid].add((tuple, pc))
                                        print(f"[USE (of write) through return value, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)}")
                                        if not fstream == None:
                                           fstream.write(f"[USE (of write) through return value, index: {index}]  of load from {hex(tuple[1])} at pc {hex(pc)}\n")                              
                                    if len(uses) == 0:
                                       noreturnValueUses.add(tuple[3])
                                    del uses
                              elif not lastEnterLr == None:
                                   noreturnValueUses.add(tuple[3])                               
                           else:                         
                                print(f"Stored data not flowing through retirn value")
                                #sys.stdin.read(1)
                           print(f"END check return value flow through store for {index}")
                       if not lastfunc == None and lastfunc.addr in cfas:
                          #print(f"Copy function detected: {hex(lastfunc.addr)} lastRead {lastRead} index {index} lasst raed value {lastReadTuple[2]} vs {tuple[2]}")
                          if lastRead == index - 1 and lastReadTuple[2] == tuple[2]:
                             sids = self.DYNfindAllSIDsForReadAddress(taintedAddressesMap, lastSessionId, lastReadTuple)
                             for sid in sids:
                                 dependencyMap[sid].append((lastReadTuple[1], lastReadTuple[2], tuple[1], tuple[2], tuple[3]))
                                 taintedAddressesMap[sid].add((tuple[1],tuple[2], tuple[3])) 
                                 print(f"[TAINT VIA COPY, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} from addr {hex(lastReadTuple[1])} orig value {hex(lastReadTuple[2])} pc {hex(tuple[3])} {self.showTime()}")
                                 if not fstream == None:                       
                                    fstream.write(f"[TAINT VIA COPY, index: {index}] addr {hex(tuple[1])} value {hex(tuple[2])} from addr {hex(lastReadTuple[1])} orig value {hex(lastReadTuple[2])} pc {hex(tuple[3])} {self.showTime()}\n")
                                 taintList.append((index, tuple[3], tuple[1])) 
                                 lastEnterLr, filter, caller_bbts, csindex, callerf, implicit_call = self.DyngetReturnAddress(tracecallchain, index, fstream)
                                 if returnValue and not tuple[3] in noreturnValueUses:
                                    fs, start_index, end_index, bbts, insts, retbb = self.DyngetSegment(tracecallchain, index, False)
                                    if not lastEnterLr == None and self.IRcheckFlowOfStoredDataIntoReturnValueRegister(returnBasedTaintMap, tracecallchain, index, fstream, insts):
                                       if not tuple[3] in noreturnValueUses:
                                          uses = self.IRfindUsesofLoadThroughReturnValue(tracecallchain, returnBasedTaintMap, tuple[3], filter, lastEnterLr, index, fstream) 
                                          for use, pc in uses:
                                              useMap[sid].add((tuple, pc))
                                              print(f"[USE (of write) through return value, index: {index}] of load from {hex(tuple[1])} at pc {hex(pc)} {self.showTime()}")
                                              if not fstream == None:
                                                 fstream.write(f"[USE (of write) through return value, index: {index}]  of load from {hex(tuple[1])} at pc {hex(pc)} {self.showTime()}\n")                              
                                          if len(uses) == 0:
                                             noreturnValueUses.add(tuple[3])
                                          del uses
                                    elif not lastEnterLr == None:
                                         noreturnValueUses.add(tuple[3])                               
                                 else:                         
                                      print(f"Stored data not flowing through retirn value")
                                      #sys.stdin.read(1)
              index += 1
        self._comprehensiveDefUse = False
        return taintList, returnBasedTaintMap, readtaintList
                         

    def IRfindCallsiteBBsForReturnAddress(self, retaddr, filter=None):
        csbbs = set() 
        caller = self.IRgetFunctionOfInstruction(retaddr)
        if caller == None:
           print(f"WARNING: Could not find function for return address {hex(retaddr)}")
           return csbbs
        retbb = None
        for ba in caller.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            index = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.IMark):
                     if st.addr == retaddr or st.addr + 1 == retaddr or st.addr == retaddr + 1:
                        retbb = bb
                        break    
                  index += 1
            if not retbb == None:
               break
        print(f"Caller {caller.name} retbb {hex(retbb.addr)} index {index} num inst {len(retbb.vex.statements)}")
        cfgnode = self.IRfindCFGNodeForStatement(caller, retbb, index)
        tbb, cmin, cmax = self.IRgetStatementIndexRangeForCFGNode(caller, cfgnode)
        preds = self.IRfindImmediatePredsInFunction(caller, cfgnode, retbb, filter)
        print(f"preds of {hex(cfgnode.addr)}")
        #preds.add((cfgnode, retbb, cmin, cmax))
        #print(f"<<<<<<<<<<<<<< Return bb: >>>>>>>>>>>>>>>>>")
        #retbb.vex.pp()
        for predt in preds:
            pred, pbb, pmin, pmax = predt  
            #bbs = self.IRgetBBsForCFGNode(caller, pred)
            #for bb in bbs:
            if pbb.vex.jumpkind == "Ijk_Call":
               csbbs.add((caller, pbb, pred))
               #print(f"Adding pred {hex(pred.addr)} of pbb {hex(pbb.addr)}")
               #pbb.vex.pp()
            else:
               print(f"skipping bb {hex(pbb.addr)}")
        return csbbs 

    def IRfindCallsitesInFunction(self, callee, caller):
        callsites = set()
        for ba in caller.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            index = 0
            ia = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.IMark):
                     ia = st.addr 
                  index += 1
            if isinstance(bb.vex.next,pyvex.IRExpr.Const):
               if bb.vex.next.con._value == callee.addr:
                  callsites.add((caller, ia, callee))
        return callsites


    #def HALfilterTransferBuffers(self, bba, instAddr):
    def HALfilterTransferBuffers(self, dataRegOffset, halCandidates, bufferInfo, localbufferInfo, snapshotInfo, returnValueInfo, filter=None):
        #bba = 0x800a8df
        #instAddr = 0x0800a8ec
        #bba = bb.addr
        #f = self.IRgetFunctionOfBlock(bba)
        #self.IRprintBBs(f)
        #index = 0
        #min = 0
        #max = 0
        #while index < len(bb.vex.statements):
        #      st = bb.vex.statements[index]
        #      if isinstance(st, pyvex.IRStmt.IMark):
        #         if st.addr == instAddr:
        #            length = self.IRgetIMarkSize(f, bb, st)
        #            min = index + 1
        #            max = index + length
        #            break
        #      index += 1
        #print(f"min {min} max {max}")
        #index = min
        #while index <= max:
        #      st = bb.vex.statements[index]
        #      print(f"Statement {st}")
        #      index += 1
        #dregsources = self.IRgetStatementWithConstant(bb, dataRegOffset, min, max)
        subuses = set()
        for dregsource in halCandidates:
            f, t1, t2, t3, dbb, cfgnode, dindex, dsub = dregsource
            st = dbb.vex.statements[dindex]
            if not isinstance(st, pyvex.IRStmt.WrTmp):
              continue 
            #dbb.vex.pp()
            #print(f"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ GETTING uses of t{str(st.tmp)}")
            uses = self.IRgetUsesInFunction(f, cfgnode, dbb, st, dindex, "t" + str(st.tmp))
            for use in uses:
                ubba, ust, ui, un, uother, uev = use
                #print(f"USE: {hex(ubba)} statement {ust} index {ui} use {un} other {uother} {uev}")
                subuses.add(use) 
        directSources = self.HALcheckDirectSourcesForReceive(subuses)
        if len(directSources) > 0:
           actualBufferAddresses = set()
           returnValueContexts = set()
           for s in directSources:
               print(f"Receive buffer source {s}")
               sf = self.IRgetFunctionAtAddress(s[0])
               callchain = []
               ult, retval, c2 = self.IRfindArgumentsForExplicitCallsRecursive(sf, s, callchain, filter)
               for u in ult:
                   if u[0] == "global":
                      print(f"Receive ultimate buffer source {u}")
                      if u[1] < self._minRAM:
                         try:
                              value = self._project.loader.memory.load(u[1], 4)
                              actualBufferAddresses.add((value, sf))
                         except KeyError:
                              continue   
                      actualBufferAddresses.add((u[1],sf))
                   if u[0] == "stack":
                      if len(callchain) == 1:
                         print(f"Last in callchain : {callchain[-1].name} caller {sf.name}")
                         css = self.IRfindCallsitesInFunction(callchain[-1], sf)
                         for c1, ia, c2 in css:
                             localbufferInfo.add((u[1],sf,ia)) 
                      elif len(callchain) > 1:
                         print(f"Callee in callchain : {callchain[-2].name} caller {callchain[-1].name}")
                         css = self.IRfindCallsitesInFunction(callchain[-2], callchain[-1])
                         for c1, ia, c2 in css: 
                             localbufferInfo.add((u[1],callchain[-1],ia))  
                      print(f"Receive ultimate buffer source {u}")
               for ret in retval:
                   returnValueContexts.add(ret)
           print(f"Receive buffer addresses:") 
           for ab, sf in actualBufferAddresses:
               print(f"Actual buffer {ab}")
           print(f"Local buffers:")
           for loff, f, ia in localbufferInfo:
               print(f"Local buffer offset {loff} in function {f.name} address {hex(ia)}")
           self.HALFindGlobalBufferAccessLocations(actualBufferAddresses, bufferInfo, snapshotInfo)   
           print(f"Returning received value:")
           for rvc in returnValueContexts:
               print(f"{rvc.name} {hex(rvc.addr)}")
               rcs = self.IRfindCallsitesOfFunction(rvc)
               for rc in rcs:
                   returnValueInfo.add((rc[0].name,rc[0].addr,rc[1],rc[2].name,rc[2].addr))
                   print(f"In function {rc[0].name} ({hex(rc[0].addr)} at instruction {hex(rc[1])} {rc[2].name} ({hex(rc[2].addr)})")
                   callers = self.IRfindImmediateCallersWithCallsite(rc[0])
                   for ca, ba in callers:
                       cf = self.IRgetFunctionAtAddress(ca)
                       # the last one is the instruction address whose return value to be symbolized rather than the actual buffer address
                       snapshotInfo.add((cf.name, ca, ba, rc[0].name, rc[0].addr, rc[1]))
                       print(f"Caller {cf.name} {hex(ca)} of {rc[0].name} {hex(rc[0].addr)} callsite {hex(ba)} returning callsite {hex(rc[1])}")
           if len(actualBufferAddresses) > 0:
              return
        recvbufs = set()
        transbufs = set()
        print(f"Size of subuses {len(subuses)}")
        # Cluster subuses and analyze just one for each cluster
        useMap = {}
        for use in subuses:
            ubba, ust, ui, un, uother, uev = use
            anon = self.IRanonymizeEvidence(uev)
            #print(f"Anonymized evidence: {anon} for use {ust}")
            #if not anon.startswith("Add"):
            #   continue
            if not anon in useMap.keys():
               useMap[anon] = set()
            useMap[anon].add(use)
            #print(f"((((((((((((((( ANON {anon} \n {use}")
        print(f"Number of clustered uses {len(useMap)}")
        for useKey in useMap:
            if len(useMap[useKey]) == 0:
               continue
            # choose a representative
            use = None
            for u in useMap[useKey]:
                use = u
                break
            ubba, ust, ui, un, uother, uev = use
            ubb = self._project.factory.block(ubba)
            f = self.IRgetFunctionOfBlock(ubba)
            baseregset = self.IRgetBaseRegSetForFunction(f)
            ucfgnode = self.IRfindCFGNodeForStatement(f, ubb, ui)
            if ucfgnode == None:
               continue  
            print(f"^^^^^^^^^ ADDRESS SOURCES of {uother} {ust} at {hex(ucfgnode.addr)}")
            vm = {}
            ev = ""
            self._lastNode = str(uother)
            self._comprehensiveDefUse = True
            bas = self.IRfindAllSourcesofAddress(f, baseregset, ucfgnode, ubb, ust, ui, uother, vm, ev, filter)
            del vm
            self._comprehensiveDefUse = False
            if str(uother) == str(ust.addr):
               # uother is receive buf address
               for r in bas:
                   p = self.IRextractPattern(r[-1])
                   if str(uother) == "t33" or str(uother) == "t15" or p[-1] == 80 or p[-1] == 84:
                      print(f"Length of tuple {len(r)} \n{r[-1]}")
                   recvbufs.add(r)
                   if len(r) == 3:
                      print(f"Receive buf source {r[0]} {r[1]} {self.IRextractPattern(r[-1])}")
                   if len(r) == 4:
                      print(f"Receive buf source {r[0]} {r[1]} {r[2]} {self.IRextractPattern(r[-1])}")
            else:
               for t in bas:
                   transbufs.add(t)
                   if len(t) == 3:
                      print(f"Transmit buf source {t[0]} {t[1]}")
                   if len(t) == 4:
                      print(f"Transmit buf source {t[0]} {t[1]} {t[2]}")
        print(f"Receive bufs:")
        for rbuf in recvbufs:
            print(f"Receive buf {rbuf[0]} {rbuf[1]} pattern {self.IRextractPattern(rbuf[-1])}")
        print(f"Transmit bufs:")
        for tbuf in transbufs:
            print(f"Transmit buf {tbuf[0]} {tbuf[1]} pattern {self.IRextractPattern(tbuf[-1])}")
        recv_buf_patterns = set()
        recvbufassign = set()
        self.HALfindBufferAssignments(recvbufs, recv_buf_patterns, recvbufassign)
        #self.HALBufferSources(recvbufs)
        self._rxBufferFindingTime = time.time()
        print(f"Time to finding rx buffers={self._rxBufferFindingTime - self._mmioAccessContextFindingTime} secs")
        self.HALbufferAndSnapshotInfo(recvbufassign, bufferInfo, localbufferInfo, snapshotInfo)
        self._rxBufferAccessFindingTime = time.time()
        print(f"Time to finding mmio access contexts={self._rxBufferAccessFindingTime - self._rxBufferFindingTime} secs")
        #self.HALfindBufferAssignments(transbufs)                

    def HALcheckDirectSourcesForReceive(self, subuses, filter=None):
        sources = set()
        sources2 = set()
        for use in subuses:
            ubba, ust, ui, un, uother, uev = use
            # skip if this is transmit
            if str(un) == str(ust.addr):
               continue
            try:
               ubb = self._project.factory.block(ubba)
            except angr.errors.SimEngineError:
               continue
            f = self.IRgetFunctionOfBlock(ubba)
            baseregset = self.IRgetBaseRegSetForFunction(f)
            ucfgnode = self.IRfindCFGNodeForStatement(f, ubb, ui)
            vm = {}
            ev = ""
            dsrcs = self.IRfindAllSourcesofAddress(f, baseregset, ucfgnode, ubb, ust, ui, un, vm, ev, filter)
            del vm
            for dsrc in dsrcs:
                if dsrc[0] == "argument": 
                   #print(f"Direct source {dsrc}") 
                   sources.add(dsrc)
            vm2 = {}
            ev2 = ""      
            dsrcs2 = self.IRfindAllSourcesofAddress(f, baseregset, ucfgnode, ubb, ust, ui, uother, vm2, ev2, filter)
            del vm2
            for dsrc in dsrcs2:
                if dsrc[0] == "argument":
                   if any([t[1] for t in dsrcs if t[0] == "argument" and not t[1] == dsrc[1]]):
                      print(f"Direct source {dsrc}") 
                      sources2.add((f.addr, dsrc[0], dsrc[1]))
        return sources2

    def HALBoundedBufferSources(self, bufferInitialSources, globalPointers):
        results = set()
        self._comprehensiveDefUse = True
        for bu in bufferInitialSources:
            print(f"Buffer initial source {hex(bu[0])} {bu[1]} {bu[2]}")
            fa = bu[0]
            res = self.HALBoundedBufferSourcesforFunction(bu, fa, globalPointers)
            for r in res:
                print(f"Buffer source {r}")
                results.add(r)
                #if r[0] == "global":
                #   return r
        self._comprehensiveDefUse = False
        return results

    def HALBoundedBufferSourcesforFunction(self, bufferInitialSource, fa, globPtrs, depth=0, filter=None):
        results = set()
        if depth > self._callerDepth:
           return results
        f = self.IRgetFunctionAtAddress(fa)
        print(f"^^^^^^^^^^^^^^^ {f.name} {hex(bufferInitialSource[0])} {bufferInitialSource[1]} {bufferInitialSource[2]} ^^^^^^^^^^^^^^^^^")
        if bufferInitialSource[1] == "global":
           results.add(bufferInitialSource)
           return results
        results = set()
        # does it have a direct caller? If so visit that one.
        callers =  self.IRfindImmediateCallers(f)
        if len(callers) > 0:
           for ca, ctype in callers:
               indirect = (ctype == 'indirect')
               c = self.IRgetFunctionAtAddress(ca) 
               print(f"Immediate caller {c.name} type {ctype}")
               self.IRfindReturnedAddressPropagationInCaller(ca, globPtrs, filter)
               srcs = self.IRfindCallerContextCalleeArgSources(c, fa, bufferInitialSource, indirect, filter)
               if not srcs == None:
                  for src in srcs:
                      results.add(src)
                      res = self.HALBoundedBufferSourcesforFunction((c.addr,) + src, c.addr, globPtrs, depth + 1)
                      for r in res:
                          results.add(r)
        return results


    def HALBufferSourcesforFunction(self, bufferInitialSource, fa, globPtrs, filter=None):
        results = set()
        f = self.IRgetFunctionAtAddress(fa)
        print(f"^^^^^^^^^^^^^^^ {f.name} {hex(bufferInitialSource[0])} {bufferInitialSource[1]} {bufferInitialSource[2]} ^^^^^^^^^^^^^^^^^")
        if bufferInitialSource[1] == "global":
           results.add(bufferInitialSource)
           return results
        results = set()
        # does it have a direct caller? If so visit that one.
        callers =  self.IRfindImmediateCallers(f)
        if len(callers) > 0:
           for ca in callers:
               c = self.IRgetFunctionAtAddress(ca) 
               print(f"Immediate caller {c.name}")
               self.IRfindReturnedAddressPropagationInCaller(ca, globPtrs, filter)
               src = self.IRfindCallerContextCalleeArgSource(c, fa, bufferInitialSource)
               if not src == None:
                  results.add(src)
               else:   
                  res = self.HALBufferSourcesforFunction(bufferInitialSource, c.addr, globPtrs)
                  for r in res:
                      if r[0] == "global":
                         results.add(r)
                         return results   
        else:
             # otherwise use implicit references to the function address 
             # to infer relevant calling contexts 
             globalMap, storedMap, funcStoreMap = self.IRfindGlobalLoadAddresses(fa)
             for fs in funcStoreMap:
                 fms = funcStoreMap[fs]
                 for fm in fms:  
                     icfa, ba, ga, afa = fm
                     cicfa = self.IRgetFunctionAtAddress(icfa)
                     print(f"Implicit caller {cicfa.name}")                     
                     self.IRfindReturnedAddressPropagationInCaller(icfa, globPtrs, filter)
                     simp = self.IRgetCallerWithImplicitCallee(icfa, bufferInitialSource, globPtrs)
                     if not simp == None:
                        for si in simp:
                            if si[0] == "global":
                               results.add(si)
                               return results
                     else:
                        res = self.HALBufferSourcesforFunction(bufferInitialSource, icfa, globPtrs)
                        for r in res:
                            if r[0] == "global":
                               results.add(r)
                               return results
        return results    

    def HALBufferSources(self, bufferInitialSources, globalPointers):
        for bu in bufferInitialSources:
            print(f"Buffer initial source {hex(bu[0])} {bu[1]} {bu[2]}")
            fa = bu[0]
            res = self.HALBufferSourcesforFunction(bu, fa, globalPointers)
            for r in res:
                if r[0] == "global":
                   return r
        return None    

    def TESTprintBBsForFunction(self, fname):
        for f in self._current_cfg.functions.values():
            if f.name == fname:
               for ba in f.block_addrs:
                   try:
                       bb = self._project.factory.block(ba)
                   except angr.errors.SimEngineError:
                       continue
                   bb.vex.pp() 
               return    

    def TESTHALfindBufferAssignments(self):
        #pattern = ['r0', 8, 'Load', 80]
        for f in self._current_cfg.functions.values():
           if f.name == "spi_stm32_transceive":
              print(f"{f.name} {hex(f.addr)}")
        bis = set()
        #self.IRfindBufferAssignments(pattern, bis)
        bis.add((0x8005ee5,"argument", "r3"))


    def TESTHALbufferAndSnapshotInfo(self):
        bis = set()
        bis.add((0x8005ee5,'argument','r3'))
        binfo = set()
        sinfo = set()
        self.HALbufferAndSnapshotInfo(bis, binfo, sinfo)
        for b in binfo:
            print(f"buffer info {b}")
        for s in sinfo:
            print(f"snapshot info {s}")
  
    def HALbufferAndSnapshotInfo(self, bis, bufferInfo, localbufferInfo, snapshotInfo, filter=None):
        globalPointers = set()
        loadAddresses = set()
        bs = self.HALBoundedBufferSources(bis, globalPointers)
        for b in bs:
            print(f"Buffer sources {b}")
            if b[1] == "global":
               f = self.IRgetFunctionAtAddress(b[0])
               loadAddresses.add((b[2],f.name, f.addr))
            if b[0] == "global":
               loadAddresses.add((b[1], "", 0))
        directAccesses, indirectAccesses = self.IRfindAddressLoadLocations(loadAddresses, filter)
        print(f"Direct load buffer accesses:")
        for da in directAccesses:
            print(f"Buffer direct load access in {da[0].name} bb {hex(da[1].addr)} instruction {hex(da[2])} buffer at {hex(da[3])}")
            #faddrs.add(da[0].addr)
            bufferInfo.add((da[0].name,da[0].addr,da[1].addr,da[2],da[3]))
        print(f"Indirect load buffer accesses:")
        for da in indirectAccesses:
            print(f"Buffer indirect load access in {da[0].name} bb {hex(da[1].addr)} instruction {hex(da[2])} buffer at {hex(da[3])}") 
            #faddrs.add(da[0].addr)
            bufferInfo.add((da[0].name,da[0].addr,da[1].addr,da[2],da[3]))
        for fn,fa,bba,ia,buf in bufferInfo:
           ff = self.IRgetFunctionAtAddress(fa)
           callers = self.IRfindImmediateCallersWithCallsite(ff)
           for ca, ba in callers:
               c = self.IRgetFunctionAtAddress(ca)
               snapshotInfo.add((c.name, ca, ba, fn, fa, buf))               
               print(f"Caller {c.name} {hex(ca)} of {fn} {hex(fa)} callsite {hex(ba)} buffer {hex(buf)}") 
        return
        #if not b == None:
        #    if len(b) == 3:
        #       print(f"Buffer ultimate source {b[0]} {b[1]} {b[2]}")
        #    if len(b) == 4:
        #       print(f"Buffer ultimate source {b[0]} {b[1]} {b[2]} {b[3]}")
        #print(f"Global Pointers:")
        #for gp in globalPointers:
        #    print(f"Global pointer address {hex(gp[1])}")
        #    loadAddresses.add(gp[1]) 
        #callersWImplicit = self.IRfindImplicitCalls()
        #callers = set()
        #for cwi in callersWImplicit:
        #    callers.add(cwi[0])
        targetCallers = self.IRgetFunctionsLoadingFromAddress(callers, loadAddresses)
        buffers = set()
        for tc in targetCallers:
            ftc = self.IRgetFunctionAtAddress(tc)
            print(f"Target function {ftc.name} {hex(ftc.addr)}")
            bufs = self.IRfindArgumentsForImplicitCalls(ftc, bis, filter)
            for buf in bufs:
                buffers.add(buf)
        actualBufferAddresses = set() 
        for buf in buffers:
            if buf[0] == "global":
               try:
                   value = self._project.loader.memory.load(buf[1], 4)
               except KeyError:
                   continue
               value = int.from_bytes(value,byteorder='little')
               actualBufferAddresses.add(value)
               print(f"Buffer {buf[0]} {hex(buf[1])} {buf[2]}")
            else:  
               print(f"Buffer {buf[0]} {buf[1]} {buf[2]}")
        for ab in actualBufferAddresses:
            print(f"Actual buffer address: {hex(ab)}")
        directAccesses, indirectAccesses = self.IRfindAddressLoadLocations(actualBufferAddresses, filter)
        print(f"Direct load buffer accesses:")
        for da in directAccesses:
            print(f"Buffer direct load access in {da[0].name} bb {hex(da[1])} instruction {hex(da[2])} buffer at {hex(da[3])}") 
        print(f"Indirect load buffer accesses:")
        for da in indirectAccesses:
            print(f"Buffer indirect load access in {da[0].name} bb {hex(da[1])} instruction {hex(da[2])} buffer at {hex(da[3])}") 
        return 
        # spi_smt32_transceive
        fc = self.IRgetFunctionAtAddress(0x8005ee5)
        callers = self.IRfindImmediateCallers(fc)
        for c in callers:
            f = self.IRgetFunctionAtAddress(c)
            print(f"Caller {hex(c)} f {f.name}")
        callers = self.IRfindCallbackAssignments(0x8005ee5)
        for c in callers:
            fa, ba, index, st = c
            f = self.IRgetFunctionAtAddress(fa)
            print(f"Caller f {f.name} bb {hex(ba)} {st}")
        callers = self.IRfindImplicitCalls()
        print(f"Implicit calls")
        for c in callers:
            fa, ba, node = c
            f = self.IRgetFunctionAtAddress(fa)
            if "transceive" in f.name:
                print("********************")
            print(f"Caller f {f.name} bb {hex(ba)} {node}")
        scanned = 0x800c234
        globalMap, storedMap, funcStoreMap = self.IRfindGlobalLoadAddresses(scanned)
        print(f"Load addresses:")
        for k in globalMap:
            print(f"Address {hex(k)} count {globalMap[k]}")
        print(f"Stored addresses:")
        for k in storedMap:
            for fn in storedMap[k]:
                if "transceive" in fn:
                    print("********************")
                    break
            print(f"Address {hex(k)} count {len(storedMap[k])} {storedMap[k]}")
        print(f"Accessing base of jump table with reference to {hex(scanned)}")
        for fs in funcStoreMap:
            for sc in funcStoreMap[fs]:
                print(f"Function {sc[0]} accessing base {hex(sc[1])} at {hex(sc[2])} scanned function {hex(sc[3])}")

    def HALfindBufferSources(self, dataRegOffset):
        halCandidates = set() 
        self.HALfilterFunctionsWithCommonSourceForPeripheralRegisters(dataRegOffset, halCandidates)
        self.HALfilterTransferBuffers(dataRegOffset, halCandidates)

    def HALfindBufferAssignments(self, bufs, patterns, bufassign, filter=None):
        for buf in bufs:
            evidence = None
            if len(buf) == 3:
               evidence  = buf[2]
            if len(buf) == 4:
               evidence  = buf[3] 
            if evidence == None:
               continue 
            pattern = self.IRextractPattern(evidence)
            print(f"********************** PATTERN {pattern} **********************")
            patterns.add(self.IRstringifyPattern(pattern))
        print(f"Number of patterns {len(patterns)}") 
        for pattern in patterns:
            print(f"Pattern {pattern} destringify {self.IRdestringifyPattern(pattern)}")
        for pattern in patterns:
            self.IRfindBufferAssignments(self.IRdestringifyPattern(pattern), bufs, bufassign, filter)    

    def HALfilterFunctionsBasedOnDynMMIOReads(self, mmioReadLocs, halCandidates, filter=None):
        for pc in mmioReadLocs:
            print(f"(Dyn MMIO Read) pc {hex(pc)}")
            f = self.IRgetFunctionOfInstruction(pc)
            if f == None:
               continue
            baseregset = self.IRgetBaseRegSetForFunction(f)
            for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                index = 0
                found = False
                while index < len(bb.vex.statements):
                      st = bb.vex.statements[index]
                      if isinstance(st, pyvex.IRStmt.IMark):
                         if st.addr == pc:
                            found = True
                         else:
                            found = False
                      if found:
                         if isinstance(st, pyvex.IRStmt.WrTmp):
                            if isinstance(st.data, pyvex.IRExpr.Load):
                               cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
                               visitedMap = {}
                               ev = "" 
                               self._comprehensiveDefUse = True
                               dasources = self.IRfindAllSourcesofAddress(f, baseregset, cfgnode, bb, st, index, st.data.addr, visitedMap, ev, filter)
                               del visitedMap
                               self._comprehensiveDefUse = False
                               for da in dasources:
                                  if len(da) == 3:
                                     t, o, e = da
                                     print(f"(Dyn MMIO Read) Function {f.name} Address source {st.data.addr}: {t} {o} ({st} {cfgnode.addr})")
                                     halCandidates.add((f, t, o, 0, bb, cfgnode, index, st.data.addr))
                                  if len(da) == 4:
                                     t, o, dto, e = da
                                     print(f"(Dyn MMIO Read) Function {f.name} Address source {st.data.addr}: {t} {o} {dto} ({st} {cfgnode.addr})")
                                     halCandidates.add((f, t, o, dto, bb, cfgnode, index, st.data.addr))
                               break   
                      index += 1
        self._mmioAccessContextFindingTime = time.time()
        print(f"Time to finding mmio access contexts={self._mmioAccessContextFindingTime - self._startTime} secs")

    def HALfilterFunctionsWithCommonSourceForPeripheralRegisters(self, dataRegOffset, statusRegOffset, mmioReadLocs, halCandidates, filter=None):
        fset = self.HALgetFunctionsWithPeripheralRegisterAccess(dataRegOffset)
        #adj = self.HALgetAdjacentRegisters(dataRegOffset)
        adj = []
        adj.append(statusRegOffset)
        matchCandidates = set()
        for f in fset:
            if not f.name == "HAL_SPI_TransmitReceive": 
               continue
            print(f"Checking matching sources for function {f.name}")
            for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                #bb.vex.pp()  
            baseregset = self.IRgetBaseRegSetForFunction(f)
            sources = self.IRgetBBsSubsWithConstant(f, dataRegOffset)
            dregdefs = set()
            dregdefsources = set()
            for source in sources:
                bb, index, sub, offset = source
                print(f"Constant source bb {hex(bb.addr)} {sub} {bb.vex.statements[index]}")
            for source in sources:
                bb, index, sub, offset = source
                #bb.vex.pp() 
                cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
                if cfgnode == None:
                   print(f"CFGNode undefined for {hex(bb.addr)} index {index}")
                   continue
                st = bb.vex.statements[index]
                ev = ""
                visitedMap = {}
                dasources = self.IRfindAllSourcesofAddress(f, baseregset, cfgnode, bb, st, index, sub, visitedMap, ev, filter)
                del visitedMap
                for da in dasources:
                    if len(da) == 3:
                       t, o, e = da
                       print(f"Function {f.name} Address source {sub}: {t} {o} ({st} {cfgnode.addr})")
                       dregdefsources.add((t, o, 0, bb, cfgnode, index, sub))
                    if len(da) == 4:
                       t, o, dto, e = da
                       print(f"Function {f.name} Address source {sub}: {t} {o} {dto} ({st} {cfgnode.addr})")
                       dregdefsources.add((t, o, dto, bb, cfgnode, index, sub))
            print(f"Function {f.name} len of dregdefsources {len(dregdefsources)} adjacent reg offsets {adj}")    
            if len(dregdefsources) == 0:
               continue
            aregdefs = set()
            anyMatch = False
            for areg in adj:
                asubinfo = self.IRgetBBsSubsWithConstant(f, areg)
                print(f"Function {f.name} bbs with constant {areg} {asubinfo}")
                for asub in asubinfo:
                    abb, aindex, anode, ao = asub
                    acfgnode = self.IRfindCFGNodeForStatement(f, abb, aindex)
                    if acfgnode == None:
                       continue
                    print(f"Status reg cand {hex(abb.addr)} {anode}")
                    ast = abb.vex.statements[aindex]
                    vm = {}
                    ev = ""
                    sources = self.IRfindAllSourcesofAddress(f, baseregset, acfgnode, abb, ast, aindex, anode, vm, ev, filter)
                    del vm
                    #sources = self.IRfindSourcesofAddressInHandlerField(f, baseregset, acfgnode, abb, ast, aindex, anode, vm, ev)
                    for source in sources:
                        print(f"Function {f.name} Status reg source for {anode} {source[0]} {source[1]}")
                        if len(source) == 3:
                           t, o, e = source
                           if any([t1 for t1, t2, t3, t4, t5, t6, t7 in dregdefsources if t1 == t and t2 == o and t3 == 0]):
                               print(f"Matching address source for offset areg and datareg in function {hex(f.addr)} {f.name}: {t} {o} ")
                               anyMatch = True
                               for dregt in dregdefsources:
                                   t1, t2, t3, tbb, tcfgnode, tindex, tsub = dregt
                                   if t1 == t and t2 == o and t3 == 0: 
                                      halCandidates.add((f, t1, t2, t3, tbb, tcfgnode, tindex, tsub))
                        if len(source) == 4:
                           t, o, dto, e = source
                           if any([t1 for t1, t2, t3, t4, t5, t6, t7 in dregdefsources if t1 == t and t2 == o and t3 == dto]):
                               print(f"Matching address source for offset areg and datareg in function {hex(f.addr)} {f.name}: {t} {o} {dto}")
                               anyMatch = True
                               for dregt in dregdefsources:
                                   t1, t2, t3, tbb, tcfgnode, tindex, tsub = dregt
                                   if t1 == t and t2 == o and t3 == dto: 
                                      halCandidates.add((f, t1, t2, t3, tbb, tcfgnode, tindex, tsub))
                    del sources
            print(f"HAL API candidates with possible data register uses: &&&&&&&&&&&&&& {len(f.block_addrs)} &&&&&&&&&&&&")
        print(f"Number of HAL candidates: {len(halCandidates)} (out of total {len(self._current_cfg.functions.values())} functions)")
        for hc in halCandidates:
            f, t1, t2, t3, tbb, tcfgnode, tindex, tsub = hc
            print(f"Function {f.name} {t1} {t2} {t3} {hex(tbb.addr)} {hex(tcfgnode.addr)} {tindex} {tsub} {tbb.vex.statements[tindex]}")
        if len(halCandidates) == 0 and not mmioReadLocs == None:
           self.HALfilterFunctionsBasedOnDynMMIOReads(mmioReadLocs, halCandidates) 
           print(f"Number of HAL candidates using dynamic trace: {len(halCandidates)} (out of total {len(self._current_cfg.functions.values())} functions)")
        self._mmioAccessContextFindingTime = time.time()
        print(f"Time to finding mmio access contexts={self._mmioAccessContextFindingTime - self._startTime} secs")

    def HALfindSimpleMMIOAccesses(self, dataRegisterAddress, bufferInfo, localBufferInfo, snapshotInfo, filter=None):
        actualBufferAddresses = set()
        self._comprehensiveDefUse = True
        for f in self._current_cfg.functions.values():
            #print(f"Function {f.name}")
            baseregset = self.IRgetBaseRegSetForFunction(f)
            foundInFunc = False
            relevantLoads = set()
            for ba in f.block_addrs:
                bb = self._project.factory.block(ba)
                #if f.name == "read":
                #if bb.addr == 0x202d68 or bb.addr == 0x202d69: 
                #    bb.vex.pp()
                ia = 0
                index = 0
                found = False
                while index < len(bb.vex.statements):
                      st = bb.vex.statements[index]
                      if isinstance(st, pyvex.IRStmt.IMark):
                         ia = st.addr
                      if isinstance(st, pyvex.IRStmt.WrTmp):
                         if isinstance(st.data, pyvex.IRExpr.Load) or isinstance(st.data, pyvex.IRStmt.LoadG):
                            if isinstance(st.data.addr, pyvex.IRExpr.Const):                     
                               la = st.data.addr.con._value
                               try:
                                   value = self._project.loader.memory.load(la, 4)
                               except KeyError:
                                   index += 1
                                   continue
                               value = int.from_bytes(value,byteorder='little')
                               if value == dataRegisterAddress:
                                  found = True
                                  foundInFunc = True
                                  relevantLoads.add(st.data) 
                                  print(f"Direct MMIO {hex(value)} address loaded at instruction {hex(ia)} in function {f.name}")                         
                      index += 1 
            if not foundInFunc:
               continue
            for ba in f.block_addrs:
                bb = self._project.factory.block(ba)
                #if f.name == "read":
                #if bb.addr == 0x202d68 or bb.addr == 0x202d69: 
                #    bb.vex.pp()
                ia = 0
                index = 0
                found = False
                while index < len(bb.vex.statements):
                      st = bb.vex.statements[index]
                      if isinstance(st, pyvex.IRStmt.IMark):
                         ia = st.addr
                      if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                         vm = {}
                         ev = "" 
                         cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
                         visited = set()
                         defs = self.IRgetDefForUse(f, cfgnode, bb, st, index, st.data, filter, visited)
                         del visited
                         matched = False
                         for d in defs:
                             dbba, di, dn, dc, dev = d
                             for rl in relevantLoads:
                                 if str(dn) == str(rl):
                                    matched = True
                                    print(f"****** {d[2]}")
                                    break
                         vm = {}
                         ev = "" 
                         sources = self.IRfindAllSourcesofAddress(f, baseregset, cfgnode, bb, st, index, st.addr, vm, ev, filter)
                         del vm
                         for s in sources:
                             print(f"Receive buffer source {s}")
                             callchain = []
                             # todo: handle return value type change
                             ult = self.IRfindArgumentsForExplicitCallsRecursive(f, s, callchain, filter)
                             for u in ult:
                                 if u[0] == "global":
                                    print(f"Receive ultimate buffer source {u}")
                                    if u[1] < self._minRAM:
                                       try:
                                           value = self._project.loader.memory.load(u[1], 4)
                                           actualBufferAddresses.add((value, sf))
                                       except KeyError:
                                           continue   
                                    actualBufferAddresses.add(u[1])
                                 if u[0] == "stack":
                                    print(f"Receive ultimate buffer source {u}")
                                    localBufferInfo.add((u[1],sf)) 

                      index += 1
        self._mmioAccessContextFindingTime = time.time()
        print(f"Time to finding mmio access contexts={self._mmioAccessContextFindingTime - self._startTime} secs")
        faddrs = set()
        directAccesses, indirectAccesses = self.IRfindAddressLoadLocations(actualBufferAddresses, filter)
        print(f"Direct load buffer accesses:")
        for da in directAccesses:
            print(f"Buffer direct load access in {da[0].name} bb {hex(da[1].addr)} instruction {hex(da[2])} buffer at {hex(da[3])}")
            faddrs.add(da[0].addr)
            bufferInfo.add((da[0].name,da[0].addr,da[1].addr,da[2],da[3]))
        print(f"Indirect load buffer accesses:")
        for da in indirectAccesses:
            print(f"Buffer indirect load access in {da[0].name} bb {hex(da[1].addr)} instruction {hex(da[2])} buffer at {hex(da[3])}") 
            faddrs.add(da[0].addr)
            bufferInfo.add((da[0].name,da[0].addr,da[1].addr,da[2],da[3]))
        for fn,fa,bba,ia,buf in bufferInfo:
           ff = self.IRgetFunctionAtAddress(fa)
           callers = self.IRfindImmediateCallersWithCallsite(ff)
           for ca, ba in callers:
               c = self.IRgetFunctionAtAddress(ca)
               snapshotInfo.add((c.name, ca, ba, fn, fa, buf))               
               print(f"Caller {c.name} {hex(ca)} of {fn} {hex(fa)} callsite {hex(ba)} buffer {hex(buf)}") 
        self._comprehensiveDefUse = False

    """ 
        BEGIN Use-Def Chain API
    """
            
    def IRfindCallersUsingDynCG(self, f):
        if f.addr in self._dyncallgraph.keys():
           return self._dyncallgraph[f.addr]
        if f.addr - 1 in self._dyncallgraph.keys():
           return self._dyncallgraph[f.addr - 1]
        if f.addr + 1 in self._dyncallgraph.keys():
           return self._dyncallgraph[f.addr + 1]
        return set()

    # limited return value handling
    def IRfindReturnValuesInFunction(self, f, reg="r0", filter=None):
        #print(f"[IRfindReturnValuesInFunction] {f.name}")
        baseregset = self.IRgetBaseRegSetForFunction(f)
        results = set()  
        for ba in f.block_addrs:
            bb =  self._project.factory.block(ba)
            if bb.vex.jumpkind == "Ijk_Ret":
               index = len(bb.vex.statements) - 1
               cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
               vm = {}
               ev = ""
               #bb.vex.pp()
               #sources = self.IRgetSourceForRegDef(f, cfgnode, reg, index)
               #for s in sources:
               #    results.add(s)
               #    print(f"{reg} source in {f.name} : {s}")
               while index >= 0:
                     st = bb.vex.statements[index]
                     if isinstance(st, pyvex.IRStmt.Put):
                        if self._project.arch.register_names[st.offset] == reg:
                           vm = {}
                           ev = ""
                           cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
                           #sources = self.IRfindAllSourcesofAddress(f, baseregset, cfgnode, bb, st, index, st.data, vm, ev) 
                           #for s in sources:
                           #    results.add(s)
                           #    print(f"{reg} source in {f.name} : {s}")
                           visited = set()
                           ldef = self.IRgetDefForUse(f, cfgnode, bb, st, index, st.data, filter, visited)
                           del visited
                           for ld in ldef:
                               ldd, li, ln, lcm, lev = ld 
                               if isinstance(ln, pyvex.IRExpr.Load) or isinstance(ln, pyvex.IRStmt.LoadG):
                                 if isinstance(ln.addr, pyvex.IRExpr.Const):
                                    la = ln.addr.con._value
                                    try:
                                        value = self._project.loader.memory.load(la, 4)
                                    except KeyError:
                                        continue
                                    value = int.from_bytes(value,byteorder='little')
                                    results.add(("global", value, lev))
                                    print(f"{reg} source in {f.name} : global {hex(value)}") 
                           break
                     index -= 1
        return results

    def IRfindPredecessorCallsites(self, f, bbas, reg, filter=None):
        sources = set()
        for ba in f.block_addrs:
            bb = self._project.factory.block(ba)
            #if ba in bbas:
            #   continue
            if bb.vex.jumpkind == "Ijk_Call":
               #bb.vex.pp() 
               isapred = False
               i = len(bb.vex.statements) - 1
               while i>= 0:
                     st = bb.vex.statements[i]
                     if isinstance(st, pyvex.IRStmt.Put):
                        if self._project.arch.register_names[st.offset] == "lr":
                           if isinstance(st.data, pyvex.IRExpr.Const):
                              lbb = self.IRgetBBForAddress(f, st.data.con._value)
                              if not lbb == None:
                                 print(f"BB of LR {hex(lbb.addr)}") 
                                 if lbb.addr in bbas:
                                    isapred = True
                                    break
                     i -= 1
               if not isapred:
                 continue
               if isinstance(bb.vex.next, pyvex.IRExpr.Const):    
                  f = self.IRgetFunctionAtAddress(bb.vex.next.con._value)
                  print(f"Pred calling {f.name}")
                  res = self.IRfindReturnValuesInFunction(f, reg, filter)
                  for r in res:
                      sources.add(r)    
               i = len(bb.vex.statements) - 1
               while i>= 0:
                     st = bb.vex.statements[i]
                     if isinstance(st, pyvex.IRStmt.Put):
                        if self._project.arch.register_names[st.offset] == "pc":
                           if isinstance(st.data, pyvex.IRExpr.Const):
                              fa = st.data.con._value
                              f = self.IRgetFunctionAtAddress(fa)
                              print(f"Pred calling {f.name}")
                              res = self.IRfindReturnValuesInFunction(f, reg, filter)
                              for r in res:
                                  sources.add(r)    
                     i -= 1                    
        return sources

    def IRfindReturnValuesofPredecessorCallsites(self, f, bb, cfgnode, reg="r0", filter=None):
        #print(f"[IRfindReturnValuesofPredecessorCallsites] {f.name} {hex(bb.addr)} {hex(cfgnode.addr)}")
        self.IRgetRegDefiningNode(f, cfgnode, bb, reg) 
        #bb.vex.pp()
        #for ba in f.block_addrs:
        #    bb = self._project.factory.block(ba)
        #    bb.vex.pp() 
        sources = set()
        preds = self.IRfindAllPredsInFunction(f, cfgnode, filter)
        bbas = set()
        for pred in preds:
            print(f"\t\tpred {hex(pred.addr)}")
            pbb = self.IRgetBasicBlockForCFGNode(f, pred)
            bbas.add(pbb.addr)
            bbas.add(pred.addr)
        bbas.add(cfgnode.addr)
        bbas.add(bb.addr)
        for ba in bbas:
            print(f"bbas {hex(ba)}")
        return self.IRfindPredecessorCallsites(f, bbas, reg, filter)
 
    def IRfindAddressLoadLocations(self, addresses, filter=None):
        directResults = set()
        indirectResults = set()
        if len(addresses) == 0:
           print(f"Skipping load location checking due to empty address set!")
           return (directResults, indirectResults)
        print(f"Checking {len(self._current_cfg.functions.values())} functions for buffer reference and access locations num addresses {len(addresses)}")
        justaddresses = set()
        functionSources = set()
        for asource in addresses:
            if len(asource) == 3:
               addr, fn, fa = asource   
               print(f"Tuple {addr} {fn}")
               print(f"Load address {hex(addr)} in function {fn}") 
               justaddresses.add(addr)
               if not fa == 0:
                  f = self.IRgetFunctionAtAddress(fa)
                  functionSources.add(f)
            elif len(asource) == 1:
               print(f"Load address {hex(addr)}")
        if len(functionSources) == 0:
           functionSources = self._current_cfg.functions.values()
        for f in functionSources:
            print(f"Function {f.name} checking load locations")
            indirect = set()
            for ba in f.block_addrs:
                bb =  self._project.factory.block(ba)
                index = 0
                ia = 0
                while index < len(bb.vex.statements):
                    st = bb.vex.statements[index]
                    if isinstance(st, pyvex.IRStmt.IMark):
                       ia = st.addr
                    if isinstance(st, pyvex.IRStmt.WrTmp):
                       if isinstance(st.data, pyvex.IRExpr.Load) or isinstance(st.data, pyvex.IRStmt.LoadG):
                          if isinstance(st.data.addr, pyvex.IRExpr.Const):
                             la = st.data.addr.con._value
                             if la in justaddresses:
                                directResults.add((f, bb, ia, la))
                             try:
                                value = self._project.loader.memory.load(la, 4)
                             except KeyError:
                                index += 1
                                continue
                             value = int.from_bytes(value,byteorder='little')
                             if value in justaddresses:
                                print(f"Indirect {hex(value)} in {f.name}")
                                indirectResults.add((f, bb, ia, value))
                          #if f.name == "packetbuf_dataptr":
                          #   bb.vex.pp()
                          else:
                             cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
                             if cfgnode == None:
                                index += 1
                                continue
                             visited = set()                 
                             dus = self.IRgetDefForUse(f, cfgnode, bb, st, index, st.data.addr, filter, visited)
                             del visited
                             for du in dus:
                                 dbba, di, dn, dco, dev = du
                                 if isinstance(dn, pyvex.IRExpr.Load):
                                    if isinstance(dn.addr, pyvex.IRExpr.Const):
                                       la = dn.addr.con._value
                                       try:
                                           value = self._project.loader.memory.load(la, 4)
                                       except KeyError:
                                           index += 1
                                           continue
                                       value = int.from_bytes(value,byteorder='little')
                                       if value in justaddresses:
                                          print(f"Indirect {hex(value)} in {f.name}")
                                          indirectResults.add((f, bb, ia, value))
                    if isinstance(st, pyvex.IRStmt.LoadG):
                       if isinstance(st.addr, pyvex.IRExpr.Const):
                          la = st.addr.con._value
                          if la in justaddresses:
                             directResults.add((f, bb, ia, la))
                          try:
                             value = self._project.loader.memory.load(la, 4)
                          except KeyError:
                             index += 1
                             continue
                          value = int.from_bytes(value,byteorder='little')
                          if value in justaddresses:
                             print(f"Indirect {hex(value)} in {f.name}")
                             indirectResults.add((f, bb, ia, value))
                       else:
                             cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
                             if cfgnode == None:
                                index += 1
                                continue
                             visited = set()                 
                             dus = self.IRgetDefForUse(f, cfgnode, bb, st, index, st.addr, filter, visited)
                             del visited 
                             for du in dus:
                                 dbba, di, dn, dco, dev = du
                                 if isinstance(dn, pyvex.IRExpr.Load):
                                    if isinstance(dn.addr, pyvex.IRExpr.Const):
                                       la = dn.addr.con._value
                                       try:
                                           value = self._project.loader.memory.load(la, 4)
                                       except KeyError:
                                           index += 1
                                           continue 
                                       value = int.from_bytes(value,byteorder='little')
                                       if value in justaddresses:
                                          print(f"Indirect {hex(value)} in {f.name}")
                                          indirectResults.add((f, bb, ia, value))
                    index += 1
        return (directResults,indirectResults) 

    def IRfindArgumentsForExplicitCallsRecursive(self, f, source, callchain, filter=None, visited=None):
        if not f.addr in self._argumentsForExplicitCalls.keys():
           self._argumentsForExplicitCalls[f.addr] = {}
        if source in self._argumentsForExplicitCalls[f.addr].keys():
           return self._argumentsForExplicitCalls[f.addr][source]
        #print(f"[IRfindArgumentsForExplicitCallsRecursive] BEGIN {f.name}")
        result = set()
        passingValueAsReturnValue = set() 
        clean = (visited == None)
        if visited == None:
           visited = set()
        if f.addr in visited:
           #print(f"Already visited {hex(f.addr)}")
           return result
        callchain.append(f)
        visited.add(f.addr)           
        callers = self.IRfindImmediateCallers(f)
        for ca, ctype in callers:
            c = self.IRgetFunctionAtAddress(ca)
            indirect = (ctype == 'indirect')
            print(f"##################### FINDING ARG of {f.name} ({hex(f.addr)}) in {c.name} type {ctype}")
            res = self.IRfindCallerContextCalleeArgSources(c, f.addr, source, indirect, filter)
            for r in res:
                if r[0] == "global":
                   result.add(r)
                else: 
                   if r[0] == "stack":
                      result.add(r)
                   v = set()
                   for vis in visited:
                       v.add(vis)
                   sres, pretval, c2 = self.IRfindArgumentsForExplicitCallsRecursive(c, r, callchain, filter, v)
                   for s in sres:
                       result.add(s)
                   for pr in pretval:
                       passingValueAsReturnValue.add(pr)
            if len(res) == 0:
               passingValueAsReturnValue.add(c) 
        #print(f"[IRfindArgumentsForExplicitCallsRecursive] END {f.name}")
        self._argumentsForExplicitCalls[f.addr][source] = (result, passingValueAsReturnValue, callchain)
        if clean:
           del visited
        return (result, passingValueAsReturnValue, callchain)

    def IRfindArgumentsForImplicitCalls(self, f, bis, filter=None):
        result = set()
        for ba in f.block_addrs:
            bb =  self._project.factory.block(ba)
            if not isinstance(bb.vex.next, pyvex.IRExpr.Const):
               index = len(bb.vex.statements) - 1
               cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
               for a, t, reg in bis:
                   sources = self.IRgetSourceForRegDef(f, cfgnode, reg, filter, None, index)
                   print(f"================= SOURCES of {reg} in {f.name} {len(sources)} ==================")
                   for source in sources:
                       if not source[0] == "global":
                          callchain = []
                          res, retval, c2 = self.IRfindArgumentsForExplicitCallsRecursive(f, source, callchain, filter)
                          for r in res:
                              if r[0] == "global":
                                 result.add(r)
                       else:
                          result.add(source)
        return result

    def IRgetFunctionsLoadingFromAddress(self, functions, loadAddresses):
        result = set()
        for fa in functions:
            f = self.IRgetFunctionAtAddress(fa)
            for ba in f.block_addrs:
                bb =  self._project.factory.block(ba)
                index = 0
                while index < len(bb.vex.statements):
                      st = bb.vex.statements[index]
                      if isinstance(st, pyvex.IRStmt.WrTmp):
                         if isinstance(st.data, pyvex.IRExpr.Load) or isinstance(st.data, pyvex.IRStmt.LoadG):
                            if isinstance(st.data.addr, pyvex.IRExpr.Const):
                               la = st.data.addr.con._value
                               try:
                                   value = self._project.loader.memory.load(la, 4)
                               except KeyError:
                                   continue
                               value = int.from_bytes(value,byteorder='little')
                               if value in loadAddresses:
                                  result.add(f.addr)                   
                      index += 1
        return result

    def IRfindReturnedAddressPropagationInCaller(self, fa, globPtrs, filter=None):
        ff = self.IRgetFunctionAtAddress(fa)
        #print(f"[IRfindReturnedAddressPropagationInCaller] {ff.name} for {hex(fa.addr)}")
        callers = self.IRfindImmediateCallers(ff)
        for ca, ctype in callers:
            c = self.IRgetFunctionAtAddress(ca) 
            baseregset = self.IRgetBaseRegSetForFunction(c)
            lrts = self.IRgetCallerContextNextInstruction(c, fa, filter)
            for lrt in lrts:
                lbb, lr = lrt
                print(f"Next instruction after callee {hex(fa)} return in {c.name} : {hex(lr[1])}")
                #lbb.vex.pp()
                tlbb = self.IRgetBBForAddress(c, lr[1])
                if tlbb == None:
                   tlbb, f = self.IRgetBBForAddressInBinary(lr[1])
                   if tlbb == None:                   
                      print(f"Could not find bb for {hex(lr[1])} in {c.name}")
                      continue
                   else:
                      c = f
                      print(f"Found bb {hex(lr[1])} in {f.name}") 
                # find uses of r0 
                lcfgnode = self.IRfindCFGNodeForInstruction(c, tlbb, lr[1])
                #if lcfgnode == None:
                #   lcfgnode = self.IRfindCFGNodeForInstruction(c, tlbb, lr[1] - 1)
                if lcfgnode == None:
                   continue         
                bb, min, max = self.IRgetStatementIndexRangeForCFGNode(c, lcfgnode)
                if bb == None:
                   continue
                temp = ""
                #bb.vex.pp()
                print(f"BB {hex(tlbb.addr)} CFGNode {hex(lcfgnode.addr)} min {min} max {max} looking for r0 use")
                index = min
                while index <= max:
                      st = bb.vex.statements[index]
                      if isinstance(st, pyvex.IRStmt.WrTmp):
                         if isinstance(st.data, pyvex.IRExpr.Get):
                            temp = "t" + str(st.tmp)
                            break
                      index += 1
                if index > max:
                   continue
                print(f"FINDING uses of {temp} in {hex(tlbb.addr)} starting from {st} at index {index}")
                uses = self.IRgetUsesInFunction(c, lcfgnode, tlbb, st, index, temp)
                for use in uses:
                    ubba, ust, ui, unode, uother, uev = use
                    #print(f"USE of r0: {use} {unode} {uother}")
                    if str(unode) == str(ust.data):
                       vm = {}
                       ev = "" 
                       ubb = self._project.factory.block(ubba)
                       ucfgnode = self.IRfindCFGNodeForStatement(c, ubb, ui)
                       if ucfgnode == None:
                          #ubb.vex.pp() 
                          print(f"Cannot find cfgnode for bb {hex(ubb.addr)} index {ui}")
                          continue 
                       sources = self.IRfindAllSourcesofAddress(c, baseregset, ucfgnode, ubb, ust, ui, uother, vm, ev, filter)
                       del vm
                       print(f"Num sources of {uother}: {len(sources)}")
                       #ubb.vex.pp()
                       for s in sources:
                           #print(f"SOURCE of use {use} : {s}")
                           if s[0] == "global":
                              print(f"********************* Global pointer address {hex(s[1])} is set in {c.name}")
                              globPtrs.add(s)
                       visited = set()
                       ev2 = ""
                       ds = self.IRgetDefForUse(c, ucfgnode, ubb, ust, ui, uother, filter, visited, ev2)
                       del visited 
                       for dbba, di, dn, co, ev in ds:
                           if isinstance(dn, pyvex.IRExpr.Load) or isinstance(dn, pyvex.IRStmt.LoadG):
                              if isinstance(dn.addr, pyvex.IRExpr.Const):
                                 la = dn.addr.con._value
                                 try:
                                     value = self._project.loader.memory.load(la, 4)
                                 except KeyError:
                                    continue
                                 value = int.from_bytes(value,byteorder='little')
                                 print(f"********************* Global pointer address {hex(value)} is set in {c.name}")
                                 globPtrs.add(("global", value, ev2))
                                   

    def IRgetCallerContextNextInstruction(self, c, callee, filter=None):
        results = set()
        for ba in c.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            if isinstance(bb.vex.next,pyvex.IRExpr.Const):
               if bb.vex.next.con._value == callee:
                  cfgnode = self.IRfindCFGNodeForStatement(c, bb, len(bb.vex.statements) - 1)
                  sources = self.IRgetSourceForRegDef(c, cfgnode, "lr", filter)
                  for s in sources:
                      print(f"Found source for lr in {c.name} wrt callee {hex(callee)}: {s}") 
                      if s[0] == "global":
                         results.add((bb, s))
                         print(f"Found source for lr in {c.name} wrt callee {hex(callee)}: {hex(s[1])}")
        return results    

    def IRgetCallerWithImplicitCallee(self, fa, bufferInitialSource, globPtrs, filter=None):
        f = self.IRgetFunctionAtAddress(fa)
        print(f"Analyzing caller {hex(fa)} {f.name} with implicit callee") 
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            if not isinstance(bb.vex.next,pyvex.IRExpr.Const):
               source = self.IRfindCallerBBContextImplicitCalleeArgSource(f, bb, bufferInitialSource, filter)
               if not source == None:
                  return source
        callers = self.IRfindImmediateCallers(f)
        for c, ctype in callers:
            source = self.HALBufferSourcesforFunction(bufferInitialSource, c, globPtrs)
            for s in source:
                if s[0] == "global":
                   return s
        return None     

    

    def IRfindCallerBBContextImplicitCalleeArgSource(self, c, bb, bufferInitialSource, filter=None):
        #print(f"Function {c.name} finding arg {bufferInitialSource[1]} source in bb {hex(bb.addr)}")
        if bufferInitialSource == "argument":
           index = len(bb.vex.statements) - 1
           cfgnode = self.IRfindCFGNodeForStatement(c, bb, index)
           if cfgnode == None:
              sources = self.IRgetSourceForRegDef(c, cfgnode, bufferInitialSource[1], filter)
              for s in sources:
                  if s[0] == "global":
                     return s
        return None  


 

    def IRfindCallerContextCalleeArgSources(self, c, callee, bufferInitialSource, indirect=False, filter=None):
        if isinstance(bufferInitialSource[0], int):
           s = None
           print(f"Length of tuple {len(bufferInitialSource)}")
           if len(bufferInitialSource) == 3:
              s = (bufferInitialSource[1],bufferInitialSource[2]) 
           if len(bufferInitialSource) == 4:
              s = (bufferInitialSource[1],bufferInitialSource[2],bufferInitialSource[3]) 
           if len(bufferInitialSource) == 5:
              s = (bufferInitialSource[1],bufferInitialSource[2],bufferInitialSource[3],bufferInitialSource[4])
           if not s == None:
              print(f"s partial tuple {s}")
              return self.IRfindCallerContextCalleeArgSourcesInternal(c, callee, s, indirect, filter)
           else:
              return set()
        else:
           return self.IRfindCallerContextCalleeArgSourcesInternal(c, callee, bufferInitialSource, indirect, filter) 
          

    def IRgetConstantLoadAddresses(self, f):
        results = set()
        indirectresults = set()
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            index = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.WrTmp):
                     if isinstance(st.data, pyvex.IRExpr.Load) or isinstance(st.data, pyvex.IRStmt.LoadG):
                        if isinstance(st.data.addr, pyvex.IRExpr.Const):
                           la = st.data.addr.con._value
                           try:
                               value = self._project.loader.memory.load(la, 4)
                               value = int.from_bytes(value, byteorder='little')
                           except KeyError:
                               continue          
                           results.add((la, bb, index, st.data))
                           indirectresults.add((value, bb, index, st.data))
                           if f.name == "bt_spi_transceive":
                              print(f"Direct load address {hex(la)} indirect load address {hex(value)} st {st}")
                  if isinstance(st, pyvex.IRStmt.LoadG):
                     print(f"Whole statement {st} addr {st.addr}")
                     if isinstance(st.addr, pyvex.IRExpr.Const):
                        la = st.addr.con._value
                        try:
                             value = self._project.loader.memory.load(la, 4)
                             value = int.from_bytes(value, byteorder='little')
                        except KeyError:
                             continue          
                        results.add((la, bb, index, "t" + str(st.dst)))
                        indirectresults.add((value, bb, index, "t" + str(st.dst)))
                        if f.name == "bt_spi_transceive":
                           print(f"Direct load address {hex(la)} indirect load address {hex(value)} st {st}")
                  index += 1
        return (results, indirectresults)  
     
    def IRfindUseofAddress(self, f, address, bb, index, node, filter=None):
        results = set()
        baseregset = self.IRgetBaseRegSetForFunction(f)
        cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
        st = bb.vex.statements[index] 
        uses = self.IRgetUsesInFunction(f, cfgnode, bb, st, index, node)
        #print(f"Num uses of {node} for st {st} {len(uses)}")
        for use in uses:
            ubba, ust, ui, un, uother, uev = use
            #print(f"Use of address {hex(address)} {node}: {ust} {un}")
            ubb = self._project.factory.block(ubba)
            ucfgnode = self.IRfindCFGNodeForStatement(f, ubb, ui)
            if str(ust.addr) == str(un):
               vm = {}
               ev = ""  
               sres = self.IRfindAllSourcesofAddress(f, baseregset, ucfgnode, ubb, ust, ui, ust.data, vm, ev, filter)
               del vm  
               for s in sres:
                   results.add(s)
        return results 
     
    def IRresolveImplicitPointers(self, f, address, filter=None):
        results = set()
        baseregset = self.IRgetBaseRegSetForFunction(f) 
        loaddirect, loadindirect = self.IRgetConstantLoadAddresses(f)
        try:
           av = self._project.loader.memory.load(address, 4)
           av = int.from_bytes(av, byteorder='little')
        except KeyError:
           av = 0
        print(f"Checking for address {hex(address)} value at address {hex(av)}")
        pointingTo = set()
        for la, bb, index, node in loaddirect:
            try:
                value = self._project.loader.memory.load(la, 4)
                value = int.from_bytes(value, byteorder='little') 
            except KeyError:
                continue
            #if value == address:
            #   print(f"Direct load address {hex(la)} pointing to {hex(address)}")               
            #if value == av:
            #   print(f"Direct load address {hex(la)} pointing to {hex(av)}")
            #if la == av:               
            #   print(f"Address {hex(address)} pointing to {hex(la)}")
            if value == av or la == av:
               s2 = self.IRfindUseofAddress(f, av, bb, index, node, filter)
               for use in s2:
                   results.add(use)
                   #ubba, ust, ui, un, uother, uev = use
                   #ubb = self._project.factory.block(ubba)
                   #ucfgnode = self.IRfindCFGNodeForStatement(f, ubb, ui)
                   #print(f"Use of global {hex(value)} : {use}")
                   #if str(ust.addr) == str(un):
                   #   iuvm = {}
                   #   iuev = uev
                   #   indirectSrcs = self.IRfindAllSourcesofAddress(f, baseregset, ucfgnode, ubb, ust, ui, uother, iuvm, iuev)
                   #   for isrc in indirectSrcs:
                   #       print(f"Indirect source {isrc} recorded to a field of global source {hex(value)}")
                   #       results.add(isrc)
        for la, bb, index, node in loadindirect:
            try:
                value = self._project.loader.memory.load(la, 4)
                value = int.from_bytes(value, byteorder='little') 
            except KeyError:
                continue
            #if value == address:
            #   print(f"Indirect load address {hex(la)} pointing to {hex(address)}")
            #if value == av:
            #   print(f"Indirect load address {hex(la)} pointing to {hex(av)}")               
            #if la == av:               
            #   print(f"Address {hex(address)} pointing to indirect {hex(la)}")
            if value == av or la == av:
               s2 = self.IRfindUseofAddress(f, av, bb, index, node, filter)
               for use in s2:
                   results.add(use)
                   #ubba, ust, ui, un, uother, uev = use
                   #ubb = self._project.factory.block(ubba)
                   #ucfgnode = self.IRfindCFGNodeForStatement(f, ubb, ui)
                   #print(f"Use of global {hex(value)} : {use}")
                   #if str(ust.addr) == str(un):
                   #   iuvm = {}
                   #   iuev = uev
                   #   indirectSrcs = self.IRfindAllSourcesofAddress(f, baseregset, ucfgnode, ubb, ust, ui, uother, iuvm, iuev)
                   #   for isrc in indirectSrcs:
                   #       print(f"Indirect source {isrc} recorded to a field of global source {hex(value)}")
                   #       results.add(isrc)
        return results

    def IRfindCallerContextCalleeArgSourcesInternal(self, c, callee, bufferInitialSource, indirect, filter=None):
        #if len(bufferInitialSource) >= 3:
        #   print(f"Checking caller context {c.name} indirect? {indirect} for callee arg source {bufferInitialSource[0]} {bufferInitialSource[1]} {bufferInitialSource[2]}")
        #elif len(bufferInitialSource) >= 2:
        #   print(f"Checking caller context {c.name} indirect? {indirect}  for callee arg source {bufferInitialSource[0]} {bufferInitialSource[1]}")
        results = set()
        for ba in c.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            if not indirect and not bb.vex.jumpkind == "Ijk_Call":
               continue
            #print(f"Call {hex(bb.addr)} {bb.vex.next}")
            if (indirect and isinstance(bb.vex.next,pyvex.IRExpr.Const)) or (not indirect and not isinstance(bb.vex.next,pyvex.IRExpr.Const)):
               continue
            if not indirect and not bb.vex.next.con._value == callee:
               continue
            #print(f"BB callsite {hex(bb.addr)} in {c.name}")
            if bufferInitialSource[0] == "argument":
               index = len(bb.vex.statements) - 1
               cfgnode = self.IRfindCFGNodeForStatement(c, bb, index)
               if cfgnode == None:
                  continue
               #print(f"Checking return values {bufferInitialSource[1]}") 
               sources = self.IRgetSourceForRegDef(c, cfgnode, bufferInitialSource[1], filter, None, 0, bb)
               for s in sources:
                   if s[0] == "global":
                      #print(f"Sources for reg {bufferInitialSource[1]} {s[0]} {hex(s[1])}")
                      stemps = self.IRresolveImplicitPointers(c, s[1], filter)
                      for stemp in stemps:
                          results.add(stemp)
                   #else:
                   #   print(f"Sources for reg {bufferInitialSource[1]} {s[0]} {s[1]}")
                   results.add(s)
               #if bufferInitialSource[1] == "r0":
               #   res2 = self.IRfindReturnValuesofPredecessorCallsites(c, bb, cfgnode, "r0")
               #   for r in res2:
               #       results.add(r) 

        return results 


    def IRfindExplicitCalleeBBs(self, f, callee):
        print(f"Finding explicit callee bbs in {f.name} for callee {callee.name}")
        results = set()
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
                #bb.vex.pp()
            except angr.errors.SimEngineError:
                continue
            print(f"\tCall {hex(bb.addr)} {bb.vex.next} (callee {callee.name} addr {hex(callee.addr)}) within {f.name}")
            if not isinstance(bb.vex.next,pyvex.IRExpr.Const):
               continue
            if not bb.vex.next.con._value == callee.addr and not bb.vex.next.con._value == callee.addr + 1:
               continue
            print(f"Finding cfgnode for {hex(bb.addr)}")
            cfgnode = self.IRfindCFGNodeForInstruction(f, bb, bb.addr)
            if cfgnode == None:
               continue
            print(f"Explicit bb {hex(bb.addr)} for callee {callee.name}")
            #bb.vex.pp()
            results.add((f, bb, cfgnode))
        return results  

    def IRfindImplicitCalleeBBs(self, f):
        print(f"Finding implicit callee bbs in {f.name}")
        results = set()
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
                #bb.vex.pp()
            except angr.errors.SimEngineError:
                continue
            if not bb.vex.jumpkind == "Ijk_Call":
               continue
            #print(f"\tCall {hex(bb.addr)} {bb.vex.next} within {f.name}")
            if isinstance(bb.vex.next,pyvex.IRExpr.Const):
               continue
            cfgnode = self.IRfindCFGNodeForInstruction(f, bb, bb.addr)
            if cfgnode == None:
               continue
            results.add((f, bb, cfgnode))
        if len(results) == 0:
           for ba in f.block_addrs:
               try:
                   bb = self._project.factory.block(ba)
               except angr.errors.SimEngineError:
                   continue
               if not isinstance(bb.vex.next,pyvex.IRExpr.Const):
                  cfgnode = self.IRfindCFGNodeForInstruction(f, bb, bb.addr)
                  if cfgnode == None:
                     continue                  
                  results.add((f, bb, cfgnode))                                 
        return results  
 
    def IRfindCallerContextCalleeArgSource(self, c, callee, bufferInitialSource, indirect=False, filter=None):
        if isinstance(bufferInitialSource[0], int):
           s = None
           print(f"Length of tuple {len(bufferInitialSource)}")
           if len(bufferInitialSource) == 3:
              s = (bufferInitialSource[1],bufferInitialSource[2]) 
           if len(bufferInitialSource) == 4:
              s = (bufferInitialSource[1],bufferInitialSource[2],bufferInitialSource[3]) 
           if len(bufferInitialSource) == 5:
              s = (bufferInitialSource[1],bufferInitialSource[2],bufferInitialSource[3],bufferInitialSource[4])
           if not s == None:
              print(f"s partial tuple {s}")
              return self.IRfindCallerContextCalleeArgSourceInternal(c, callee, s, indirect, filter)
           else:
              return set()
        else:
           return self.IRfindCallerContextCalleeArgSourceInternal(c, callee, bufferInitialSource, indirect, filter) 


    def IRfindCallerContextCalleeArgSourceInternal(self, c, callee, bufferInitialSource, indirect, filter=None):
        print(f"Checking caller context {c.name} for callee arg source {bufferInitialSource}")
        for ba in c.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            if isinstance(bb.vex.next,pyvex.IRExpr.Const):
               if bb.vex.next.con._value == callee:
                  if bufferInitialSource[1] == "argument":
                     index = len(bb.vex.statements) - 1
                     cfgnode = self.IRfindCFGNodeForStatement(c, bb, index)
                     if cfgnode == None:
                        continue
                     sources = self.IRgetSourceForRegDef(c, cfgnode, bufferInitialSource[1], filter)
                     for s in sources:
                         print(f"Sources for reg {bufferInitialSource[1]} {sources}")
                         if s[0] == "global":
                            return s
        return None  

    def IRgetRegOffset(self, regname):
        if regname == 'r0':
           return 8
        if regname == 'r1':
           return 12
        if regname == 'r2':
           return 16
        if regname == 'r3':
           return 20
        return None

    # in this new version start parameter is not being used, should check calling contexts that use those
    def IRgetSourceForRegDef(self, f, cfgnode, reg, filter=None, visited=None, start=0, obb=None):
        clean = (visited == None)
        if visited == None:
           visited = set()
        if cfgnode.addr in visited:
           return set()
        visited.add(cfgnode.addr)          
        baseregset = self.IRgetBaseRegSetForFunction(f)
        if obb == None:
           bb, min, max = self.IRgetStatementIndexRangeForCFGNode(f, cfgnode)
        else:
           bb, min, max = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(f, cfgnode, obb)
        if bb == None:
           return set() 
        st =  bb.vex.statements[max]
        vm = {}
        regnode = pyvex.IRExpr.Get(self.IRgetRegOffset(reg), "Ity_I32")
        print(f"[IRgetSourceForRegDef] regnode {regnode} from cgnode addr {hex(cfgnode.addr)}")
        sres = self.IRfindAllSourcesofAddress(f, baseregset, cfgnode, bb, st, max, regnode, vm, "", filter)
        print(f"[IRgetSourceForRegDef] result length :{len(sres)}")
        if clean:
           del visited
        return sres
    

    def IRgetSourceForRegDefOld(self, f, cfgnode, reg, filter=None, visited=None, start=0, obb=None):
        clean = (visited == None)
        if visited == None:
           visited = set()
        result = set() 
        if cfgnode.addr in visited:
           return result
        visited.add(cfgnode.addr)          
        baseregset = self.IRgetBaseRegSetForFunction(f)
        if obb == None:
           bb, min, max = self.IRgetStatementIndexRangeForCFGNode(f, cfgnode)
        else:
           bb, min, max = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(f, cfgnode, obb)
        if bb == None:
           return result
        index = max
        if not start == 0 and start <= max: 
           index = start 
        print(f"[Source reg def] bb:")
        bb.vex.pp()
        while index >= min:
              #print(f"start {start} max {max} index {index}") 
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.Put):
                 if reg == 'r0' and self._project.arch.register_names[st.offset] == 'pc':
                    print(f"PC value {st.data}")
                    if isinstance(st.data, pyvex.IRExpr.Const):
                       callee = self.IRgetFunctionAtAddress(st.data.con._value)
                       if not callee == None and self.IRmayReturnAValue(callee):
                          print(f"Checking {callee.name} for return value for r0 within {f.name}") 
                          retvaldefs = self.IRgetReturnValueUltimateDefs(callee, 1, filter)
                          for retvald in retvaldefs:
                              rbba,ri,rn,rc,rev = retvald
                              if isinstance(rn, pyvex.IRExpr.Get):
                                 if self._project.arch.register_names[rn.offset] in ['r0', 'r1', 'r2', 'r3']:
                                    if index - 1 <= min:
                                       tres = self.IRgetDefForUse(func, cfgnode, bb, bb.vex.statements[index-1], index-1, rn, filter, visited, "", 0, 1)
                                    else:
                                       rcfgnode = self.IRfindCFGNodeForStatement(func, bb, index-1)
                                       tres = self.IRgetDefForUse(func, rcfgnode, bb, bb.vex.statements[index-1], index-1, rn, filter, visited, "", 0, 1)
                                    for t in tres:
                                        results.add(t)
                                    del tres
                              elif isinstance(rn, pyvex.IRExpr.Load):
                                   print(f"Load def detected from a callee {callee.name} for {node}")
                                   results.add(retvald) 
                          del retvaldefs
                 if self._project.arch.register_names[st.offset] == reg:
                    print(f"Source of {st.data} in cfgnode {hex(cfgnode.addr)}")
                    cfgnode2 = self.IRfindCFGNodeForStatement(f, bb, index)
                    cres = set()
                    if isinstance(st.data, pyvex.IRExpr.Const):
                       results = set()
                       results.add(("global", st.data.con._value, str(st)))
                       #return results
                    v = set() 
                    ds = self.IRgetDefForUse(f, cfgnode2, bb, st, index, st.data, filter, v)
                    for d in ds:
                        dbba, di, dn, dc, ev = d
                        print(f"Source from def use {d}")
                        if cfgnode.addr == 0x4020cd:
                           print(f"node {dn} )))))))))))))))))))))))))))))))))))))))))))))))))))))))))))")
                        if isinstance(dn, pyvex.IRExpr.Load) or isinstance(dn, pyvex.IRStmt.LoadG):
                           if isinstance(dn.addr, pyvex.IRExpr.Const):
                              la = dn.addr.con._value
                              try:
                                   value = self._project.loader.memory.load(la, 4)
                                   value = int.from_bytes(value, byteorder='little')
                              except KeyError:
                                   continue
                              cres.add(("global",value,ev))
                              dbb = self._project.factory.block(dbba)
                              dst = dbb.vex.statements[di]
                              dcfgnode = self.IRfindCFGNodeForStatement(f, dbb, di)
                              # find uses of tmp in case it may be used to store the real buffer source
                              # in some field of the global source
                              if not isinstance(dst, pyvex.IRStmt.WrTmp):
                                 continue
                              #dbb.vex.pp()
                              #print(f"Statement whose rhs is load ({dn}): {dst}")
                              #self.IRprintBBs(f)                                                            
                              iuses = self.IRgetUsesInFunction(f, dcfgnode, dbb, dst, di, "t" + str(dst.tmp))
                              for use in iuses:
                                  ubba, ust, ui, un, uother, uev = use
                                  # if the data in the source happens to be an arg or a global then record this
                                  ubb = self._project.factory.block(ubba)
                                  ucfgnode = self.IRfindCFGNodeForStatement(f, ubb, ui)
                                  #print(f"Use of global {hex(value)} : {use}")
                                  if str(ust.addr) == str(un):
                                     iuvm = {}
                                     iuev = uev
                                     indirectSrcs = self.IRfindAllSourcesofAddress(f, baseregset, ucfgnode, ubb, ust, ui, uother, iuvm, iuev, filter)
                                     del iuvm
                                     for isrc in indirectSrcs:
                                         #print(f"Indirect source {isrc} recorded to a field of global source {hex(value)}")
                                         cres.add(isrc)  
                    #if len(cres) > 0:
                    #   return cres 
                    vm = {}
                    ev = ""
                    sres = self.IRfindAllSourcesofAddress(f, baseregset, cfgnode2, bb, st, index, st.data, vm, ev, filter)
                    del vm
                    for s in sres:
                        print(f"Source from all sources {s}")
                        cres.add(s)
                    ev2 = "" 
                    ures = self.IRgetDefUseUltimate(f, cfgnode2, bb, st, index, st.data, ev2, filter) 
                    for u in ures:
                        ubba, ui, un, uc, uev = u
                        print(f"Source from def use ultimate {u}")
                        if isinstance(un, pyvex.IRExpr.Get):
                           cres.add(("argument", self._project.arch.register_names[un.offset], uev))
                    return cres
              index -= 1
        preds = self.IRfindImmediatePredsInFunction(f, cfgnode, bb, filter)
        for p in preds:    
            pred, pbb, pmin, pmax = p
            #v = set()
            #for vis in visited:
            #    v.add(vis)
            res = self.IRgetSourceForRegDef(f, pred, reg, filter, visited, start)
            for r in res:
                result.add(r)
        if clean:
           del visited
        return result 

    def IRanonymizeEvidence(self, ev):
        result = ""
        mtokens = ev.splitlines()
        for mtoken in mtokens:
           stokens = mtoken.split(self._TUPLEDELIMITER)
           if len(stokens) == 1:
              continue  
           target = stokens[-1]
           delimiters = r'[ =(),]'
           tokens = re.split(delimiters, target)
           for t in tokens:
               if not t.startswith("t"):
                  result += t
        return result
        
    def IRstringifyPattern(self, pattern):
        if len(pattern) == 0:
           return ""
        result = '['
        i = 0
        while i < len(pattern):
              if isinstance(pattern[i], str):
                 result += pattern[i];
              else:
                 result += str(pattern[i])
              if not i == len(pattern) - 1:
                 result += ','
              i += 1
        result += ']'
        return result

    def IRdestringifyPattern(self, patternstr):
        if patternstr == "":
           return []
        pattern = []
        tokens = patternstr.split(',')
        i = 0
        while i < len(tokens):
              tstr = tokens[i]  
              if '[' in tstr:
                  tstr = tstr.split('[')[1]
              if ']' in tstr:
                  tstr = tstr.split(']')[0]
              if not tstr == "Load" and not "r" in tstr and not "cc" in tstr and not 'sp' in tstr:
                 pattern.append(int(tstr))
              else:
                 pattern.append(tstr)
              i += 1
        return pattern

    def IRprintBBs(self, f):
        print(f"BBs of function at {hex(f.addr)} {f.name}") 
        for ba in f.block_addrs:
            try:
               bb = self._project.factory.block(ba)
               #index = 0
               #while index < len(bb.vex.statements):
               #      st = bb.vex.statements[index]
               #      if isinstance(st, pyvex.IRStmt.LoadG):
               #         print(f"LoadG child exps")
               #         for ce in st.child_expressions:
               #             print(f"Child {ce}")
               #      index += 1
            except angr.errors.SimEngineError:
               continue
            bb.vex.pp()

    # argreg, (const or L)*
    def IRfindBufferAssignments(self, pattern, bufferSources, bufassign, filter=None):
       #pattern = ["r0", 8, "Load", 80, "Load"]
       # find functions and basic blocks with the constants 
       # constants do not need to span the same bb
       cfs = None
       i = 0
       while i < len(pattern):
           if isinstance(pattern[i], int):
              if cfs == None:
                 cfs = self.IRgetFunctionsWithConstant(pattern[i])
              else:
                 tmp = set()
                 for f in cfs:
                     if self.IRisFunctionWithConstant(f, pattern[i]):
                        tmp.add(f)
                 cfs = tmp 
           i += 1
       print(f"Num functions with constants in pattern: {len(cfs)}")
       for f in cfs:
           print(f"{f.name}")
       for f in cfs:
           #if not f.name == "spi_stm32_transceive":
           #   continue
           #self.IRfindSourcesOfStoreAddresses(f)
           #return
           baseregset = self.IRgetBaseRegSetForFunction(f)
           if len(baseregset) == 0:
              baseregset.add('sp')
              baseregset.add('r7')              
           print(f"Baseregset {baseregset} function {f.name}")
           #self.IRprintBBs(f)
           print(f"FINDING ASSIGNMENTS in {f.name}")
           candidates = set()
           i = 0
           while i < len(pattern):
                 if isinstance(pattern[i], int):
                    tmp = self.IRgetBBsSubsWithConstant(f, pattern[i])
                    for t in tmp:
                        candidates.add(t)
                 i += 1
           subuses = set()
           for source in candidates:
               ddb, dindex, dsub, do = source
               st = ddb.vex.statements[dindex]
               cfgnode = self.IRfindCFGNodeForStatement(f, ddb, dindex)
               if not isinstance(st, pyvex.IRStmt.WrTmp):
                  continue
               if cfgnode == None:
                  continue
               #ddb.vex.pp()
               #print(f"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ GETTING uses of t{str(st.tmp)}")
               uses = self.IRgetUsesInFunction(f, cfgnode, ddb, st, dindex, "t" + str(st.tmp))
               for use in uses:
                   ubba, ust, ui, un, uother, uev = use
                   #print(f"USE: {hex(ubba)} statement {ust} index {ui} use {un} other {uother} {uev}")
                   subuses.add(use)
           print(f"Size of subuses {len(subuses)}")
           # Cluster subuses and analyze just one for each cluster
           useMap = {}
           for use in subuses:
               ubba, ust, ui, un, uother, uev = use
               if isinstance(ust.data, pyvex.IRExpr.Const):
                  continue
               anon = self.IRanonymizeEvidence(uev)
               if not "Add" in anon:
                  continue
               if not anon in useMap.keys():
                  useMap[anon] = set()
               useMap[anon].add(use)
               #print(f"((((((((((((((( ANON {anon} \n {use}")
           print(f"Number of clustered uses {len(useMap)}")
           for useKey in useMap:
               if len(useMap[useKey]) == 0:
                  continue
               # choose a representative
               use = None
               for u in useMap[useKey]:
                   use = u
                   break
               ubba, ust, ui, un, uother, uev = use
               try:
                   bb = self._project.factory.block(ubba)
               except angr.errors.SimEngineError:
                   continue
               vm = {}
               ev = ""
               cfgnode = self.IRfindCFGNodeForStatement(f, bb, ui)
               instaddr = self.IRInstructionAddress(bb, ui)
               print(f"Finding cfgnode for {hex(instaddr)} in {hex(bb.addr)} index {ui} {ust}")               
               if not cfgnode == None:
                  print(f"Finding address source for {hex(cfgnode.addr)} in {hex(bb.addr)} index {ui} {ust}")
                  #continue
                  self._comprehensiveDefUse = True
                  aps = self.IRfindAllSourcesofAddress(f, baseregset, cfgnode, bb, ust, ui, ust.addr, vm, ev, filter)
                  del vm
                  self._comprehensiveDefUse = False
                  for ap in aps:
                      evid = ap[-1]
                      ep = self.IRextractPattern(evid)
                      print(f"Function {f.name} pattern {pattern} vs evidence pattern {ep}")
                      if self.IRmatchesPatternExceptFirst(ep, pattern):
                         vm2 = {}
                         ev2 = "" 
                         self._comprehensiveDefUse = True
                         bas = self.IRfindAllSourcesofAddress(f, baseregset, cfgnode, bb, ust, ui, ust.data, vm2, ev2, filter)
                         del vm2 
                         self._comprehensiveDefUse = False
                         for ba in bas:
                             if len(ba) == 3:
                                #bpattern = self.IRextractPattern(ba[2])
                                print(f"Buffer source in function {f.name} {ba[0]} {ba[1]}")
                                #print(f"Buffer pattern: {ba[2]}")
                                bufassign.add((f.addr, ba[0], ba[1], ba[2]))
                             if len(ba) == 4:
                                #bpattern = self.IRextractPattern(ba[3])
                                print(f"Buffer source in function {f.name} {ba[0]} {ba[1]} {ba[2]}")
                                #print(f"Buffer pattern: {ba[3]}")
                                bufassign.add((f.addr, ba[0], ba[1], ba[2], ba[3]))

     
    def IRfindSourcesOfStoreAddresses(self, f, filter=None):
        min, max = self.IRgetFunctionAddressRange(f)
        baseregset = self.IRgetBaseRegSetForFunction(f)
        for ba in f.block_addrs:
            if not ba == 0x800608b:
               continue
            bb = self._project.factory.block(ba)         
            #bb.vex.pp()
            #bb.pp()
            index = 0
            instaddr = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.IMark):
                     instaddr = st.addr
                  #if not instaddr == 0x8006096 and not instaddr == 0x8006097:
                  #if not instaddr == 0x800608e and not instaddr == 0x800608f:
                  #   index += 1
                  #   continue
                  print(f"Statement {st} address {hex(instaddr)} function min address {hex(min)} max address {hex(max)}")
                  if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                     if not isinstance(st.data, pyvex.IRExpr.Const):
                        cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
                        if not cfgnode == None:
                           print(f"Finding address source for {hex(cfgnode.addr)} in {hex(bb.addr)} inst address {hex(instaddr)} index {index} {st}")
                           vm = {}
                           ev = ""
                           self._comprehensiveDefUse = True
                           aps = self.IRfindAllSourcesofAddress(f, baseregset, cfgnode, bb, st, index, st.addr, vm, ev, filter)
                           del vm 
                           self._comprehensiveDefUse = False
                           for ap in aps:
                               evid = ap[-1]
                               print(f"Function {f.name}  inst address {hex(instaddr)} evidence pattern {self.IRextractPattern(evid)} {evid}")
                  index += 1
                         
    def IRextractPattern(self, evidence):
        pattern = []
        tokens = self.IRtokenizeEvidence(evidence) 
        index = len(tokens) - 1
        offset = 0
        while index >= 0:
              subtokens = tokens[index].split(',')
              if len(subtokens) < 5:
                 break
              length = len(subtokens)
              node = subtokens[length-2]
              o = int(subtokens[length-1].split(')')[0])
              if "GET" in node and index == len(tokens) - 1:
                 reg = node.split("=")[-1]
                 reg = int(reg.split(")")[0])
                 if reg in self._project.arch.register_names.keys():
                    pattern.append(self._project.arch.register_names[reg])
              elif "LD" in node:
                 pattern.append(offset)
                 offset = 0
                 pattern.append("Load")
              if o > offset:
                 offset = o
              index -= 1
        pattern.append(offset)
        #print(f"$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ Pattern {pattern} for evidence {evidence}") 
        return pattern

    def IRtokenizeEvidence(self, evidence):
        temp = evidence.splitlines()
        result = []
        index = 0
        while index < len(temp):
            if not temp[index] == "":
               result.append(temp[index])
            index += 1
        return result

    def IRfindStatementIndex(self, bb, pst):
        index = 0
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.IMark):
                 addr = st.addr
              if str(pst) == str(st):
                 return index
              index += 1
        return None

    def IRInstructionAddress(self, bb, sindex):
        index = 0
        addr = 0
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.IMark):
                 addr = st.addr
              if index == sindex:
                 return addr
              index += 1
        return 0

    def IRmatchesPatternExceptFirst(self, p1, p2):
        tp1 = []
        i = 0
        while i < len(p1):
              if not i == 0:
                 tp1.append(p1[i])
              i += 1
        tp2 = []
        i = 0
        while i < len(p2):
              if not i == 0:
                 tp2.append(p2[i])
              i += 1
        stp1 = self.IRstringifyPattern(tp1) 
        stp2 = self.IRstringifyPattern(tp2) 
        return stp1 == stp2

    def IRmatchesPattern(self, evidence, pattern):
        if len(pattern) == 0:
           return False
        tokens = self.IRtokenizeEvidence(evidence)
        #print(f"Tokens {tokens}")
        index = len(tokens) - 1
        current = 0
        offset = 0
        seen = set()
        while index >= 0:
              subtokens = tokens[index].split(',')
              #print(f"subtokens {subtokens}")
              if len(subtokens) < 5:
                 break
              length = len(subtokens)
              node = subtokens[length-2]
              if str(node) in seen:
                 seen.add(str(node))
                 index -= 1
                 continue
              seen.add(str(node))  
              o = int(subtokens[length-1].split(')')[0])
              #print(f"Node {node} current offset {offset} pattern entry {current}")    
              if o > offset:
                 offset = o
              if "GET" in node and current == 0:
                 reg = node.split("=")[-1]
                 reg = int(reg.split(")")[0])
                 if reg in self._project.arch.register_names.keys():
                    if self._project.arch.register_names[reg] == pattern[current]:         
                       current += 1
              elif "LD" in node:
                 if current >= len(pattern):
                    return False
                 if offset == pattern[current]:
                    offset = 0
                    current += 1
                    if pattern[current] == "Load":
                       current += 1
                    else:
                       return False
                 else:
                    return False
              index -= 1
        if current == len(pattern):
           return True
        return False  
                
    def IRgetUsesInFunctionNode(self, func, cfgnode, bb, ost, index, node, visited, evidence, depth=0):
        #print(f"{hex(bb.addr)} {index} {ost} {node}")
        if depth > self._usesDepthBound:
           return set()
        if not isinstance(node, pyvex.IRExpr.RdTmp) and not isinstance(node, pyvex.IRStmt.Put) and not isinstance(node, str):
           return set()
        if "Cmp" in str(ost) or "calculate" in str(ost):
            return set()
        if (bb.addr, str(node), index) in visited:
           return set()
        #bb.vex.pp()  
        result = set()
        visited.add((bb.addr, str(node), index))
        #pbb, pmin, pmax = self.IRgetStatementIndexRangeForCFGNode(func, cfgnode)
        pbb, pmin, pmax = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(func, cfgnode, bb)
        i = index
        while i <= pmax:
             st = pbb.vex.statements[i]
             if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                if str(st.addr) == str(node):
                   ev = evidence
                   ev += "\n(%s%s%d%s%s)\n" % (hex(bb.addr), self._TUPLEDELIMITER, i, self._TUPLEDELIMITER, st)
                   #print(f"Evidence: {evidence}")
                   result.add((bb.addr, st, i, st.addr, st.data, ev))
                else:
                   if isinstance(st.data, pyvex.IRExpr.RdTmp):
                      if str(st.data) == str(node):
                         ev = evidence
                         ev += "\n(%s%s%d%s%s)\n" % (hex(bb.addr), self._TUPLEDELIMITER, i, self._TUPLEDELIMITER, st)
                         #print(f"Evidence: {evidence}")
                         result.add((bb.addr, st, i, st.data, st.addr, ev))
                   elif isinstance(st.data, pyvex.IRExpr.Load) or isinstance(st.data, pyvex.IRStmt.LoadG):
                      if str(st.data.addr) == str(node):
                         ev = evidence                        
                         ev += "\n(%s%s%d%s%s)\n" % (hex(bb.addr), self._TUPLEDELIMITER, i, self._TUPLEDELIMITER, st)
                         #print(f"Evidence: {evidence}")
                         result.add((bb.addr, st, i, st.data.addr, st.addr, ev))
                   else:   
                      for ce in st.data.child_expressions:
                          if str(node) == str(ce):
                             ev = evidence
                             ev += "\n(%s%s%d%s%s)\n" % (hex(bb.addr), self._TUPLEDELIMITER, i, self._TUPLEDELIMITER, st)
                             #print(f"Evidence: {evidence}")
                             result.add((bb.addr, st, i, ce, st.addr, ev))
             elif isinstance(st, pyvex.IRStmt.WrTmp):
                if isinstance(st.data, pyvex.IRExpr.RdTmp):
                   if str(st.data) == str(node):
                      ev = evidence
                      ev += "\n(%s%s%d%s%s)\n" % (hex(bb.addr), self._TUPLEDELIMITER, i, self._TUPLEDELIMITER, st)
                      res = self.IRgetUsesInFunctionNode(func, cfgnode, bb, st, i, "t" + str(st.tmp), visited, ev, depth + 1)
                      for r in res:
                          result.add(r)
                elif isinstance(st.data, pyvex.IRExpr.Get):
                     if isinstance(node, pyvex.IRStmt.Put):
                        if st.data.offset == node.offset:
                           ev = evidence                           
                           ev += "\n(%s%s%d%s%s)\n" % (hex(bb.addr), self._TUPLEDELIMITER, i, self._TUPLEDELIMITER, st)
                           res = self.IRgetUsesInFunctionNode(func, cfgnode, bb, st, i, "t" + str(st.tmp), visited, ev, depth + 1)
                           for r in res:
                               result.add(r)                            
                elif isinstance(st.data, pyvex.IRExpr.Load) or isinstance(st.data, pyvex.IRStmt.LoadG):
                     if str(st.data.addr) == str(node):
                        ev = evidence                           
                        ev += "\n(%s%s%d%s%s)\n" % (hex(bb.addr), self._TUPLEDELIMITER, i, self._TUPLEDELIMITER, st)
                        res = self.IRgetUsesInFunctionNode(func, cfgnode, bb, st, i, "t" + str(st.tmp), visited, ev, depth + 1)
                        for r in res:
                            result.add(r)                            
                else:
                   for ce in st.data.child_expressions:
                      if str(node) == str(ce):
                         ev = evidence
                         ev += "\n(%s%s%d%s%s)\n" % (hex(bb.addr), self._TUPLEDELIMITER, i, self._TUPLEDELIMITER, st)
                         res = self.IRgetUsesInFunctionNode(func, cfgnode, bb, st, i, "t" + str(st.tmp), visited, ev, depth + 1)
                         for r in res:
                             result.add(r)
             elif isinstance(st, pyvex.IRStmt.Put):
                if isinstance(st.data, pyvex.IRExpr.RdTmp):
                   if str(st.data) == str(node):
                      ev = evidence
                      ev += "\n(%s%s%d%s%s)\n" % (hex(bb.addr), self._TUPLEDELIMITER, i, self._TUPLEDELIMITER, st)
                      res = self.IRgetUsesInFunctionNode(func, cfgnode, bb, st, i, st, visited, ev, depth + 1)
                      for r in res:
                          result.add(r)
                elif isinstance(st.data, pyvex.IRExpr.Load) or isinstance(st.data, pyvex.IRStmt.LoadG):
                     if str(st.data.addr) == str(node):
                        ev = evidence                           
                        ev += "\n(%s%s%d%s%s)\n" % (hex(bb.addr), self._TUPLEDELIMITER, i, self._TUPLEDELIMITER, st)
                        res = self.IRgetUsesInFunctionNode(func, cfgnode, bb, st, i, st, visited, ev, depth + 1)
                        for r in res:
                            result.add(r)                            
                else:
                   for ce in st.data.child_expressions:
                      if str(node) == str(ce):
                         ev = evidence
                         ev += "\n(%s%s%d%s%s)\n" % (hex(bb.addr), self._TUPLEDELIMITER, i, self._TUPLEDELIMITER, st)
                         res = self.IRgetUsesInFunctionNode(func, cfgnode, bb, st, i, st, visited, ev, depth + 1)
                         for r in res:
                             result.add(r)
             i += 1
        if len(result) > 0 and i >= len(pbb.vex.statements) and not isinstance(node, pyvex.IRStmt.Put):
           return result
        succs = self.IRfindImmediateSuccsInFunction(func, cfgnode, bb)
        for s in succs:
            succ, sbb, smin, smax = s
            if sbb == None:
               continue
            if not sbb.addr == bb.addr and isinstance(node, pyvex.IRExpr.RdTmp):
               continue
            sst = sbb.vex.statements[smin]
            ev = evidence
            if self._comprehensiveDefUse:
               vn = set()
               for v in visited:
                   vn.add(v)
               res = self.IRgetUsesInFunctionNode(func, succ, sbb, sst, smin, node, vn, ev, depth + 1)
            else:
               res = self.IRgetUsesInFunctionNode(func, succ, sbb, sst, smin, node, visited, ev, depth + 1)
            for r in res:
                result.add(r)
        return result

    def IRgetUsesInFunction(self, func, cfgnode, bb, st, index, node, visited=None):
           if not func.addr in self._usesInFunction.keys():
              self._usesInFunction[func.addr] = {}
           if (bb.addr, str(node), index) in self._usesInFunction[func.addr].keys():
               return self._usesInFunction[func.addr][(bb.addr, str(node), index)]
           clean = (visited == None)
           if visited == None:
              visited = set()
           ev = ""
           res = self.IRgetUsesInFunctionNode(func, cfgnode, bb, st, index, node, visited, ev)
           self._usesInFunction[func.addr][(bb.addr, str(node), index)] = res
           if clean:
              del visited 
           return res

    def IRgetFunctionSize(self, name):
        for f in self._current_cfg.functions.values():
            if f.name == name:
               return f.size
        return 0

    def IRgetFunctionOfInstruction(self, pc):
        maxaddr = 0
        maxf = None
        for f in self._current_cfg.functions.values():
            min, max = self.IRgetFunctionAddressRange(f)
            if pc >= min - 1 and pc <= max:
               if min > maxaddr:
                  #print(f"[Function of instruction] min {hex(min)} max {hex(max)} pc {hex(pc)} f {f.name} addr {hex(f.addr)}")
                  maxaddr = min
                  maxf = f
        return maxf

    def IRgetFunctionsOfInstruction(self, pc):
        results = set()    
        for f in self._current_cfg.functions.values():
            min, max = self.IRgetFunctionAddressRange(f)
            if pc >= min - 1 and pc <= max:
               #print(f"[Function of instruction] min {hex(min)} max {hex(max)} pc {hex(pc)} f {f.name} addr {hex(f.addr)}")
               results.add(f)
        return results

    def IRgetFunctionsWithConstant(self, constantValue):
        result = set()
        for f in self._current_cfg.functions.values():
            if self.IRisFunctionWithConstant(f, constantValue):
               #print(f"Function with constant offset {constantValue} {hex(f.addr)} {f.name}") 
               result.add(f)
        return result  

    def IRisFunctionWithConstant(self, func, constantValue):
        for ba in func.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            index = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.WrTmp):
                     sub, o = self.IRgetOffsetAndSubForNode(bb, st.data)
                     if not sub == None and not o == None: 
                        if o == constantValue:
                           return True
                  index += 1   
        return False    

    def IRgetStatementWithConstant(self, bb, constantValue, min, max):
        result = set()
        index = min
        while index <= max:
             st = bb.vex.statements[index]
             if isinstance(st, pyvex.IRStmt.WrTmp):
                sub, o = self.IRgetOffsetAndSubForNode(bb, st.data)
                if not sub == None and not o == None:
                   if o == constantValue:
                      result.add((bb, index, sub))
             index += 1
        return result

     
    def IRgetBBsWithConstant(self, func, constantValue):
        result = set()
        for ba in func.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            index = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.WrTmp):
                     sub, o = self.IRgetOffsetAndSubForNode(bb, st.data)
                     if not sub == None and not o == None: 
                        if o == constantValue:
                           result.add(bb)
                           break
                  index += 1   
        return result         

    def IRisBBWithConstant(self, bb, constantValue):
        index = 0
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.WrTmp):
                 sub, o = self.IRgetOffsetAndSubForNode(bb, st.data)
                 if not sub == None and not o == None: 
                    if o == constantValue:
                       return True
              index += 1   
        return False         

    
    def IRgetBBsSubsWithConstant(self, func, constantValue):
        result = set()
        for ba in func.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            index = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.WrTmp):
                     sub, o = self.IRgetOffsetAndSubForNode(bb, st.data)
                     if not sub == None and not o == None: 
                        if o == constantValue:
                           result.add((bb, index, sub, o))
                           break
                  index += 1   
        return result         

    def IRisArgDefined(self, func, bb, cfgnode, argno):
        if not cfgnode.addr in self._defInCFGNodeForReg.keys():
           self._defInCFGNodeForReg[cfgnode.addr] = {}
        if argno in self._defInCFGNodeForReg[cfgnode.addr].keys():
           return self._defInCFGNodeForReg[cfgnode.addr][argno]
        pbb, pmin, pmax = self.IRgetStatementIndexRangeForCFGNode(func, cfgnode)
        index = pmin
        while index <= pmax:
              #print(f"cfgnode {hex(cfgnode.addr)} index {index} {pmin},{pmax} bb max {len(bb.vex.statements)}")
              st = pbb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.Put):
                 if self._project.arch.register_names[st.offset] == argno:
                    self._defInCFGNodeForReg[cfgnode.addr][argno] = True
                    return True 
              index += 1
        self._defInCFGNodeForReg[cfgnode.addr][argno] = False
        return False

    def IRisArgDefinedFrom(self, func, bb, index, halArgNo):
        cfgnode = self.IRfindCFGNodeForStatement(func, bb, index)
        if cfgnode == None:
           return False
        preds = self.IRfindAllPredsInFunction(func, cfgnode)
        for pred in preds:
            if self.IRisArgDefined(func, bb, pred, halArgNo):
               return True
        return False
            
    def IRfindArgSourceFrom(self, caller, baseregset, bb, callsiteIndex, halArgNo, limit=4, filter=None):
        result = set()
        args = ['r0', 'r1', 'r2', 'r3']
        argseen = set()
        index = callsiteIndex
        while index >= 0:
              if len(result) >= 4:
                 break
              #print(f"index: {index} bb {len(bb.vex.statements)}")
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.Put):
                 reg = self._project.arch.register_names[st.offset] 
                 if reg in args and not reg in argseen:
                    argseen.add(self._project.arch.register_names[st.offset])
                    visitedMap = {}
                    evidence = ""
                    cfgnode = self.IRfindCFGNodeForStatement(caller, bb, index)
                    if not cfgnode == None:
                       dss = self.IRfindAllSourcesofAddress(caller, baseregset, cfgnode, bb, st, index, st.data, visitedMap, evidence, filter)
                       del visitedMap
                       for ds in dss:
                           if len(ds) == 3:
                              t, o, e = ds
                              #print(f"ARG TYPE {t} argno {o} vs {halArgNo}")                
                              if t == "argument" and o == halArgNo:
                                 result.add(reg)
                           if len(ds) == 4:
                              t, o, dtsof, e = ds
                              #print(f"ARG TYPE {t} argno {o} vs {halArgNo}")                
                              if t == "argument" and o == halArgNo:
                                 result.add(reg)       
              index -= 1
        return result

    def IRfindCFGNodeForInstruction(self, func, bb, addr):
        if func.addr in self._instCFGNodeMap.keys():
           if addr in self._instCFGNodeMap[func.addr]:
              return self._instCFGNodeMap[func.addr][addr] 
        nodes = set()
        an = self._current_cfg.get_all_nodes(addr)
        for a in an:
            nodes.add(a)    
        an = self._current_cfg.get_any_node(addr)
        if not an == None:
           nodes.add(an)    
        an = self._current_cfg.get_all_nodes(addr + 1)
        for a in an:
            nodes.add(a)    
        an = self._current_cfg.get_any_node(addr + 1)
        if not an == None:
           nodes.add(an)    
        if len(nodes) == 0:
           an = self._current_cfg.get_all_nodes(bb.addr)
           for a in an:
               nodes.add(a)    
           an = self._current_cfg.get_any_node(bb.addr)
           if not an == None:
              nodes.add(an)    
        #print(f"!!!!!! Number of nodes for addr {hex(addr)}: {len(nodes)} !!!!!")
        #for node in nodes:
        #    print(f"\t\tBasic block {hex(node.block_id)} for node {hex(node.addr)}")
        maxpred = None
        max = 0 
        for node in nodes:
            predstr = ""
            numpreds = 0
            try:
                preds = self._current_cfg.get_all_predecessors(node, self._predDepth)
                if len(preds) >= max:
                   maxpred = node
                   max = len(preds)
                   #print(f"\t\tBasic block maxpred {hex(maxpred.block_id)} for node {hex(maxpred.addr)}")        
                for pred in preds:
                    predstr += " %s" % (hex(pred.addr))  
            except RecursionError:
                numpreds = -1
            numpreds = len(preds)
            #print(f"\t\tBasic block {hex(node.block_id)} for node {hex(node.addr)} with predecessors {predstr}")
        if not func.addr in self._instCFGNodeMap.keys():
           self._instCFGNodeMap[func.addr] = {}
        self._instCFGNodeMap[func.addr][addr] = maxpred
        return maxpred 
        #for cfgnode in nodes:
        #    cbb, min, max = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(func, cfgnode, bb)
        #    if not min == None and not max == None:
        #       return cfgnode
        #return None
    


    def IRfindCFGNodeForStatement(self, func, bb, index, oldcfgnode=None):
        ia = self.IRfindPCFromStatementIndex(func, bb, index)
        if not oldcfgnode == None:
           f1 = (ia >= cfgnode.addr and ia < cfgnode.addr + cfgnode.size)
           f2 = (ia + 1 >= cfgnode.addr and ia + 1 < cfgnode.addr + cfgnode.size)
           if f1 or f2:
              return oldcfgnode
        min, max = self.IRgetBBAddressRange(bb) 
        nodes = set()
        for st in bb.vex.statements:
            if isinstance(st, pyvex.IRStmt.IMark):
               an = self._current_cfg.get_all_nodes(st.addr)
               for a in an:
                   #print(f"Node {hex(a.addr)} for {hex(st.addr)} size {a.size}")
                   nodes.add(a)    
               an = self._current_cfg.get_any_node(st.addr)
               if not an == None:
                  #print(f"Node {hex(an.addr)} for {hex(st.addr)} size {an.size}")
                  nodes.add(an)    
               an = self._current_cfg.get_all_nodes(st.addr + 1)
               for a in an:
                   #print(f"Node {hex(a.addr)} for {hex(st.addr + 1)} size {a.size}")
                   nodes.add(a)    
               an = self._current_cfg.get_any_node(st.addr + 1)
               if not an == None:
                  #print(f"Node {hex(an.addr)} for {hex(st.addr + 1)} size {an.size}")
                  nodes.add(an)
        #print(f"\t!!!!!! Number of nodes for statement {bb.vex.statements[index]}: {len(nodes)} !!!!!")
        maxbbaddr = 0
        maxbbnode = None
        maxnodeaddr = 0
        #for node in nodes:
        #    print(f"\t\t\tCFGNODE {hex(node.addr)} for {hex(bb.addr)} range [{hex(min)},{hex(max)}] size {node.size}")
        for node in nodes:
            temp = self.IRgetBBsForCFGNode(func, node)
            #print(f"\tNum bbs of cfgnode {hex(node.addr)}: {len(temp)}")
            for tba in temp:
                withinbb = node.addr >= min and node.addr < max
                withinnode = (ia >= node.addr and ia < node.addr + node.size) or (ia + 1 >= node.addr and ia + 1 < node.addr + node.size)
                #print(f"\t\tbb addr {hex(tba.addr)} maxbb {hex(maxbbaddr)} maxcfgn {hex(maxnodeaddr)} node {hex(node.addr)} node max {hex(node.addr + node.size)} min {hex(min)} max {hex(max)} pc {hex(ia)} withinbb? {withinbb} withinnode? {withinnode}")
                if tba.addr > maxbbaddr and node.addr > maxnodeaddr and withinbb and withinnode:
                   maxbbaddr = tba.addr
                   maxnodeaddr = node.addr
                   maxbbnode = node
        #if maxbbnode == None:
        #   bb.vex.pp()
        #print(f"\t\tCHOSEN: node {hex(maxbbnode.addr)}")        
        if maxbbnode == None:
           # last resort when cfgnode size values are not computed accurately
           lastnode = None 
           i = 0
           while i < len(bb.vex.statements):
                 st = bb.vex.statements[i]
                 if isinstance(st, pyvex.IRStmt.IMark):
                    if st.addr <= ia:
                       an = self._current_cfg.get_any_node(st.addr)
                       if not an == None:
                          lastnode = an 
                       else:
                          an = self._current_cfg.get_all_nodes(st.addr)
                          for a in an:
                              lastnode = a
                              break 
                          if len(an) == 0:
                             an = self._current_cfg.get_any_node(st.addr + 1)
                             if not an == None:
                                lastnode = an
                             else:
                                an = self._current_cfg.get_all_nodes(st.addr + 1)
                                for a in an:
                                    lastnode = a
                                    break
                    else:
                       break 
                 i += 1
           #print(f"lastnode {hex(lastnode.addr)}")
           return lastnode            
        return maxbbnode 

    def IRfindDefForStackLocation(self, func, baseregset, stackoffset, evidence, reg="sp", filter=None):
        #print(f"[IRfindDefForStackLocation] {stackoffset}")
        results = set()
        for ba in func.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            index = 0
            while index < len(bb.vex.statements):
                st = bb.vex.statements[index]
                if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                   if not isinstance(st.data, pyvex.IRExpr.Const):
                      cfgnode = self.IRfindCFGNodeForStatement(func, bb, index)
                      if not cfgnode == None:
                         # read from data register
                         evcopy = evidence 
                         dtuples = self.IRgetDefUseUltimate(func, cfgnode, bb, st, index, st.addr, evcopy, filter)
                         for dtuple in dtuples:
                             dbba, di, dn, dc, ev = dtuple
                             dbb = self._project.factory.block(dbba)
                             dst = dbb.vex.statements[di]
                             if dc == stackoffset:
                                #print(f"Local var address node: ({hex(dbba)},{di},{dst},{dn},{dc}) reg {reg} vs {self._project.arch.register_names[dn.offset]}")
                                if isinstance(dn, pyvex.IRExpr.Get):
                                   if reg == self._project.arch.register_names[dn.offset]:
                                      results.add((bb.addr, index, st.data, 0, ev))   
                index += 1
        return results  

    def IRfindDefForStackLocationFromCFGNode(self, func, baseregset, ocfgnode, stackoffset, evidence, reg="sp", filter=None):
        #print(f"[IRfindDefForStackLocation] {stackoffset}")
        results = set()
        targetcfgnodes = self.IRfindAllPredsInFunction(func, ocfgnode, filter)
        for tcfgnode in targetcfgnodes:
            bb, bmin, bmax = self.IRgetStatementIndexRangeForCFGNode(func, tcfgnode)
            index = bmin
            while index <= bmax:                                                   
                st = bb.vex.statements[index]
                if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                   if not isinstance(st.data, pyvex.IRExpr.Const):
                      cfgnode = tcfgnode
                      if not cfgnode == None:
                         # read from data register
                         evcopy = evidence
                         evcopy += "\n(%s,%d,%s,%s)\n" % (hex(bb.addr),index,st,st.addr) 
                         dtuples = self.IRgetDefUseUltimate(func, cfgnode, bb, st, index, st.addr, evcopy, filter)
                         for dtuple in dtuples:
                             dbba, di, dn, dc, ev = dtuple
                             dbb = self._project.factory.block(dbba)
                             dst = dbb.vex.statements[di]
                             if dc == stackoffset:
                                #print(f"Local var address node: ({hex(dbba)},{di},{dst},{dn},{dc}) reg {reg} vs {self._project.arch.register_names[dn.offset]}")
                                if isinstance(dn, pyvex.IRExpr.Get):
                                   if reg == self._project.arch.register_names[dn.offset]:
                                      results.add((bb.addr, index, st.data, 0, ev))
                         del dtuples 
                index += 1
        del targetcfgnodes
        return results  

    def IRfindImmediateSuccsInFunction(self, func, cfgnode, bb):
        min, max = self.IRgetFunctionAddressRange(func)
        succs = self._current_cfg.get_all_successors(cfgnode, self._predDepth)
        results = set()
        alternatives = set()
        for succ in succs:
            if succ.addr < min - 1 or succ.addr > max:
               continue
            sbb, smin, smax = self.IRgetStatementIndexRangeForCFGNode(func, succ)
            results.add((succ, sbb, smin, smax))
        return results   

    
    def IRisBBAccessingMemory(self, bb):
        index = 0
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                 return True
              if isinstance(st, pyvex.IRStmt.WrTmp):
                 if isinstance(st, pyvex.IRExpr.Load):
                    return True
              index += 1
        return False

    def IRfindExplicitlyCalledFunctions(self):
        results = set()
        for func in self._current_cfg.functions.values():
            for ba in func.block_addrs:
                try:
                    bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                    continue
                if bb.vex.jumpkind == "Ijk_Call":
                   if isinstance(bb.vex.next, pyvex.IRExpr.Const):
                      if bb.vex.next.con._value == func.addr or bb.vex.next.con._value == func.addr - 1 or bb.vex.next.con._value == func.addr + 1:
                         results.add(func.addr)
        return results

    def IRexpandFilterBBs(self, bbs):
        IRfindAllPredsInFunction(self, func, cfgnode)

    def IRfindImmediatePredsInFunction(self, func, cfgnode, bb, filter=None):
        #if func.addr in self._skipPredComputationForFunction.keys():
        #   print(f"Skipping preds computation for {func.name} since no explicit calls!!!")
        #   return set()
        if bb == None:
           return set()
        if self._optimizePreds:
           return self.IRfindClosestPredInFunction(func, cfgnode, bb, filter)
        if cfgnode.addr == func.addr:
           return set()
        min, max = self.IRgetFunctionAddressRange(func)
        #print(f"Finding all preds of {hex(cfgnode.addr)}")
        results = set()
        try:
            preds = self._current_cfg.get_all_predecessors(cfgnode, self._predDepth)
        except RecursionError:
            print(f"Recursion error in IRfindImmediatePredsInFunction for {hex(cfgnode.addr)} within {func.name}")
            if not func.addr in self._skipPredComputationForFunction.keys():
               self._skipPredComputationForFunction[func.addr] = set()
            self._skipPredComputationForFunction[func.addr].add(cfgnode.addr) 
            return results
        alternatives = set()
        eliminated = []
        reason = ""
        for pred in preds:
            if not filter == None:
               if not (pred.addr in filter or pred.addr - 1 in filter):
                  ebbs = self.IRgetBBsForCFGNode(func, pred)
                  bbwitoutmemaccess = False
                  for ebb in ebbs:
                      if not self.IRisBBAccessingMemory(ebb):
                         bbwitoutmemaccess = True
                         break
                  if not bbwitoutmemaccess:  
                     #print(f"\tSkipping {hex(pred.addr)} curr {hex(cfgnode.addr)}")
                     reason += " Not in filter %s " % (hex(pred.addr))
                     eliminated.append(pred)
                     continue
                  del ebbs 
            #print(f"\tpred {hex(pred.addr)} min {hex(min)} max {hex(max)}")
            if pred.addr < min - 1 or pred.addr > max:
               #print(f"Skipping {hex(pred.addr)} out of function address range [{hex(min)},{hex(max)}]")
               reason += " Not in function range %s vs [%s, %s] for function %s " % (hex(pred.addr), hex(min), hex(max), func.name)
               eliminated.append(pred)
               continue
            pbb, pmin, pmax = self.IRgetStatementIndexRangeForCFGNode(func, pred)
            if pbb == None:
               #print(f"\tNone bb returned by IRgetStatementIndexRangeForCFGNode")
               reason += " None returned for statement range"
               eliminated.append(pred)
               continue
            if not bb.addr == pbb.addr and pbb.vex.jumpkind == "Ijk_Ret":
               #print(f"------------------------------------ SKIPPING RETURN {hex(pred.addr)} for {hex(cfgnode.addr)}")
               reason += " Pred is a return site"
               eliminated.append(pred)
               continue
            #if not cfgnode.addr == bb.addr and not pbb.addr == bb.addr:
            #   if self.IRcfgnodeCoveredByPred(func, cfgnode, pred):
            #      alternatives.add((pred,pbb, pmin, pmax))
            #   print(f"------------------------------------ SKIPPING ALTERNATIVE {hex(pred.addr)} for {hex(cfgnode.addr)}")
            #   continue
            #print(f"Predecessor {hex(pred.addr)} curr {hex(cfgnode.addr)}")
            results.add((pred, pbb, pmin, pmax))
        if len(results) == 0 and len(alternatives) > 0:
           return alternatives
        if len(results) == 0:
           temp = self.IRgetBBsForCFGNode(func, cfgnode)
           #print(f"Num bbs of cfgnode {hex(cfgnode.addr)}: {len(temp)}")
           for tba in temp:
               #print(f"bb addr {hex(tba.addr)}")
               bbcnodes = self._current_cfg.get_all_nodes(tba.addr)
               for bbcnode in bbcnodes:
                   #print(f"bb's cfgnode {hex(bbcnode.addr)}")
                   if not filter == None:
                      if not (bbcnode.addr in filter or bbcnode.addr - 1 in filter):
                         #print(f"\t\t\tNot in filter: {hex(bbcnode.addr)}")
                         continue 
                   pbb, pmin, pmax = self.IRgetStatementIndexRangeForCFGNode(func, bbcnode)
                   results.add((bbcnode, pbb, pmin, pmax))
               del bbcnodes
           del temp
           #if cfgnode.addr == 0x40a997:
           #   allnodes = self._current_cfg.get_all_nodes(cfgnode.addr)
           #   print(f"Number of nodes: {len(allnodes)}")
           #   for node in allnodes:
           #       nbb = self._project.factory.block(node.block_id)
           #       if nbb == None:
           #          print(f"node {hex(node.addr)} block_addr {hex(node.block_id)} bb none")
           #       else: 
           #          print(f"node {hex(node.addr)} block_addr {hex(node.block_id)} bb {hex(nbb.addr)}")
           #   temp = self.IRgetBBsForCFGNode(func, cfgnode)
           #   print(f"Num bbs of cfgnode {hex(cfgnode.addr)}: {len(temp)}")
           #   for tba in temp:
           #       print(f"bb addr {hex(tba.addr)}")
           #       bbcnodes = self._current_cfg.get_all_nodes(tba.addr)
           #       for bbcnode in bbcnodes:
           #           print(f"\tcfgnode {hex(bbcnode.addr)} for the bb")
        #if len(results) == 0:
        #   print(f"No Predecessors of {hex(cfgnode.addr)}")
        #   if cfgnode.addr == 0x40a83b: 
        #          estr = ""
        #          for el in eliminated:
        #              estr += " %s" % (hex(el.addr))
        #              ebbs = self.IRgetBBsForCFGNode(func, el)
        #              for ebb in ebbs:
        #                  print(f"~~~~~~~~~~~~~ ELIMINATED PRED ~~~~~~~~~~~~~~~~~~")
        #                  ebb.vex.pp() 
        #                  print(f"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        #          print(f"Eliminated: {estr} reason {reason}")                   
        #if len(results) == 1:
        #   for res in results:
        #       estr = ""
        #       for el in eliminated:
        #           estr += " %s" % (hex(el.addr))
        #           ebbs = self.IRgetBBsForCFGNode(func, el)
        #            for ebb in ebbs:
        #                print(f"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        #                ebb.vex.pp() 
        #                print(f"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        #       print(f"eliminated: {estr} reason {reason}")   
        #       if res[0].addr == cfgnode.addr:
        #          print(f"Self-cycle through a single pred for cfgnode {hex(cfgnode.addr)}, eliminated: {estr} reason {reason}")                   
        #predstr = ""
        #for res in results:
        #    predstr += " %s" % (hex(res[0].addr))
        #print(f"Preds of {hex(cfgnode.addr)}: {predstr}")
        #if reason != "":
        #   print(f"Reason omitted for preds of {hex(cfgnode.addr)}: {reason}")
        return results   
 

    def IRfindClosestPredInFunction(self, func, cfgnode, bb, filter=None):
        min, max = self.IRgetFunctionAddressRange(func)
        results = set()
        try:
           preds = self._current_cfg.get_all_predecessors(cfgnode, self._predDepth)
        except RecursionError:
           return results
        alternatives = set()
        for pred in preds:
            if not filter == None:
               if not (pred.addr in filter or pred.addr - 1 in filter):
                  #print(f"Skipping {hex(pred.addr)} curr {hex(cfgnode.addr)}")
                  continue
            if pred.addr < min - 1 or pred.addr > max:
               continue
            pbb, pmin, pmax = self.IRgetStatementIndexRangeForCFGNode(func, pred)
            if not bb.addr == pbb.addr and pbb.vex.jumpkind == "Ijk_Ret":
               continue
            if not cfgnode.addr == bb.addr and not pbb.addr == bb.addr:
               if self.IRcfgnodeCoveredByPred(func, cfgnode, pred):
                  alternatives.add((pred, pbb, pmin, pmax))
               continue
            #print(f"Predecessor {hex(pred.addr)} curr {hex(cfgnode.addr)}")
            results.add((pred, pbb, pmin, pmax))
        #print(f"Unoptimized preds: {len(results)} alternatives: {len(alternatives)}")
        if len(results) == 0 and len(alternatives) > 0:
           i = 0
           for alt in alternatives:
               results.add(alt)
               i += 1
               if i >= self._optimizedMaxPred:
                  break
           return results
        if len(results) > 0:
           i = 0
           subset = set()
           for r in results:
               subset.add(r)
               i += 1
               if i >= self._optimizedMaxPred:
                  break
           return subset
        if len(results) == 0:
           print(f"No Predecessors of {hex(cfgnode.addr)}")         
        return results   
           
    def IRfindAllPredsInFunction(self, func, cfgnode, filter=None):
        bb = self.IRgetBasicBlockForCFGNode(func, cfgnode)
        #if self._optimizePreds:
        #   return self.IRfindClosestPredInFunction(func, cfgnode, bb
        preds = self.IRfindImmediatePredsInFunction(func, cfgnode, bb, filter)
        result = set()
        visited = set() 
        while len(preds) > 0:
            predt = preds.pop()
            pred, pbb, pmin, pmax = predt
            result.add(pred)
            visited.add(pred.addr)   
            npreds = self.IRfindImmediatePredsInFunction(func, pred, pbb, filter)
            for npredt in npreds:
                npred, npbb, npmin, npmax = npredt
                if not npred.addr in visited:
                   preds.add(npredt)
                   visited.add(npred.addr)
                   result.add(npred)
        #print(f"Size of all preds: {len(result)}")
        del visited
        return result
        # old implementation that could not be configured easily
        min, max = self.IRgetFunctionAddressRange(func)
        #print(f"Function range min {hex(min)} max {hex(max)}")
        bb, bmin, bmax = self.IRgetStatementIndexRangeForCFGNode(func, cfgnode)
        result = set()
        try:
            preds = self._current_cfg.get_all_predecessors(cfgnode, self._predDepth)
        except RecursionError:
            return result
        visited = set() 
        for pred in preds:
            if not filter == None:
               if not (pred.addr in filter or pred.addr - 1 in filter):
                  #print(f"Skipping {hex(pred.addr)} curr {hex(cfgnode.addr)}")
                  continue
            if pred.addr < min - 1 or pred.addr > max:
               continue
            pbb, pmin, pmax = self.IRgetStatementIndexRangeForCFGNode(func, pred)
            if not bb.addr == pbb.addr and pbb.vex.jumpkind == "Ijk_Ret":
               # this should not be possible but for some reason angr gives such infeasble preds
               continue
            #print(f"Predecessor {hex(pred.addr)} curr {hex(cfgnode.addr)}")
            result.add(pred)
            visited.add(pred.addr)
        preds = set()
        for r in result:
            preds.add(r)
        while len(preds) > 0:
            current = preds.pop()
            if current.addr < min - 1  or current.addr > max:
               continue
            bb, bmin, bmax = self.IRgetStatementIndexRangeForCFGNode(func, current)
            try:
                tpreds = self._current_cfg.get_all_predecessors(current, self._predDepth)
            except RecursionError:
                continue 
            for tpred in tpreds:
                if not filter == None:
                   if not (tpred.addr in filter or pred.addr - 1 in filter):
                      #print(f"Skipping {hex(pred.addr)} curr {hex(cfgnode.addr)}")
                      continue
                if tpred.addr < min - 1 or tpred.addr > max:
                   continue
                pbb, pmin, pmax = self.IRgetStatementIndexRangeForCFGNode(func, tpred)
                if not bb.addr == pbb.addr and pbb.vex.jumpkind == "Ijk_Ret":
                   # this should not be possible but for some reason angr gives such infeasble preds
                   continue 
                if not tpred.addr in visited:
                   #print(f"Predecessor2 {hex(pred.addr)} curr {hex(cfgnode.addr)}")
                   preds.add(tpred)
                   visited.add(tpred.addr)
                   result.add(tpred)
        if len(results) == 0:
           print(f"No Predecessors of {hex(cfgnode.addr)}")
        del visited
        return result

    def IRfindDefForStackLocationFromCFGNode(self, func, baseregset, ocfgnode, stackoffset, evidence, reg="sp", filter=None):
        #print(f"[IRfindDefForStackLocationFromCFGNode] {stackoffset} {hex(ocfgnode.addr)}")
        results = set()
        targetcfgnodes = self.IRfindAllPredsInFunction(func, ocfgnode, filter)
        #for ba in func.block_addrs:
        for tcfgnode in targetcfgnodes:
            #try:
            #   bb = self._project.factory.block(ba)
            #except angr.errors.SimEngineError:
            #   continue
            bb, bmin, bmax = self.IRgetStatementIndexRangeForCFGNode(func, tcfgnode)
            index = bmin
            while index <= bmax:
                st = bb.vex.statements[index]
                if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                   #print(f"Tracing from {st} at {hex(tcfgnode.addr)}")
                   if not isinstance(st.data, pyvex.IRExpr.Const):
                      #cfgnode = self.IRfindCFGNodeForStatement(func, bb, index)
                      cfgnode = tcfgnode 
                      if not cfgnode == None:
                         # read from data register
                         evcopy = evidence 
                         dtuples = self.IRgetDefUseUltimate(func, cfgnode, bb, st, index, st.addr, evcopy, filter)
                         for dtuple in dtuples:
                             dbba, di, dn, dc, ev = dtuple
                             dbb = self._project.factory.block(dbba)
                             dst = dbb.vex.statements[di]
                             if dc == stackoffset:
                                #print(f"Local var address node: ({hex(dbba)},{di},{dst},{dn},{dc}) reg {reg} vs {self._project.arch.register_names[dn.offset]}")
                                if isinstance(dn, pyvex.IRExpr.Get):
                                   if reg == self._project.arch.register_names[dn.offset]:
                                      results.add((bb.addr, index, st.data, 0, ev))   
                index += 1
        return results  

    def IRupdateAllSourcesDepthOnEnter(self):
        if self._allsourcedepth == None:
           self._allsourcedepth = 0
        else:
           self._allsourcedepth += 1           
        

    def IRupdateAllSourcesDepthOnExit(self):
        if self._allsourcedepth == 0:
           self._allsourcedepth = None
        else: 
           self._allsourcedepth -= 1           
 
    def IRgetReturnBBs(self, f):
        results = set()
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            if bb.vex.jumpkind == "Ijk_Ret":
               results.add(bb)
        return results

    def IRgetReturnBBAddresses(self, f):
        results = set()
        num = 0
        lastbb = None
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            lastbb = bb
            num += 1
            if bb.vex.jumpkind == "Ijk_Ret":
               results.add(bb.addr)
            #print(f"Is a return bb of {f.name}?")
            #bb.vex.pp()
        if len(results) == 0 and num == 1:
           results.add(lastbb.addr)
        return results

    def IRgetReturnValueDefsOld(self, f, ccdepth, filter=None):
        baseregset = self.IRgetBaseRegSetForFunction(f)
        #if not f.addr in self._functionRetDefs.keys():
        #   self._functionRetDefs[f.addr] = set()  
        #else:
        #   return self._functionRetDefs[f.addr] 
        results = set()
        retcfgns = self.IRmayReturnAValue(f)
        for r in retcfgns:
            rbb, ri = r
            cfgnode = self.IRfindCFGNodeForStatement(f, rbb, ri)
            if cfgnode == None:
               print(f"Warning: Could not find for {hex(rbb.addr)} index {ri}")
               rbb.vex.pp()  
            rst = rbb.vex.statements[ri]
            v = set()
            #print(f"Return value def checking for st {rst} cfgnode {hex(cfgnode.addr)} in function {f.name}")
            tres = self.IRgetDefForUse(f, cfgnode, rbb, rst, ri, rst.data, filter, v, "", 0, ccdepth)
            for res in tres:
                results.add(res)
            del v
            del tres
        del retcfgns
        #self._functionRetDefs[f.addr] = results
        return results 

    def IRgetReturnValueUltimateDefs(self, f, ccdepth, filter=None):
        baseregset = self.IRgetBaseRegSetForFunction(f)
        if not f.addr in self._functionRetUltimateDefs.keys():
           self._functionRetUltimateDefs[f.addr] = set()  
        else:
           return self._functionRetUltimateDefs[f.addr] 
        results = set()
        retcfgns = self.IRmayReturnAValue(f)
        for r in retcfgns:
            rbb, ri = r
            cfgnode = self.IRfindCFGNodeForStatement(f, rbb, ri)
            rst = rbb.vex.statements[ri]
            v = set()
            vU = set()
            #print(f"Return value def checking for st {rst} cfgnode {hex(cfgnode.addr)} in function {f.name}")
            tres = self.IRgetDefUseUltimate(f, cfgnode, rbb, rst, ri, rst.data, "", filter, v, vU, 0, ccdepth)
            for res in tres:
                results.add(res)
            del v
            del tres
        del retcfgns
        self._functionRetUltimateDefs[f.addr] = results
        return results 

    def IRgetGetExprForReg(self, f, reg, visited=None):
        for ba in f.block_addrs:
            try:  
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            index = 0
            while index <len(bb.vex.statements):
                st = bb.vex.statements[index]
                if isinstance(st, pyvex.IRStmt.WrTmp):
                   if isinstance(st.data, pyvex.IRExpr.Get): 
                      if st.data.offset in self._project.arch.register_names.keys() and self._project.arch.register_names[st.data.offset] == reg:
                         return st.data
                index += 1
        # it is ok to find it from any function
        if visited == None:
           visited = set()
        visited.add(f.addr)
        res = self.IRgetGetExprForRegFromAnyFunction(reg, visited)
        del visited
        return res
  
    def IRgetReturnValueDefForBB(self, f, ccdepth, rbb, filter=None): 
        results = set()
        node = self.IRgetGetExprForReg(f, 'r0')
        ri = len(rbb.vex.statements) - 1
        cfgnode = self.IRfindCFGNodeForStatement(f, rbb, ri)
        if cfgnode == None:
           print(f"Warning: Could not find for {hex(rbb.addr)} index {ri}")
           rbb.vex.pp()  
        rst = rbb.vex.statements[ri]
        v = set()
        #print(f"Return value def checking for st {rst} cfgnode {hex(cfgnode.addr)} in function {f.name}")
        tres = self.IRgetDefForUse(f, cfgnode, rbb, rst, ri, node, filter, v, "", 0, ccdepth)
        for res in tres:
            results.add((rbb, cfgnode, res))
        del v
        #self._functionRetDefs[f.addr] = results
        return results 

    def IRgetGetExprForRegFromAnyFunction(self, reg, visited):
        for f in self._current_cfg.functions.values():
            if f.addr in visited:
               continue
            visited.add(f.addr)
            node = self.IRgetGetExprForReg(f, reg, visited)
            if not node == None:
               return node
        return None 



    def IRgetReturnValueDefs(self, f, ccdepth, filter=None): 
        results = set()
        rbbs = self.IRgetReturnBBs(f)
        node = self.IRgetGetExprForReg(f, 'r0')
        for rbb in rbbs:
            ri = len(rbb.vex.statements) - 1
            cfgnode = self.IRfindCFGNodeForStatement(f, rbb, ri)
            if cfgnode == None:
               print(f"Warning: Could not find for {hex(rbb.addr)} index {ri}")
               rbb.vex.pp()  
            rst = rbb.vex.statements[ri]
            v = set()
            #print(f"Return value def checking for st {rst} cfgnode {hex(cfgnode.addr)} in function {f.name}")
            tres = self.IRgetDefForUse(f, cfgnode, rbb, rst, ri, node, filter, v, "", 0, ccdepth)
            for res in tres:
                results.add((rbb, cfgnode, res))
            del v
            del tres
        del rbbs
        #self._functionRetDefs[f.addr] = results
        return results 


    def RDmerge(self, result, rd):
        for o in rd.keys():
            if not o in result.keys():
               result[o] = set()
            for t in rd[o]:
               result[o].add(t)    

    def IRgetReturnValueReachingDefs(self, f): 
        print(f"[IRgetReturnValueReachingDefs]")
        rmap = {}
        results = {}
        rbbs = self.IRgetReturnBBs(f)
        node = self.IRgetGetExprForReg(f, 'r0')
        for rbb in rbbs:
            ri = len(rbb.vex.statements) - 1
            cfgnode = self.IRfindCFGNodeForStatement(f, rbb, ri)
            if cfgnode == None:
               print(f"Warning: Could not find for {hex(rbb.addr)} index {ri}")
               rbb.vex.pp()  
            rst = rbb.vex.statements[ri]
            #print(f"Return value def checking for st {rst} cfgnode {hex(cfgnode.addr)} in function {f.name}")
            temp = self.RDgetReachingDefsForCFGNodeDefs(f, rbb, cfgnode, ri, rst, node)
            if not cfgnode.addr in rmap.keys():
               rmap[cfgnode.addr] = set()
            for to in temp.keys():
                for td in temp[to]:
                    rmap[cfgnode.addr].add((rbb, cfgnode, td))  
            print(f"len of temp: {len(temp)}")
            self.RDmerge(results, temp)  
        del rbbs
        #self._functionRetDefs[f.addr] = results
        return rmap, results 
     

    def IRgetReturnValueSources(self, f, baseregset, filter=None):
        if not f.addr in self._functionRetSources.keys():
           self._functionRetSources[f.addr] = set()  
        else:
           return self._functionRetSources[f.addr] 
        results = set()   
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            if bb.vex.jumpkind == "Ijk_Ret":
               # find the most recent definitions of r0
               cfgnode = self.IRfindCFGNodeForStatement(f, bb, len(bb.vex.statements) - 1)
               rdefs = self.IRgetRegDefiningNode(f, cfgnode, bb, 'r0', filter)
               for r in rdefs:
                  rcfnode, rbb, ri, rn = r
                  rst = rbb.vex.statements[ri]
                  vm = {}
                  srcs = self.IRfindAllSourcesofAddress(f, baseregset, rcfnode, rbb, rst, ri, rn, vm, "", filter, True)
                  for src in srcs:
                      results.add(src)
        self._functionRetSources[f.addr] = results
        return results 

    #@profile
    # three types of sources: ("argument", regname), ("global", constantaddress), ("stack", offset) 
    # case: address == Load(Get(reg) + offset)
    def IRfindAllSourcesofAddress(self, func, baseregset, cfgnode, bb, st, index, node, visitedMap, evidence, filter=None, comprehensive=True):
        result = set()
        self.IRupdateAllSourcesDepthOnEnter()
        if self._allsourcedepth > 2 * self._allsourcedepthBound:
           self.IRupdateAllSourcesDepthOnExit()
           return result
        hash = self.UtilgetHashList([bb.addr, index])
        if not func.addr in visitedMap.keys():
           visitedMap[func.addr] = set()
        if hash in visitedMap[func.addr]:
           self.IRupdateAllSourcesDepthOnExit()
           return result
        #self.DebugShowGlobalSizes()
        #print(f"[IRfindAllSourcesofAddress] DEPTH: {self._allsourcedepth} {node} cfgnode {hex(cfgnode.addr)} bb {hex(bb.addr)} st {st} index {index} map id {id(visitedMap)}")
        #bb.vex.pp() 
        visitedMap[func.addr].add(hash)
        evcopy0 = evidence
        # The simplest case of arg being a source
        r0s = self.IRgetDefUseUltimate(func, cfgnode, bb, st, index, node, evcopy0, filter)
        args = ['r0', 'r1', 'r2', 'r3']
        for r0 in r0s:
            rdda, ri, rn, rc, re = r0
            #print(f"Potential base case for ult. def of {st},{node},{hex(cfgnode.addr)},{hex(bb.addr)} source {r0}")
            if isinstance(rn, pyvex.IRExpr.Get):
               if self._project.arch.register_names[rn.offset] in args:
                  #print(f"Detected an arg source: {self._project.arch.register_names[rn.offset]} ev1: {evcopy0} ev2: {re}")
                  result.add(("argument", self._project.arch.register_names[rn.offset], re)) 
               else:
                  result.add(("stack", rc, re))
            if isinstance(rn, pyvex.IRExpr.Load) or isinstance(rn, pyvex.IRStmt.LoadG):
               if isinstance(rn.addr, pyvex.IRExpr.Const):
                  if rn.addr.con._value >= self._minRAM:
                     result.add(("global", rn.addr.con._value, re)) 
                  else:                 
                     try:
                         value = self._project.loader.memory.load(rn.addr.con._value, 4)
                     except KeyError:
                         continue
                     value = int.from_bytes(value,byteorder='little')
                     result.add(("global", value, re))                      
        del r0s 
        if comprehensive:
           evcopy1 = evidence
           if self._allsourcedepth > self._allsourcedepthBound:
              r1s = self.IRfindSourcesofAddressFromAddressStoredInLocal(func, baseregset, cfgnode, bb, st, index, node, visitedMap, evcopy1, filter)
           else:
              vm1 = {}
              r1s = self.IRfindSourcesofAddressFromAddressStoredInLocal(func, baseregset, cfgnode, bb, st, index, node, vm1, evcopy1, filter)
              del vm1
           for r1 in r1s:
               result.add(r1)
           del r1s
           evcopy2 = evidence
           r2s = self.IRfindSourcesofAddressFromIndirectAddressStoredInLocal(func, cfgnode, bb, st, index, node, evcopy2, filter)
           for r2 in r2s:
               #print(f"RESULTS from [IRfindSourcesofAddressFromIndirectAddressStoredInLocal] {r2}")
               result.add(r2)
           del r2s
           evcopy3 = evidence
           if self._allsourcedepth > self._allsourcedepthBound:
              r3s = self.IRfindSourcesofAddressInHandlerField(func, baseregset, cfgnode, bb, st, index, node, visitedMap, evcopy3, filter)
           else:
              vm2 = {}
              r3s = self.IRfindSourcesofAddressInHandlerField(func, baseregset, cfgnode, bb, st, index, node, vm2, evcopy3, filter)
              del vm2
           for r3 in r3s:
               #print(f"RESULTS from [IRfindSourcesofAddressInHandlerField] {r3}")
               result.add(r3) 
           del r3s
        self.IRupdateAllSourcesDepthOnExit()
        return result 

    def IRfindSourceOfLocalOffset(self, func, baseregset, offset, reg, visitedMap, evidence, filter=None):
        #print(f"[IRfindSourceOfLocalOffset] {offset}")
        result = set() 
        lsrc = self.IRfindDefForStackLocation(func, baseregset, offset, evidence, reg, filter)
        for src in lsrc:
            sbba, si, sn, so, ev = src
            sbb = self._project.factory.block(sbba)
            scfgnode = self.IRfindCFGNodeForStatement(func, sbb, si)
            #print(f"Source of local offset {src} {scfgnode} for {hex(sbb.addr)} index {si}")
            if scfgnode == None:
               continue
            sst = sbb.vex.statements[si]
            #print(f"From [IRfindSourceOfLocalOffset] {offset}")
            lss = self.IRfindAllSourcesofAddress(func, baseregset, scfgnode, sbb, sst, si, sn, visitedMap, ev, filter)           
            for ls in lss:
                result.add(ls)
        return result

    def IRfindSourceOfLocalOffsetFromCFGNode(self, func, baseregset, cfgnode, offset, reg, visitedMap, evidence, filter=None):
        #self.DebugShowGlobalSizes()
        #print(f"[IRfindSourceOfLocalOffsetFromCFGNode] {offset} {hex(cfgnode.addr)}")
        result = set() 
        hash = self.UtilgetHashList([cfgnode.addr, offset])    
        if not func.addr in visitedMap.keys():
           visitedMap[func.addr] = {}
        if hash in visitedMap[func.addr]:
           return result
        visitedMap[func.addr].add(hash)
        lsrc = self.IRfindDefForStackLocationFromCFGNode(func, baseregset, cfgnode, offset, evidence, reg, filter)
        for src in lsrc:
            sbba, si, sn, so, ev = src
            sbb = self._project.factory.block(sbba)
            scfgnode = self.IRfindCFGNodeForStatement(func, sbb, si)
            #print(f"Source of local offset {src} {scfgnode} for {hex(sbb.addr)} index {si}")
            if scfgnode == None:
               continue
            sst = sbb.vex.statements[si]
            print(f"From [IRfindSourceOfLocalOffsetFromCFGNode] {offset}")
            lss = self.IRfindAllSourcesofAddress(func, baseregset, scfgnode, sbb, sst, si, sn, visitedMap, ev, filter)
            for ls in lss:
                result.add(ls)
            del lss
        del lsrc 
        return result


    # case 0: address == Get(reg) + offset0
    def IRfindSourcesofAddressFromLocalOrArg(self, func, cfgnode, bb, st, index, node, visitedMap, evidence, filter=None):
        args = ['r0', 'r1', 'r2', 'r3']
        dts = self.IRgetDefUseUltimate(func, cfgnode, bb, st, index, node, evidence, filter)
        for dt in dts:
            dbba, di, dn, dc, ev = dt
            dbb = self._project.factory.block(dbba)
            dst = dbb.vex.statements[di]
            #print(f"Address source for {node} at {index} {hex(bb.addr)}: ({hex(dbba)},{dst},{di},{dn},{dc})")
            if isinstance(dn,pyvex.IRExpr.Get):
               if self._project.arch.register_names[dn.offset] in args:
                  if dc == 0:
                     result.add(("argument", self._project.arch.register_names[dn.offset], ev))
                  else: 
                     result.add(("argument", self._project.arch.register_names[dn.offset], dc, ev))
                  #print(f"!!!!!!!!!!!!!!!! ARGUMENT {self._project.arch.register_names[dn.offset]} !!!!!!!!!!!!!!!!!!!!!!")
               if "sp" == self._project.arch.register_names[dn.offset]:
                  if dc < 0:
                     lss = self.IRfindSourceOfLocalOffsetFromCFGNode(func, baseregset, cfgnode, dc, "sp", visitedMap, ev, filter)
                     for ls in lss:
                         if len(ls) == 3:
                            t, o, e = ls 
                            #print(f"(Original) Address source for {node} at {index} {hex(bb.addr)}: ({hex(dbba)},{dst},{di},{dn},{dc})")
                            #print(f"!!!!!!!!!!!!!!!!!!! SP offset indirect {o} !!!!!!!!!!!!!!!!!!!!!!!")
                         elif len(ls) == 4:
                            t, o, dtoff, e = ls 
                            #print(f"(Original) Address source for {node} at {index} {hex(bb.addr)}: ({hex(dbba)},{dst},{di},{dn},{dc})")
                            #print(f"!!!!!!!!!!!!!!!!!!! SP offset indirect {o} !!!!!!!!!!!!!!!!!!!!!!!")
                         result.add(ls)
                  else: 
                     result.add(("stack", dc, ev))
                     #print(f"!!!!!!!!!!!!!!!!!!!!! SP offset {dc} def ultimate for {node} : {dn} !!!!!!!!!!!!!!!!!!!!!!!!!")
               if "r7" == self._project.arch.register_names[dn.offset]:
                  if dc < 0:
                     lss = self.IRfindSourceOfLocalOffsetFromCFGNode(func, baseregset, cfgnode, dc, "r7", visitedMap, ev, filter)
                     for ls in lss:
                         if len(ls) == 3:
                            t, o, e = ls  
                            #print(f"!!!!!!!!!!!!!!!!! R7 offset {o} !!!!!!!!!!!!!!!!!!!!!!")
                         elif len(ls) == 4:
                            t, o, dtoff, e = ls  
                            #print(f"!!!!!!!!!!!!!!!!! R7 offset {o} !!!!!!!!!!!!!!!!!!!!!!")
                         result.add(ls)
                  else: 
                     result.add(("stack", dc, ev))                  
                     #print(f"!!!!!!!!!!!!!!!!! R7 offset {dc} def ultimate for {node} : {dn} !!!!!!!!!!!!!!!!!!!!!!")
        return result


    # case 1: address == Load(Get(reg) + offset)
    def IRfindSourcesofAddressFromAddressStoredInLocal(self, func, baseregset, cfgnode, bb, st, index, node, visitedMap, evidence, filter=None):
        #self.DebugShowGlobalSizes() 
        #print(f"[IRfindSourcesofAddressFromAddressStoredInLocal] bb {hex(bb.addr)} cfgnode {hex(cfgnode.addr)} node {node} map id {id(visitedMap)}")
        result = set()
        hash = self.UtilgetHashList([bb.addr, index])
        if not func.addr in visitedMap.keys():
           visitedMap[func.addr] = set()
        if hash in visitedMap[func.addr]:
           return result
        visitedMap[func.addr].add(hash)
        args = ['r0', 'r1', 'r2', 'r3']
        dts = self.IRgetLoadAddressDefUltimate(func, cfgnode, bb, st, index, node, evidence, None, filter)
        for dt in dts:
            dbba, di, dn, dc, ev = dt
            dbb = self._project.factory.block(dbba)
            dst = dbb.vex.statements[di]
            #print(f"Address source {node} at {index} {hex(bb.addr)}: ({hex(dbba)},{dst},{di},{dn},{dc})")
            if isinstance(dn, pyvex.IRExpr.Const):
               if dn.con._value >= self._minRAM:
                  result.add(("global",dn.con._value, ev)) 
                  print(f"!!!!!!!!!!!!!!!! GLOBAL {dn.con._value} !!!!!!!!!!!!!!!!!!!!!!")
            if isinstance(dn,pyvex.IRExpr.Get):
               if self._project.arch.register_names[dn.offset] in args:
                  if dc == 0:
                     result.add(("argument", self._project.arch.register_names[dn.offset], ev))
                  else:
                     result.add(("argument", self._project.arch.register_names[dn.offset], dc, ev))
                  print(f"!!!!!!!!!!!!!!!! ARGUMENT {self._project.arch.register_names[dn.offset]} !!!!!!!!!!!!!!!!!!!!!!")
               if "sp" == self._project.arch.register_names[dn.offset]:
                  if dc < 0:
                     lss = self.IRfindSourceOfLocalOffsetFromCFGNode(func, baseregset, cfgnode, dc, "sp", visitedMap, ev, filter)
                     for ls in lss:
                         if len(ls) == 3:
                            t, o, e = ls 
                            print(f"(Original) Address source {node} at {index} {hex(bb.addr)}: ({hex(dbba)},{dst},{di},{dn},{dc})")
                            print(f"!!!!!!!!!!!!!!!! SP offset indirect {o} !!!!!!!!!!!!!!!!")
                         elif len(ls) == 4:
                            t, o, dtoff, e = ls 
                            print(f"(Original) Address source {node} at {index} {hex(bb.addr)}: ({hex(dbba)},{dst},{di},{dn},{dc})")
                            print(f"!!!!!!!!!!!!!!!! SP offset indirect {o} !!!!!!!!!!!!!!!!")
                         result.add(ls)
                     del lss
                  else: 
                     result.add(("stack", dc, ev))
                     print(f"!!!!!!!!!!!!!!!! SP offset {dc} def ultimate for {node} : {dn} !!!!!!!!!!!!!!!!")
               if "r7" == self._project.arch.register_names[dn.offset]:
                  if dc < 0:
                     lss = self.IRfindSourceOfLocalOffsetFromCFGNode(func, baseregset, cfgnode, dc, "r7", visitedMap, ev, filter)
                     for ls in lss:
                         if len(ls) == 3:
                            t, o, e = ls  
                            print(f"!!!!!!!!!!!!!!!! R7 offset {o} !!!!!!!!!!!!!!!!")
                         elif len(ls) == 4:
                            t, o, dtoff, e = ls  
                            print(f"!!!!!!!!!!!!!!!! R7 offset {o} !!!!!!!!!!!!!!!!")
                         result.add(ls)
                     del lss
                  else: 
                     result.add(("stack", dc, ev))                  
                     print(f"!!!!!!!!!!!!!!!! R7 offset {dc} def ultimate for {node} : {dn} !!!!!!!!!!!!!!!!")
        del dts
        return result

    # case 2: address == Load(Load(Get(basereg) + offset)) + dtoffset)
    def IRfindSourcesofAddressFromIndirectAddressStoredInLocal(self, func, cfgnode, bb, st, index, node, evidence, filter=None):
        #print(f"[IRfindSourcesofAddressFromIndirectAddressStoredInLocal] {node} {hex(cfgnode.addr)}")
        result = set()
        args = ['r0', 'r1', 'r2', 'r3']
        dts = self.IRgetLoadAddressDef(func, cfgnode, bb, st, index, node, evidence, filter)
        for dt in dts:
            dbba, di, dn, dc, ev = dt
            dbb = self._project.factory.block(dbba)
            #print(f"di {di} dbb {hex(dbb.addr)} len {len(dbb.vex.statements)}") 
            dst = dbb.vex.statements[di]
            cfgnode1 = self.IRfindCFGNodeForStatement(func, dbb, di)
            if cfgnode1 == None:
               continue
            #print(f"Address source1 {node} at {index} {hex(bb.addr)}: ({hex(dbba)},{dst},{di},{dn},{dc})")
            dts2 = self.IRgetLoadAddressDefUltimate(func, cfgnode1, dbb, dst, di, dn, ev, None, filter)
            for dt2 in dts2:
                dbba2, di2, dn2, dc2, ev2 = dt2
                dbb2 = self._project.factory.block(dbba2)
                dst2 = dbb2.vex.statements[di2]
                #print(f"Address source2 for {dn}: ({hex(dbba2)},{dst2},{di2},{dn2},{dc2})")
                if isinstance(dn2, pyvex.IRExpr.Const):
                   if dn2.con._value >= self._minRAM:
                      result.add(("global",dn2.con._value, ev2)) 
                      print(f"!!!!!!!!!!!!!!!! GLOBAL {dn2.con._value} !!!!!!!!!!!!!!!!!!!!!!")
                if isinstance(dn2,pyvex.IRExpr.Get):
                   if self._project.arch.register_names[dn2.offset] in args:
                      if dc2 == 0:
                         result.add(("argument", self._project.arch.register_names[dn2.offset], ev2))
                      else:
                         result.add(("argument", self._project.arch.register_names[dn2.offset], dc2, ev2))
                      print(f"!!!!!!!!!!!!!!!! ARGUMENT {self._project.arch.register_names[dn2.offset]} ({dc2} {dc}) !!!!!!!!!!!!!!!!!!!!!!")
                   if "sp" == self._project.arch.register_names[dn2.offset]:
                      if dc2 >= 0:
                         result.add(("stack", dc2, ev2))
                         print(f"!!!!!!!!!!!!!!!! SP offset {dc2} def ultimate for {dn} : {dn2} !!!!!!!!!!!!!!!!")
                   if "r7" == self._project.arch.register_names[dn2.offset]:
                      if dc2 >= 0:
                         result.add(("stack", dc2, ev2))                  
                         print(f"!!!!!!!!!!!!!!!! R7 offset {dc2} def ultimate for {dn} : {dn2} !!!!!!!!!!!!!!!!")
            del dts2
        del dts
        return result

    # case 3: Load(Load(Load(local_address)) + bufoffset)
    # computes handler->buff 
    # What has tainted Load(Load(local_address)) + bufoffset, used as an address in store?
    def IRfindSourcesofAddressInHandlerField(self, func, baseregset, cfgnode, bb, st, index, node, visitedMap, evidence, filter=None): 
        #self.DebugShowGlobalSizes() 
        #print(f"[IRfindSourcesofAddressInHandlerField] {node}")
        result = set()
        hash = self.UtilgetHashList([bb.addr, index])
        if not func.addr in visitedMap.keys():
           visitedMap[func.addr] = set()
        if hash in visitedMap[func.addr]:
           return result
        visitedMap[func.addr].add(hash)
        args = ['r0', 'r1', 'r2', 'r3']
        dts = self.IRgetLoadAddressDef(func, cfgnode, bb, st, index, node, evidence, filter)
        for dt in dts:
            dbba, di, dn, dc, ev = dt
            dbb = self._project.factory.block(dbba)
            dst = dbb.vex.statements[di]
            cfgnode1 = self.IRfindCFGNodeForStatement(func, dbb, di)
            if cfgnode1 == None:
               continue
            #print(f"Address source1 for {node}: ({hex(dbba)},{dst},{di},{dn},{dc})")
            dts2 = self.IRgetLoadAddressDefUltimate(func, cfgnode1, dbb, dst, di, dn, ev, None, filter)
            for dt2 in dts2:
                dbba2, di2, dn2, dc2, ev2 = dt2
                #print(f"Asrc ultimate def: {dt2}")
                if not isinstance(dn2, pyvex.IRExpr.Get):
                   continue
                dbb2 = self._project.factory.block(dbba2)
                dst2 = dbb2.vex.statements[di2]
                cfgnode2 = self.IRfindCFGNodeForStatement(func, dbb2, di2)
                if cfgnode2 == None:
                   continue
                print(f"```````````````````````Address source2 for {dn}: ({hex(dbba2)},{dst2},{di2},{dn2},{dc2}) ({dc2} {dc})```````````````")
                if self._project.arch.register_names[dn2.offset] in args:
                   if dc == 0:
                      result.add(("argument",self._project.arch.register_names[dn2.offset], ev2))
                   else:                      
                      result.add(("argument",self._project.arch.register_names[dn2.offset], dc, ev2))                   
                if self._project.arch.register_names[dn2.offset] in baseregset:
                   # TODO: Make it configurable
                   subres = self.IRfindAssignmentsToHandlerFieldFromCFGNode(func, baseregset, cfgnode, dc2, dc, visitedMap, ev2, filter)
                   # ightweight version focusing on the same bb 
                   #subres = self.IRfindAssignmentsToHandlerFieldInBB(func, baseregset, bb, dc2, dc, visitedMap, ev2)
                   for sub in subres:
                       result.add(sub)
                   del subres 
            del dts2
        del dts
        return result

    # find sources of assignments to addresses in the form Load(Load(localOffset)
    def IRfindAssignmentsToHandlerField(self, func, baseregset, localOffset, handlerFieldOffset, visitedMap, evidence, filter=None):
        #print(f"[IRfindAssignmentsToHandlerField]")
        result = set()
        for ba in func.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            index = 0
            while index < len(bb.vex.statements):
                st = bb.vex.statements[index]
                if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                   if not isinstance(st.data, pyvex.IRExpr.Const):
                      cfgnode = self.IRfindCFGNodeForStatement(func, bb, index)
                      if not cfgnode == None:
                         # is the address matching Load(Load(localOffset)) + handlerFieldOffset
                         if not isinstance(st.data, pyvex.IRExpr.Const):
                            eve = evidence
                            eve += "\n(%s,%d,%s,%s)\n" % (hex(bb.addr), index, st, st.addr)
                            (fr, er) = self.IRisLoadLoadLocalWithFieldOffset(func, baseregset, cfgnode, bb, st, index, st.addr, localOffset, handlerFieldOffset, eve, filter)
                            if fr:
                               #print(f"From [IRfindAssignmentsToHandlerField] {offset}")
                               eve += "\n" + er 
                               subres = self.IRfindAllSourcesofAddress(func, baseregset, cfgnode, bb, st, index, st.data, visitedMap, eve, filter)
                               for sub in subres:
                                   result.add(sub)
                index += 1
        return result               

    # find sources of assignments to addresses in the form Load(Load(localOffset)
    def IRfindAssignmentsToHandlerFieldFromCFGNode(self, func, baseregset, ocfgnode, localOffset, handlerFieldOffset, visitedMap, evidence, filter=None):
        #print(f"[IRfindAssignmentsToHandlerFieldFromCFGNode] localoffset {localOffset} handler field offset {handlerFieldOffset} {hex(ocfgnode.addr)}")
        result = set()
        targetcfgnodes = self.IRfindAllPredsInFunction(func, ocfgnode, filter)
        targetcfgnodes.add(ocfgnode)
        #print(f"Num preds: {len(targetcfgnodes)}")
        for tcfgnode in targetcfgnodes:
            #try:
            #   bb = self._project.factory.block(ba)
            #except angr.errors.SimEngineError:
            #   continue
            bb, bmin, bmax = self.IRgetStatementIndexRangeForCFGNode(func, tcfgnode)
            index = bmin
            #print(f"tcfgnode min {bmin} max {bmax} bb {hex(bb.addr)}")
            while index <= bmax:
                st = bb.vex.statements[index]
                if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                   #print(f"Tracing from {st} at {hex(tcfgnode.addr)}")
                   if not isinstance(st.data, pyvex.IRExpr.Const):
                      cfgnode = tcfgnode
                      if not cfgnode == None:
                         # is the address matching Load(Load(localOffset)) + handlerFieldOffset
                         if not isinstance(st.data, pyvex.IRExpr.Const):
                            eve = evidence
                            eve += "\n(%s,%d,%s,%s)\n" % (hex(bb.addr), index, st, st.addr)
                            (fr, er) = self.IRisLoadLoadLocalWithFieldOffset(func, baseregset, cfgnode, bb, st, index, st.addr, localOffset, handlerFieldOffset, eve, filter)
                            if fr:
                               #print(f"From [IRfindAssignmentsToHandlerFieldFromCFGNode] {localOffset}")
                               eve += "\n" + er
                               subres = self.IRfindAllSourcesofAddress(func, baseregset, cfgnode, bb, st, index, st.data, visitedMap, eve, filter)
                               for sub in subres:
                                   result.add(sub)
                index += 1
        return result               


    # SINGLE BB VERSION: find sources of assignments to addresses in the form Load(Load(localOffset)
    def IRfindAssignmentsToHandlerFieldInBB(self, func, baseregset, bb, localOffset, handlerFieldOffset, visitedMap, evidence, filter=None):
        #print(f"[IRfindAssignmentsToHandlerFieldBB]")
        result = set()
        index = 0
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                 if not isinstance(st.data, pyvex.IRExpr.Const):
                    cfgnode = self.IRfindCFGNodeForStatement(func, bb, index)
                    if not cfgnode == None:
                       # is the address matching Load(Load(localOffset)) + handlerFieldOffset
                       eve = evidence
                       eve += "\n(%s,%d,%s,%s)\n" % (hex(bb.addr), index, st, st.addr)                     
                       (fr, er) = self.IRisLoadLoadLocalWithFieldOffset(func, baseregset, cfgnode, bb, st, index, st.addr, localOffset, handlerFieldOffset, eve, filter)
                       if fr:
                          eve += "\n" + er
                          subres = self.IRfindAllSourcesofAddress(func, baseregset, cfgnode, bb, st, index, st.data, visitedMap, eve, filter=None)
                          for sub in subres:
                              result.add(sub)
              index += 1
        return result               

    # is the address matching Load(Load(localOffset)) + handlerFieldOffset                     
    def IRisLoadLoadLocalWithFieldOffset(self, func, baseregset, cfgnode, bb, st, index, node, localOffset, handlerFieldOffset, evidence, filter=None):
        #print(f"[IRisLoadLoadLocalWithFieldOffset] {node} {st} {index} {hex(bb.addr)} lo: {localOffset} ho: {handlerFieldOffset}")
        result = set()
        visited = set()
        dts = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, evidence)
        for dt in dts:
            dbba, di, dn, dc, ev = dt
            dbb = self._project.factory.block(dbba)
            dst = dbb.vex.statements[di]
            #print(f"Address source1 for {node}: ({hex(dbba)},{dst},{di},{dn},{dc})")
            if not isinstance(dn, pyvex.IRExpr.Load) and not isinstance(dn, pyvex.IRStmt.LoadG):
               continue
            if not dc == handlerFieldOffset:
               continue
            cfgnode1 = self.IRfindCFGNodeForStatement(func, dbb, di)
            if cfgnode1 == None:
               continue
            evcpy = evidence + "\n" + ev + "\n" 
            dts2 = self.IRgetLoadAddressDefUltimate(func, cfgnode1, dbb, dst, di, dn, evcpy, None, filter)
            for dt2 in dts2:
                dbba2, di2, dn2, dc2, ev2 = dt2
                dbb2 = self._project.factory.block(dbba2)
                dst2 = dbb2.vex.statements[di2]
                #print(f"Address source2 for {dn}: ({hex(dbba2)},{dst2},{di2},{dn2},{dc2})")
                if not isinstance(dn2, pyvex.IRExpr.Get):
                   continue
                if not dc2 == localOffset:
                   continue
                if self._project.arch.register_names[dn2.offset] in baseregset:
                   #print(f"Address source3 for {dn2}: ({hex(dbba3)},{dst3},{di3},{dn3},{dc3})")         
                   return (True, ev2)
        del visited
        return (False,"")



    # is L(argname) + offsetif self._project.arch.register_names[dn2.offset] in 
    def IRisDefLoadArgOffset(self, func, cfgnode, bb, index, node, argname, offset, evidence, filter=None):
        #print(f"[IRisDefLoadArgOffset] {node}")
        visited = set()
        st = bb.vex.statements[index]
        ds = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, evidence)
        del visited
        for d in ds:
            dbba, di, dn, dc, ev = d
            dbb = self._project.factory.block(dbba)
            dcfgnode = self.IRfindCFGNodeForStatement(func, dbb, di)
            if dcfgnode == None:
               continue
            evcpy = evidence + ev
            #print(f"Def of {node}: ({hex(dbba)},{di},{dn},{dc})") 
            (fr, er) = self.IRisDefLoadArgOffsetInternal(func, dcfgnode, dbb, di, dn, argname, offset, evcpy, filter)
            if fr:
               return (True, er)
        return (False, er) 

    def IRisDefLoadArgOffsetInternal(self, func, cfgnode, bb, index, node, argname, offset, evidence, filter=None):
        st = bb.vex.statements[index]
        ld = self.IRgetLoadAddressDef(func, cfgnode, bb, st, index, node, evidence, filter)
        for ldt in ld:
            lbba, li, ln, lc, ev = ldt
            #print(f"O candidate tuple for {node}: ({hex(lbba)},{li},{ln},{lc}) vs offset {offset}")             
            if not lc == offset:
               continue
            if isinstance(ln, pyvex.IRExpr.Get):
               if self._project.arch.register_names[ln.offset] == argname:
                  return (True, ev)
        return (False, "")

    # is L(L(argname) + offset)
    def IRisDefLoadLoadArgOffset(self, func, cfgnode, bb, index, node, argname, offset, evidence, filter=None):
        #print(f"[IRisDefLoadLoadArgOffset] {node}")
        visited = set()
        st = bb.vex.statements[index]
        ds = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, evidence)
        del visited
        for d in ds:
            dbba, di, dn, dc, ev = d
            dbb = self._project.factory.block(dbba)
            dcfgnode = self.IRfindCFGNodeForStatement(func, dbb, di)
            if dcfgnode == None:
               continue
            evcpy = evidence + ev
            (fr, er) = self.IRisDefLoadLoadArgOffsetInternal(func, dcfgnode, dbb, di, dn, argname, offset, evcpy, filter)
            if fr:
               return (True, er)
        return (False, "")

    def IRisDefLoadLoadArgOffsetInternal(self, func, cfgnode, bb, index, node, argname, offset, evidence, filter=None):
        st = bb.vex.statements[index]
        ld = self.IRgetLoadAddressDef(func, cfgnode, bb, st, index, node, evidence, filter)
        for ldt in ld:
            lbba, li, ln, lc, ev = ldt
            if not lc == offset:
               continue
            lbb = self._project.factory.block(lbba)
            lst = lbb.vex.statements[li]
            print(f"FOUND MATCHING OFFSET from ({hex(bb.addr)},{node},{index} loadaddr def ({hex(lbba)},{ln},{li},{lc})")
            if isinstance(ln, pyvex.IRExpr.Load) or isinstance(ln, pyvex.IRStmt.LoadG):
               # now we need to request a load def ultimate and match the register
               lcfgnode = self.IRfindCFGNodeForStatement(func, lbb, li)
               if not lcfgnode == None:
                   ld2 = self.IRgetDefUseUltimate(func, lcfgnode, lbb, lst, li, ln.addr, ev, filter)
                   for ldt2 in ld2:
                       lbba2, li2, ln2, lc2, ev2 = ldt2
                       if isinstance(ln2, pyvex.IRExpr.Get):
                          if self._project.arch.register_names[ln2.offset] == argname:
                             return (True, ev2)
        return (False, "")



    # L(return_tuple) + offset
    #def IRgetDefLoadWithOffset(self, func, cfgnode, bb, index, node, argname, offset):
    #    print(f"[IRgetDefLoadWithOffset] {node}")
    #    result = set() 
    #    st = bb.vex.statements[index]
    #    ld = self.IRgetLoadAddressWithOffset(func, cfgnode, bb, st, index, node, offset)
    #    for ldt in ld:
    #        lbba, li, ln, lc = ldt
    #        lbb = self._project.factory.block(lbba)
    #        lst = lbb.vex.statements[li]
    #        print(f"O candidate tuple: ({hex(lbba)},{li},{lst},{ln},{lc}) vs offset {offset}")
    #        if not lc == offset:
    #           continue 
    #        if isinstance(lst, pyvex.IRExpr.Load):
    #           result.add(ldt)
    #    return result 

                            
    # L(L(return_tuple) + offset)
    def IRgetDefLoadLoadWithOffset(self, func, cfgnode, bb, index, node, argname, offset, evidence, filter=None):
        #print(f"[IRgetDefLoadLoadWithOffset] {node} {offset}")
        result = set()
        visited = set()
        st = bb.vex.statements[index]
        ds = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, evidence)
        del visited
        for d in ds:
            dbba, di, dn, dc, ev = d
            dbb = self._project.factory.block(dbba)
            dcfgnode = self.IRfindCFGNodeForStatement(func, dbb, di)
            if dcfgnode == None:
               continue
            evcpy = evidence + ev
            sub = self.IRgetDefLoadLoadWithOffsetInternal(func, dcfgnode, dbb, di, dn, argname, offset, evcpy, filter)
            for s in sub:
                result.add(s)
        return result  

    def IRgetDefLoadLoadWithOffsetInternal(self, func, cfgnode, bb, index, node, argname, offset, evidence, filter=None):
        #print(f"[IRgetDefLoadLoadWithOffsetInternal] {node} {offset}")
        result = set() 
        st = bb.vex.statements[index]
        ld = self.IRgetLoadAddressDef(func, cfgnode, bb, st, index, node, evidence, filter)
        for ldt in ld:
            lbba, li, ln, lc, ev = ldt
            lbb = self._project.factory.block(lbba)
            lst = lbb.vex.statements[li]
            #print(f"LO candidate tuple: ({hex(lbba)},{li},{lst},{ln},{lc}) vs offset {offset}")
            if not lc == offset:
               continue 
            if isinstance(ln, pyvex.IRExpr.Load) or isinstance(ln, pyvex.IRStmt.LoadG):
               # now we need to request a load def ultimate and match the offset
               #print(f"LO tuple: ({hex(lbba)},{li},{lst},{ln},{lc})")
               lcfgnode = self.IRfindCFGNodeForStatement(func, lbb, li)
               if not lcfgnode == None:
                   ld2 = self.IRgetLoadAddressDef(func, lcfgnode, lbb, lst, li, ln.addr, ev, filter)
                   for ldt2 in ld2:
                       result.add(ldt2)
        return result 

    # Check the first basic block of func to find args that may be stored at local_offset wrt basereg reg
    def IRgetRegsDefiningAtLocalOffset(self, baseregset, func, reg, local_offset, evidence, filter=None):
        result = set()
        bb = self._project.factory.block(func.addr)
        index = 0
        while index < len(bb.vex.statements):
            st = bb.vex.statements[index]
            if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
               if not isinstance(st.data, pyvex.IRExpr.Const):
                  cfgnode = self.IRfindCFGNodeForStatement(func, bb, index)
                  eve = evidence
                  eve += "\n(%s,%d,%s,%s)\n" % (hex(bb.addr), index, st, st.addr)
                  dts = self.IRgetDefUseUltimate(func, cfgnode, bb, st, index, st.addr, eve, filter)
                  for dt in dts:
                      dbba, di, dn, dc, ev = dt
                      if isinstance(dn, pyvex.IRExpr.Get):
                         print(f"Local offset {local_offset} wrt {self._project.arch.register_names[dn.offset]}: {dc} baseregset: {baseregset}")
                         if self._project.arch.register_names[dn.offset] in baseregset and dc == local_offset:
                            dts2 = self.IRgetDefUseUltimate(func, cfgnode, bb, st, index, st.data, ev, filter)
                            print(f"Candidate def length {len(dts2)} of {st} for {st.data} in {hex(bb.addr)}")
                            for dt2 in dts2:
                                dbba2, di2, dn2, dc2, ev2 = dt2
                                print(f"Candidate {dt2}")
                                if isinstance(dn2, pyvex.IRExpr.Get):
                                   result.add((self._project.arch.register_names[dn2.offset], ev2))
            index += 1
        return result        


    # is L(Get(basereg) + localoffset) + offset
    def IRisDefLoadLoadBaseRegThenOffset(self, baseregset, func, cfgnode, bb, index, node, argname, offset, evidence, filter=None):
        #print(f"[IRisDefLoadLoadBaseRegThenOffset] {node} {offset}")
        (fr, er) = self.IRisDefLoadLoadBaseRegThenOffsetInternal(baseregset, func, cfgnode, bb, index, node, argname, offset, evidence, filter)
        if fr:
           return (True, er)
        else:
           return (False, "")        
        visited = set()
        st = bb.vex.statements[index]
        ds = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, evidence)
        del visited 
        for d in ds:
            dbba, di, dn, dc, ev = d
            dbb = self._project.factory.block(dbba)
            dcfgnode = self.IRfindCFGNodeForStatement(func, dbb, di)
            if dcfgnode == None:
               continue
            evcpy = evidence + ev
            (fr, er) = self.IRisDefLoadLoadBaseRegThenOffsetInternal(baseregset, func, dcfgnode, dbb, di, dn, argname, offset, evcpy, filter)
            if fr:
               return (True, er)
        return (False, "")

    def IRisDefLoadLoadBaseRegThenOffsetInternal(self, baseregset, func, cfgnode, bb, index, node, argname, offset, evidence, filter=None):
        #print(f"[IRisDefLoadLoadBaseRegThenOffset] {node}")
        st = bb.vex.statements[index]
        ld = self.IRgetLoadAddressWithOffset(func, cfgnode, bb, st, index, node, offset, evidence, filter)
        for lldt in ld:
            # check if this may be a locally stored data sourcing from argname 
            lbba, li, ln, lc, ev = lldt
            lbb = self._project.factory.block(lbba)
            lst = lbb.vex.statements[li]
            #print(f"LO tuple: ({hex(lbba)},{li},{lst},{ln},{lc})")
            lcfgnode = self.IRfindCFGNodeForStatement(func, lbb, li)
            if not lcfgnode == None:
                uts = self.IRgetDefUseUltimate(func, lcfgnode, lbb, lst, li, ln.addr, ev, filter) 
                for ut in uts:
                    ubba, ui, un, uc, uev = ut
                    print(f"Ultimate def: ({hex(ubba)},{ui},{un},{uc}) baseregset {baseregset}")
                    if isinstance(un, pyvex.IRExpr.Get):
                       if self._project.arch.register_names[un.offset] in baseregset:
                          print(f"Checking local offset {uc} for {un.offset}")
                          cregt = self.IRgetRegsDefiningAtLocalOffset(baseregset, func, un.offset, uc, uev, filter)
                          for e1, e2 in cregt:
                              if argname == e1:
                                 return (True, e2)
        return (False, "") 
   

    # is L(L(Get(basereg) + localoffset) + offset)
    def IRisDefLoadLoadLoadBaseRegThenOffset(self, baseregset, func, cfgnode, bb, index, node, argname, offset, evidence, filter=None):
        #print(f"[IRisDefLoadLoadLoadBaseRegThenOffset] {node} {offset}")
        visited = set()
        st = bb.vex.statements[index]
        ds = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, evidence)
        del visited
        for d in ds:
            dbba, di, dn, dc, ev = d
            dbb = self._project.factory.block(dbba)
            dcfgnode = self.IRfindCFGNodeForStatement(func, dbb, di)
            if dcfgnode == None:
               continue
            evcpy = evidence + ev
            (fr, er) = self.IRisDefLoadLoadLoadBaseRegThenOffsetInternal(baseregset, func, dcfgnode, dbb, di, dn, argname, offset, evcpy, filter)
            if fr:
               return (True, er)
        return (False, "")


    def IRisDefLoadLoadLoadBaseRegThenOffsetInternal(self, baseregset, func, cfgnode, bb, index, node, argname, offset, evidence, filter=None):
        #print(f"[IRisDefLoadLoadLoadBaseRegThenOffsetInternal] {node} {offset}")
        ld = self.IRgetDefLoadLoadWithOffset(func, cfgnode, bb, index, node, argname, offset, evidence, filter)
        for lldt in ld:
            # check if this may be a locally stored data sourcing from argname 
            lbba, li, ln, lc, ev = lldt
            lbb = self._project.factory.block(lbba)
            lst = lbb.vex.statements[li]
            #print(f"LLO tuple: ({hex(lbba)},{li},{lst},{ln},{lc}) baseregset {baseregset}")
            lcfgnode = self.IRfindCFGNodeForStatement(func, lbb, li)
            if not lcfgnode == None:
                if isinstance(ln, pyvex.IRExpr.Load) or isinstance(ln, pyvex.IRStmt.LoadG):
                   uts = self.IRgetDefUseUltimate(func, lcfgnode, lbb, lst, li, ln.addr, ev, filter)
                else:
                   uts = self.IRgetDefUseUltimate(func, lcfgnode, lbb, lst, li, ln, ev, filter)
                for ut in uts:
                    ubba, ui, un, uc, uev = ut
                    #print(f"Ultimate def for {ln} ({lc}) : ({hex(ubba)},{ui},{un},{uc}) ")
                    to = uc
                    if self.IRselfdef(func, lbb, li, ln, ut):
                       to = lc 
                    if isinstance(un, pyvex.IRExpr.Get):
                       if self._project.arch.register_names[un.offset] in baseregset:
                          cregt = self.IRgetRegsDefiningAtLocalOffset(baseregset, func, un.offset, to, uev, filter)
                          for e1, e2 in cregt:
                             if argname == e1:
                                return (True, evidence + "\n" + ev + "\n" + e2)
        return (False, "") 

    def IRreplaceEvidence(self, tuples, evidence):
        if evidence == "":
           return tuples
        result = set()
        for tuple in tuples:
            print(f"Replacing {tuple[4]} with {evidence}")  
            result.add((tuple[0], tuple[1], tuple[2], tuple[3], evidence))
        return result 

    def IRappendEvidence(self, tuples, evidence):
        if evidence == "":
           return tuples
        result = set()
        for tuple in tuples:
            result.add((tuple[0], tuple[1], tuple[2], tuple[3], evidence + tuple[4]))
        return result

    def UtilgetHash(self, obj):
        hash_object = hashlib.sha256(str(obj).encode())
        return hash_object.hexdigest()

    def UtilgetHashList(self, objList):
        hstr = ""
        i = 0
        while i < len(objList):
              hstr += str(objList[i])
              i += 1
        hash_object = hashlib.sha256(hstr.encode())
        return hash_object.hexdigest()

    def IRclearDefUseUltimate(self, bound=5):
        if len(self._def_for_use_ultimate_in_func) > bound:
           print(f"Recycling map for DefUseUltimate with size {len(self._def_for_use_ultimate_in_func)}") 
           del self._def_for_use_ultimate_in_func
           self._def_for_use_ultimate_in_func = {}        

    #@profile
    def IRgetDefUseUltimate(self, func, cfgnode, bb, st, index, node, evidence, filter=None, visited=None, visitedU=None, c=0, ccdepth=0):
        #self.IRclearDefUseUltimate()
        if not func.addr in self._def_for_use_ultimate_in_func.keys():
           self._def_for_use_ultimate_in_func[func.addr] = {}
        hash = self.UtilgetHashList([bb.addr, index, str(node)])
        if hash in self._def_for_use_ultimate_in_func[func.addr].keys():
           return self.IRappendEvidence(self._def_for_use_ultimate_in_func[func.addr][hash], evidence)
        #print(f"[IRgetDefUseUltimate] {node} in {st} at {index} in {hex(bb.addr)}")
        clean = (visited == None)
        if visited == None:
           visited = set() 
        cleanU = (visitedU == None)
        if visitedU == None:
           visitedU = set()   
        d = self.IRgetDefUseUltimateCompute(func, cfgnode, bb, st, index, node, "", filter, visited, visitedU, c, ccdepth)
        if isinstance(node, pyvex.IRExpr.Get) and len(d) == 0:
           d.add((bb.addr, index, node, c, ""))
        if len(d) == 0:
           d = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, "", c, ccdepth)
        self._def_for_use_ultimate_in_func[func.addr][hash] = d
        if clean:
           del visited
        if cleanU:
           del visitedU
        return self.IRappendEvidence(d, evidence)

    def IRgetDefUseUltimateCompute(self, func, cfgnode, bb, st, index, node, evidence, filter=None, visited=None, visitedU=None, c=0, ccdepth=0):
        #print(f"[IRgetDefUseUltimateCompute] {st} {node} {index} {hex(bb.addr)}")
        if index < 0:
           #print(f"Return {index}")
           return set()
        clean = (visited == None)
        cleanU = (visitedU == None) 
        if visited == None:
           visited = set() 
        if visitedU == None:
           visitedU = set()
        result = set()
        hash = self.UtilgetHashList([index, st, str(node), cfgnode.addr]) 
        if hash in visitedU:
           #print(f"Return {index},{st} already in visitedU")
           return set()
        visitedU.add(hash)
        #print(f"entry {node} {st} at {index} offset {c} in {hex(bb.addr)}")
        ds = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, evidence, c, ccdepth)
        for d in ds:
            dbba, di, dn, co, ev = d
            #print(f"DEF USE result DN {dn}")
            if isinstance(dn,pyvex.IRExpr.Const):
               continue
            dbb = self._project.factory.block(dbba)
            dcfgnode = self.IRfindCFGNodeForStatement(func, dbb, di)
            if dcfgnode == None:
               continue
            dst = dbb.vex.statements[di]
            #print(f"so far {dn} {dst} at {di} offset {co} in {hex(dbba)} cfgnode {hex(dcfgnode.addr)}")
            if isinstance(dn, pyvex.IRExpr.Get):
               #if func.addr == dbb.addr:
               result.add(d)
               if self._project.arch.register_names[dn.offset] == 'r0' and ccdepth < self._defusecallchaindepthBound:
                  #print(f"Return value possibility checking for r0 in {func.name} from {hex(dcfgnode.addr)}")
                  if di - 1 < len(dbb.vex.statements):
                     dcfg2 = self.IRfindCFGNodeForStatement(func, dbb, di - 1)
                     tres = self.IRfindDefsForNode(func, dcfg2, dbb, dbb.vex.statements[di-1], di-1, dn, filter, visited, ev, co, ccdepth)
                     for t in tres:
                         result.add(t)
                     del tres
               #else:
               #   print(f"WARNING: Unexpected case with Get: use {node} at {index} in {hex(bb.addr)} : {dn} at {di} in {hex(dbb.addr)}")
            if isinstance(dn, pyvex.IRExpr.Load) or isinstance(dn, pyvex.IRStmt.LoadG):
               if isinstance(dn.addr, pyvex.IRExpr.Const):
                  result.add(d)
               else: 
                  ds2 = self.IRgetDefUseUltimateCompute(func, dcfgnode, dbb, dst, di - 1, dn.addr, ev, filter, visited, visitedU, 0, ccdepth)
                  for ds2i in ds2:
                      result.add(ds2i)
                  del ds2 
        if clean:
           del visited
        if cleanU:
           del visitedU
        if len(result) == 0:
           return ds
        del ds
        return result 

    def IRgetDefUseUltimateComputeOld(self, func, cfgnode, bb, st, index, node, evidence, filter=None, visited=None, visitedU=None, c=0):
        if index < 0:
           print(f"Return {index}")
           return set()
        if visited == None:
           visited = set() 
        if visitedU == None:
           visitedU = set()
        result = set()
        if (index, st, cfgnode.addr) in visitedU:
           print(f"Return {index},{st} already in visitedU")
           return set()
        visitedU.add((index, st, cfgnode.addr))
        ds = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, evidence, c)
        for dbba, di, dn, co, ev in ds:
            print(f"use1: {node} at {index} {hex(bb.addr)} off {c} def: {dn} at {di} {hex(dbba)} off {co}")            
            if isinstance(dn,pyvex.IRExpr.Const):
               continue
            dbb = self._project.factory.block(dbba)
            dcfgnode = self.IRfindCFGNodeForStatement(func, dbb, di)
            if dcfgnode == None:
               continue
            #print(f"di {di} num st {len(dbb.vex.statements)}")
            if di > 0:
               stn = dbb.vex.statements[di-1]
            else:
               continue
            #c2 = 0 
            #if not isinstance(dn, pyvex.IRExpr.Load):
            #   c2 = co
            if dbba == func.addr and di <= 1: #already ultimate
               print(f"Skipping {dn} in ultimate compute {hex(dbba)}")
               continue
            dsp = self.IRgetDefForUse(func, dcfgnode, dbb, stn, di-1, dn, filter, visited, evidence, co) 
            for dp in dsp:
                subresult = set()
                dbbap, dip, dnp, cop, dev = dp
                dbbp = self._project.factory.block(dbbap)
                if isinstance(dnp,pyvex.IRExpr.Const):
                   continue              
                if dip > 0:
                   stp = dbbp.vex.statements[dip-1]
                   ni = dip - 1
                else:
                   stp = dbbp.vex.statements[dip]
                   ni = dip 
                print(f"use2: {dn} at {di} {hex(dbb.addr)} off {co} def: {dnp} at {dip} {hex(dbbap)} off {cop}")
                #if not self.IRselfdef(func, dbb, di, dn, dp):
                if not isinstance(dn,pyvex.IRExpr.Load) and not isinstance(dn,pyvex.IRStmt.LoadG) and dbbp.addr == dbb.addr and dip == di and dnp == dn:
                   print(f"Skipping {dn} due to self")
                   continue
                else:
                   cfgnodep = self.IRfindCFGNodeForStatement(func, dbbp, dip)
                if not cfgnodep == None:
                   #print(f"dip {dip} num st {len(dbbp.vex.statements)}")
                   #print(f"Num child {len(dnp.child_expressions)} cop {cop}")
                   if isinstance(dnp, pyvex.IRExpr.Get) or isinstance(dnp, pyvex.IRExpr.RdTmp): # num child for Get is 0
                      evcpy = ev + dev
                      dus = self.IRgetDefUseUltimateCompute(func, cfgnodep, dbbp, stp, ni, dnp, evcpy, filter, visited, visitedU, cop)
                      for du in dus:
                          subresult.add(du)
                   c3 = 0
                   if not isinstance(dnp, pyvex.IRExpr.Load) and not isinstance(dnp, pyvex.IRStmt.LoadG):
                      c3 = cop
                   nc, toff = self.IRgetOffsetAndSubForNode(dbbp, dnp)
                   if not nc == None:
                      c3 += toff
                      #print(f"In ultimate offset from binory op {toff} c3 {c3}")
                   for ce in dnp.child_expressions:
                       if not isinstance(dnp,pyvex.IRExpr.Get) and isinstance(ce,pyvex.IRExpr.Const):
                          continue
                       evcpy = ev + dev
                       dus = self.IRgetDefUseUltimateCompute(func, cfgnodep, dbbp, stp, ni, ce, evcpy, filter, visited, visitedU, c3)
                       print(f"\tULTIMATE use: {dn} at {di} {hex(dbb.addr)} def: {dus}")                       
                       for du in dus:
                           dua, dui, dun, duco, duev = du
                           if not isinstance(dun, pyvex.IRExpr.Get):
                              duabb = self._project.factory.block(dua)
                              dcfgnode = self.IRfindCFGNodeForStatement(func, duabb, dui)
                              if dcfgnode == None:
                                 continue
                              dust = dbbp.vex.statements[dui]
                              dus2 = self.IRgetDefUseUltimateCompute(func, dcfgnode, duabb, dust, dui, dun, duev, filter, visited, visitedU, duco)
                              for du2 in dus2:
                                  dua2, dun2, dui2, duco2, duev2 = du2
                                  print(f"\tULTIMATE use: {dun} at {dui} {hex(duabb.addr)} def: {du2}")                       
                                  if isinstance(dun2, pyvex.IRExpr.Get):
                                     subresult.add(dun2)
                                  else:
                                     print(f"WARNING: Unexpected case in ultimate compute!") 
                           else:
                              subresult.add(du)
                if len(subresult) == 0:
                   subresult.add(dp)
                for s in subresult:
                    result.add(s)
        if len(result) == 0:
           return ds
        else:        
           return result  

    def IRgetLoadAddressDefUltimate(self, func, cfgnode, bb, st, index, node, evidence, offsetlist=None, filter=None):
        #print(f"[IRgetLoadAddressDefUltimate] {node}")
        result = set()
        visited = set()
        ds = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, evidence)
        del visited
        #print(f"Size of def for use for {node} cfgnode {hex(cfgnode.addr)} bb {hex(bb.addr)}: {len(ds)}")
        for dbba, di, dn, co, ev in ds:
            #print(f"def of {node}: {dn} at {hex(dbba)} {di}")   
            if isinstance(dn, pyvex.IRExpr.Load) or isinstance(dn, pyvex.IRStmt.LoadG):
               if not offsetlist == None:
                  offsetlist.append((dbba, di, dn, co))   
               if isinstance(dn.addr, pyvex.IRExpr.Const):
                  continue
               dbb = self._project.factory.block(dbba)
               dcfgnode = self.IRfindCFGNodeForStatement(func, dbb, di)
               dst = dbb.vex.statements[di]
               #print(f"Load def for {node} : {dn} at {hex(dbb.addr)} {dst}")   
               if not dcfgnode == None:
                   evcpy = evidence + ev 
                   ud = self.IRgetDefUseUltimate(func, dcfgnode, dbb, dst, di, dn.addr, evcpy, filter)
                   for udd in ud:
                       #print(f"Ultimate def of load addr: {ud}")
                       result.add(udd)
                   del ud
        del ds
        return result 

    # L(return_tuple) + offset
    def IRgetLoadAddressWithOffset(self, func, cfgnode, bb, st, index, node, offset, evidence, filter=None):
        #print(f"[IRgetLoadAddressDef] {node}")
        result = set()
        visited = set()
        ds = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, evidence)
        del visited
        for udd in ds:
            dbba, di, dn, co, ev = udd
            #print(f"L candidate tuple: ({hex(dbba)},{di},{dn},{co})")        
            if isinstance(dn, pyvex.IRExpr.Load) or isinstance(dn, pyvex.IRStmt.LoadG):
               if not co == offset:
                  continue
               evcpy = evidence + ev
               result.add((dbba, di, dn, co, evcpy))
        return result 


    def IRgetLoadAddressDef(self, func, cfgnode, bb, st, index, node, evidence, filter=None):
        #print(f"[IRgetLoadAddressDef] {node}")
        result = set()
        visited = set()
        ds = self.IRgetDefForUse(func, cfgnode, bb, st, index, node, filter, visited, evidence)
        for dbba, di, dn, co, ev in ds:
            #print(f"L candidate tuple: ({hex(dbba)},{di},{dn},{co})")        
            if isinstance(dn, pyvex.IRExpr.Load) or isinstance(dn, pyvex.IRStmt.LoadG):
               dbb = self._project.factory.block(dbba)
               dcfgnode = self.IRfindCFGNodeForStatement(func, dbb, di)
               dst = dbb.vex.statements[di] 
               if not dcfgnode == None:
                   evcpy = evidence + ev
                   ud = self.IRgetDefForUse(func, dcfgnode, dbb, dst, di, dn.addr, filter, visited, evcpy)
                   for udd in ud:
                       result.add(udd)
        del visited
        return result 

    def IRselfdef(self, func, bb, index, node, dtuple):
        dba, di, dnode, co, ev = dtuple
        #if dba == bb.addr and di == index and node == dnode:
        if dba == bb.addr and node == dnode:
           return True
        return False
 
    def IRcomputeBasicBlockAddrRange(self, func, bb):
        if not func.addr in self._func_bb_addr_range.keys():
           self._func_bb_addr_range[func.addr] = {}
        if bb.addr in self._func_bb_addr_range[func.addr].keys():
           return self._func_bb_addr_range[func.addr][bb.addr]
        min = bb.addr
        max = bb.addr
        i = 0
        for st in bb.vex.statements:
            if isinstance(st, pyvex.IRStmt.IMark):
               if st.addr < min:
                  min = st.addr
               if st.addr > max:
                  max = st.addr            
            i += 1
        if min <= max:
           self._func_bb_addr_range[func.addr][bb.addr] = (min, max)     
           return (min, max)
        return (None, None) 

    def IRgetBasicBlockAddrRange(self, func, bb):
        if not func.addr in self._func_bb_addr_range.keys():
           self._func_bb_addr_range[func.addr] = {} 
        if not bb.addr in self._func_bb_addr_range[func.addr].keys():
           self._func_bb_addr_range[func.addr][bb.addr] = self.IRcomputeBasicBlockAddrRange(func, bb)
        return self._func_bb_addr_range[func.addr][bb.addr]  


    def IRgetBasicBlockForCFGNode(self, func, cfgnode):
        if cfgnode.addr in self._bbForCFG:
           return self._bbForCFG[cfgnode.addr]
        #print(f"finding bb for cfgnode {hex(cfgnode.addr)}")
        for ba in func.block_addrs:
            try:
               bb = self._project.factory.block(ba)
               min, max = self.IRgetBasicBlockAddrRange(func, bb)
               #print(f"[IRgetBasicBlockForCFGNode] bb addr {hex(ba)} cfgnode address {hex(cfgnode.addr)} min {hex(min)} max {hex(max)}")
               if cfgnode.addr >= min - 1 and cfgnode.addr <= max:
                  self._bbForCFG[cfgnode.addr] = bb
                  return bb
            except angr.errors.SimEngineError:
               continue
        #print(f"Returning None for bb")
        return None

    # Returns the number of Vex instructions for a real instruction
    def IRgetIMarkSize(self, func, bb, st):
        if not isinstance(st, pyvex.IRStmt.IMark):
           return 0
        if not func.addr in self._imarkLength.keys():
           self._imarkLength[func.addr] = {}
        if not bb.addr in self._imarkLength[func.addr].keys():
           self._imarkLength[func.addr][bb.addr] = {}
        if st in self._imarkLength[func.addr][bb.addr].keys():
           return self._imarkLength[func.addr][bb.addr][st]
        index = 0
        last = 0
        lastSt = None
        while index < len(bb.vex.statements):
              cst = bb.vex.statements[index]
              if isinstance(cst,pyvex.IRStmt.IMark):
                 if cst == st:
                    lastSt = cst
                    last = index
                 elif lastSt == st:
                     self._imarkLength[func.addr][bb.addr][st] = index - last - 1
                     return index - last - 1
                 else:
                    lastSt = None
                    last = 0  
              index += 1
        if lastSt == st:
           self._imarkLength[func.addr][bb.addr][st] = index - last - 1
           return index - last - 1  
        return 0 

    def IRgetBBForAddressInBinary(self, addr):
        for func in self._current_cfg.functions.values():
            for ba in func.block_addrs:
                bb = self._project.factory.block(ba)
                for st in bb.vex.statements:
                    if isinstance(st,pyvex.IRStmt.IMark):
                       if addr == st.addr or addr - 1 == st.addr or addr + 1 == st.addr:
                          return (bb, func)
        return (None, None)

    def IRgetBBForAddress(self, func, addr):
        print(f"[IRgetBBForAddress] function {func.name} addr {hex(func.addr)} {hex(addr)}")
        for ba in func.block_addrs:
            bb = self._project.factory.block(ba)
            for st in bb.vex.statements:
                if isinstance(st,pyvex.IRStmt.IMark):
                   #print(f"\tstatement {hex(st.addr)} vs {hex(addr)}") 
                   if addr == st.addr or addr - 1 == st.addr or addr + 1 == st.addr:
                      return bb
        return None

    def IRgetBBsForCFGNode(self, func, cfgnode):
        bbs = set()
        for ba in func.block_addrs:
            bb = self._project.factory.block(ba)
            for st in bb.vex.statements:  
                if isinstance(st,pyvex.IRStmt.IMark):
                   if cfgnode.addr - st.addr == 1 or st.addr - cfgnode.addr == 1:
                      bbs.add(bb)
                   if cfgnode.addr == st.addr or cfgnode.addr == st.addr + 1:
                      bbs.add(bb)
        return bbs

    def IRgetBBForCFGNode(self, func, cfgnode):
        for ba in func.block_addrs:
            bb = self._project.factory.block(ba)
            for st in bb.vex.statements:
                if isinstance(st,pyvex.IRStmt.IMark):
                   if cfgnode.addr - st.addr == 1 or st.addr - cfgnode.addr == 1:
                      return bb
                   if cfgnode.addr == st.addr or cfgnode.addr & ~1 == st.addr or cfgnode.addr == st.addr & ~1:
                      return bb
        return None
 
    def IRgetClosestStatementIndexForAddress(self, func, cfgnode, bb, addr):
        bb, min, max = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(func, cfgnode, bb)
        index = max
        while index >= min:
            st = bb.vex.statements[index]
            if isinstance(st, pyvex.IRStmt.IMark):
               if st.addr <= addr:
                  return index
            index -= 1
        return None

    def IRgetStatementIndexRangeForCFGNodeWithBasicBlock(self, func, cfgnode, bb):
        #print(f"[IRgetStatementIndexRangeForCFGNodeWithBasicBlock] {hex(cfgnode.addr)}")
        if cfgnode == None or bb == None:
           return set()
        if (cfgnode.addr, bb.addr) in self._cfgnodeStmtRange.keys():
           return self._cfgnodeStmtRange[(cfgnode.addr, bb.addr)]
        res = set()
        index = 0
        min = -1
        max = -1
        withinrange = False
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st,pyvex.IRStmt.IMark):
                 if cfgnode.addr == st.addr or cfgnode.addr == st.addr + 1:
                    min = index
                    max = index
                 withinrange = st.addr < cfgnode.addr + cfgnode.size or st.addr + 1 < cfgnode.addr + cfgnode.size
              if withinrange: 
                 max = index  
              index += 1   
        return (bb, min, max)
        max = 0
        min = len(bb.vex.statements) - 1
        i = 0
        check = True
        for st in bb.vex.statements:
            if isinstance(st,pyvex.IRStmt.IMark):
               length = self.IRgetIMarkSize(func, bb, st)
               print(f"@@@ i {i} max {max} st.addr {hex(st.addr)} {st.addr} vs instr addrs {cfgnode.instruction_addrs} length {length}")
               if not check or st.addr in cfgnode.instruction_addrs or st.addr + 1 in cfgnode.instruction_addrs:
                  if i + length >= max:
                     max = i + length
                  if i <= min:
                     min = i
               if length == 0: # fix what seems to be an issue in angr's CFG node construction
                  check = False
                  if i + length >= max:
                     max = i + length
                  if i <= min:
                     min = i
               i += length + 1
        print(f"min {min} {max}")
        if min <= max:
           self._cfgnodeStmtRange[(cfgnode.addr, bb.addr)] = (bb, min,max)
           return (bb, min,max)
        bb.vex.pp()
        return (None, None, None)

    def IRgetStatementIndexRangeForCFGNode(self, func, cfgnode):
        if cfgnode.addr in self._cfgnodeStmtRange.keys():
           return self._cfgnodeStmtRange[cfgnode.addr]
        bb = self.IRgetBasicBlockForCFGNode(func, cfgnode)
        if bb == None:
           print(f"bb not found in [IRgetStatementIndexRangeForCFGNode]") 
           return (None, None, None)
        return self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(func, cfgnode, bb) 
        res = set()
        max = 0
        min = len(bb.vex.statements) - 1
        i = 0
        for st in bb.vex.statements:
            if isinstance(st,pyvex.IRStmt.IMark):
               #print(f"st.addr {st.addr} vs instr addrs {cfgnode.instruction_addrs}")
               if st.addr in cfgnode.instruction_addrs or st.addr + 1 in cfgnode.instruction_addrs:
                  if i >= max:
                     max = i
                  if i <= min:
                     min = i  
            i += 1
        print(f"[IRgetStatementIndexRangeForCFGNode] min {min} max {max}")
        if min <= max:
           self._cfgnodeStmtRange[cfgnode.addr] = (bb, min,max)
           return (bb, min,max)
        return (None, None, None)
  
    

    def IRgetOffsetAndSubForNode(self, bb, node):
        if isinstance(node,pyvex.IRExpr.Binop):
           nc = None
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  nc = ce
                  break
           if node.op == 'Iop_Add64' or node.op == 'Iop_Add32' or node.op == 'Iop_Add16':
              off = 0
              for ce in node.child_expressions:
                  if isinstance(ce,pyvex.IRExpr.Const):
                     off = ce.con._value
                     break
              return (nc, off)
           if node.op == 'Iop_Sub64' or node.op == 'Iop_Sub32' or node.op == 'Iop_Sub16':
              off = 0
              for ce in node.child_expressions:
                  if isinstance(ce,pyvex.IRExpr.Const):
                     off = ce.con._value
                     break
              return (nc, -off)
        return (None, None) 


    def IRgetRegisterDefs(self, f, cfgnode):
        if not f.addr in self._regdefs.keys():
           self._regdefs[f.addr] = {}
        if cfgnode.addr in self._regdefs[f.addr].keys():
           return self._regdefs[f.addr][cfgnode.addr]
        pbb, pmin, pmax = self.IRgetStatementIndexRangeForCFGNode(f, cfgnode)
        regOffsets = set()
        i = pmin
        while i <= pmax:
              pst = pbb.vex.statements[i]
              if isinstance(pst, pyvex.IRStmt.Put):
                 regOffsets.add(pst.offset)
              i += 1
        self._regdefs[f.addr][cfgnode.addr] = regOffsets
        return regOffsets

    def IRgetTempDefs(self, f, cfgnode):
        if not f.addr in self._tempdefs.keys():
           self._tempdefs[f.addr] = {}
        if cfgnode.addr in self._tempdefs[f.addr].keys():
           return self._tempdefs[f.addr][cfgnode.addr]
        pbb, pmin, pmax = self.IRgetStatementIndexRangeForCFGNode(f, cfgnode)
        tempOffsets = set()
        i = pmin
        while i <= pmax:
              pst = pbb.vex.statements[i]
              if isinstance(pst, pyvex.IRStmt.WrTmp):
                 tempOffsets.add(pst.tmp)
              i += 1
        self._tempdefs[f.addr][cfgnode.addr] = tempOffsets
        return tempOffsets

    def IRupdateDefsForNodeDepthOnEnter(self):
        if self._defsfornodedepth == None:
           self._defsfornodedepth = 0
           self._defsfornodenumpaths = 0 
           if len(self._lastGetDefTuple) > 0:
              self._lastGetDefTuple.clear()
        else:
           self._defsfornodedepth += 1   

    def IRupdateDefsForNodeDepthOnExit(self):
        if self._defsfornodedepth == 0:
           self._defsfornodedepth = None 
           self._defsfornodenumpaths += 1 
        else:
           self._defsfornodedepth -= 1
        # relying on the fact that we push something each time
        self._lastGetDefTuple.pop()
        

    # either explicitly sets r0 or calls another function that may return a value
    def IRmayReturnAValue(self, f):
        results = set()
        callsites = set() 
        for ba in f.block_addrs:
            try:  
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            if bb.vex.jumpkind == "Ijk_Call":
               callsites.add(bb)
            elif not isinstance(bb.vex.next, pyvex.IRExpr.Const):
               callsites.add(bb)
            else:
               callee = self.IRgetFunctionOfInstruction(bb.vex.next.con._value)
               if not callee == None and not callee.addr == f.addr:
                  callsites.add(bb)
            index = 0
            while index <len(bb.vex.statements):
                st = bb.vex.statements[index]
                if isinstance(st, pyvex.IRStmt.Put) and st.offset in self._project.arch.register_names.keys():
                   if self._project.arch.register_names[st.offset] == 'r0':
                      results.add((bb, index))
                index += 1
        return results

    def IRgetMaxIndex(self, bb, maxAddr):
        index = 0
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.IMark):
                 if st.addr == maxAddr or st.addr == maxAddr - 1:
                    return index - 1 
              index += 1
        return len(bb.vex.statements) - 1

    # record definitions of registers
    def IRgenerateBaselineDefsForCFGNode(self, f, bb, cfgnode):
        results = {}
        tbb, min, max = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(f, cfgnode, bb)
        sia = 0
        index = min
        while index <= max:
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.IMark):
                 sia = st.addr
              if isinstance(st, pyvex.IRStmt.Put):
                 results[st.offset] = (bb.addr, cfgnode.addr, sia, st)
              index += 1
        return results

    def IRprintReachingDefs(self, f):
        if not f.addr in self._CFG[f.addr]:
           print(f"Control-Flow Graph for {f.name} has not been constructed yet!")
        if not f.addr in self._reachingDefsBase.keys():
           print(f"Reaching Defs Base for {f.name} has not been constructed yet!")
        if not f.addr in self._reachingDefsIn.keys():
           print(f"Reaching Defs In for {f.name} has not been constructed yet!")
        if not f.addr in self._reachingDefsOut.keys():
           print(f"Reaching Defs Out for {f.name} has not been constructed yet!")
        for ca in self._reachingDefsOut[f.addr].keys():
            print(f"Baseline Reaching Definitions for {hex(ca)}")
            for o in self._reachingDefsBase[f.addr][ca]:
                rdt = self._reachingDefsBase[f.addr][ca][o]
                print(f"ba {hex(rdt[0])} cfgn {hex(rdt[1])} inst {hex(rdt[2])} st {rdt[3]}")                 
            print(f"Reaching Definitions In for {hex(ca)}")
            for o in self._reachingDefsIn[f.addr][ca]:
                for rdt in self._reachingDefsIn[f.addr][ca][o]:
                    print(f"ba {hex(rdt[0])} cfgn {hex(rdt[1])} inst {hex(rdt[2])} st {rdt[3]}")                 
            print(f"Reaching Definitions Out for {hex(ca)}")
            for o in self._reachingDefsOut[f.addr][ca]:
                for rdt in self._reachingDefsOut[f.addr][ca][o]:
                    print(f"ba {hex(rdt[0])} cfgn {hex(rdt[1])} inst {hex(rdt[2])} st {rdt[3]}")                 


    def IRupdateReachingDefs(self, f):
        change = False
        for sa in self._CFG[f.addr].keys():
            ets = self._CFG[f.addr][sa]
            for offset in self._reachingDefsOut[f.addr][sa].keys():
                for et in ets:
                    if not offset in self._reachingDefsIn[f.addr][et[2].addr].keys():
                       self._reachingDefsIn[f.addr][et[2].addr][offset] = set()
                    rdts = self._reachingDefsOut[f.addr][sa][offset]
                    for rdt in rdts:
                        if not rdt in self._reachingDefsIn[f.addr][et[2].addr][offset]: 
                           self._reachingDefsIn[f.addr][et[2].addr][offset].add(rdt)
                           change = True
                        if not offset in self._reachingDefsBase[f.addr][et[2].addr].keys():
                           if not et[2].addr in self._reachingDefsOut[f.addr].keys():
                              self._reachingDefsOut[f.addr][et[2].addr] = set()
                           if not offset in self._reachingDefsOut[f.addr][et[2].addr].keys():
                              self._reachingDefsOut[f.addr][et[2].addr][offset] = set()
                           if not rdt in self._reachingDefsOut[f.addr][et[2].addr][offset]:
                              self._reachingDefsOut[f.addr][et[2].addr][offset].add(rdt)  
                              change = True 
        return change 

    def IRgenerateReachingDefs(self, f):
        self.IRgenerateCFGsForFunction(f)
        if f.addr in self._reachingDefsIn.keys() and len(self._reachingDefsIn[f.addr]) > 0:
           return
        if not f.addr in self._reachingDefsOut.keys():
           self._reachingDefsOut[f.addr] = {}
        if not f.addr in self._reachingDefsIn.keys():
           self._reachingDefsIn[f.addr] = {}
        if not f.addr in self._reachingDefsBase.keys():
           self._reachingDefsBase[f.addr] = {}
        for sa in self._CFG[f.addr].keys():
            for et in self._CFG[f.addr][sa]:
                if not sa in self._reachingDefsOut[f.addr].keys():
                   self._reachingDefsOut[f.addr][sa] = {}
                   self._reachingDefsBase[f.addr][sa] = self.IRgenerateBaselineDefsForCFGNode(f, et[1], et[0])
                   for offset in self._reachingDefsBase[f.addr][sa].keys():
                       if not offset in self._reachingDefsOut[f.addr][sa].keys():
                          self._reachingDefsOut[f.addr][sa][offset] = set()
                       self._reachingDefsOut[f.addr][sa][offset].add(self._reachingDefsBase[f.addr][sa][offset])
            self._reachingDefsIn[f.addr][sa] = {}
        for sa in self._RCFG[f.addr].keys():
            for et in self._RCFG[f.addr][sa]:
                if not sa in self._reachingDefsOut[f.addr].keys():
                   self._reachingDefsOut[f.addr][sa] = {}
                   self._reachingDefsBase[f.addr][sa] = self.IRgenerateBaselineDefsForCFGNode(f, et[1], et[0])
                   for offset in self._reachingDefsBase[f.addr][sa].keys():
                       if not offset in self._reachingDefsOut[f.addr][sa].keys():
                          self._reachingDefsOut[f.addr][sa][offset] = set()
                       self._reachingDefsOut[f.addr][sa][offset].add(self._reachingDefsBase[f.addr][sa][offset])
            self._reachingDefsIn[f.addr][sa] = {}
        i = 0
        while self.IRupdateReachingDefs(f):
            print(f"Updating reaching defs for {f.name}")
            i += 1
        print(f"Reaching defs for {f.name} converged in {i} steps")
        

    def IRgenerateCFGsForFunction(self, f):
        if f.addr in self._CFG.keys():
           return
        self._CFG[f.addr] = {}
        self._RCFG[f.addr] = {}
        min, max = self.IRgetFunctionAddressRange(f)
        for s, d in self._current_cfg.graph.edges():
            if s.addr >= min and s.addr <= max and d.addr >= min and d.addr <= max:
               sbbs = self.IRgetBBsForCFGNode(f, s)
               dbbs = self.IRgetBBsForCFGNode(f, d)
               if not s.addr in self._CFG[f.addr]:
                  self._CFG[f.addr][s.addr] = set()
               for sbb in sbbs:
                   self._CFG[f.addr][s.addr].add((s, sbb, d))
               if not d.addr in self._RCFG[f.addr]:
                  self._RCFG[f.addr][d.addr] = set()
               for dbb in dbbs:
                  self._RCFG[f.addr][d.addr].add((d, dbb, s))
                  
       
    #@profile
    # to do: enrich filter data structure to compute the new filter for inter-procedural analysis
    def IRfindDefsForNode(self, func, cfgnode, bb, st, index, node, filter, visited, evidence, c=0, ccdepth=0):
        self.IRupdateDefsForNodeDepthOnEnter()
        #if isinstance(node, pyvex.IRExpr.Get):
        #   self._lastGetDefTuple.append((bb.addr, index, node, c, evidence))
        #else:
        self._lastGetDefTuple.append((bb.addr, index, node, c, evidence))
        #if self._defsfornodedepth == 0:
        #print(f"[IRfindDefsForNode] DEPTH: {self._defsfornodedepth} Bound {self._defsfornodedepthBound} {func.name} ({hex(func.addr)}) {st} {index} {node} {hex(bb.addr)} {hex(cfgnode.addr)} cfgnode size {cfgnode.size} comprehensive? {self._comprehensiveDefUse} filter? {not filter == None} {self.showTime()}")
        #bb.vex.pp()
        #print(f"num visited {len(visited)} bb {hex(bb.addr)} {st}")
        result = set()
        hash1 = self.UtilgetHashList([cfgnode.addr, str(st), str(node), c])
        hash2 = self.UtilgetHashList([cfgnode.addr, str(st), str(node)])
        if (hash1,hash2) in visited:
           #if self._lastNode == "t23" or self._lastNode == "t5" or self._lastNode == "t47" or self._lastNode == "t53":
           #print(f"[IRfindDefsForNode] Already visited {hex(cfgnode.addr)}")
           self.IRupdateDefsForNodeDepthOnExit()
           return result
        ms = [h2 for h1, h2 in visited if h2 == hash2]
        #print(f"defnode cfgnode {hex(cfgnode.addr)} bb {hex(bb.addr)} st {st} {node} index {index} off {c} similar {len(ms)}")        
        if len(ms) > self._defusecyclebound:
           if len(self._lastGetDefTuple) > 0:
              last = self._lastGetDefTuple[-1]
              first = self._lastGetDefTuple[0] 
              if not last[2] == first[2]:  
                 result.add(last)  
           self.IRupdateDefsForNodeDepthOnExit() 
           return result
        del ms
        #print(f"Adding {hex(cfgnode.addr)} {st} {node} {c}")
        visited.add((hash1, hash2))           
        cbb, min, max = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(func, cfgnode, bb)
        #print(f"cfgnode {hex(cfgnode.addr)} range [{min},{max}] bb {hex(bb.addr)} cbb {hex(cbb.addr)}") 
        if cbb == None:
           self.IRupdateDefsForNodeDepthOnExit()
           return result  
        if not cbb.addr in func.block_addrs:
           self.IRupdateDefsForNodeDepthOnExit()
           return result
        #if not cbb.addr == bb.addr:
        #   print(f"cbb {hex(cbb.addr)} vs bb {hex(bb.addr)}") 
        if isinstance(node, pyvex.IRExpr.Load) or isinstance(node, pyvex.IRStmt.LoadG):
           # adjusting index 
           if index < len(bb.vex.statements) - 1:
              evidence += "\n(%s,%d,%s,%s,%d)" % (hex(bb.addr),index+1,st,node,c)
              result.add((bb.addr,index + 1,node, c, evidence))
           else:
              evidence += "\n(%s,%d,%s,%s,%d)" % (hex(bb.addr),index,st,node,c)
              result.add((bb.addr,index,node, c, evidence))
           self.IRupdateDefsForNodeDepthOnExit()
           return result
        if not isinstance(node, pyvex.IRExpr.RdTmp) and not isinstance(node, pyvex.IRExpr.Get):
           sub, soff = self.IRgetOffsetAndSubForNode(bb, node)
           if not sub == None and not soff == None and self._defsfornodedepth < self._defsfornodedepthBound:
              #print(f"In defnode, c {c} {node} {st} in {hex(bb.addr)} offset extracted {soff} searching for def for {sub}")
              if self._comprehensiveDefUse:
                 vn = set()
                 for v in visited:
                     vn.add(v)   
                 rs = self.IRfindDefsForNode(func, cfgnode, bb, st, index, sub, filter, vn, evidence, c + soff, ccdepth)
                 del vn
              else: 
                 rs = self.IRfindDefsForNode(func, cfgnode, bb, st, index, sub, filter, visited, evidence, c + soff, ccdepth)
              for r in rs:
                  #print(f"After offset for sub {r}")
                  result.add(r)
              del rs
           for ce in node.child_expressions:
               if (not sub == None and str(ce) == str(sub)) or self._defsfornodedepth >= self._defsfornodedepthBound:
                  continue  
               if self._comprehensiveDefUse:
                  vn = set()
                  for v in visited:
                      vn.add(v)
                  rs = self.IRfindDefsForNode(func, cfgnode, bb, st, index, ce, filter, vn, evidence, c, ccdepth)
                  del vn
               else: 
                  rs = self.IRfindDefsForNode(func, cfgnode, bb, st, index, ce, filter, visited, evidence, c, ccdepth)
               for r in rs:
                   result.add(r)
               del rs
           self.IRupdateDefsForNodeDepthOnExit()
           return result  
        sameBB = False
        sameNode = None
        sameSt = None
        sameIndex = -1
        i = index
        if i > len(cbb.vex.statements) - 1:
           i = len(cbb.vex.statements) - 1
        #skip = False
        #if isinstance(node, pyvex.IRExpr.RdTmp):
        #   td = self.IRgetTempDefs(func, cfgnode)
        #   if not node._tmp in td:
        #      skip = True
        #if isinstance(node, pyvex.IRExpr.Get):
        #   rd = self.IRgetRegisterDefs(func, cfgnode)
        #   if not node.offset in rd:
        #      skip = True
        #while i>=min and not skip:
        while i>=min:
           cst = cbb.vex.statements[i]
           if isinstance(node, pyvex.IRExpr.RdTmp):
              if isinstance(cst, pyvex.IRStmt.WrTmp):
                 if node._tmp == cst.tmp and self._defsfornodedepth < self._defsfornodedepthBound:
                    #print(f"WrTmp {node} RdTmp match {cst} {hex(cbb.addr)} => {cst.data}")
                    #ccfgnode = self.IRfindCFGNodeForStatement(func, cbb, i)
                    ev = evidence
                    ev += "\n(%s,%d,%s,%s,%d)\n" % (hex(cbb.addr),i,cst,node,c)
                    if func.addr == bb.addr and isinstance(cst.data, pyvex.IRExpr.Get):
                       ev += "\n(%s,%d,%s,%s,%d)\n" % (hex(cbb.addr),i,cst,cst.data,c)                       
                    #print(f"i {i} min {min} max {max}")
                    ncst = cst
                    if i >= 1:
                       ncst = cbb.vex.statements[i-1]
                       d = self.IRfindDefsForNode(func, cfgnode, cbb, ncst, i-1, cst.data, filter, visited, ev, c, ccdepth)
                       #print(f"=============== len(d) {len(d)} cfgnode {hex(cfgnode.addr)} node {node} cst {cst}") 
                       #print(f"RdTmp result: {d} i {i}")
                       if len(d) == 0:
                          result.add((cbb.addr,i,cst.data,c,ev))
                       else:
                          for de in d:
                              result.add(de)
                       del d
                       self.IRupdateDefsForNodeDepthOnExit()  
                       return result
                    else:
                       if cbb.addr == func.addr:
                          result.add((cbb.addr,i,cst.data,c, ev))
                          self.IRupdateDefsForNodeDepthOnExit() 
                          return result                  
                       else:                         
                          node = cst.data
                          # to be continued with predecessor
                          break                          
           if isinstance(node, pyvex.IRExpr.Get):
              if isinstance(cst, pyvex.IRStmt.Put):
                 if node.offset == cst.offset and self._defsfornodedepth < self._defsfornodedepthBound:
                    #print(f"Get {node} Put match {cst} {hex(cbb.addr)} => {cst.data}")
                    #ccfgnode = self.IRfindCFGNodeForStatement(func, cbb, i)
                    ev = evidence 
                    ev += "\n(%s,%d,%s,%s,%d)\n" % (hex(cbb.addr),i,cst,node,c)
                    ncst = cst
                    if i >= 1:
                       ncst = cbb.vex.statements[i-1] 
                       ncfgnode = self.IRfindCFGNodeForStatement(func, cbb, i-1)
                       #print(f"ncfgnode for cbb {hex(cbb.addr)} ncst {ncst} {i-1} in {func.name}")
                       d = self.IRfindDefsForNode(func, ncfgnode, cbb, ncst, i-1, cst.data, filter, visited, ev, c, ccdepth)
                       if len(d) == 0:
                          if func.addr == cbb.addr:                       
                             result.add((cbb.addr,i,cst.data,c, ev))
                             result.add((cbb.addr,i,node,c, ev))
                          else:
                             break  
                       else:
                          for de in d:  
                              result.add(de)
                       del d
                       self.IRupdateDefsForNodeDepthOnExit() 
                       return result
                    else:
                       if cbb.addr == func.addr:
                          result.add((cbb.addr,i,cst.data,c, ev))
                          self.IRupdateDefsForNodeDepthOnExit() 
                          return result                  
                       else:                         
                          node = cst.data
                          # to be continued with predecessor
                          break  
              if ccdepth < self._defusecallchaindepthBound: 
                 if self._project.arch.register_names[node.offset] == 'r0':
                    address = 0  
                    if isinstance(cst, pyvex.IRStmt.Put) and self._project.arch.register_names[cst.offset] == 'pc':
                       if isinstance(cst.data, pyvex.IRExpr.Const):
                          address = cst.data.con._value
                    if isinstance(cst, pyvex.IRStmt.Exit) and self._project.arch.register_names[cst.offsIP] == 'pc':
                       if isinstance(cst.dst, pyvex.IRExpr.Const):
                          address = cst.dst.con._value
                    if not address == 0:                          
                       callee = self.IRgetFunctionAtAddress(address)
                       if not callee == None and self.IRmayReturnAValue(callee):
                          #print(f"Checking {callee.name} for return value for r0 within {func.name}")
                          oc = self._comprehensiveDefUse
                          self._comprehensiveDefUse = False 
                          retvaldefs = self.IRgetReturnValueUltimateDefs(callee, ccdepth + 1, None)
                          self._comprehensiveDefUse = oc                           
                          found = False
                          for retvald in retvaldefs:
                              rbba,ri,rn,rc,rev = retvald
                              if isinstance(rn, pyvex.IRExpr.Get) and self._defsfornodedepth < self._defsfornodedepthBound:
                                 if self._project.arch.register_names[rn.offset] in ['r1', 'r2', 'r3']:
                                    if i - 1 <= min:
                                       tres = self.IRfindDefsForNode(func, cfgnode, cbb, cbb.vex.statements[i-1], i-1, rn, filter, visited, rev, rc, ccdepth)
                                    else:
                                       rcfgnode = self.IRfindCFGNodeForStatement(func, cbb, i-1)
                                       tres = self.IRfindDefsForNode(func, rcfgnode, cbb, cbb.vex.statements[i-1], i-1, rn, filter, visited, rev, rc, ccdepth)
                                    for t in tres:
                                        result.add(t)
                                        found = True
                                    del tres
                              elif isinstance(rn, pyvex.IRExpr.Load):
                                   #print(f"Load def detected from a callee {callee.name} for {node}")
                                   result.add(retvald)
                                   found = True 
                          del retvaldefs
                          if found:
                             #print(f"Ending path due to return value flow detection in callee {callee.name}")                              
                             self.IRupdateDefsForNodeDepthOnExit()
                             return result  
           i -= 1 
        if len(result) > 0:
           #print(f"Return before pred {len(result)}")
           self.IRupdateDefsForNodeDepthOnExit()
           return result
        if cfgnode.addr == func.addr:
           #print(f"Return before pred {len(result)}")
           self.IRupdateDefsForNodeDepthOnExit()
           return result
        preds = self.IRfindImmediatePredsInFunction(func, cfgnode, bb, filter)
        #print(f"Immediate preds in findnode {len(preds)}")
        for predt in preds:
            pred, pbb, pmin, pmax = predt
            pmax = self.IRgetMaxIndex(pbb, cfgnode.addr)
            #print(f"pred {hex(pred.addr)} of {hex(cfgnode.addr)} min {pmin} max {pmax}")
            if ccdepth < self._defusecallchaindepthBound and self._defsfornodedepth < self._defsfornodedepthBound: 
               if not pbb.addr == bb.addr and isinstance(pbb.vex.next, pyvex.IRExpr.Const):
                  if isinstance(node, pyvex.IRExpr.Get) and self._project.arch.register_names[node.offset] == 'r0':
                     callee = self.IRgetFunctionAtAddress(pbb.vex.next.con._value)
                     if not callee == None and self.IRmayReturnAValue(callee):
                        #print(f"PRED {callee.name} length {len(pbb.vex.statements)}")
                        #pbb.vex.pp()
                        if not callee == None and self.IRmayReturnAValue(callee):
                           #print(f"Checking {callee.name} for return value for r0 within {func.name}")
                           oc = self._comprehensiveDefUse
                           self._comprehensiveDefUse = False 
                           retvaldefs = self.IRgetReturnValueUltimateDefs(callee, ccdepth + 1, None)
                           self._comprehensiveDefUse = oc 
                           found = False
                           for retvald in retvaldefs:
                               rbba,ri,rn,rc,rev = retvald
                               if isinstance(rn, pyvex.IRExpr.Get):
                                  if self._project.arch.register_names[rn.offset] in ['r1', 'r2', 'r3']:
                                     rindex = len(pbb.vex.statements) - 1
                                     rcfgnode = self.IRfindCFGNodeForStatement(func, pbb, rindex)
                                     tres = self.IRfindDefsForNode(func, rcfgnode, pbb, pbb.vex.statements[rindex], rindex, rn, filter, visited, rev, rc, ccdepth)
                                     for t in tres:
                                         result.add(t)
                                         found = True
                                     del tres
                               elif isinstance(rn, pyvex.IRExpr.Load):
                                    #print(f"Load def detected from a callee {callee.name} for {node}")
                                    result.add(retvald)
                                    found = True                            
                           del retvaldefs
                           if found:
                              #print(f"Skipping pred due to return value flow detection in callee {callee.name}")
                              continue
            evcopy = evidence
            if self._defsfornodedepth < self._defsfornodedepthBound:
               if self._comprehensiveDefUse:
                  vn = set()
                  for v in visited:
                      vn.add(v)
                  rs = self.IRfindDefsForNode(func, pred, pbb, pbb.vex.statements[pmax-1], pmax, node, filter, vn, evcopy, c, ccdepth)
                  for r in rs:
                      result.add(r)
                  del vn
               else:
                  rs = self.IRfindDefsForNode(func, pred, pbb, pbb.vex.statements[pmax-1], pmax, node, filter, visited, evcopy, c, ccdepth)
                  for r in rs:
                      result.add(r)
               del rs
        del preds 
        self.IRupdateDefsForNodeDepthOnExit()
        return result

    def IRcfgnodePredCoveredBy(self, func, cfgnode, bb):
        bmin, bmax = self.IRgetBasicBlockAddrRange(func, bb) 
        addr1 = cfgnode.addr - 2
        addr2 = cfgnode.addr - 4
        if addr1 >= bmin - 1 or addr1 <= bmax:
           return True
        if addr2 >= bmin -1 or addr2 <= bmax:
           return True
        return False
    
    def IRcfgnodeCoveredByPred(self, func, cfgnode, pred):
        pmin = pred.addr
        pmax = pmin
        for pa in pred.instruction_addrs:
            if pa > pmax:
               pmax = pa
        addr1 = cfgnode.addr - 2
        addr2 = cfgnode.addr - 4
        if addr1 >= pmin - 1 and addr1 <= pmax:
           return True
        if addr2 >= pmin - 1 and addr2 <= pmax:
           return True
        return False
        

    def IRgetFunctionAddressRange(self, func):
        if func.addr in self._functionAddressRange.keys():
           return self._functionAddressRange[func.addr]
        min = func.addr
        max = func.addr
        for ba in func.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            for st in bb.vex.statements:
                if isinstance(st, pyvex.IRStmt.IMark):
                   if st.addr >= max:
                      max = st.addr
        self._functionAddressRange[func.addr] = (min, max)
        return (min,max)  

    def IRclearDefForUse(self, bound=5):
        if len(self._def_for_use_in_func) > bound:
           print(f"Recycling map for DefForUse with size {len(self._def_for_use_in_func)}") 
           del self._def_for_use_in_func
           self._def_for_use_in_func = {}       

    def IRgetDefForUse(self, func, cfgnode, bb, st, index, node, filter, visited, evidence="", c=0, ccdepth=0):
        #print(f"getdef for use {node} off {c}")
        #self.IRclearDefForUse()
        if not func.addr in self._def_for_use_in_func.keys():
           self._def_for_use_in_func[func.addr] = {}
        hash = self.UtilgetHashList([bb.addr, index, str(node)])        
        if hash in self._def_for_use_in_func[func.addr].keys():
           return self.IRappendEvidence(self._def_for_use_in_func[func.addr][hash], evidence)
        clean = (visited == None)
        if visited == None:
           visited = set()
        d = self.IRfindDefsForNode(func, cfgnode, bb, st, index, node, filter, visited, "", c, ccdepth)   
        if isinstance(node, pyvex.IRExpr.Get) and len(d) == 0:
           d.add((bb.addr, index, node, c, "")) 
        self._def_for_use_in_func[func.addr][hash] = d
        if clean:
           del visited
        return self.IRappendEvidence(d, evidence)

    def IRgenDefUseForStatement(self, func, cfgnode, bb, st, index, filter=None):
        visited = set()
        if isinstance(st, pyvex.IRStmt.Put):
           dsd = self.IRgetDefForUse(func, cfgnode, bb, st, index, st.data, filter, visited)
           for d in dsd:
               self.IRaddDefUse(func, (bb.addr, index, st), d)
           dso = self.IRgetDefForUse(func, cfgnode, bb, st, index, st.offset, filter, visited)
           for d in dso:
               self.IRaddDefUse(func, (bb.addr, index, st), d)
        if isinstance(st, pyvex.IRStmt.WrTmp):
           dsd = self.IRgetDefForUse(func, cfgnode, bb, st, index, st.data, filter, visited)
           for d in dsd:
               self.IRaddDefUse(func, (bb.addr, index, st), d)
        if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
           dsd = self.IRgetDefForUse(func, cfgnode, bb, st, index, st.data, filter, visited)
           for d in dsd:
               self.IRaddDefUse(func, (bb.addr, index, st), d)
           dsa = self.IRgetDefForUse(func, cfgnode, bb, st, index, st.addr, filter, visited)
           for d in dsa:
               self.IRaddDefUse(func, (bb.addr, index, st), d)
        del visited   

    def IRaddDefUse(self, func, use_tuple, def_tuple):
        #print(f"Adding use {use_tuple} def {def_tuple}")
        if not func.addr in self._def_for_use_in_func.keys():
           self._def_for_use_in_func[func_addr] = {}  
        if use_tuple in self._def_for_use_in_func[func.addr].keys():
           return 
        if not use_tuple in self._def_for_use_in_func[func.addr].keys():
           self._def_for_use_in_func[func.addr][use_tuple] = set()
        self._def_for_use_in_func[func.addr][use_tuple].add(def_tuple)

    def IRgenDefUseForCFGNode(self, func, cfgnode, filter=None):
        bb, min, max = self.IRgetStatementIndexRangeForCFGNode(func, cfgnode)
        if bb == None:
           print(f"WARNING: Could not find instruction range and bb for cfgnode {cfgnode} addr {hex(cfgnode.addr)}")
           return
        index =  max
        while index >=min:
             st = bb.vex.statements[index]
             if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                self.IRgenDefUseForStatement(func, cfgnode, bb, st, index, filter)
             if isinstance(st, pyvex.IRStmt.WrTmp):
                if isinstance(st.data, pyvex.IRExpr.Load) or isinstance(st.data, pyvex.IRStmt.LoadG):
                   self.IRgenDefUseForStatement(func, cfgnode, bb, st, index, filter)
             index -= 1

    # self._uses: map f.addr -> map (bb.addr, stmt_idx, node) -> set of (bb.addr, stmt_idx, node)
    def IRgenDefUse(self, func, filter=None):
        print(f"Generating DEF-USE for {func.name}") 
        for ba in func.block_addrs:
            an = self._current_cfg.get_all_nodes(ba)
            for cfgnode in an:
                print(f"Function {func.name} cfgnode {hex(cfgnode.addr)}")
                self.IRgenDefUseForCFGNode(func, cfgnode, filter)
        print(f"USES for {func.name}")               
        for t1 in self._def_for_use_in_func[func.addr].keys():
            ba1, stindex1, node1 = t1
            for t2 in self._def_for_use_in_func[func.addr][t1]:
                ba2, stindex2, node2, co = t2
                print(f"t1 ({hex(ba1),stindex1,node1}) t2 ({hex(ba2),stindex2,node2,co})")

    """
        END Use-Def Chain API
    """

    def IRgetArgMatchOffsetInFunction(self, func, baseregset, bb, node, type="Store", exprType="lhs"):
        if not self.IRderivedFromBaseregisterRelaxed(bb, node, baseregset):
           return None
        offset, basereg = self.IRcomputeStackOffsetAtBasicBlock(func, bb, node, type, exprType)
        #print(f"Offset for {node} is {offset}")
        args = ['r0','r1','r2','r3']
        for reg in args:
            ao = self.IRgetLocalOffsetForReg(func, reg)
            if ao == offset:
               #print(f"Matching the offset of reg {reg}")
               return reg
        if not offset == None:
           argoff = "arg_sp_offset_%d" % (offset)
           print(f"Possibly an argno >= 4 for offset {offset} in function {hex(func.addr)} name {func.name}")
           return argoff
        return None

    def IRgetArgName(self, argno):
        if argno == 0:
           return "r0"
        if argno == 1:
           return "r1"
        if argno == 2:
           return "r2"
        if argno == 3:
           return "r3"
        return ""

    def IRgetArgNo(self, arg):
        if arg == "r0":
           return 0
        if arg == "r1":
           return 1
        if arg == "r2":
           return 2
        if arg == "r3":
           return 3
        return None

    def IRgetNextArg(self, arg):
        if arg == "r0":
           return "r1"
        if arg == "r1":
           return "r2" 
        return None

    def IRgetUltimateConstant(self, bb, node):
        if isinstance(node,pyvex.IRExpr.Const):
           return node.con._value
        else:
           dnode = self.IRgetDefStmt(bb, node)
           if dnode == None:
              return None
           if isinstance(dnode.data, pyvex.IRExpr.Load) or isinstance(dnode.data, pyvex.IRStmt.LoadG):
              if isinstance(dnode.data.addr,pyvex.IRExpr.Const):
                 valuebv = self._initial_state.memory.load(dnode.data.addr.con._value,4)
                 value = self._initial_state.solver.eval(valuebv)
                 return int.from_bytes(value.to_bytes(4,byteorder='little'),byteorder='big')
              else:
                 return self.IRgetUltimateConstant(bb, dnode.data)                 
        return None

    def IRgetLoadSource(self, bb, node, l=None):
        dnode = self.IRgetDefStmt(bb, node)
        if not dnode == None:
           return self.IRgetLoadSource(bb, dnode.data, l)
        if isinstance(node, pyvex.IRExpr.Load) or isinstance(node, pyvex.IRStmt.LoadG):
           if l == None:
              return self.IRGetNodeSource(bb, node.addr)
           else:
              return (None, None)
        for ce in node.child_expressions:
            t, s = self.IRgetLoadSource(bb, ce, l)
            if t == None or s == None:
               continue
            return (t,s)  
        return (None, None)


    def IRGetNodeSource(self, bb, node):
        cval = self.IRgetUltimateConstant(bb, node)
        if not cval == None:
           return ("global",cval)
        else:
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              if isinstance(dnode.data,pyvex.IRExpr.Get):
                 return ("argument", self._project.arch.register_names[dnode.data.offset]) 
           reg, co = self.IRgetsFromArg(bb, node)
           if not reg == None:
              return ("argument", reg)
           else:
              reg, co = self.IRgetsFromArgIndirect(bb, node)
              if not reg == None:
                 return ("argument", reg)
        return (None, None)

    def IRGetArgSource(self, bb, argname, index):
        #bb.vex.pp()
        # print(f"Get arg source for {argname} in {hex(bb.addr)} up to index {index}")
        source = None
        i = 0
        for s in bb.vex.statements:
           i += 1
           if i >= index:
              break
           if isinstance(s,pyvex.IRStmt.Put):
              if self._project.arch.register_names[s.offset] == argname:
                 source = s.data
        # print(f"source {source}")
        if source == None:
           return (None, None)
        cval = self.IRgetUltimateConstant(bb, source) 
        if not cval == None:
           return ("global",cval)
        else:
           reg, co = self.IRgetsFromArg(bb, source)
           if not reg == None:
              return ("argument", reg)
           else:
              reg, co = self.IRgetsFromArgIndirect(bb, source)
              if not reg == None:
                 return ("argument", reg)
        return (None, None)

    def IRCalleeArgFlowsFromCallerArg(self, bb, callee, calleearg):
        # print(f"Is arg {calleearg} of {hex(callee)} flowing from some arg in {hex(bb.addr)}")
        puts = [x for x in bb.vex.statements if x.tag == 'Ist_Put']
        data = None
        for p in puts:
            if calleearg == self._project.arch.register_names[p.offset]:
               data = p.data
        if data == None:
           return False
        #bb.vex.pp()
        # print(f"{data} Flows from an arg?")
        r, c = self.IRgetsFromArg(bb, data)
        return r

    def IRisReachable(self, f1, f2):
        if f1.addr == f2.addr:
           return True
        callers = self.IRfindImmediateCallersWithCallsite(f2)
        for caller in callers:
            ca, cs = caller
            if f1.addr == ca:
               return True
            caf = self.IRgetFunctionAtAddress(ca)
            if self.IRisReachable(f1, caf):
               return True
        return False  

    def FWcheckError(self,entry,funtosim,entry_state,harg="r0", sarg="r1", maxsteps=1000):
        # print(f"Checking for error state")
        self._project.hook(funtosim,self.HALReceiveModel(handler_argname=harg,size_argname=sarg))
        simgr = self._project.factory.simgr(entry_state,save_unconstrained=True)
        stepno = 0
        while stepno < maxsteps and len(simgr.unconstrained)==0:
              simgr.step()
              if len(simgr.active) == 0:
                 # print(f"No active states left after {stepno} steps!")
                 break
              stepno += 1
              # print(f"At step {stepno} number of active states: {len(simgr.active)}")
        if len(simgr.unconstrained) > 0:
           unconstrained_state = simgr.unconstrained[0]
           fa = unconstrained_state.callstack.current_function_address
           sp = unconstrained_state.callstack.current_stack_pointer
           # print(f"Memory error tainted function {hex(fa)} stack pointer {hex(sp)} and pc {unconstrained_state.regs.pc} ")
        else:
           print(f"Analysis ended without an error after {stepno} steps")


    def IRcaptureFromFunctionInit(self, fa, filter=None):
        f = self.IRgetFunctionAtAddress(fa)
        firstbb = self._project.factory.block(fa)
        ia = 0
        index = 0
        registerUpdates = {} 
        memoryAccessAddr = 0
        while index < len(firstbb.vex.statements):
              st = firstbb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.IMark):
                 ia = st.addr
              if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                 memoryAccessAddr = ia
              if isinstance(st, pyvex.IRStmt.WrTmp):
                 if isinstance(st.data, pyvex.IRExpr.Load):
                    memoryAccessAddr = ia
              if isinstance(st, pyvex.IRStmt.Put):
                 reg = self._project.arch.register_names[st.offset]
                 ev = ""
                 visited = set()  
                 cfgnode = self.IRfindCFGNodeForStatement(f, firstbb, index)
                 ldu = self.IRgetDefForUse(f, cfgnode, firstbb, st, index, st.data, filter, visited, ev)
                 del visited
                 for ld in ldu:
                     ldbba, ldi, ldn, ldc, ldev = ld
                     print(f"Node {ldn}")
                     if not isinstance(ldn, pyvex.IRExpr.Load):
                        continue 
                     ldbb = self._project.factory.block(ldbba)
                     lia = self.IRInstructionAddress(ldbb, ldi)
                     print(f"Instruction address {hex(lia)} for {st} reg {reg} index {index} vs ldindex {ldi} bb {len(ldbb.vex.statements)} vs first bb {len(firstbb.vex.statements)}")
                     if not lia in registerUpdates.keys():                         
                        registerUpdates[lia] = set()
                     registerUpdates[lia].add(reg)
              index += 1
        return memoryAccessAddr, registerUpdates  
         

    def IRprintPath(self, path):
        print(f"Path length {len(path)}")
        i = len(path) - 1
        while i >= 0:
              fa = path[i][0]
              f = self.IRgetFunctionAtAddress(fa)
              print(f"Function {f.name} {hex(fa)} bb addr {hex(path[i][1].addr)} cfgnode addr {hex(path[i][2].addr)} index {path[i][3]}")
              i -= 1


    def IRconvertSize(self, type):
        if str(type) == 'Ity_I8':
           return 1
        if str(type) == 'Ity_I16':
           return 2
        if str(type) == 'Ity_I32':
           return 4 
        if str(type) == 'Ity_I64':
           return 8
        return 0

    

    def IRgetBBAddressRange(self, bb):
        min = 0xffffffff
        max = 0
        index = 0
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.IMark):
                 if st.addr < min:
                    min = st.addr
                 if st.addr > max:
                    max = st.addr
              index += 1
        #print(f"BB Range min {hex(min)} {hex(max)} addr {hex(bb.addr)} max u size {hex(bb.addr + bb.size)}")
        return min, min + bb.size

    def IRgetUseofLoad(self, bb, tempno):
        index = 0
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.WrTmp):
                 if isinstance(st.data, pyvex.IRExpr.Load):
                    if isinstance(st.data.addr, pyvex.IRExpr.RdTmp):
                       if tempno == st.data.addr.tmp:
                          return st.data
              index += 1
        return None

    def IRextractLoadAddresses(self, f, bb, cfgnode, min, max, loadAddresses):
        index = min
        while index <= max:
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.WrTmp):
                 if isinstance(st.data, pyvex.IRExpr.Load):
                    if isinstance(st.data.addr, pyvex.IRExpr.Const):
                       la = st.data.addr.con._value
                       try:
                           value = self._project.loader.memory.load(la, 4)
                       except KeyError:
                           # this memory address is not readable
                           index += 1
                           continue
                       value = int.from_bytes(value,byteorder='little')
                       if value >= self._minRAM:
                          ld = self.IRgetUseofLoad(bb, st.tmp)
                          if ld == None:
                             loadAddresses.add((value, self.IRconvertSize(st.data.ty)))
                          else: 
                             loadAddresses.add((value, self.IRconvertSize(ld.ty))) 
              index += 1

    # A path is a sequence of (fa, ba, index) 
    # unroll is used to unroll inter-procedural cycles
    # if entry is given the path is terminated at the entry unless unrolling requires additional steps
    # if entry is not given path generation contrinues until no more callers
    # paths is a dictionary to individual paths
    def IRenumeratePaths(self, paths, loadAddresses, f, bb, index, entryf=None, entrybb=None, entryindex=0, unroll=1, intraunroll=0, limit=10, depth=2):
        cfgnode = self.IRfindCFGNodeForStatement(f, bb, index)
        xbb, min, max = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(f, cfgnode, bb)
        paths[0] = [(f.addr, bb, cfgnode, index)]
        self.IRextractLoadAddresses(f, bb, cfgnode, min, max, loadAddresses)
        print(f"original path {hex(paths[0][0][0])} {hex(paths[0][0][1].addr)} {hex(paths[0][0][2].addr)}")
        levels = {}
        levels[0] = 1
        edgevisited = {}
        edgevisited[0] = {}
        return self.IRenumeratePathsInternal(paths, levels, edgevisited, loadAddresses, entryf, entrybb, entryindex, unroll, intraunroll, limit, depth)

    # icfgEdgeCoverage is a two dimensional dictionary [callee.addr][caller.addr] keeping the count of covered edges
    def IRenumeratePathsInternal(self, paths, levels, edgevisited, loadAddresses, entryf, entrybb, entryindex, unroll, intraunroll, limit, depth):
        size = len(paths)  
        newpaths = {}
        newlevels = {}
        newedgevisited = {}
        count = 0
        completed = 0
        for pkey in paths.keys():
            path = paths[pkey]
            level = levels[pkey]
            if level > depth:
               #print(f"Path reached depth limit")
               completed += 1
               newpaths[count] = copy.deepcopy(path)
               newlevels[count] = levels[pkey]
               newedgevisited[count] = edgevisited[pkey]
               count += 1               
               continue
            pfa, pbb, pcfgnode, pindex = path[-1]
            #print(f"Last entry in path: cfgnode {hex(pcfgnode.addr)} bb {hex(pbb.addr)}")
            if not entryf == None and not entrybb == None:
               if entryf.addr == pfa and entrybb.addr == pbb.addr and entryindex == pindex:
                  #print(f"Entry reached!")
                  completed += 1
                  newpaths[count] = copy.deepcopy(path)
                  newlevels[count] = levels[pkey]
                  newedgevisited[count] = edgevisited[pkey]
                  count += 1
                  continue
            # intra predecessors
            if not pfa == pbb.addr or not pindex == 0:
               #print(f"Intra pred")
               pf = self.IRgetFunctionAtAddress(pfa)
               #pbb = self._project.factory.block(pbba)
               #cfgnode =  self.IRfindCFGNodeForStatement(pf, pbb, pindex)
               preds = self.IRfindImmediatePredsInFunction(pf, pcfgnode, pbb, filter)
               skipped = False
               expanded = False
               for pr in preds:
                  if count > limit:
                     skipped = True
                     continue
                  pred, prbb, pmin, pmax = pr
                  #print(f"Pred of cfgnode {hex(pcfgnode.addr)} bb {hex(pbb.addr)} : cfgnode {hex(pred.addr)} bb {hex(prbb.addr)}")
                  edge = (pred.addr, pcfgnode.addr)
                  if edge in edgevisited[pkey].keys():
                     if edgevisited[pkey][edge] > intraunroll:
                        skipped = True
                        #self.IRprintBBs(pf)
                        #print(f"Intra unroll limit reached for edge {hex(pred.addr)} {hex(pcfgnode.addr)} ")
                        continue
                     else:
                        newedgevisited[count] = copy.deepcopy(edgevisited[pkey])
                        newedgevisited[count][edge] = edgevisited[pkey][edge] + 1
                  else:
                     newedgevisited[count] = copy.deepcopy(edgevisited[pkey])
                     newedgevisited[count][edge] = 0                  
                  xbb, min, max = self.IRgetStatementIndexRangeForCFGNodeWithBasicBlock(pf, pred, prbb)
                  if max == None:
                     print(f"Max index is none for {hex(pred.addr)} and bb {hex(prbb.addr)}")              
                  tuple = (pfa, prbb, pred, min) 
                  p = copy.deepcopy(path)
                  p.append(tuple)
                  #self.IRprintPath(p)
                  newpaths[count] = p
                  newlevels[count] = levels[pkey]
                  count += 1
                  expanded = True
                  self.IRextractLoadAddresses(pf, prbb, pred, pmin, pmax, loadAddresses)
               if skipped and not expanded:
                  #print(f"Preserving after skips for intra pred")
                  completed += 1
                  newpaths[count] = copy.deepcopy(path)
                  newlevels[count] = levels[pkey]
                  newedgevisited[count] = edgevisited[pkey]
                  count += 1                  
            else:
                # icfg predecessors 
                skipped = False
                expanded = False
                pff = self.IRgetFunctionAtAddress(pfa)
                callers = self.IRfindImmediateCallersWithCallsite(pff)
                if len(callers) == 0:
                   print(f"No callers of {pff.name} {hex(pff.addr)}") 
                for caller in callers:
                    if count > limit:
                       skipped = True
                       continue
                    ca, ba = caller
                    rep = 0
                    i = 0
                    while i < len(path) - 1:
                          if path[i][0] == pfa and path[i+1][0] == ca:
                             rep += 1
                          i += 1
                    if rep > unroll:
                       skipped = True
                       #print(f"Inter unroll limit reached")                       
                       continue                    
                    caf = self.IRgetFunctionAtAddress(ca) 
                    exitbbs = self.IRfindReturnBasicBlocks(caf)
                    for exitbb in exitbbs:
                        #print(f"Inter pred")
                        cfgnode = self.IRfindCFGNodeForStatement(caf, exitbb, len(exitbb.vex.statements) - 1)
                        tuple = (ca, exitbb, cfgnode, len(exitbb.vex.statements) - 1)
                        p = copy.deepcopy(path)
                        p.append(tuple)
                        newpaths[count] = p
                        newlevels[count] = levels[pkey] + 1
                        newedgevisited[count] = {}
                        count += 1
                        expanded = True
                if skipped and not expanded:
                   #print(f"Preserving after skips for inter pred")
                   completed += 1
                   newpaths[count] = copy.deepcopy(path)
                   newlevels[count] = levels[pkey]
                   newedgevisited[count] = edgevisited[pkey]
                   count += 1                  
        #for pkey in paths.keys():
        #    print(f"\tpsize {len(paths[pkey])}")  
        #for pkey in newpaths.keys():
        #    print(f"\tnpsize {len(newpaths[pkey])}")  
        if len(newpaths) > 0:
            del paths
            del levels
            del edgevisited
            paths = newpaths
            levels = newlevels
            edgevisited = newedgevisited
            if not completed == size:
               #print(f"\tNext step..")
               paths = self.IRenumeratePathsInternal(paths, levels, edgevisited, loadAddresses, entryf, entrybb, entryindex, unroll, intraunroll, limit, depth)
        return paths
  
    def IRfindReturnBasicBlocks(self, f):
        exitbbs = set()
        for ba in f.block_addrs:
            bb =  self._project.factory.block(ba)
            if bb.vex.jumpkind == "Ijk_Ret":
               exitbbs.add(bb)
        return exitbbs
    def IRfindFunctionsWithoutCallers(self):
        withoutcallers = set() 
        for f in self._current_cfg.functions.values():
            callers =  self.IRfindImmediateCallers(f)
            if len(callers) == 0:
               withoutcallers.add(f)
        return withoutcallers 

    def IRfindImmediateCallers(self, callee):
        callers = set()
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                if isinstance(bb.vex.next,pyvex.IRExpr.Const):
                   if bb.vex.next.con._value == callee.addr:
                      callers.add(f.addr)
        dcs = self.IRfindCallersUsingDynCG(callee)
        callersWithType = set()
        for dc, bba in dcs:
            if dc in callers:
               callersWithType.add((dc,'direct'))               
            else:
               callersWithType.add((dc,'indirect'))
        return callersWithType 

    def IRgetBBForInstruction(self, f, ia):
        for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                index = 0
                while index < len(bb.vex.statements):
                      st = bb.vex.statements[index]
                      if isinstance(st, pyvex.IRStmt.IMark):
                         if st.addr == ia or (ia + 1) == st.addr or ia == (st.addr + 1):
                            return (bb, index)
                      index += 1
        return (None, None)  

    def IRgetStatementIndexForInstructioninBB(self, bb, ia, cst):
        index = 0
        while index < len(bb.vex.statements):
              st = bb.vex.statements[index]
              if isinstance(st, pyvex.IRStmt.IMark):
                 sia = st.addr
              if sia == ia and str(cst) == str(st):
                 return index
              index += 1
        return index

    def IRgetStatementIndexForInstruction(self, f, ia):
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                index = 0
                while index < len(bb.vex.statements):
                      st = bb.vex.statements[index]
                      if isinstance(st, pyvex.IRStmt.IMark):
                         if st.addr == ia:
                            return (bb, index)
                      index += 1
        return (None, None)               

    def IRfindCallsitesWithNonConstantArg(self, callee, argreg, filter=None):
        nonconstantargcs = set()
        callsites = self.IRfindCallsitesOfFunction(callee)
        for callsite in callsites:
            caller, ia, callee = callsite
            baseregset = self.IRgetBaseRegSetForFunction(caller)
            print(f"Caller {caller.name} at {hex(caller.addr)} pc {hex(ia)}")
            bb, iaindex = self.IRgetStatementIndexForInstruction(caller, ia)
            index = iaindex
            found = False
            while index >= 0:
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.Put):
                     reg = self._project.arch.register_names[st.offset]
                     if reg == argreg:
                        found = True
                        if not isinstance(st.data, pyvex.IRExpr.Const):
                           nonconstantargcs.add(callsite)
                           print(f"\t Nonconstant arg in caller {caller.name} at bb {hex(bb.addr)} index {index} st {st}")
                           ev = ""
                           vm = {}
                           cfgnode = self.IRfindCFGNodeForStatement(caller, bb, index)
                           defs = self.IRgetDefUseUltimate(caller, cfgnode, bb, st, index, st.data, ev, filter)
                           for d in defs:
                               dbba, di, dn, dc, dev = d
                               dbb = self._project.factory.block(dbba)
                               print(f"\t\t dbb {hex(dbba)} di {di} dn {dn} {dbb.vex.statements[di]}") 
                           #srcs = self.IRfindAllSourcesofAddress(caller, baseregset, cfgnode, bb, st, index, st.data, vm, ev)
                           #for src in srcs:
                           #    print(f"\t\t{src[0]} {src[1]}")
                           #self.IRprintBBs(caller)
                        break
                  index -= 1 
            if not found:
               # must use caller's argreg directly
               nonconstantargcs.add(callsite)  
               print(f"\t Nonconstant arg must be passed as {argreg} of caller {caller.name}")
        return nonconstantargcs  

    def IRfindCallsitesOfFunction(self, callee):
        callsites = set()
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                index = 0
                ia = 0
                while index < len(bb.vex.statements):
                      st = bb.vex.statements[index]
                      if isinstance(st, pyvex.IRStmt.IMark):
                         ia = st.addr 
                      index += 1
                if isinstance(bb.vex.next,pyvex.IRExpr.Const):
                   if bb.vex.next.con._value == callee.addr:
                      callsites.add((f, ia, callee))
        return callsites

    def IRfindAllCallsites(self):
        if not self._allcallsites == None:
           return self._allcallsites
        callsites = set()
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                index = 0
                ia = 0
                while index < len(bb.vex.statements):
                      st = bb.vex.statements[index]
                      if isinstance(st, pyvex.IRStmt.IMark):
                         ia = st.addr 
                      index += 1
                if isinstance(bb.vex.next,pyvex.IRExpr.Const):
                   cf = self.IRgetFunctionAtAddress(bb.vex.next.con._value)
                   if not cf == None:
                      callsites.add((f.addr, ia, cf.addr))
        self._allcallsites = callsites
        return callsites

    def IRfindImmediateCallersWithCallsite(self, callee):
        callers = set()
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                except RecursionError:
                    continue
                if isinstance(bb.vex.next,pyvex.IRExpr.Const):
                   if bb.vex.next.con._value == callee.addr:
                      callers.add((f.addr, bb.addr))
        dcs = self.IRfindCallersUsingDynCG(callee)
        for dc in dcs:
            callers.add(dc)
        return callers 
  
    def IRfindGlobalLoadAddresses(self, scannedFuncAddress, span=0x2000):
        globalsMap = {}
        storedAddresssMap = {}
        funcMap = {}
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                index = 0
                instaddr = ba
                while index < len(bb.vex.statements):
                      st = bb.vex.statements[index]                     
                      if isinstance(st, pyvex.IRStmt.IMark):
                         instaddr = st.addr 
                      if isinstance(st, pyvex.IRStmt.WrTmp):
                         if isinstance(st.data, pyvex.IRExpr.Load) or isinstance(st.data, pyvex.IRStmt.LoadG):
                            if isinstance(st.data.addr, pyvex.IRExpr.Const):
                               la = st.data.addr.con._value
                               if not la in globalsMap:
                                  globalsMap[la] = 0
                               globalsMap[la] = globalsMap[la] + 1
                               try:
                                   value = self._project.loader.memory.load(la, 4)
                               except KeyError:
                                    # this memory address is not readable
                                    index += 1
                                    continue
                               #valuebv = self._initial_state.memory.load(la,4)
                               #value = self._initial_state.solver.eval(valuebv)
                               #value = int.from_bytes(value.to_bytes(4,byteorder='little'),byteorder='big')
                               value = int.from_bytes(value,byteorder='little')
                               #print(f"Referred value {hex(value)}")
                               if value >= self._minRAM:
                               #if value >= 0x20003200:
                                  if not value in storedAddresssMap:
                                     storedAddresssMap[value] = set()
                                  storedAddresssMap[value].add(f.name)
                                  base = value
                                  #print(f"Base {hex(base)} from load address {hex(la)}")
                                  for i in range(span):
                                      ila = base + i*4
                                      try:
                                          value = self._project.loader.memory.load(ila, 4)
                                      except KeyError:
                                           # this memory address is not readable
                                          continue
                                      #valuebv = self._initial_state.memory.load(ila,4)
                                      #value = self._initial_state.solver.eval(valuebv)
                                      #value = int.from_bytes(value.to_bytes(4,byteorder='little'),byteorder='big')
                                      value = int.from_bytes(value,byteorder='little')
                                      #if value > 0x8005000:
                                      #   print(f"Found function reference {hex(value)} at {hex(ila)} base {hex(base)}")
                                      if value == scannedFuncAddress or value == (scannedFuncAddress - 1) or value == (scannedFuncAddress + 1):
                                         print(f"Base {hex(base)} address {hex(ila)} {hex(value)}")                                      
                                         if not base in funcMap:
                                            funcMap[base] = set()
                                         funcMap[base].add((f.addr, base, ila, scannedFuncAddress)) 
                                      
                      index += 1
        return (globalsMap, storedAddresssMap, funcMap)  
                     

    def IRfindImplicitCalls(self):
        callers = set()
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                if not isinstance(bb.vex.next,pyvex.IRExpr.Const):
                   callers.add((f.addr, ba, bb.vex.next))
        return callers 
            
     

    def IRfindCallbackAssignments(self, callee):
        callers = set()
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                index = 0
                instaddr = ba
                while index < len(bb.vex.statements):
                      st = bb.vex.statements[index]                     
                      if isinstance(st, pyvex.IRStmt.IMark):
                         instaddr = st.addr 
                      if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                         if isinstance(st.data, pyvex.IRExpr.Const):
                            if st.data.con._value >= self._minRAM:                        
                               print(f"Callback assignment in {f.name} at {hex(instaddr)} {st}")
                               if st.data.con._value == callee:
                                  callers.add((f.addr, ba, index, st))
                               elif st.data.con._value == callee - 1:
                                  callers.add((f.addr, ba, index, st))
                               elif st.data.con._value == callee + 1:
                                  callers.add((f.addr, ba, index, st))
                      index += 1
        return callers

    def IRfindCallers(self, handler_argname, func, argname):
        callers = set()
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                try:
                   bb = self._project.factory.block(ba)
                except angr.errors.SimEngineError:
                   continue
                #if f.name == "HAL_SPI_Receive_IT":
                #  # print(f"Function {f.name} and bb {hex(ba)}")
                #  bb.vex.pp()
                if isinstance(bb.vex.next,pyvex.IRExpr.Const):
                   #if f.name == "HAL_SPI_Receive_IT":
                   #   # print(f"bb {hex(ba)}  target {hex(bb.vex.next.con._value)} vs func {hex(func)}")
                   if bb.vex.next.con._value == func:
                      # print(f"Function {hex(func)} called by {hex(f.addr)}")
                      ty, source = self.IRGetArgSource(bb, argname, len(bb.vex.statements))
                      if not ty == None and not source == None:
                         carg = self.IRCalleeArgFlowsFromCallerArg(bb, func, handler_argname)
                         # print(f"handler arg flowing from {carg} and type and buf arg source {ty} {source} ")
                         if ty == "argument" and not carg == None:
                            temp = self.IRfindCallers(carg, f.addr, source)
                            for t in temp:
                                callers.add(t)
                         else:               
                            # to do: generalize size arg finding             
                            callers.add((f.addr, ty, source, self.IRgetNextArg(source)))
                      else:
                         # to do: infer size when global buffer is used	
                         callers.add((f.addr,"top", None, 1)) 
                #i = 0
                #for p in bb.vex.statements:
                #    i += 1
                #    if not isinstance(p,pyvex.IRStmt.Put):
                #       continue
                #    if not p.offset in self._project.arch.register_names:
                #       continue
                #    if self._project.arch.register_names[p.offset] == "pc":
                #       if isinstance(p.data,pyvex.IRExpr.Const):
                #          if f.name == "HAL_SPI_Receive_IT":
                #             # print(f"bb {hex(ba)} {i} target {hex(p.data.con._value)} vs func {hex(func)}")
                #          if p.data.con._value == func or p.data.con._value == func - 1 or p.data.con._value - 1 == func: 
                #             ty, source = self.IRGetArgSource(bb, argname, i)
                #             if not ty == None and not source == None:  
                #                callers.add((f.addr, ty, source))
        return callers  

    def IRisGetFrom(self, one, bb, reg):
        defone = self.IRgetDefStmt(bb, one)
        if defone == None:
           return False
        if isinstance(defone.data,pyvex.IRExpr.Get):
           return reg == self._project.arch.register_names[defone.data.offset]
        return False 

    def IRgetBaseOffset(self, bb, node, depth=1):
        dnode = self.IRgetDefStmtForDepth(bb, node, depth)
        if dnode == None:
           return None
        if not isinstance(dnode.data,pyvex.IRExpr.Load) and not isinstance(dnode.data,pyvex.IRStmt.LoadG):
           return self.IRgetConstantFromBinary(bb, dnode.data)           
           #return None
        # print(f"Load detected {dnode.data}")
        if isinstance(dnode.data.addr,pyvex.IRExpr.RdTmp):
           return self.IRgetConstantFromBinary(bb, dnode.data.addr)
        return None               
  
    def IRgetsFromArg(self, bb, node): 
        co = self.IRgetBaseOffset(bb, node)
        if co == None:
           return (None, None)
        # print(f"case offset {co}")
        f = self.IRgetFunctionOfBlock(bb.addr)
        try:
          ebb = self._project.factory.block(f.addr)
        except angr.errors.SimEngineError:
          return (None, None)
        #ebb.vex.pp()
        stores = [x for x in ebb.vex.statements if x.tag == 'Ist_Store']
        for s in stores:
            co2 = self.IRgetConstantFromBinary(ebb, s.addr)
            if co2 == co:
               dd = self.IRgetDefStmt(ebb, s.data)
               if dd == None:
                  continue
               # print(f"Offset {co2} is {dd.data} a get? ")
               if isinstance(dd.data,pyvex.IRExpr.Get):
                  reg = self._project.arch.register_names[dd.data.offset]
                  return (reg, co)
        return (None, None) 

    def IRgetsFromArgIndirect(self, bb, node):
        # print(f"Checking indirect {node}") 
        co = self.IRgetBaseOffset(bb, node)
        if co == None:
           return (None, None)
        # print(f"case offset {co}")
        f = self.IRgetFunctionOfBlock(bb.addr)
        for bba in f.block_addrs:
            try:
               bb2 = self._project.factory.block(bba)
            except angr.errors.SimEngineError:
               continue
            stores = [x for x in bb2.vex.statements if x.tag == 'Ist_Store']
            for s in stores:
               for d in range(1,6):
                if co == self.IRgetBaseOffset(bb2, s.data,d):
                   # print(f"found the source with the target offset {s.data}")
                   rreg, rco = self.IRgetsFromArg(bb2, s.addr)
                   # print(f"Address {s.addr} related to arg?")
                   if not rreg == None and not rco == None:
                      return (rreg, rco)
        return (None, None) 



    def IRfindOffsetFromTop(self, bb, top, sub):
        dtop = self.IRgetDefStmt(bb, top)
        if dtop == None:  
           return False
        nc = self.IRgetNonConstantFromBinary(bb, dtop.data)
        c = self.IRgetConstantFromBinary(bb, dtop.data)
        if not nc == None and not c == None:
           return c.con._value
        return -1


    def IRisArgReg(self, regname):
       return regname in ["r0","r1","r2","r3"] 

    def IRgetBaseRegSetForFunction(self, f):
        regs = ["r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","lr"]
        baseregs = set()
        baseregs.add('sp')
        baseregs.add('r7') 
        return baseregs
        for reg in regs: 
            br = self.IRgetBaseRegSetForFunctionAndParameter(f,reg)
            if br == None:
               continue
            for bra in br:
                baseregs.add(bra)
        if len(baseregs) == 0:
           baseregs.add('sp')
           baseregs.add('r7')              
        return baseregs

    def IRgetBaseRegSetForFunctionAndParameter(self, f, parameterReg):
        if isinstance(parameterReg,int):
           parameterReg = self.IRgetArgName(parameterReg) 
        if f == None:
           return None
        try:
           bb1 = self._project.factory.block(f.addr)
        except angr.errors.SimEngineError:
           return None
        stores = [x for x in bb1.vex.statements if x.tag == 'Ist_Store']
        localaddr = None
        for s in stores:
            if self.IRisGetFrom(s.data, bb1, parameterReg):
               localaddr = s.addr
               break
        if localaddr == None:
           return None
        # print(f"Local address {localaddr}")
        baseregset = self.IRfindBaseRegSet(bb1, localaddr)
        return baseregset

    

    """
        Finds direct copying from args to arg (parameterReg) pointed handler
    """
    def HALextractWithoutStackAccess(self, f, parameterReg):
        if f == None:
           return None
        if isinstance(parameterReg,int):
           parameterReg = self.IRgetArgName(parameterReg)        
        resultsCallback = set()
        resultsBuffer = set()
        fa = 0
        datastroffset = -1
        for bb2a in f.block_addrs:
            try:  
               bb2 = self._project.factory.block(bb2a)
            except angr.errors.SimEngineError:
               continue
            stores = [x for x in bb2.vex.statements if x.tag == 'Ist_Store']
            for s in stores:
                if self.IRfunctionReferences(bb2a):
                   fa = self.IRfunctionReference(bb2, s.data)
                   if fa:
                      datastroffset = self.IRmatchFindDataStructureOffsetDirectFromArg(bb2, s.addr, parameterReg)
                      if not datastroffset == None:
                         print(f"Function {hex(fa)} is stored at an offset {datastroffset} of the handler (WO STACK ACCESS) in function {hex(f.addr)} name {f.name}") 
                         resultsCallback.add((f.addr, datastroffset, fa))
                argreg = self.IRdefinedbyReg(bb2, s.data)
                if not self.IRisArgReg(argreg):
                   continue 
                if not argreg == None and not argreg == parameterReg:
                   datastroffset = self.IRmatchFindDataStructureOffsetDirectFromArg(bb2, s.addr, parameterReg)
                   if not datastroffset == None:
                      print(f"Buffer flowing from arg {argreg} is stored at an offset {datastroffset} of the handler (WO STACK ACCESS) in function {hex(f.addr)} name {f.name}")
                      resultsBuffer.add((f.addr, datastroffset, "argument", argreg))
        return (resultsCallback, resultsBuffer)
        

    def HALextract(self, f, parameterReg):
        rc = set()
        rb = set()
        rc1, rb1 = self.HALextractWithoutStackAccess(f, parameterReg)
        if not rc1 == None:
           for c in rc1:
               rc.add(c)
        if not rb1 == None:
           for b in rb1:
               rb.add(b)
        rc2, rb2 = self.HALextractThroughStackAccess(f, parameterReg)
        if not rc2 == None:
           for c in rc2:
               rc.add(c)
        if not rb2 == None:
           for b in rb2:
               rb.add(b)
        return (rc, rb)

    def HALextractThroughStackAccess(self, f, parameterReg):
        if f == None:
           return (None,None)
        #if f.name == "HAL_UART_Receive" or f.name == "HAL_SPI_Receive_IT" or f.name == "HAL_I2C_Mem_Read" or f.name == "HAL_I2C_Mem_Write":
        if f.name == "HAL_I2C_Mem_Read":  
           for tba in f.block_addrs:
              tbb = self._project.factory.block(tba)
              tbb.vex.pp() 
        if isinstance(parameterReg,int):
           parameterReg = self.IRgetArgName(parameterReg)
        try:        
           bb1 = self._project.factory.block(f.addr)
        except angr.errors.SimEngineError:
           return (None,None)
        stores = [x for x in bb1.vex.statements if x.tag == 'Ist_Store']
        localaddr = None
        for s in stores:
            if self.IRisGetFrom(s.data, bb1, parameterReg):
               localaddr = s.addr
               break
        if localaddr == None:
           #for tba in f.block_addrs:
           #   tbb = self._project.factory.block(tba)
           #   tbb.vex.pp()
           return (None,None)
        print(f"Local address {localaddr}")
        baseregset = self.IRfindBaseRegSet(bb1, localaddr)
        for br in baseregset:
           # print(f"Base register inferred as {br}")
           self._inferred_base_reg.add(br)
        localbaseAddr = None
        puts = [x for x in bb1.vex.statements if x.tag == 'Ist_Put']          
        for p in puts:
            for br in baseregset:
               if br == self._project.arch.register_names[p.offset]:
                  localbaseAddr = p.data
                  break
        if localbaseAddr == None:
           return (None,None)
        print(f"Local base address {localbaseAddr}")
        localOffset = self.IRfindOffsetFromTop(bb1, localaddr, localbaseAddr)
        #print(f"Local variable offset {localOffset}")
        resultsCallback = set()
        resultsBuffer = set()
        fa = 0
        datastroffset = -1
        for bb2a in f.block_addrs:
            try:  
               bb2 = self._project.factory.block(bb2a)
            except angr.errors.SimEngineError:
               continue
            stores = [x for x in bb2.vex.statements if x.tag == 'Ist_Store']
            for s in stores:
                if self.IRfunctionReferences(bb2a):
                   # print(f"Checking store {s}")
                   fa = self.IRfunctionReference(bb2, s.data)
                   if fa:
                      # print(f"Function reference in {s.data} offset obtained from {s.addr}")
                      #datastroffset = self.IRmatchFindDataStructureOffset(bb2, s.addr, localOffset, baseregset)
                      datastroffset = self.IRmatchFindDataStructureOffset(bb2, s.addr, baseregset)
                      if not datastroffset == -1:
                         print(f"Function {hex(fa)} is stored at an offset {datastroffset} of the handler vs {localOffset}") 
                         resultsCallback.add((f.addr, datastroffset, fa))
                      #else:
                         # print(f"No offset!")
                argreg, localOffsetForReg = self.IRgetsFromArg(bb2, s.data)
                if not self.IRisArgReg(argreg):
                   continue 
                if not argreg == None and not localOffsetForReg == None:
                   # print(f"Flowing from arg {argreg}")
                   #datastroffset = self.IRmatchFindDataStructureOffset(bb2, s.addr, localOffsetForReg, baseregset)
                   datastroffset = self.IRmatchFindDataStructureOffset(bb2, s.addr, baseregset)
                   if not datastroffset == -1:
                      print(f"Buffer flowing from arg {argreg} is stored at an offset {datastroffset} of the handler vs {localOffset}")
                      resultsBuffer.add((f.addr, datastroffset, "argument", argreg))
                   #else:
                      # print(f"No offset!")
                   #todo: handle global buffer assignments
        return (resultsCallback, resultsBuffer)

    def IRgetRegAliasFromFirstBasicBlock(self, f, reg):
        alias = set()
        if f == None:
           return alias
        bb = self._project.factory.block(f.addr)
        puts = [x for x in bb.vex.statements if x.tag == 'Ist_Put']
        for put in puts:
            dnode = self.IRgetDefStmt(bb, put.data)
            if dnode == None:
               continue
            if isinstance(dnode.data,pyvex.IRExpr.Get):
               if reg == self._project.arch.register_names[dnode.data.offset]:
                  alias.add(self._project.arch.register_names[put.offset])
        return alias    

    def IRgetRegistersinGet(self, bb):
        results = set()
        for st in bb.vex.statements:
            if isinstance(st, pyvex.IRStmt.WrTmp):
               if isinstance(st.data, pyvex.IRExpr.Get):
                  results.add(self._project.arch.register_names[st.data.offset])
        return results

    def IRgetDefStmtForDepth(self, bb, rd, depth=1):
        # print(f"def for {rd} with depth {depth}")
        if depth <= 1:
           if isinstance(rd, pyvex.IRExpr.Load) or isinstance(rd, pyvex.IRStmt.LoadG):
              return rd
           else:  
              return self.IRgetDefStmt(bb, rd)
        dnode = self.IRgetDefStmt(bb,rd)
        if dnode == None: 
           return None
        if isinstance(dnode.data,pyvex.IRExpr.Unop):
           # print(f"Unary operand {dnode.data}")
           for c in dnode.data.child_expressions:
              res = self.IRgetDefStmtForDepth(bb, c, depth-1)
              if not res == None:
                 return res 
        return self.IRgetDefStmt(bb, rd)

    def IRgetDefStmt(self, bb, rd):
        if not isinstance(rd,pyvex.IRExpr.RdTmp):
           return None
        wrtmp = [x for x in bb.vex.statements if x.tag == 'Ist_WrTmp']
        for wt in wrtmp:
            if wt.tmp == rd._tmp:
               return wt
        return None         


    #def IRchildLoadDefinedBy(self, bb, node, localOffset, baseregset):
    def IRchildLoadDefinedBy(self, bb, node, baseregset):
        if not isinstance(node,pyvex.IRExpr.RdTmp):
           return False 
        dnode = self.IRgetDefStmt(bb,node) 
        if not isinstance(dnode.data,pyvex.IRExpr.Load) and not isinstance(dnode.data,pyvex.IRStmt.LoadG):
           return False
        if not isinstance(dnode.data.addr,pyvex.IRExpr.RdTmp):
           return False 
        d2 = self.IRgetDefStmt(bb,dnode.data.addr)
        if d2 == None:
           return False
        nc = self.IRgetNonConstantFromBinary(bb, d2.data)        
        if nc == None:
           return False
        for br in baseregset:
            if self.IRisDefinedBy(bb, nc, br):
               return True
        return False

    """ 
         Set of registers defined by an IR node nc in basic block bb
    """ 
    def IRgetRegsDefinedBy(self, bb, nc):
        result = set()
        puts = [x for x in bb.vex.statements if x.tag == 'Ist_Put']
        for p in puts:
            if p.data == nc:
               result.add(self._project.arch.register_names[p.offset])
        return result

    """
       Find base registers that are defined by a subexpression in node
    """
    def IRfindBaseRegSet(self, bb, node):
        result = set()
        if not isinstance(node,pyvex.IRExpr.RdTmp):
           return result
        dnode = self.IRgetDefStmt(bb,node)
        if dnode == None:
           return result
        nc = self.IRgetNonConstantFromBinary(bb, dnode.data)
        if nc == None:
           return result
        result = self.IRgetRegsDefinedBy(bb, nc)
        return result

    """
       Get alias temp for node  
    """
    def IRgetAliasTmp(self, bb, node):
        dnode = self.IRgetDefStmt(bb, node)
        if dnode == None:
           return None
        if isinstance(dnode.data,pyvex.IRExpr.RdTmp):
           return dnode.data
        return None 

    """
       Get nonconstant subexpression from node
    """
    def IRgetNonConstantFromBinary(self, bb, node):
        tnode = node
        if not isinstance(node,pyvex.IRExpr.Binop):
           dnode = self.IRgetDefStmt(bb,node)
           if dnode == None:
              return None
           if isinstance(dnode.data, pyvex.IRExpr.Binop):
              tnode = dnode.data
           else:  
              al = self.IRgetAliasTmp(bb, node)
              if al == None:
                 return None
              else:
                 dal = self.IRgetDefStmt(bb,al)
                 if not isinstance(dal.data,pyvex.IRExpr.Binop):
                    return None
                 else:
                    tnode = dal.data
        for c in tnode.child_expressions:
            if not isinstance(c,pyvex.IRExpr.Const):
               return c
        return None   

    """
        Get constant subexpression from node
    """
    def IRgetConstantFromBinary(self, bb, node):
        tnode = node
        if not isinstance(node,pyvex.IRExpr.Binop):
           dnode = self.IRgetDefStmt(bb,node)
           if dnode == None:
              return None
           if isinstance(dnode.data, pyvex.IRExpr.Binop):
              tnode = dnode.data
           else:  
              al = self.IRgetAliasTmp(bb, node)
              # print(f"Alias of {node} is {al}")
              if al == None:
                 return None
              else:
                 dal = self.IRgetDefStmt(bb,al)
                 if not isinstance(dal.data,pyvex.IRExpr.Binop):
                    return None
                 else:
                    tnode = dal.data
        for c in tnode.child_expressions:
            if isinstance(c,pyvex.IRExpr.Const):
               return c
        return None   


    def IRgetLocalOffsetForReg(self, func, reg):
        if not func.addr in self._localOffset.keys():
           self.IRcomputeStackOffsetAtEntry(func)
        if reg in self._localOffset[func.addr]:
           return self._localOffset[func.addr][reg]
        else:
           if reg in self._localOffset[func.addr]:
              return self._localOffset[func.addr][reg]
           else:
              self._localOffset[func.addr][reg] = None
              return None


    def IRgetOffsetAndSub(self, bb, node):
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRgetOffsetAndSub(bb,dnode.data)
           else:
              return (None,0) 
        if isinstance(node,pyvex.IRExpr.Unop):
           for ce in node.child_expressions:
               return (ce,0)
        if isinstance(node,pyvex.IRExpr.Binop):
           nc = None
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  nc = ce
                  break
           if node.op == 'Iop_Add64' or node.op == 'Iop_Add32' or node.op == 'Iop_Add16':
              off = 0
              for ce in node.child_expressions:
                  if isinstance(ce,pyvex.IRExpr.Const):
                     off = ce.con._value
                     break
              return (nc, off)
           else:
              if node.op == 'Iop_Sub64' or node.op == 'Iop_Sub32' or node.op == 'Iop_Sub16':
                 off = 0
                 for ce in node.child_expressions:
                     if isinstance(ce,pyvex.IRExpr.Const):
                        off = ce.con._value
                        break
                 return (nc, -off)
              else:
                 return (nc,0)
        return (None,0)

    #def IRcomputeStackOffsetForNode(self, func, node, baseregUpdates, stmts, size):
    def IRcomputeStackOffsetForNode(self, func, baseregset, bb, node, stmts, size, type="Store", exprType="lhs"):
        print(f"Computing offset for {node}")
        if not func.addr in self._localOffset.keys():
           self.IRcomputeStackOffsetAtEntry(func)
        index = -1
        for i in range(size):
            if type == "Store" and (isinstance(stmts[i],pyvex.IRStmt.Store) or isinstance(stmts[i],pyvex.IRStmt.StoreG)):
               if exprType=="lhs" and stmts[i].addr == node:
                  index = i - 1
                  break
               if exprType=="rhs" and stmts[i].data == node:
                  index = i - 1
                  break
            # for Put exprType is not relevant!
            if type == "Put" and isinstance(stmts[i],pyvex.IRStmt.Put):
               if stmts[i].data == node:
                  index = i - 1
                  break
        if index <= -1:
           print(f"Offset computation stuck at {node}")
           return (None, None)
        #last, offset = self.IRgetOffsetAndSub(bb, node)
        last = None
        offset = 0
        if last == None:
           last = node
        #print(f"index={index} last={last} offset={offset}")
        j = index
        baseregReached = False
        basereg = None
        while j >= 0:
           if isinstance(last,pyvex.IRExpr.RdTmp):
              if stmts[j].tag == 'Ist_WrTmp':
                 if stmts[j].tmp == last._tmp:
                    if isinstance(stmts[j].data,pyvex.IRExpr.Load) or isinstance(stmts[j].data,pyvex.IRStmt.LoadG):
                       #reset offset
                       offset = 0
                       print(f"Resetting offset to {offset}")
                       last = stmts[j].data.addr
                    else:
                       if isinstance(stmts[j].data,pyvex.IRExpr.Get):
                          if self._project.arch.register_names[stmts[j].data.offset] in baseregset:
                             baseregReached = True
                             basereg = self._project.arch.register_names[stmts[j].data.offset] 
                             break 
                       l, lo = self.IRgetOffsetAndSub(bb,stmts[j].data)
                       if not l == None:
                          last = l
                       else:
                          last = stmts[j].data
                       offset += lo
                       print(f"Adding {lo} => {offset} due to {stmts[j].data} next {last}")
           if isinstance(last,pyvex.IRExpr.Get):
              if self._project.arch.register_names[last.offset] in baseregset:
                 baseregReached = True
                 basereg = self._project.arch.register_names[last.offset]
                 break 
              if isinstance(stmts[j],pyvex.IRStmt.Put):
                 if last.offset == stmts[j].offset:
                    l,lo = self.IRgetOffsetAndSub(bb,stmts[j].data)
                    if not l == None:
                       last = l
                    else:
                       last = stmts[j].data
                    offset += lo
                    print(f"Adding {lo} => {offset} due to {stmts[j].data} next {last}")
           j -= 1
        if baseregReached:
           #print(f"Base register {basereg} reached final offset value {offset} for {node} in {hex(func.addr)} name {func.name} bb {hex(bb.addr)}")
           if not bb.addr == func.addr and not bb.addr + 1 == func.addr:
              offset += self._localOffset[func.addr][basereg]
           return (offset, basereg)
        else:
           print(f"Offset computation stuck at {node}")
           return (None,None) 

    def IRcomputeStackOffsetAtBasicBlock(self, func, bbc, node, type="Store", exprType="lhs"):
        baseregset = self.IRgetBaseRegSetForFunction(func)
        #bb = self._project.factory.block(func.addr)
        stmts = {}
        #baseregUpdates = {}
        #for br in baseregset:
        #    baseregUpdates[br] = [] 
        i = 0
        for s in bbc.vex.statements:
            stmts[i] = s 
            #if isinstance(s,pyvex.IRStmt.Put):
            #   if self._project.arch.register_names[s.offset] in baseregset:
            #      baseregUpdates[self._project.arch.register_names[s.offset]].insert(-1,i)
            i += 1
        return self.IRcomputeStackOffsetForNode(func, baseregset, bbc, node, stmts, i, type, exprType)
        #return self.IRcomputeStackOffsetForNode(func, node, baseregUpdates, stmts, i)


    def IRdefinedbyReg(self, bb, node):
        rnode = self.IRdefinedbyRegGetNode(bb, node)
        if rnode == None:
           return None
        if isinstance(rnode,pyvex.IRExpr.Get):
           return self._project.arch.register_names[rnode.offset]
        return None

    def IRdefinedbyRegGetNode(self, bb, node):
        if isinstance(node,pyvex.IRExpr.Get):
           return node
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRdefinedbyRegGetNode(bb, dnode.data)
           else:
              return None
        for ce in node.child_expressions:
            if not isinstance(ce,pyvex.IRExpr.Const):
               r = self.IRdefinedbyRegGetNode(bb, ce)
               if not r == None:
                  return r
        return None

    def IRdefinedbyRegGetNodeWStmt(self, bb, node, stmt=None):
        if isinstance(node,pyvex.IRExpr.Get):
           return (node, stmt)
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRdefinedbyRegGetNodeWStmt(bb, dnode.data, stmt)
           else:
              return (None,stmt)
        if self.IRisStatement(node):
           stmt = node
        for ce in node.child_expressions:
            if not isinstance(ce,pyvex.IRExpr.Const):
               r,s = self.IRdefinedbyRegGetNodeWStmt(bb, ce, stmt)
               if not r == None:
                  return (r,s)
        return (None,stmt)


    def IRcomputeBaseregisterOffsets(self, func, baseregset):
        if not func.addr in self._localOffset.keys():
           self._localOffset[func.addr] = {}
        complete = True
        for br in baseregset:
            if not br in self._localOffset[func.addr].keys():
               complete = False
               break
        if complete:
           return 
        try:
           bb = self._project.factory.block(func.addr)
        except angr.errors.SimEngineError:
           return
        stmts = {}
        i = 0
        for s in bb.vex.statements:
            stmts[i] = s 
            i += 1
        j = i - 1
        while j>=0:
           if isinstance(stmts[j],pyvex.IRStmt.Put):
              ps = stmts[j]
              for br in baseregset:
                  if br in self._localOffset[func.addr].keys():
                     continue 
                  if self._project.arch.register_names[ps.offset] == br:
                     offset, basereg = self.IRcomputeStackOffsetForNode(func, baseregset, bb, ps.data, stmts, i, "Put")
                     if not offset == None:
                        self._localOffset[func.addr][br] = offset
                        print(f"Function {func.name} base register {br} offset {offset}") 
           j -= 1
            

    def IRcomputeStackOffsetAtEntry(self, func):
        baseregset = self.IRgetBaseRegSetForFunction(func)
        try:
           bb = self._project.factory.block(func.addr)
        except angr.errors.SimEngineError:
           return
        stmts = {}
        i = 0
        for s in bb.vex.statements:
            stmts[i] = s 
            i += 1
        # find the most recent sp update and use that to adjust the offsets
        self.IRcomputeBaseregisterOffsets(func, baseregset)
        if len(baseregset) == 0:
           return
        if not "sp" in self._localOffset[func.addr].keys():
           return 
        print(f"baseregset {baseregset}")
        stackAdjustment = self._localOffset[func.addr]["sp"] 
        print(f"Stack pointer adjustment offset for function {hex(func.addr)} name {func.name} is {stackAdjustment}")
        if not func.addr in self._localOffset.keys():
           self._localOffset[func.addr] = {}  
        stores = [x for x in bb.vex.statements if x.tag == 'Ist_Store']
        for s in stores:
            reg = self.IRdefinedbyReg(bb, s.data)
            #print(f"Is {s.data} defined by reg {reg}")
            if self.IRisArgReg(reg):
               #offset = self.IRcomputeStackOffsetForNode(func, s.addr, baseregUpdates, stmts, i)
               offset, basereg = self.IRcomputeStackOffsetForNode(func, baseregset, bb, s.addr, stmts, i, "Store", "lhs")
               #print(f"Offset for {s.addr} is {offset} in {hex(func.addr)}")
               if not offset == None and not basereg == None:
                  self._localOffset[func.addr][reg] = offset
                  print(f"Local offset for register {reg} is {self._localOffset[func.addr][reg]} wrt base register {basereg} in function {hex(func.addr)} name {func.name}")
        return stackAdjustment


    def IRderivedFromBaseregisterRelaxed(self, bb, node, baseregset):
        if isinstance(node,pyvex.IRExpr.Get): 
           #print(f"reg {self._project.arch.register_names[node.offset]} in {baseregset}")
           if self._project.arch.register_names[node.offset] in baseregset:
              return True
           else:
              return False
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRderivedFromBaseregisterRelaxed(bb, dnode.data, baseregset)
           else:
              return False
        else:
           if isinstance(node,pyvex.IRExpr.Load) or isinstance(node,pyvex.IRStmt.LoadG):
              return self.IRderivedFromBaseregisterRelaxed(bb, node.addr, baseregset)
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  if self.IRderivedFromBaseregisterRelaxed(bb, ce, baseregset):
                     return True
        return False
 


    def IRderivedFromBaseregister(self, bb, node, baseregset):
        if isinstance(node,pyvex.IRExpr.Get): 
           #print(f"reg {self._project.arch.register_names[node.offset]} in {baseregset}")
           if self._project.arch.register_names[node.offset] in baseregset:
              return True
           else:
              return False
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRderivedFromBaseregister(bb, dnode.data, baseregset)
           else:
              return False
        else:
           if isinstance(node,pyvex.IRExpr.Load) or isinstance(node,pyvex.IRStmt.LoadG):
              return False
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  if self.IRderivedFromBaseregister(bb, ce, baseregset):
                     return True
        return False


    def IRgetStmtIndex(self, bb, stmt):
        i = 0
        for s in bb.vex.statements:
            if str(s) == str(stmt):
               return i
            i += 1
        return None

    def IRgetOffsetOverCFGNode(self, func, bborig, bbcur, depth, c=None, reg=None, visited=None):
        #print(f"CFGNode: current bb {hex(bbcur.addr)} c {c} reg {reg} visited {visited}")
        if reg == None:
           return None
        if bbcur.addr in visited:
           return None
        visited.add(bbcur.addr)
        s1, s2 = self.IRGetArgSource(bbcur, reg, len(bbcur.vex.statements))
        if s1 == None and s2 == None:
           cfgnode = self._current_cfg.get_any_node(bbcur.addr)
           res = set()
           try:
               preds = self._current_cfg.get_all_predecessors(cfgnode, self._predDepth)
           except RecursionError:
               return res
           for pred in preds:
               f = self.IRgetFunctionAtAddress(pred.addr)
               if f == None:
                  f = self.IRgetFunctionOfBlock(pred.addr)
               if f == None:
                  print(f"WARNING: Function for {hex(pred.addr)} could not be found!!!")
                  continue
               if not f.addr == func.addr:
                  continue
               try:
                  bb = self._project.factory.block(pred.addr)
               except angr.errors.SimEngineError:
                  continue 
               sub = self.IRgetOffsetOverCFGNode(func, bborig, bb, depth, c, reg, visited) 
               if not sub == None: 
                  for s in sub:
                      res.add(s)
           if not c == None and len(res) == 0:
              res.add(c)
           return res
        else:
           return set()           
           #return self.IRgetOffsetOverCFG(func, bborig, bbcur, sr, depth, c, reg, visited)  


    def IRgetOffsetOverCFG(self, func, bborig, bbcur, node, depth, c=None, reg=None, visited=None):
        #print(f"CFG: current bb {hex(bbcur.addr)} c {c} reg {reg} visited {visited}")
        res = set()
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bbcur, node)
           if not dnode == None:
              r = self.IRgetOffsetOverCFG(func, bborig, bbcur, dnode.data, depth, c, reg, visited)
              if not r == None:
                 for v in r:
                     res.add(v)
           return res
        else:
           if isinstance(node,pyvex.IRExpr.Get):
              if not c == None:
                 r = self._project.arch.register_names[node.offset]
                 if self.IRisArgReg(r):
                    if reg == None:
                       reg = r
                    else:
                       return res
                    # get definitions of r in the same basic block 
                    s1, s2 = self.IRGetArgSource(bbcur, r, len(bbcur.vex.statements))
                    if s1 == None and s2 == None:
                       # check predecessors
                       clean = (visited == None)
                       if visited == None:
                          visited = set()
                       cfgnode = self._current_cfg.get_any_node(bbcur.addr)
                       try:
                           preds = self._current_cfg.get_all_predecessors(cfgnode, self._predDepth)
                       except RecursionError:
                           return res
                       for pred in preds:
                           f = self.IRgetFunctionAtAddress(pred.addr)
                           if f == None:
                              f = self.IRgetFunctionOfBlock(pred.addr)
                           if f == None:
                              print(f"WARNING: Function for {hex(pred.addr)} could not be found!!!")
                              continue
                           if not f.addr == func.addr:
                              continue
                           try:
                              bb = self._project.factory.block(pred.addr)
                           except angr.errors.SimEngineError:
                              continue 
                           sub = self.IRgetOffsetOverCFGNode(func, bborig, bb, depth, c, r, visited)
                           if not sub == None: 
                              for s in sub:
                                  res.add(s)
                       if len(res) == 0:
                          res.add(c)
                       if clean:
                          del visited
                       return res
                 # todo if we can precisely find reg defs then we can keep searching
                 return set()
              else:
                 return res
           if isinstance(node,pyvex.IRExpr.Unop):
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     return self.IRgetOffsetOverCFG(func, bborig, bbcur, ce, depth, c, reg, visited)
           if isinstance(node,pyvex.IRExpr.Binop):
              coe = None
              if c == None:
                 for ce in node.child_expressions:
                     if isinstance(ce,pyvex.IRExpr.Const):
                        coe = ce.con._value
                        break
              else:
                 coe = c
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     r = self.IRgetOffsetOverCFG(func, bborig, bbcur, ce, depth, coe, reg, visited)
                     if not r == None:
                        for v in r:
                            res.add(v)
              return res 
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  r = self.IRgetOffsetOverCFG(func, bborig, bbcur, ce, depth, c, reg, visited)
                  if not r == None:
                     for v in r:
                         res.add(v)
           return res 

 
    # Data structure offset will be checked assuming local access wrt a base register or via an arg reg 
    def IRgetOffsetFromLocalOrArg(self, func, baseregset, bb, node, depth):
        lres = self.IRgetOffsetBeforeLoadFromBaseReg(bb, node, baseregset, depth)
        if lres == None:
           return self.IRgetOffsetOverCFG(func, bb, bb, node, depth)
        else:
           res = set()
           res.add(lres) 
           return res

    # L1( arg ) + offset 
    def IRgetOffsetBeforeLoadDirectlyFromRegWoSecondLoad(self, bb, node, c=None):
        tuples = set()
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRgetOffsetBeforeLoadDirectlyFromRegWoSecondLoad(bb, dnode.data, c)
           else:
              return set()
        else:
           if isinstance(node,pyvex.IRExpr.Load) or isinstance(node,pyvex.IRStmt.LoadG):
              return self.IRgetOffsetBeforeLoadDirectlyFromRegWoSecondLoad(bb,node.addr,c) 
           if isinstance(node,pyvex.IRExpr.Get):
              if c == None:
                 return set()
              reg = self._project.arch.register_names[node.offset]
              tuples.add((reg, c))
              return tuples 
           if isinstance(node,pyvex.IRExpr.Unop):
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     tres = self.IRgetOffsetBeforeLoadDirectlyFromRegWoSecondLoad(bb, ce, c)
                     for t in tres:
                         tuples.add(t)
              return tuples
           if isinstance(node,pyvex.IRExpr.Binop):
              coe = None
              if c == None:
                 for ce in node.child_expressions:
                     if isinstance(ce,pyvex.IRExpr.Const):
                        coe = ce.con._value
                        break
              else:
                 coe = c
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     tres = self.IRgetOffsetBeforeLoadDirectlyFromRegWoSecondLoad(bb, ce, coe)
                     for t in tres:
                         tuples.add(t)
              return tuples
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  tres = self.IRgetOffsetBeforeLoadDirectlyFromRegWoSecondLoad(bb, ce, c)
                  for t in tres:
                      tuples.add(t)
           return tuples
        return set()

    # L2(...L1( arg ) + offset ...)
    def IRgetOffsetBeforeLoadDirectlyFromReg(self, bb, node, c=None, l=None):
        tuples = set() 
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRgetOffsetBeforeLoadDirectlyFromReg(bb, dnode.data, c, l)
           else:
              return set()
        else:
           if isinstance(node,pyvex.IRExpr.Load) or isinstance(node,pyvex.IRStmt.LoadG):
              if l == None and not c == None:
                 c = None
              return self.IRgetOffsetBeforeLoadDirectlyFromReg(bb, node.addr, c, node)
           if isinstance(node,pyvex.IRExpr.Get):  
              if c == None:
                 return set() 
              reg = self._project.arch.register_names[node.offset]
              tuples.add((reg, c))
              return tuples
           if isinstance(node,pyvex.IRExpr.Unop):
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     tres = self.IRgetOffsetBeforeLoadDirectlyFromReg(bb, ce, c, l)
                     for t in tres:
                         tuples.add(t)
              return tuples 
           if isinstance(node,pyvex.IRExpr.Binop):
              coe = None
              if c == None:
                 for ce in node.child_expressions:
                     if isinstance(ce,pyvex.IRExpr.Const):
                        coe = ce.con._value
                        break
              else:
                 coe = c
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     tres = self.IRgetOffsetBeforeLoadDirectlyFromReg(bb, ce, coe, l)
                     for t in tres:
                         tuples.add(t)
              return tuples 
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  tres = self.IRgetOffsetBeforeLoadDirectlyFromReg(bb, ce, c, l)
                  for t in tres:
                      tuples.add(t)
           return tuples 
        return set()

    # L1(... local ...) + offset
    def IRgetOffsetBeforeLoadFromBaseReg(self, bb, node, baseregset, depth, c=None):
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRgetOffsetBeforeLoadFromBaseReg(bb, dnode.data, baseregset, depth, c)
           else:
              return None
        else:
           if isinstance(node,pyvex.IRExpr.Load) or isinstance(node,pyvex.IRStmt.LoadG):
              if c == None:
                 return None
              #print(f"dtoffset in 2nd load checked for {node}")
              if self.IRderivedFromBaseregister(bb, node.addr, baseregset):
                 return c
              else:
                 return None 
           if isinstance(node,pyvex.IRExpr.Unop):
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     return self.IRgetOffsetBeforeLoadFromBaseReg(bb, ce, baseregset, depth, c) 
           if isinstance(node,pyvex.IRExpr.Binop):
              coe = None
              if c == None:
                 for ce in node.child_expressions:
                     if isinstance(ce,pyvex.IRExpr.Const):
                        coe = ce.con._value
                        break
              else:
                 coe = c
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     r = self.IRgetOffsetBeforeLoadFromBaseReg(bb, ce, baseregset, depth, coe)
                     if not r == None:
                        return r
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  r = self.IRgetOffsetBeforeLoadFromBaseReg(bb, ce, baseregset, depth, c)
                  if not r == None:
                     return r
        return None  


    # L1(L2(... local ...)) + offset
    def IRgetOffsetBeforeFirstLoadForSecondLoadFromBaseReg(self, bb, node, baseregset, depth, c=None, l1=None):
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRgetOffsetBeforeFirstLoadForSecondLoadFromBaseReg(bb, dnode.data, baseregset, depth, c, l1)
           else:
              return None
        else:
           if isinstance(node,pyvex.IRExpr.Load) or isinstance(node,pyvex.IRStmt.LoadG):
              if c == None:
                 return None
              if l1 == None:
                 #print(f"l1: {node}")
                 return self.IRgetOffsetBeforeFirstLoadForSecondLoadFromBaseReg(bb, node.addr, baseregset, depth, c, node)
              else:
                 #print(f"dtoffset in 2nd load checked for {node}")
                 if self.IRderivedFromBaseregister(bb, node.addr, baseregset):
                    return c
                 else:
                    return None 
           if isinstance(node,pyvex.IRExpr.Unop):
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     return self.IRgetOffsetBeforeFirstLoadForSecondLoadFromBaseReg(bb, ce, baseregset, depth, c, l1) 
           if isinstance(node,pyvex.IRExpr.Binop):
              coe = None
              if c == None and l1 == None:
                 for ce in node.child_expressions:
                     if isinstance(ce,pyvex.IRExpr.Const):
                        coe = ce.con._value
                        break
              else:
                 coe = c
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     r = self.IRgetOffsetBeforeFirstLoadForSecondLoadFromBaseReg(bb, ce, baseregset, depth, coe, l1)
                     if not r == None:
                        return r
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  r = self.IRgetOffsetBeforeFirstLoadForSecondLoadFromBaseReg(bb, ce, baseregset, depth, c, l1)
                  if not r == None:
                     return r
        return None  

    # L1(L2(... local ...) + offset)
    def IRgetFirstLoadOffsetForSecondLoadFromBaseReg(self, bb, node, baseregset, depth, c=None, l1=None):
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRgetFirstLoadOffsetForSecondLoadFromBaseReg(bb, dnode.data, baseregset, depth, c, l1)
           else:
              return None
        else:
           if isinstance(node,pyvex.IRExpr.Load) or isinstance(node,pyvex.IRStmt.LoadG):
              if l1 == None:
                 #print(f"l1: {node}")
                 return self.IRgetFirstLoadOffsetForSecondLoadFromBaseReg(bb, node.addr, baseregset, depth, c, node)
              else:
                 if c == None:
                    return self.IRgetFirstLoadOffsetForSecondLoadFromBaseReg(bb, node.addr, baseregset, depth, c, node)
                 else:
                    #print(f"dtoffset in 2nd load checked for {node}")
                    if self.IRderivedFromBaseregister(bb, node.addr, baseregset):
                       return c
                    else:
                       return None 
           if isinstance(node,pyvex.IRExpr.Unop):
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     return self.IRgetFirstLoadOffsetForSecondLoadFromBaseReg(bb, ce, baseregset, depth, c, l1) 
           if isinstance(node,pyvex.IRExpr.Binop):
              coe = None
              if c == None and not l1 == None:
                 for ce in node.child_expressions:
                     if isinstance(ce,pyvex.IRExpr.Const):
                        coe = ce.con._value
                        break
              else:
                 coe = c
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     r = self.IRgetFirstLoadOffsetForSecondLoadFromBaseReg(bb, ce, baseregset, depth, coe, l1)
                     if not r == None:
                        return r
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  r = self.IRgetFirstLoadOffsetForSecondLoadFromBaseReg(bb, ce, baseregset, depth, c, l1)
                  if not r == None:
                     return r
        return None  

    # L1(L2(L3(... local ...)) + offset)
    def IRgetFirstLoadOffsetForThirdLoadFromBaseReg(self, bb, node, baseregset, depth, c=None, l1=None, l2=None):
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRgetFirstLoadOffsetForThirdLoadFromBaseReg(bb, dnode.data, baseregset, depth, c, l1, l2)
           else:
              return None
        else:
           if isinstance(node,pyvex.IRExpr.Load) or isinstance(node,pyvex.IRStmt.LoadG):
              if l1 == None:
                 #print(f"l1: {node}")
                 return self.IRgetFirstLoadOffsetForThirdLoadFromBaseReg(bb, node.addr, baseregset, depth, c, node, l2)
              else:
                 if c == None:
                    #print(f"Second load!!!")
                    return None
                    #return self.IRgetFirstLoadOffsetForThirdLoadFromBaseReg(bb, node.addr, baseregset, depth, c, l1, l2)
                 else:
                    if l2 == None:
                       #print(f"l2: {node}")
                       return self.IRgetFirstLoadOffsetForThirdLoadFromBaseReg(bb, node.addr, baseregset, depth, c, l1, node)
                    else:
                       #print(f"dtoffset in 3rd load checked for {node.addr}")
                       if self.IRderivedFromBaseregister(bb, node.addr, baseregset):
                          return c
                       else:
                          return None 
           if isinstance(node,pyvex.IRExpr.Unop):
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     return self.IRgetFirstLoadOffsetForThirdLoadFromBaseReg(bb, ce, baseregset, depth, c, l1, l2) 
           if isinstance(node,pyvex.IRExpr.Binop):
              coe = None
              if c == None and not l1 == None:
                 for ce in node.child_expressions:
                     if isinstance(ce,pyvex.IRExpr.Const):
                        coe = ce.con._value
                        break
              else:
                 coe = c
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     r = self.IRgetFirstLoadOffsetForThirdLoadFromBaseReg(bb, ce, baseregset, depth, coe, l1, l2)
                     if not r == None:
                        return r
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  r = self.IRgetFirstLoadOffsetForThirdLoadFromBaseReg(bb, ce, baseregset, depth, c, l1, l2)
                  if not r == None:
                     return r
        return None  


    # L1(L2(L3(... local ...) + offset))
    def IRgetSecondLoadOffsetForThirdLoadFromBaseReg(self, bb, node, baseregset, depth, c=None, l1=None, l2=None):
        if isinstance(node,pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if not dnode == None:
              return self.IRgetSecondLoadOffsetForThirdLoadFromBaseReg(bb, dnode.data, baseregset, depth, c, l1, l2)
           else:
              return None
        else:
           if isinstance(node,pyvex.IRExpr.Load) or isinstance(node,pyvex.IRStmt.LoadG):
              if l1 == None:
                 #print(f"l1: {node}")
                 return self.IRgetSecondLoadOffsetForThirdLoadFromBaseReg(bb, node.addr, baseregset, depth, c, node, l2)
              else:
                 if l2 == None:
                    #print(f"l2: {node}")
                    return self.IRgetSecondLoadOffsetForThirdLoadFromBaseReg(bb, node.addr, baseregset, depth, c, l1, node)
                 else:
                    if c == None:
                       return None
                    else:
                       #print(f"dtoffset in 3rd load checked for {node.addr}")
                       if self.IRderivedFromBaseregister(bb, node.addr, baseregset):
                          return c
                       else:
                          return None 
           if isinstance(node,pyvex.IRExpr.Unop):
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     return self.IRgetSecondLoadOffsetForThirdLoadFromBaseReg(bb, ce, baseregset, depth, c, l1, l2) 
           if isinstance(node,pyvex.IRExpr.Binop):
              coe = None
              if c == None and not l1 == None and not l2 == None:
                 for ce in node.child_expressions:
                     if isinstance(ce,pyvex.IRExpr.Const):
                        coe = ce.con._value
                        break
              else:
                 coe = c
              for ce in node.child_expressions:
                  if not isinstance(ce,pyvex.IRExpr.Const):
                     r = self.IRgetSecondLoadOffsetForThirdLoadFromBaseReg(bb, ce, baseregset, depth, coe, l1, l2)
                     if not r == None:
                        return r
           for ce in node.child_expressions:
               if not isinstance(ce,pyvex.IRExpr.Const):
                  r = self.IRgetSecondLoadOffsetForThirdLoadFromBaseReg(bb, ce, baseregset, depth, c, l1, l2)
                  if not r == None:
                     return r
        return None  

    def IRmatchFindDataStructureOffsetDirectFromArg(self, bb, node, parameterReg):
        if isinstance(node, pyvex.IRExpr.Const):
           return node.con._value
        if isinstance(node, pyvex.IRExpr.RdTmp):
           dnode = self.IRgetDefStmt(bb, node)
           if dnode == None:
              return None
           return self.IRmatchFindDataStructureOffsetDirectFromArg(bb, dnode.data, parameterReg)
        if isinstance(node,pyvex.IRExpr.Binop):
           if node.op == 'Iop_Add64' or node.op == 'Iop_Add32' or node.op == 'Iop_Add16':
              offset = 0
              for ce in node.child_expressions:
                  res =  self.IRmatchFindDataStructureOffsetDirectFromArg(bb, ce, parameterReg)
                  if res == None:
                     return None
                  if not isinstance(res, int):
                     res = int(res, 16)
                  offset += res
              return offset
        if isinstance(node,pyvex.IRExpr.Unop):
           for ce in node.child_expressions:
               res =  self.IRmatchFindDataStructureOffsetDirectFromArg(bb, ce, parameterReg)
               return res
        if isinstance(node,pyvex.IRExpr.Get):
           if self._project.arch.register_names[node.offset] == parameterReg:
              return 0
           else:
              return None
        return None             

    """
        Return the offset used when accessing a local variable wrt a base register in baseregset
    """
    #def IRmatchFindDataStructureOffset(self, bb, node, localOffset, baseregset):
    def IRmatchFindDataStructureOffset(self, bb, node, baseregset, depth=1):
        dnode = self.IRgetDefStmtForDepth(bb,node, depth)
        if dnode == None:
           return -1
        nc = self.IRgetNonConstantFromBinary(bb, dnode.data)
        if nc == None:
           return -1 
        if self.IRchildLoadDefinedBy(bb, nc, baseregset):
           dtsoffset = self.IRgetConstantFromBinary(bb, dnode.data)
           if not dtsoffset == None:
              return dtsoffset.con._value
        return -1 


    def IRisStatement(self, node):
        if isinstance(node, pyvex.IRStmt.IMark):
           return True
        if isinstance(node, pyvex.IRStmt.Put):
           return True
        if isinstance(node, pyvex.IRStmt.PutI):
           return True
        if isinstance(node, pyvex.IRStmt.AbiHint):
           return True
        if isinstance(node, pyvex.IRStmt.WrTmp):
           return True
        if isinstance(node, pyvex.IRStmt.Store):
           return True
        if isinstance(node, pyvex.IRStmt.CAS):
           return True
        if isinstance(node, pyvex.IRStmt.LLSC):
           return True
        if isinstance(node, pyvex.IRStmt.MBE):
           return True
        if isinstance(node, pyvex.IRStmt.Exit):
           return True
        if isinstance(node, pyvex.IRStmt.LoadG):
           return True
        if isinstance(node, pyvex.IRStmt.StoreG):
           return True

      

    """
       Is node defined wrt to register localBaseReg
    """
    def IRisDefinedBy(self, bb, node, localBaseReg):
        dnode = self.IRgetDefStmt(bb, node)
        if dnode == None:
           return False 
        if isinstance(dnode.data,pyvex.IRExpr.Get):
           if localBaseReg == self._project.arch.register_names[dnode.data.offset]:
              return True
        nc = self.IRgetNonConstantFromBinary(bb, dnode.data)
        if nc == None:
           return False
        dnode2 = self.IRgetDefStmt(bb, nc)
        if dnode2 == None:
           return False
        if isinstance(dnode2.data,pyvex.IRExpr.Get):
           if localBaseReg == self._project.arch.register_names[dnode2.data.offset]:
              return True
        return False 

    """
       Get function referred by loading the function address from a constant address 
    """
    def IRfunctionReference(self, bb, node):
        dnode = self.IRgetDefStmt(bb, node)
        if dnode == None:
           return False
        # print(f"fr 0? {dnode.data} load")
        if isinstance(dnode.data,pyvex.IRExpr.Load) or isinstance(dnode.data,pyvex.IRStmt.LoadG):
           # print(f"fr 1? {dnode.data.addr} const")
           if isinstance(dnode.data.addr,pyvex.IRExpr.Const):
              # print(f"fr 2? {dnode.data.addr.con._value} const")
              return self.IRgetFunctionStoredAtAddress(dnode.data.addr.con._value)
        return 0

    def IRgetFunctionAtAddress(self, addr):
        for f in self._current_cfg.functions.values():
            if f.addr == addr or f.addr & ~1 == addr or f.addr == addr  & ~1:
               return f
        return None

    """
        Get the function that includes basic block address ba
    """
    def IRgetFunctionOfBlock(self, ba):
        for f in self._current_cfg.functions.values():
            if ba in f.block_addrs:
               return f
        return None

    """
       Get function whose address is stored in address addr
    """
    def IRgetFunctionStoredAtAddress(self, addr):
        valuebv = self._initial_state.memory.load(addr,4)
        value = self._initial_state.solver.eval(valuebv)
        value = int.from_bytes(value.to_bytes(4,byteorder='little'),byteorder='big')
        if value in self._current_cfg.functions:
           return value
        else:
           return 0 

    """
       Returns true if the basic block address bba refers to some address that stores a function address
    """
    def IRfunctionReferences(self, bba):
         try: 
            bb = self._project.factory.block(bba)
         except angr.errors.SimEngineError:
            return False
         for ia in bb.instruction_addrs:
             xrefs = self._current_cfg.kb.xrefs.get_xrefs_by_ins_addr(ia)
             for xref in xrefs:
                  valuebv = self._initial_state.memory.load(xref.dst,4)
                  value = self._initial_state.solver.eval(valuebv)
                  value = int.from_bytes(value.to_bytes(4,byteorder='little'),byteorder='big')
                  if value in self._current_cfg.functions:
                     return True
         return False 

    def IRgetLoadsAtAddress(self, ia):
        results = set() 
        f = self.IRgetFunctionOfInstruction(ia)
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            found = False
            sta = 0
            index = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.IMark):
                     if found:
                        break
                     sta = st.addr
                  if isinstance(st, pyvex.IRStmt.WrTmp):
                     if isinstance(st.data, pyvex.IRExpr.Load):
                        if sta == ia or sta == ia - 1:
                           results.add((f, bb, index))
                           found = True
                  index += 1
        return results

    def IRgetStoresAtAddress(self, ia):
        results = set() 
        f = self.IRgetFunctionOfInstruction(ia)
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            found = False
            sta = 0
            index = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.IMark):
                     if found:
                        break
                     sta = st.addr
                  if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                     if sta == ia or sta == ia - 1:
                        results.add((f, bb, index))
                        print(f"Store inst found in {f.name} bb {hex(bb.addr)} st {st} for pc {hex(ia)}")
                        found = True
                  index += 1
        return results

    def IRgetStoresAtAddressWithinFunction(self, f, ia):
        results = set() 
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                print(f"Error getting bb for {hex(ba)}")
                continue
            found = False
            sta = 0
            index = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.IMark):
                     if found:
                        break
                     sta = st.addr
                  if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                     if sta == ia or sta == ia - 1:
                        results.add((f, bb, index))
                        print(f"Store inst found in {f.name} bb {hex(bb.addr)} st {st} for pc {hex(ia)}")
                        found = True
                  index += 1
        return results

    def IRgetStoreAtAddress(self, ia):
        f = self.IRgetFunctionOfInstruction(ia)
        for ba in f.block_addrs:
            try:
                bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
                continue
            sta = 0
            index = 0
            while index < len(bb.vex.statements):
                  st = bb.vex.statements[index]
                  if isinstance(st, pyvex.IRStmt.IMark):
                     sta = st.addr
                  if isinstance(st, pyvex.IRStmt.Store) or isinstance(st, pyvex.IRStmt.StoreG):
                     if sta == ia:
                        return (f, bb, index)
                  index += 1
        return (None, None, None)  

    def IRmultipleStoreInstructions(self, bb, ia):
        stmts = {}
        i = 0
        ms = None
        for s in bb.vex.statements:
            stmts[i] = s
            i += 1
        index = 0
        j = 0
        for j in range(i):
            if isinstance(stmts[j],pyvex.IRStmt.IMark):
               if stmts[j].addr == ia or stmts[j].addr == ia - 1:
                  ms = stmts[j]
                  index = j + 1
                  break
        if ms:
           num = 0
           for j in range(ms.len):
               if isinstance(stmts[index + j],pyvex.IRStmt.Store) or isinstance(stmts[index + j],pyvex.IRStmt.StoreG):
                  print(f"Store instruction (IN CHECK) {stmts[index + j]}") 
                  num += 1
           if num > 1:
              return True
        return False 

    def IRcomputeOffsetWrtNode(self, bb, node, refnode):
        if node == refnode:
           return 0
        dnode = self.IRgetDefStmt(bb, node)
        o = 0
        for ce in dnode.data.child_expressions:
            if isinstance(ce,pyvex.IRExpr.Const):
               o = ce.con._value
               break
        for ce in dnode.data.child_expressions:
            if not isinstance(ce,pyvex.IRExpr.Const):
               return o + self.IRcomputeOffsetWrtNode(bb, ce, refnode)
        return 0

    def IRcomputeStoreDiff(self, bb, ia):
        stmts = {}
        i = 0
        ms = None
        for s in bb.vex.statements:
            stmts[i] =s
            i += 1
        begin = 0
        end = 0 
        j = 0
        for j in range(i):
            if isinstance(stmts[j],pyvex.IRStmt.IMark):
               if stmts[j].addr == ia or stmts[j].addr == ia - 1:
                  ms = stmts[j]
                  begin = j
                  end = begin + stmts[j].len - 1
                  break
        nodes = []
        index = end
        lastStore = None
        while index >= begin:
            if isinstance(stmts[index],pyvex.IRStmt.Store) or sinstance(stmts[index],pyvex.IRStmt.StoreG):
               lastStore = stmts[index].addr
               break
            index -= 1
        index = begin
        refnode = None
        while index <= end:
            if isinstance(stmts[index],pyvex.IRStmt.Store) or isinstance(stmts[index],pyvex.IRStmt.StoreG):
               refnode = stmts[index].addr
               break
            index += 1
        return self.IRcomputeOffsetWrtNode(bb, lastStore, refnode)
 
         
         
    def IRcopyToArgViaPointerFromArg(self, arg1, arg2):
        return False

    def IRcopyToArgViaPointerFromArgPointer(self, arg1, arg2):
        return False

    def IRgetBasicBlockForAddress(self, f, addr):
        for block_addr in f.block_addrs:
            current_block = self._project.factory.block(block_addr)
            if addr in current_block.instruction_addrs:
               return current_block
        return None

    def FArun(self,entry,funtosim,harg="r0", sarg="r1", maxsteps=1000):
        entry_state = self._project.factory.entry_state(
                          add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                          angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
                        )
        entry_state.register_plugin('callstack',CallStack()) 
        entry_state.ip = entry
        self.FAcheckError(entry,funtosim,entry_state,harg,sarg,maxsteps)

    def FArunIterative(self,entry1, entry2, entry3,funtosim,harg="r0", sarg="r1", maxsteps=1000):
        entry_state = self._project.factory.entry_state(
                          add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                          angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
                        )
        entry_state.register_plugin('callstack',CallStack()) 
        entry_state.ip = entry1
        next_state = self.FAreachingAddressFrom(entry_state,entry1,entry2)
        if next_state == None:
           return
        next_state = self.FAreachingAddressFrom(next_state,entry2,entry3)
        if next_state == None:
           return        
        self.FAcheckError(entry3,funtosim,next_state,harg,sarg,maxsteps)

    def FAreachingAddressFrom(self, entry_state, fromAddress, targetAddress):
        entry_state.ip = fromAddress
        simgr = self._project.factory.simgr(entry_state)
        # print(f"Exploring to reach target address {targetAddress}")
        simgr.explore(find=targetAddress)               
        if simgr.found:
           # print(f"Reached target")
           return simgr.found[0]
        else: 
           # print(f"Could not reached target!")
           return None

    def FAcheckError(self,entry,funtosim,entry_state,harg="r0", sarg="r1", maxsteps=1000):
        # print(f"Checking for error state")
        self._project.hook(funtosim,self.HALReceiveModel(handler_argname=harg,size_argname=sarg)) 
        simgr = self._project.factory.simgr(entry_state,save_unconstrained=True)
        stepno = 0
        while stepno < maxsteps and len(simgr.unconstrained)==0:
              simgr.step()
              if len(simgr.active) == 0:
                 # print(f"No active states left after {stepno} steps!")
                 break
              stepno += 1
              # print(f"At step {stepno} number of active states: {len(simgr.active)}")
        if len(simgr.unconstrained) > 0:
           unconstrained_state = simgr.unconstrained[0]
           fa = unconstrained_state.callstack.current_function_address
           sp = unconstrained_state.callstack.current_stack_pointer
           # print(f"Memory error tainted function {hex(fa)} stack pointer {hex(sp)} and pc {unconstrained_state.regs.pc} ") 
        else:
           print(f"Analysis ended without an error after {stepno} steps")

    class HALReceiveModel(angr.SimProcedure):
     unique = 0

     def run(self, peripheral="SPI", handler_argname="r0", size_argname="r1"):
         #make the buffer pointed by handler_arg symbolic
         sarg = self.state.regs[size_argname]
         sarg_value = self.state.solver.eval(sarg)
         harg = self.state.regs[handler_argname]
         harg_value = self.state.solver.eval(harg)
         i = 0
         # print(f"In HALReceiveModel..")
         # print(f"Symbolizing the buffer at {harg_value} for num {sarg_value} items")
         while i < sarg_value:
             symbol_name = "%s_%d_%d" % (peripheral,self.unique,i)
             symbol = self.state.solver.BVS(symbol_name,8)
             address = harg_value + (8*i)
             self.state.memory.write(address, symbol)
             i += 1
         self.unique += 1

