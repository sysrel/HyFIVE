import os
import json
import sys
import angr
import logging
import pyvex
import angr
import time
import claripy
from .HALAPIAnalysis import HybridAnalyzer

#angr.loggers.disable_root_logger()
#logging.disable(logging.ERROR)
log = logging.getLogger("TAILOR")

def getFunctionInfo(elf_file, name):
    project = angr.Project(elf_file, auto_load_libs=False)
    current_cfg = project.analyses.CFG()
    for f in current_cfg.functions.values():
        print(f"FUnction {f} vs {name}")
        if f.name == name:
           return f.addr,f.size
    return None,0


class Tailor:
    def __init__(self, **kwargs):
        config_path = kwargs.get('config_path')
        if config_path == None:
           self._config = dict((k, v) for k, v in kwargs.items() if v)
        else:
           self._config = json.load(open(config_path))
           # remove empty keys from the config
           self._config = dict((k, v) for k, v in self._config.items() if v)
           self._default_config = {}  
           self._resultsdir = os.environ.get('HYFIVE_RESULTS', "")
           if self._resultsdir == "":
              print(f"Environment variable HYFIVE_RESULTS is not set!")
              sys.exit()
              print(f"results dir: {self._resultsdir}")
           if not self._resultsdir == "":
              self._fw_path = self._resultsdir + "/" + self._config['fw_path']
           else:
              self._fw_path = self._config['fw_path']
           self._binary = self._fw_path + "/" + self._config['bin']
           self._functionAddressRange = {}
           if self._config['output'] == "":
              self._outputdir = self._resultsdir
              # since this is informational purposes, we want to keep confi info anonymous
              self._default_config['output'] = ""
           else: 
              self._outputdir = self._resultsdir + "/" + self._config['output']
           print("Firmware directory: %s" % self._fw_path)

    def runSingle(self, **kwargs):
        self.analyzeSingleMMIO()

    def analyzeSingleMMIO(self):
        print(f"Analysis starts for single MMIO")
        self._tracecallchain = {}
        self._dyncallgraph = {}  
        self._functionAddressRange = {}
        self._traceUse = {}
        self._traceLoads = set()
        self._traceDef = {} 
        self._traceDefofUse = {}
        self._traceStackAddresses = set()

        self._MMIO_datareg = self._config['MMIO_datareg'] if 'MMIO_datareg' in self._config else None
        self._project = angr.Project(self._config['bin'], auto_load_libs=False)
        self._current_cfg = self._project.analyses.CFG(collect_data_references=True,
                                                       extra_cross_references=True)
        self._fw_path = self._config['fw_path']
        self._minRAM = 0
        if "text" in self._project.loader.main_object.sections_map.keys():
            self._minRAM = self._project.loader.main_object.sections_map["text"].max_addr
        if ".text" in self._project.loader.main_object.sections_map.keys():
            self._minRAM = self._project.loader.main_object.sections_map[".text"].max_addr
        if self._minRAM == 0:
           self._minRAM = 0x20000000
        self._analysis_type = self._config['analysis_type'] 

        if 'entry_point_limit' in self._config.keys():
           self._entry_point_limit = self._config['entry_point_limit']
        else:
           self._entry_point_limit = None

        if 'taint_pc' in self._config:
           self._taint_pc = self._config['taint_pc']
        else:
           self._taint_pc = None

        # this will typically be used inside a container therefore we do not need a separate default config for anonymization purposes
        self._default_config = self._config
        if 'result_file_desc' in self._config.keys():
           self._result_file_desc = self._config['result_file_desc']
        else:
           self._result_file_desc = ""

        if 'return_value_tracking' in self._config.keys():
           if self._config['return_value_tracking'] == "True":    
              self._return_value_tracking = True
           else:
              self._return_value_tracking = False
        else:
           self._return_value_tracking = False

        if 'trace' in self._config.keys():
           self._trace = self._config['trace']
        else:
           self._trace = None

        if 'trace_path' in self._config.keys():
           self._trace_path = self._config['trace_path']
        else:
           self._trace_path = None
      

        if 'trace_dir' in self._config.keys():
           self._trace_dir = self._config['trace_dir']
        else:
            self._trace_dir = None

        if 'trace_index' in self._config.keys():
            self._trace_index = self._config['trace_index']
        else:
            self._trace_index = None
        if 'taint_index' in self._config.keys():
            self._taint_index = self._config['taint_index']
        else:
            self._taint_index = None

        if 'entry_point_limit' in self._config.keys():
           self._entry_point_limit = self._config['entry_point_limit']
        else:
           self._entry_point_limit = None

        if 'multi_hop_taint' in self._config.keys():
           if self._config['multi_hop_taint'] == "True":
              self._one_hop_taint = False
           elif self._config['multi_hop_taint'] == "False":
              self._one_hop_taint = True
           else:
              print(f"Correct format for multi_hop_taint is True or False!")
              sys.exit()  
        else:
           self._one_hop_taint = False

        if 'callchain_depth_bound' in self._config.keys():
           self._callchain_depth_bound = self._config['callchain_depth_bound']
        else:
           self._callchain_depth_bound = 3

        self._iranalyzer = HybridAnalyzer(self._project, self._current_cfg, self._minRAM, self._config, self._default_config, self._result_file_desc)
        # we should get the input directory for copy functions from config
        self._iranalyzer.IRinitstats()
        if "trace_guided_analysis" in self._analysis_type or "HAL_API_Extraction_Complex_TraceGuided" in self._analysis_type:
           if not self._trace == None or not self._trace_path == None:
              sp, lr, registerInitValues, mmioReadLocs, index = self.parseTraceFile(self._dyncallgraph, True, False, 75000)
              self._iranalyzer.InitSetDynamicCallGraph(self._dyncallgraph)
              delta = self._iranalyzer.IRupdatestats("parse_trace_file_for_call_graph_generation")
              print(f"Trace processing time={delta}")
           elif not self._trace_dir == None:
              self.parseTraceFilesForCallGraph(self._dyncallgraph)           
              self._iranalyzer.InitSetDynamicCallGraph(self._dyncallgraph)
              delta = self._iranalyzer.IRupdatestats("parse_trace_file_for_call_graph_generation")
              print(f"Trace processing time={delta}")
        #if "find_copy_functions" in self._analysis_type or ("trace_guided_analysis" in self._analysis_type and not "read_copy_functions" in self._analysis_type):
        if "find_copy_functions" in self._analysis_type:
            self._iranalyzer.IRfindCopyFunctions(['r1','r2'], 'add', 1)
            delta = self._iranalyzer.IRupdatestats("find_copy_functions")
            print(f"Finding copy functions time={delta}")
        if "read_copy_functions" in self._analysis_type:
           self._iranalyzer.IRreadCopyFunctions()
           delta = self._iranalyzer.IRupdatestats("read_copy_functions")
           print(f"Reading copy functions time={delta}")           
        if "trace_guided_analysis" in self._analysis_type:
           if not self._trace == None or not self._trace_path == None:
              if not self._trace_index == None:  
                 self.ANATraceGuidedStaticAnalysis(self._return_value_tracking, self._trace_index, self._entry_point_limit, self._one_hop_taint, self._taint_pc)
                 delta = self._iranalyzer.IRupdatestats("trace_guided_analysis")
                 print(f"Trace guided analysis time={delta}") 
              else:
                 print(f"trace_index is not specified, required for trace_guided_analysis!")
           elif not self._trace_dir == None:
                 self.ANATraceGuidedStaticAnalysisForTraceSet(self._return_value_tracking, self._trace_index, self._entry_point_limit, self._one_hop_taint) 
                 delta = self._iranalyzer.IRupdatestats("trace_guided_analysis")
                 print(f"Trace guided analysis time={delta}") 
        self._iranalyzer.IRprintStats(self._config['statistics_path'])
  
    def check_load_address(self, current_path, guards_info, *_, **__):
        """
        Checks if loading from a specific address
        :param current_path: angr current path
        :param guards_info:  guards (ITE) information
        :return: None
        """

        try:
            current_state = current_path.active[0]
            current_addr = current_state.addr
            cfg = self._current_cfg
            current_node = cfg.get_any_node(current_addr)
            current_block = self._project.factory.block(current_addr)
            print(f"Executing addr {hex(current_addr)}")
            print(f"Current CFG node {current_node}")
            #current_block.pp()  
            #current_block.vex.pp()  
            for con_addr in current_block.vex.all_constants:
                print(f"Constant {con_addr}") 
        except TimeOutException as to:
            raise to
        except Exception as e:
            log.error(f"Something went terribly wrong: {str(e)}")     


    def findFunctionsWithConstant(self, initial_state): 
        # Scan inline data for references to the MMIO base and MMIO data channel 
        # Find references to addresses that are not part of the block addresses and are within delta of the block address range
        endianness = 'little' if self._project.arch.memory_endness == Endness.LE else 'big'
        target_base = hex(int(self._config['MMIO_base_addr'],16))
        target_addr = hex(int(self._config['MMIO_base_addr'],16) + int(self._config['data_reg_offset'],16))
        print(f"Checking constant {target_addr}")  
        cfg = self._current_cfg
        allconst = set()
        allblockaddr = set()
        for f in cfg.functions.values():
          if f.name == "SPI_WIFI_Init":
             print(f"Function name {f.name}")
             print(f"Block addresses {f.block_addrs}")
             for ba in f.block_addrs:
                 print(f"Block address {hex(ba)}")
                 allblockaddr.add(hex(ba))
             print(f"\tBlock address range {hex(min(f.block_addrs))}-{hex(max(f.block_addrs))}")
          for block_addr in f.block_addrs:
            current_block = self._project.factory.block(block_addr)
            if f.name == "SPI_WIFI_Init":
               current_block.pp()
               current_block.vex.pp()
               for stmt in current_block.vex.statements:
                 if isinstance(stmt, pyvex.IRStmt.Store):
                    print(f"Store instruction data {stmt.data} dest {stmt.addr} at block addr {hex(block_addr)}")
                    if hasattr(stmt.data, 'tmp'):
                       tmpdata = stmt.data.tmp
                       tmpvalue = initial_state.scratch.temps[tmpdata] if tmpdata < len(initial_state.scratch.temps) else None
                       print(f"\tConstant data {tmpvalue}")  
                    if hasattr(stmt.addr, 'tmp'):
                       tmpaddr = stmt.addr.tmp
                       tmpvalue = initial_state.scratch.temps[tmpaddr] if tmpaddr < len(initial_state.scratch.temps) else None
                       print(f"\tConstant addr {tmpvalue}")  
                    s = self._project.factory.blank_state(
                           remove_options={
                                angr.options.LAZY_SOLVES
                           }
                    )
                    s.ip = block_addr
                    simgr = self._project.factory.simgr(s)
                    s.inspect.b("mem_write", when=angr.BP_AFTER, action=self.actionMemWrite)
                    n = len(simgr.active)
                    print(f"Before execution : {n}")
                    self.resetActionResults()
                    simgr.step()
                    self.printIfBreakPoint(s)
                    if len(simgr.active) == 0:
                       print(f"No successor ")
                       succ = s
                    else:
                       succ = simgr.active[0]
                    n = len(simgr.active)
                    sip = succ.solver.eval(succ.ip)
                    print(f"ip after step {hex(sip)}")
                    cb = self._project.factory.block(sip)
                    if hasattr(stmt.data, 'tmp'):
                       tmpdata = stmt.data.tmp
                       print(f"tmpdata {tmpdata} vs Size of scratch temps {len(s.scratch.temps)}")
                       #for ts in s.scratch.temps:
                       #   print(f"temps {ts}")
                       #tmpdataexpr = s.scratch.tmp_expr(tmpdata)
                       #print(f"scratch tmp data: {tmpdataexpr}")
                       tmpvalue = s.scratch.temps[tmpdata] if tmpdata < len(s.scratch.temps) else None
                       print(f"\tConstant data {tmpvalue}")  
                    if hasattr(stmt.addr, 'tmp'):
                       tmpaddr = stmt.addr.tmp
                       print(f"tmpaddr {tmpaddr} vs Size of scratch temps {len(s.scratch.temps)}")
                       tmpvalue = s.scratch.temps[tmpaddr] if tmpaddr < len(s.scratch.temps) else None
                       print(f"\tConstant addr {tmpvalue}")                      
                    print(f"Successors of block addr {block_addr}")
                    print(f"Successors of block addr {block_addr} : {n} ip {sip} current block: ")
                    cb.pp()
            if f.name == "SPI_WIFI_Init":
               for ia in current_block.instruction_addrs:
                   print(f"Address of the current instruction {hex(ia)}")
                   xrefs = cfg.kb.xrefs.get_xrefs_by_ins_addr(ia)
                   for xref in xrefs:
                       valuebv = initial_state.memory.load(xref.dst,4)
                       value = initial_state.solver.eval(valuebv)
                       value = int.from_bytes(value,byteorder='big')
                       print(f"\t\tXref {xref} dest: {hex(xref.dst)} content: {valuebv} {hex(value)}")
                       if value == self._MMIO_base:
                          self._MMIO_word.add(xref) 
               for con_addr in current_block.vex.all_constants:
                   allconst.add(hex(con_addr.value))
                   print(f"\t\tConstant {con_addr}") 
               if target_addr == con_addr:
                  print(f"\t\tFound constant {con_addr}")
        print(f"All block addresses {list(dict.fromkeys(allblockaddr))}")
        print(f"All constants {list(dict.fromkeys(allconst))}")
        diff = set.difference(allconst, allblockaddr)
        print(f"Constants that do not correspond to block addresses {list(dict.fromkeys(diff))}")

    def printIfBreakPoint(self, state):
        if self.breakPointHappened:
           if self.breakPointType == "writeMem":
              print(f"Writemem: {self.breakPointType} {self._write_addr} {self._write_expr}")
           if self.breakPointType == "readMem":
              print(f"Readmem: {self._read_addr} {self._read_expr} {self._read_expr}")

    def recordTaintForMemWrite(self, state, change, num_base, num_data_reg):
        if self.breakPointHappened and self.breakPointType == "writeMem":
           wa = state.solver.eval(self._write_addr)
           if isinstance(wa,int):
              wa = hex(wa)
           wd = state.solver.eval(self._write_expr)
           if isinstance(wd,int):
              wd = hex(wd)
           if wd == self._target_base:
              if not wd in self._MMIO_base_pointers:
                 print(f"Recording write address {wa} write expr {wd}")
                 self._MMIO_base_pointers.add(wa)
                 change = True
                 num_base += 1
           if wd in self._MMIO_base_pointers:
              if not wa in self._MMIO_base_pointers:
                 print(f"Recording write address {wa} write expr {wd}")
                 self._MMIO_base_pointers.add(wa)
                 change = True
                 num_base += 1 
           if wd == self._target_addr:
              if not wa in self._MMIO_datareg_pointers:
                 print(f"Recording write address {wa} write expr {wd}")
                 self._MMIO_datareg_pointers.add(wa)
                 change = True
                 num_data_reg += 1
           if wd in self._MMIO_datareg_pointers:
              if not wa in self._MMIO_datareg_pointers:
                 print(f"Recording write address {wa} write expr {wd}")
                 self._MMIO_datareg_pointers.add(wa)
                 change = True
                 num_data_reg += 1 

    def resetActionResults(self):
        self.breakPointHappened = False
        self.breakPointType = "None"
        self._write_addr = None
        self._write_expr = None
        self._read_addr = None
        self._read_expr = None
        self._tmp_write_num = None
        self._tmp_write_expr = None
        self._function_address = None
        self._address = None
        self._statement = None

    def actionStatement(self, state):
        #print(f"actionStatement {state.inspect.statement}")
        self.breakPointHappened = True
        self.breakPointType = "statement"  
        self._statement = state.inspect.statement

    def actionMemWrite(self, state):
        #print(f"actionMemWrite")
        self.breakPointHappened = True
        self.breakPointType = "writeMem"  
        self._write_addr = state.inspect.mem_write_address
        self._write_expr = state.inspect.mem_write_expr

    def actionMemWriteToBaseSet(self, state):
        #print(f"actionMemWriteToSet instruction address {state.regs.pc}")
        self.breakPointHappened = True
        self.breakPointType = "writeMem"  
        self._write_addr = state.inspect.mem_write_address
        self._write_expr = state.inspect.mem_write_expr
        ias = state.regs.pc
        ia = state.solver.eval(ias)
        block = self._project.factory.block(ia)
        fa = self.getFunctionAddress(block.addr)
        self.recordTaintForMemWriteToSet(state, self._target_base_set, self._copy_target_set, ia, block.addr, fa)

    def actionMemWriteToDataRegSet(self, state):
        print(f"actionMemWriteToSet instruction address {state.regs.pc}")
        self.breakPointHappened = True
        self.breakPointType = "writeMem"  
        self._write_addr = state.inspect.mem_write_address
        self._write_expr = state.inspect.mem_write_expr
        ias = state.regs.pc
        ia = state.solver.eval(ias)
        block = self._project.factory.block(ia)
        fa = self.getFunctionAddress(block.addr)
        self.recordTaintForMemWriteToSet(state, self._target_datareg_set, self._copy_target_set, ia, block.addr, fa)

    def actionMemRead(self, state):
        #print(f"actionMemRead")
        self.breakPointHappened = True
        self.breakPointType = "readMem"  
        self._read_addr = state.inspect.mem_read_address
        self._read_expr = state.inspect.mem_read_expr
        block = self._project.factory.block(state.regs.pc)
        self.recordTaintAddrInst(state, target_base_set, target_addr_set, block.addr, block.function)

    def actionTmpWrite(self, state):
        #print(f"actionTmpWrite")
        self.breakPointHappened = True
        self.breakPointType = "tmpWrite"  
        self._tmp_write_num = state.inspect.tmp_write_num
        self._tmp_write_expr = state.inspect.tmp_write_expr

    def actionCall(self, state):
        #print(f"actionCall")
        self.breakPointHappened = True
        self.breakPointType = "call"  
        self._function_address = state.inspect.function_address 

    def actionIrsb(self, state):
        #print(f"actionIrsb {hex(state.inspect.address)}")
        self.breakPointHappened = True
        self.breakPointType = "irsb"  
        self._address = state.inspect.address  

    def recordTaintAddrInst(self, state, target_base_set, target_addr_set, block_address, func):
        if self.breakPointHappened and self.breakPointType == "readMem":
           rai = state.solver.eval(self._read_addr)
           ra = rai
           if isinstance(rai,int):
              ra = hex(ra)
           rd = state.solver.eval(self._read_expr)
           if isinstance(rd,int):
              rd = hex(rd)
           print(f"Read address ra {ra} expr {rd}")
           #if rai in self._xrefAdjustments.keys():
           #   if any([e1 for e1, e2, e3, e4, e5 in target_base_set if e1 == self._xrefAdjustments[rai]]):
           #      tuple = (hex(self._xrefAdjustments[rai]),func.addr,block_address)
           #      print(self.ppAccess(tuple,"MMIO Base "))
           #      self._MMIO_base_accesses.add(tuple)
           if any([e1 for e1, e2, e3, e4, e5 in target_base_set if e1 == ra]):
              tuple = (ra,func.addr,block_address)
              print(self.ppAccess(tuple,"MMIO Base "))
              self._MMIO_base_accesses.add(tuple)
           if any([e1 for e1, e2, e3, e4, e5 in target_addr_set if e1 == ra]):
              tuple = (ra,func.addr,block_address)
              print(self.ppAccess(tuple,"MMIO Date register "))
              self._MMIO_datareg_accesses.add(tuple)

    def taintOneStep(self, change, num_base, num_data_reg):
        endianness = 'little' if self._project.arch.memory_endness == Endness.LE else 'big'
        target_base = hex(int(self._config['MMIO_base_addr'],16))
        target_addr = hex(int(self._config['MMIO_base_addr'],16) + int(self._config['data_reg_offset'],16))
        #print(f"Checking constant {target_addr}")
        cfg = self._current_cfg
        for f in cfg.functions.values():
          #if not f.name == "SPI_WIFI_Init":
          #   continue
          for block_addr in f.block_addrs:
            #print(f"Block address {hex(block_addr)}")
            current_block = self._project.factory.block(block_addr)
            s = self._project.factory.blank_state(
                           remove_options={
                                angr.options.LAZY_SOLVES
                           }
                )
            s.ip = block_addr
            simgr = self._project.factory.simgr(s)
            s.inspect.b("mem_write", when=angr.BP_BEFORE, action=self.actionMemWrite)
            n = len(simgr.active)
            self.resetActionResults()
            try:
              simgr.step()
            except RuntimeError as e:
              print(f"Possibly recursion depth issue, skipping {block_addr} in function {f.name}") 
              continue
            #self.printIfBreakPoint(s)
            self.recordTaintForMemWrite(s,change,num_base,num_data_reg)            

    def collectTaint(self):
        change = False
        i = 0
        num_base = 0
        num_data_reg = 0
        while i == 0 or change == True:
           i += 1
           num1 = 0
           num2 = 0
           change = False
           self.taintOneStep(change, num1, num2)
           num_base += num1
           num_data_reg += num2
           print(f"Taint step {i}, found {num_base} new base address taints, found {num_data_reg} new target address taints") 
        print(f"Taint analysis finished")

    def findTaintAddressingInstructions(self, initial_state, target_base_set, target_addr_set):
        endianness = 'little' if self._project.arch.memory_endness == Endness.LE else 'big'
        print(f"Finding instructions accessing target data")
        cfg = self._current_cfg
        for f in cfg.functions.values():
          for block_addr in f.block_addrs:
            #print(f"Block address {hex(block_addr)}")
            try:
               current_block = self._project.factory.block(block_addr)
            except angr.errors.SimEngineError:
               continue
            numLoad = 0
            for stmt in current_block.vex.statements:
                if isinstance(stmt, pyvex.IRStmt.WrTmp):
                   if isinstance(stmt.data,pyvex.IRExpr.Load):
                      numLoad += 1
            if numLoad == 0:
               continue
            relevant = False
            for ia in current_block.instruction_addrs:
               xrefs = cfg.kb.xrefs.get_xrefs_by_ins_addr(ia)
               for xref in xrefs:
                  #if xref.dst in self._xrefAdjustments.keys():
                  #   member, depth = self.isScanSetMember(self._xrefAdjustments[xref.dst], target_base_set)
                  #   if member:
                  #      print(f"Relevant instruction {hex(ia)} (DUE TO XREF ADJUSTMENT!!!)")
                  #      relevant = True
                  #      break 
                  member, depth = self.isScanSetMember(xref.dst, target_base_set)
                  if member:
                     print(f"Relevant instruction {hex(ia)}")
                     relevant = True
                     break
                  else:
                     member, depth = self.isScanSetMember(xref.dst, target_addr_set)
                     if member:
                        print(f"Relevant instruction {hex(ia)}")
                        relevant = True
                        break
                  valuebv = initial_state.memory.load(xref.dst,4)
                  value = initial_state.solver.eval(valuebv)
                  value = int.from_bytes(value.to_bytes(4,byteorder='little'),byteorder='big')
                  member, depth = self.isScanSetMember(value, target_base_set)
                  if member:
                     print("Relevant instruction {hex(ia)}")
                     relevant = True
                     break
                  else:
                     member, depth = self.isScanSetMember(value, target_addr_set)
                     if member:
                        print("Relevant instruction {hex(ia)}")
                        relevant = True
                        break
            if not relevant:
               continue
            print(f"Num loads in relevant Block address {hex(block_addr)} is {numLoad} in function {f.name}")
            s = self._project.factory.blank_state(
                           remove_options={
                                angr.options.LAZY_SOLVES
                           }
                )
            s.ip = block_addr
            simgr = self._project.factory.simgr(s)
            s.inspect.b("mem_read", when=angr.BP_BEFORE, action=self.actionMemRead)
            n = len(simgr.active)
            error = False
            for i in range(0,numLoad):
               self.resetActionResults()
               try:
                 simgr.step()
               except RuntimeError as e:
                 print(f"Possibly recursion depth issue, skipping {block_addr} in function {f.name}")
                 error = True
               #if error: 
               #  continue
               #else:  
               #  self.recordTaintAddrInst(s, target_base_set, target_addr_set, block_addr, f)
        #self._klog.log_line(f"Number of instructions that load base address is {len(self._MMIO_base_accesses)}\n") 
        #for at in self._MMIO_base_accesses:
        #    self._klog.log_line(self.ppAccess(at, "MMIO Base"))
        #self._klog.log_line(f"Number of instructions that load data register address is {len(self._MMIO_datareg_accesses)}\n") 
        #for ra, fa, ba in self._MMIO_datareg_accesses:
        #    self._klog.log_line(self.ppAccess(at, "MMIO Data register"))
          
    def ppAlias(self, aliasTuple, start=""):
        print(f"{aliasTuple[0]} {aliasTuple[1]} {aliasTuple[2]} {aliasTuple[3]} {aliasTuple[4]}")
        return "%s alias %s at depth %d loaded in function at address %s name %s at block address %s" % (start,aliasTuple[0],aliasTuple[1],hex(aliasTuple[2]),hex(aliasTuple[3]),self.functionName(aliasTuple[4]))

    def ppAccess(self, accessTuple, start=""):
        return "%s %s accessed in function %s name %s at block address %s" % (start,accessTuple[0],hex(accessTuple[1]),self.functionName(accessTuple[1]),hex(accessTuple[2]))

    def reportTaint(self):
        print(f"Total of {len(self._MMIO_base_pointers)} addresses that directly or indirectly pointing to base address")
        for bt in self._MMIO_base_pointers:
           print(f"\t {bt}")
        print(f"Total of {len(self._MMIO_datareg_pointers)} addresses that directly or indirectly pointing to data register address")
        for bt in self._MMIO_datareg_pointers:
           print(f"\t {bt}")
        print(f"Total of {len(self._MMIO_base_accesses)} instructions that directly or indirectly pointing to base address")
        for bt in self._MMIO_base_accesses:
           print(self.ppAccess(bt,"MMIO Base "))
        print(f"Total of {len(self._MMIO_datareg_accesses)} instructions that directly or indirectly pointing to data register address")
        for bt in self._MMIO_datareg_accesses:
           print(self.ppAccess(bt,"MMIO Data register "))

    def recordTaintForMemWriteToSet(self, state, target_set, change_set, ia, block_addr, fn):
        change = False
        if self.breakPointHappened and self.breakPointType == "writeMem":
           wai = state.solver.eval(self._write_addr)
           wa = wai
           if isinstance(wa,int):
              wa = hex(wa)
           wdi = state.solver.eval(self._write_expr)
           wd = wdi
           if isinstance(wd,int):
              wd = hex(wd)
           #print(f"Recording ? Write {wa} and {wd} in function {hex(fn)} name {self.functionName(fn)}") 
           #if not wa == "0xffffffff" and any([e1 for (e1, e2, e3, e4, e5) in target_set if e1 == wd]):
           if wai >= 0x20000000 and wai < 0x50000000 and any([e1 for (e1, e2, e3, e4, e5) in target_set if e1 == wd]):
              dl = [e2 for (e1, e2, e3, e4, e5) in target_set if e1 == wd]
              for depth in dl:
                 #pbb = self.getBasicBlock(ia)
                 #pbb.vex.pp()
                 #if self._iranalyzer.IRmultipleStoreInstructions(pbb, ia):
                 #   diff = self._iranalyzer.IRcomputeStoreDiff(pbb, ia)
                 #   print(f"Store address diff: {diff}")
                 #   if diff > 0:
                 #      iwa = int(wa,16)
                 #      self._xrefAdjustments[iwa] = iwa - diff 
                 #      change_set.add((hex(iwa - diff), depth + 1, ia, block_addr, fn)) 
                 #      print(f"Recording write address {hex(iwa - diff)} write expr {wd} DUE TO multiple store address adjustment")
                 #else:
                 print(f"Recording write address {wa} write expr {wd} instruction address {hex(ia)}")
                 change_set.add((wa, depth + 1, ia, block_addr, fn))
                 change = True
           valuebv = self._initial_state.memory.load(int(wd,16),4)
           value = self._initial_state.solver.eval(valuebv)
           value = int.from_bytes(value.to_bytes(4,byteorder='little'),byteorder='big')
           #if not wa == "0xffffffff" and any([e1 for (e1, e2, e3, e4, e5) in target_set if e1 == hex(value)]):
           if wai > 0x20000000 and wai < 0x50000000 and any([e1 for (e1, e2, e3, e4, e5) in target_set if e1 == hex(value)]):
              dl = [e2 for (e1, e2, e3, e4, e5) in target_set if e1 == hex(value)]
              for depth in dl:
                 #pbb = self.getBasicBlock(ia)
                 #pbb.vex.pp()
                 #if self._iranalyzer.IRmultipleStoreInstructions(pbb, ia):
                 #   diff = self._iranalyzer.IRcomputeStoreDiff(pbb, ia)
                 #   print(f"Store address diff: {diff}")
                 #   if diff > 0:
                 #      iwa = int(wa,16)
                 #      self._xrefAdjustments[iwa] = iwa - diff 
                 #      change_set.add((hex(iwa - diff), depth + 1, ia, block_addr, fn)) 
                 #      print(f"Recording write address {hex(iwa - diff)} write expr {wd} DUE TO multiple store address adjustment")
                 #else:
                 print(f"Recording write address {wa} write expr {wd} instruction address {hex(ia)}")
                 change_set.add((wa, depth, ia, block_addr, fn))
                 change = True
        return change


    def collectTaintForSet(self, target_set, initial_state, base):
        change = False
        changeLocal = False
        i = 0
        while i == 0 or changeLocal == True:
           i += 1
           changeLocal = self.taintOneStepForSet(target_set, initial_state, base)
           if changeLocal:
              change = True
              print(f"Taint step {i}, found new taints")
        print(f"Taint analysis finished")
        return change
 
    def taintOneStepForSet(self, target_set, initial_state, base): 
        change = False
        endianness = 'little' if self._project.arch.memory_endness == Endness.LE else 'big'
        cfg = self._current_cfg
        new_stuff = set()
        prevsize = len(target_set)
        self._copy_target_set = set()
        for ta, depth, ia, block_addr, fn in target_set:
            if block_addr == 0x0:
               continue
            print(f"Block address {hex(block_addr)}")
            current_block = self._project.factory.block(block_addr)
            numStore = 0
            for stmt in current_block.vex.statements:
                if isinstance(stmt, pyvex.IRStmt.Store):
                   numStore += 1
            print(f"Num stores in Block address {hex(block_addr)} is {numStore}") 
            if numStore == 0: 
               continue
            for inst in current_block.instruction_addrs:
               s = self._project.factory.blank_state(
                           remove_options={
                                angr.options.LAZY_SOLVES
                           }
                    )
               s.ip = inst
               simgr = self._project.factory.simgr(s)
               if base:
                  s.inspect.b("mem_write", when=angr.BP_BEFORE, action=self.actionMemWriteToBaseSet)
               #else:
               #   s.inspect.b("mem_write", when=angr.BP_BEFORE, action=self.actionMemWriteToDataRegSet)
               n = len(simgr.active)
               error = False
               try:
                  #print(f"Stepping at {s.ip}")
                  simgr.step()
               except RuntimeError as e:
                  print(f"Possibly recursion depth issue, skipping {block_addr} in function {f.name}")
                  error = True 
                  continue
                  """
                  print(f"ta {ta}")
                  if not error:
                    changeLocal = self.recordTaintForMemWriteToSet(s,target_set, new_stuff, ta, depth, ia, block_addr, fn, True)
                    if changeLocal:
                       change = True
                    else:
                       current_block.vex.pp()
                       valuebv = initial_state.memory.load(int(ta,16),4)
                       value = initial_state.solver.eval(valuebv)
                       value = int.from_bytes(value.to_bytes(4,byteorder='little'),byteorder='big')
                       changeLocal = self.recordTaintForMemWriteToSet(s,target_set, new_stuff, hex(value), depth, ia, block_addr, fn, False)
                       if changeLocal:
                          change = True
                  """
        for ns in self._copy_target_set:
           print(f"Adding {ns}")
           target_set.add(ns)
        print(f"prevsize={prevsize} vs {len(target_set)}")
        return len(target_set) != prevsize 
         
    def taintMultiStep(self, initial_state, target_base_set, target_addr_set):
        changeScan = False
        changeCopy = False
        i = 0
        print(f"Initially {len(target_base_set)} tuples for target base set:")
        for at in target_base_set:
           print(self.ppAlias(at, "MMIO Base "))
        print(f"Initially {len(target_addr_set)} tuples for target addr set:")
        for at in target_addr_set:
           print(self.ppAlias(at, "MMIO Data register "))
        while i == 0 or changeScan or changeCopy:
           print(f"Starting scanning for MMIO targets iteration {i}")
           print(f"TAINT STEP {i}")
           changeScan = self.scanForMMIOAddress(initial_state, target_base_set, target_addr_set)
           if changeScan:
              print(f"Change detected in scanning for MMIO targets, current size base set {len(target_base_set)} and target set {len(target_addr_set)}")
              changeCopy1 = self.collectTaintForSet(target_base_set, initial_state, True)
              changeCopy2 = self.collectTaintForSet(target_addr_set, initial_state, False)
              if changeCopy1 or changeCopy2:
                 print(f"Detected a change in copying target addresses current size base set {len(target_base_set)} and target set {len(target_addr_set)}")
           i += 1
        #self._klog.log_line(f"Iteration ended with {len(target_base_set)} tuples for target base set:\n")
        #for at in target_base_set:
        #   self._klog.log_line(self.ppAlias(at, "MMIO Base "))
        #self._klog.log_line(f"Iteration ended with {len(target_addr_set)} tuples for target data register set:\n")
        #for at in target_addr_set:
        #   self._klog.log_line(self.ppAlias(at, "MMIO Data register ")) 


    def scanForMMIOAddress(self, initial_state, target_base_set, target_addr_set):
       change = False
       changeLocal = False
       i = 0
       while i == 0 or changeLocal == True:
          changeLocal = False
          print(f"Scanning iteration {i}")
          print(f"SCAN STEP {i}")
          changeLocal = self.scanForMMIOAddressOneStep(initial_state, target_base_set, target_addr_set)
          i += 1
          print(f"Change in scanning? {changeLocal}")
          if changeLocal:
             change = True
             print(f"Change in MMIO address references")
       return change

    def isScanSetMember(self, addr, scanset):
        for ta, depth, ia, ba, fn in scanset:
            if hex(addr) == ta:
               return (True, depth)
        return (False, 0)


    def getBasicBlock(self, iaddr):
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                bb = self._project.factory.block(ba)
                for ia in bb.instruction_addrs:
                    if ia == iaddr:
                       bb = self._project.factory.block(ba)
                       return bb
        return None

    def getFunctionAddressRange(self, func):
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

    def getFunctionAddressFromInstruction(self, pc):
        for f in self._current_cfg.functions.values():
            min, max = self.getFunctionAddressRange(f)
            if pc >= min - 1 and pc <= max:
               return f.addr
        return 0

    def getFunctionFromInstruction(self, pc):
        for f in self._current_cfg.functions.values():
            min, max = self.getFunctionAddressRange(f)
            if pc >= min - 1 and pc <= max:
               return f
        return None
    
    def getClosestFunctionForInstruction(self, iaddr):
        dist = 0x1000000
        result = None
        for f in self._current_cfg.functions.values():
            if f.addr > iaddr:
               if f.addr - iaddr < dist:
                  dist = f.addr - iaddr
                  result = f
                  if dist == 0:
                     return result
        return result
   
    def getFunctionAddress(self, block_addr):
        closest = None
        diff = 64
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                if block_addr - ba >= 0 and block_addr - ba < diff:
                   closest = f
                   diff = block_addr - ba
                # in case block_addr is off by 1 due to thumb mode addressing
                aba = block_addr - 1  
                if ba == block_addr or ba == aba or ba - 1 == block_addr:
                   return f.addr         
        #print(f"Could not find function for bb {hex(block_addr)}")
        if not closest == None:
           return closest.addr
        return 0 

    def getFunction(self, block_addr):
        for f in self._current_cfg.functions.values():
            for ba in f.block_addrs:
                # in case block_addr is off by 1 due to thumb mode addressing
                if ba == block_addr or ba == block_addr & ~1 or ba & ~1 == block_addr:
                   return f         
        #print(f"Could not find function for bb {hex(block_addr)}")
        return None 

    

    def scanForMMIOAddressOneStep(self, initial_state, target_base_set, target_addr_set):
        change = False
        endianness = 'little' if self._project.arch.memory_endness == Endness.LE else 'big'
        cfg = self._current_cfg
        for f in cfg.functions.values():
          #if f.name != "SPI_WIFI_Init":
          #   continue
          #print(f"\tBlock address range {hex(min(f.block_addrs))}-{hex(max(f.block_addrs))}")
          for block_addr in f.block_addrs:
            try:
               current_block = self._project.factory.block(block_addr)
            except angr.errors.SimEngineError:
               continue
            hasStoreOrLoad = True
            #hasStoreOrFalse = False
            #for stmt in current_block.vex.statements:
            #    if isinstance(stmt, pyvex.IRStmt.Store):
            #       hasStoreOrLoad = True
            #       break
            #    if isinstance(stmt, pyvex.IRStmt.Put):
            #       if isinstance(stmt.data,pyvex.IRExpr.Load):
            #          hasStoreOrLoad = True
            #          break 
            if hasStoreOrLoad:
               for ia in current_block.instruction_addrs:
                   xrefs = cfg.kb.xrefs.get_xrefs_by_ins_addr(ia)
                   for xref in xrefs:
                      xrefDst = xref.dst  
                      #if xref.dst in self._xrefAdjustments.keys():
                      #   xrefDst = self._xrefAdjustments[xref.dst] 
                      valuebv = initial_state.memory.load(xrefDst,4)
                      value = initial_state.solver.eval(valuebv)
                      value = int.from_bytes(value.to_bytes(4,byteorder='little'),byteorder='big')
                      member, depth = self.isScanSetMember(value, target_base_set)
                      if member:
                         hv = hex(xrefDst)
                         new_stuff = set() 
                         if not any([(av,fnv) for (av, dv, iav, bav, fnv) in target_base_set if hv == av and f.addr == fnv]):
                            tuple = (hex(xrefDst),depth+1,ia,block_addr,f.addr)
                            new_stuff.add(tuple)
                            change = True
                            print(f"Adding a new tuple change? {change}")
                         for ns in new_stuff:
                             target_base_set.add(ns)
                      member, depth = self.isScanSetMember(value, target_addr_set)
                      if member:
                         hv = hex(xrefDst)                          
                         new_stuff = set() 
                         if not any([(av,fnv) for (av, dv, iav, bav, fnv) in target_addr_set if hv == av and f.addr == fnv]):
                            tuple = (hex(xrefDst),depth+1,ia,block_addr,f.addr)
                            new_stuff.add(tuple)
                            change = True
                            print(f"Adding a new tuple change? {change}")
                         for ns in new_stuff:
                             target_addr_set.add(ns)
                      # Also check the xref itself!
                      member, depth = self.isScanSetMember(xrefDst, target_base_set)
                      if member:
                         hv = hex(xrefDst)                          
                         new_stuff = set() 
                         if not any([(av,fnv) for (av, dv, iav, bav, fnv) in target_base_set if hv == av and f.addr == fnv]):
                            tuple = (hex(xrefDst),depth,ia,block_addr,f.addr)
                            new_stuff.add(tuple)
                            change = True
                            print(f"Adding a new tuple change? {change}")
                         for ns in new_stuff:
                             target_base_set.add(ns)
    
        return change

    def findParameterFlows(self, target_base_set):
        cfg = self._current_cfg
        for ta, depth, ia, block_addr, fa in target_base_set:
            try:
              fun = cfg.functions[fa]
            except KeyError as e:
              continue
            self.findParameterFlowsForFunction(fun, self._target_base_set)

    def arg_reg_names(p, n=-1):
      """
      Gets the first n argument register names. If n=-1, it will return all argument registers
      :param p: the project
      :param n: the number of elements to retrieve
      :return: the name of the register
      """
      if n < 0:
        return _ordered_argument_regs_names[p.arch.name]
      return _ordered_argument_regs_names[p.arch.name][:n]

    def findParameterFlowsForFunction(self, f, target_base_set):
        print(f"Function {f.name}")
        lastMark = 1
        for block_addr in f.block_addrs:
            current_block = self._project.factory.block(block_addr)
            print(f"Block address {hex(block_addr)} num statements {len(current_block.vex.statements)}")
            for i in range(1,len(current_block.vex.statements)):
                stmt = current_block.vex.statements[i]
                if stmt.tag == 'Ist_IMark':
                   put_stmts = [s for s in current_block.vex.statements[lastMark:i] if s.tag == 'Ist_Put' and self._project.arch.register_names[s.offset] == 'r0']
                   lastMark = i
                   if not put_stmts:
                      continue
                   put_stmt = put_stmts[-1]
                   # is the arg 
                   stmt_idx = current_block.vex.statements.index(put_stmt)
                   inst_addr = [x.addr for x in current_block.vex.statements[:stmt_idx] if hasattr(x, 'addr')][-1]
                   print(f"\tIs argument of put stmt {put_stmt} at index {stmt_idx} {hex(inst_addr)} relevant?")
                   s = self._project.factory.blank_state(
                           remove_options={
                               angr.options.LAZY_SOLVES
                           }
                      )
                   s.ip = block_addr
                   simgr = self._project.factory.simgr(s)
                   self.initCallFiltering(stmt_idx)
                   s.inspect.b("statement",when=angr.BP_BEFORE,action=self.actionStatementArgChecking) 
                   s.inspect.b("call",when=angr.BP_AFTER,action=self.actionCallForDataFlow)
                   s.inspect.b("tmp_write",when=angr.BP_AFTER,action=self.actionTmpWrite) #,targetExpr=tmp_write_expr)
                   s.step()
                   self.resetCallFiltering()

    def actionCallForDataFlow(self, state):
        #print(f"actionCallForDataFlow")
        if self._relevantCall:
           fa = state.solver.eval(state.inspect.function_address)
           if self.functionName(fa) == "":
              fa -= 1
           print(f"Expanding data flows using function {hex(fa)} {self.functionName(fa)}") 

    def actionStatementArgChecking(self, state):
        #print(f"actionStatementArgChecking")
        if state.inspect.statement == self._targetStatement:
           self._relevantPut = True

    def actionTmpWrite(self, state):
        #print(f"actionTmpWrite")
        expr = state.solver.eval(state.inspect.tmp_write_expr)
        if isinstance(expr,int):
           expr = hex(expr)
        if any([e1 for (e1, e2, e3, e4, e5) in self._target_base_set if expr == e1]): 
           self._relevantCall = True

    def initCallFiltering(self, ts):
        self._statementRelevant = False
        self._targetStatement = ts
        self._relevantCall = False
        self._relevantPut = False

    def resetCallFiltering(self):
        self._statementRelevant = False
        self._targetStatement = None
        self._relevantCall = False
        self._relevantPut = False


    def recordCallbackAssignment(self, state, target_base_set, block_addr, f):
        if self.breakPointHappened and self.breakPointType == "writeMem":
           wa = state.solver.eval(self._write_addr)
           wd = state.solver.eval(self._write_expr)
           print(f"Record callback for Write address {wa} write expr {wd} {self.functionName(wd)}") 
           if wd in self._functionEntry:
              print(f"Callback assignment? Write address {wa} write expr {wd} {self.functionName(wd)}")
              diff, ta = self.isWithinRange(wa, target_base_set, self._handler_data_size)
              if diff >=0 and ta >= 0:
                 self._callback_assignments.add((ta,diff,wa,block_addr,f.addr))
           # Consider the thumb case, where wd = functionAddress + 1 
           adjusted = wd - 1
           if adjusted in self._functionEntry:
              print(f"Callback assignment? Write address {wa} write expr {adjusted} {self.functionName(adjusted)}")
              diff, ta = self.isWithinRange(wa, target_base_set, self._handler_data_size)
              if diff >=0 and ta >= 0:
                 self._callback_assignments.add((ta,diff,wa,block_addr,f.addr))
           


    def isWithinRange(self, value, target_base_set, bound):
        if not isinstance(value,int):
           value = int(value,16)
        for e1, e2, e3, e4, e5 in target_base_set:
            ta = e1
            if not isinstance(ta,int):
               ta = int(ta,16)
            if value >= ta and value < ta + bound:
               diff = value - ta
               return (diff, ta)
        return (-1,-1) 

    def functionName(self, faddr):
        cfg = self._current_cfg
        #print(f"function address {faddr}")
        try:
           f = cfg.functions[faddr]
           return f.name
        except KeyError as e:
           return ""


    def findFunctionPointerAssignments(self, initial_state, target_base_set):
        print(f"Find function pointer assignments")
        endianness = 'little' if self._project.arch.memory_endness == Endness.LE else 'big'
        callback_assign_blocks = set()
        cfg = self._current_cfg
        for f in cfg.functions.values():
          for block_addr in f.block_addrs:
            current_block = self._project.factory.block(block_addr)
            hasStore = False
            for stmt in current_block.vex.statements:
                if isinstance(stmt, pyvex.IRStmt.Store):
                   hasStore = True
                   break
            if hasStore:
               for ia in current_block.instruction_addrs:
                   xrefs = cfg.kb.xrefs.get_xrefs_by_ins_addr(ia)
                   for xref in xrefs:
                      valuebv = initial_state.memory.load(xref.dst,4)
                      value = initial_state.solver.eval(valuebv)
                      value = int.from_bytes(value.to_bytes(4,byteorder='little'),byteorder='big')
                      if value in self._functionEntry:
                         fn = self.functionName(value)
                         print(f"Found a reference to a function {hex(value)} {fn} in function {f.name}")
                      if xref.dst in self._functionEntry:
                         fn = self.functionName(value)
                         print(f"Found a reference to a function {hex(xref.dst)} {fn} in function {f.name}")
                      if any([e5 for e1, e2, e3, e4, e5 in target_base_set if e5 == value]):
                         callback_assign_blocks.add(block_addr)
                      else:
                         if any([e5 for e1, e2, e3, e4, e5 in target_base_set if e5 == xref.dst]):
                            callback_assign_blocks.add(block_addr)
        for block_addr in callback_assign_blocks:
            current_block = self._project.factory.block(block_addr)
            numStore = 0
            for stmt in current_block.vex.statements:
                if isinstance(stmt, pyvex.IRStmt.Store):
                   numStore += 1
            print(f"Num stores in Block address {hex(block_addr)} is {numStore}")
            if numStore == 0:
               continue
            s = self._project.factory.blank_state(
                           remove_options={
                                angr.options.LAZY_SOLVES
                           }
                )
            s.ip = block_addr
            simgr = self._project.factory.simgr(s)
            s.inspect.b("mem_write", when=angr.BP_AFTER, action=self.actionMemWrite)
            error = False
            for i in range(0,numStore):
               self.resetActionResults()
               try:
                 simgr.step()
               except RuntimeError as e:
                 print(f"Possibly recursion depth issue, skipping {block_addr} in function {f.name}")
                 error = True
               if error:
                  continue
               else:
                  self.recordCallbackAssignment(s, target_base_set, block_addr, f)
        #self._klog.log_line(f"Number of MMIO relevant callback assignments {len(self._callback_assignments)}\n")
        #for ta, diff, cb, ba, fa in self._callback_assignments:
        #    self._klog.log_line(f"Callback address {hex(cb)} {self.functionName(cb)} stored at an offset {diff} of addess {hex(ta)} in block address {hex(ba)} in function {hex(fa)} {self.functionName(fa)}\n")

    def collectFunctionEntryAddresses(self):
        endianness = 'little' if self._project.arch.memory_endness == Endness.LE else 'big'
        cfg = self._current_cfg
        for f in cfg.functions.values():
           self._functionEntry.add(f.addr)

    def writeReturnValueInfo(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        ostr = ""
        for tuple in self._returnValueInfo:
            fd.write(f"Received value returned in function name={tuple[0]},address={hex(tuple[1])},callsite instruction={hex(tuple[2])},callee={tuple[3]},buffer={hex(tuple[4])}\n")
        fd.close() 

    def writeLocalBufferInfo(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        ostr = ""
        for tuple in self._localbufferInfo:
            fd.write(f"Buffer accessing function name={tuple[1].name},address={hex(tuple[1].addr)},sp offset={tuple[0]}\n")
        fd.close() 

    def writeBufferInfo(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        ostr = ""
        for tuple in self._bufferInfo:
            fd.write(f"Buffer accessing function name={tuple[0]},address={hex(tuple[1])},basic block={hex(tuple[2])},instruction={hex(tuple[3])},buffer={hex(tuple[4])}\n")
        fd.close() 

    def writeSnapshotInfo(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        ostr = ""
        for tuple in self._snapshotInfo:
            fd.write(f"Caller name={tuple[0]},address={hex(tuple[1])},callsite={hex(tuple[2])},callee name={tuple[3]},address={hex(tuple[4])},buffer={hex(tuple[5])}\n")
        fd.close() 

    def writeReceiveAliases(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        ostr = ""
        for tuple in self._receiveBufferAliases:
            if len(tuple) == 6:
               t1, t2, t3, t4, t5, t6 = tuple
               hrfFunc = self.getFunction(t1)
               fd.write(f"Function addr {hex(t1)} name {hrfFunc.name} creates an alias of receive buffer {t2} {t3} {t4} {t5} : {t6}\n")
            elif len(tuple) == 7:
               t1, t2, t3, t4, t5, t6, t7 = tuple
               hrfFunc = self.getFunction(t1)
               fd.write(f"Function addr {hex(t1)} name {hrfFunc.name} creates an alias of receive buffer {t2} {t3} {t4} {t5} : {t6} {t7}\n")
        fd.close()

    def writeTransmitAliases(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        ostr = ""
        for tuple in self._transmitBufferAliases:
            if len(tuple) == 7:
               t1, t2, t3, t4, t5, t6, t7 = tuple
               hrfFunc = self.getFunction(t1)
               fd.write(f"Function addr {hex(t1)} name {hrfFunc.name} creates an alias of transmit buffer {t2} {t3} {t4} : {t5} {t6} {t7}")
            elif len(tuple) == 7:
               t1, t2, t3, t4, t5, t6, t7, t8 = tuple
               hrfFunc = self.getFunction(t1)
               fd.write(f"Function addr {hex(t1)} name {hrfFunc.name} creates an alias of transmit buffer {t2} {t3} {t4} : {t5} {t6} {t7} {t8}")
        fd.close()

    def writeHandlerReceivingFunctions(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        ostr = ""
        #for tuple in self._handlerReceivingFunctions:
        #    ostr += self.ppCallArgPass(tuple) + "\n"
        for fa, ano in self._halF:
            hrfFunc = self.getFunction(fa)
            fd.write(f"Function addr {hex(fa)} name {hrfFunc.name} arg {ano}\n")
        fd.close()       

    def writeHandlerReceivingFunctionContexts(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        ostr = ""
        for fa in self._halCtx:
            hrfFunc = self.getFunction(fa)
            fd.write(f"Function addr {hex(fa)} name {hrfFunc.name}\n")
        fd.close()       


    def writeReceiveBuffers(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        for rbuf in self._receiveBuffers:
            fd.write(f"Receive buffer offset={rbuf}\n")
        fd.close()       

    def writeTransmitBuffers(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        for tbuf in self._transmitBuffers:
            fd.write(f"Transmit buffer offset={tbuf}\n")
        fd.close()       

    def writeReceiveFunctions(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        for cbf,doff in self._receiveISRs:
            fd.write(f"Receive type ISR/function {hex(cbf.addr)} name {cbf.name} stores to buffer at offset {doff}\n")
        fd.close()

    def writeTransmitFunctions(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        for cbf,doff in self._transmitISRs:
            fd.write(f"Transmit type ISR/function {hex(cbf.addr)} name {cbf.name} copies from buffer at offset {doff}\n")
        fd.close()

    def writeMMIOReceiveTaints(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        for rtt in self._receiveTaints:
            if len(rtt) == 0:
               f1, type, offset = rtt
               fd.write(f"Function {hex(f1.addr)} name {f1.name} receives from data regiser into type {type} at location {offset}\n")
            elif len(rtt) == 4:
               f1, type, offset, dtoffset = rtt
               fd.write(f"Function {hex(f1.addr)} name {f1.name} receives from data regiser into type {type} at location {offset} handler field offset {dtoffset}\n")
        fd.close()       

    def writeMMIOTransmitTaints(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        for ttt in self._transmitTaints:
            if len(ttt) == 3:
               f1, type, offset = ttt
               fd.write(f"Function {hex(f1.addr)} name {f1.name} taints data register with data from type {type} at location {offset} \n")
            elif len(ttt) == 4:
               f1, type, offset, dtoffset = ttt
               fd.write(f"Function {hex(f1.addr)} name {f1.name} taints data register with data from type {type} at location {offset} handler field offset {dtoffset}\n")
        fd.close()       

    def writeBaseAliases(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        for at in self._target_base_set:
            fd.write(self.ppAlias(at, "MMIO Base "))
            fd.write("\n") 
        fd.close()

    def writeDRAliases(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        for at in self._target_datareg_set:
            fd.write(self.ppAlias(at, "MMIO Data register "))
            fd.write("\n") 
        fd.close()

    def writeBaseAccesses(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        for at in self._MMIO_base_accesses:
            fd.write(self.ppAccess(at, "MMIO Base "))
            fd.write("\n") 
        fd.close()

    def writeDRAccesses(self, fname):
        if 'output' in self._config.keys():
           fname = self._config['output'] + "/" + fname
        fd = open(fname, "w")
        for at in self._MMIO_datareg_accesses:
            fd.write(self.ppAccess(at, "MMIO Data register "))
            fd.write("\n") 
        fd.close()

    def getFirstArgSetting(self, b_addr):
       b = self._project.factory.block(b_addr)
       put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put']
       for stmt in put_stmts:
           #print(f"Offset for RO {self._project.arch.registers['r0']} vs {stmt.offset}") 
           if stmt.offset in self._project.arch.registers['r0']:
              return True
       return False

    def actionRegWriteForHandlerReceiving(self, state):
       #print(f"Reg write offset {state.inspect.reg_write_offset} value {state.inspect.reg_write_expr}")
       offset = state.solver.eval(state.inspect.reg_write_offset)
       if offset in self._project.arch.registers['r0']:
          value = state.solver.eval(state.inspect.reg_write_expr)
          if any([e1 for e1, e2, e3, e4, e5 in self._target_base_set if hex(value) == e1]):
             #print(f"Assigning {value} to r0")
             self._relevantCall = True
             self._relevantArg = 0
          else:
             self._relevantCall = False
       if offset in self._project.arch.registers['r1']:
          value = state.solver.eval(state.inspect.reg_write_expr)
          if any([e1 for e1, e2, e3, e4, e5 in self._target_base_set if hex(value) == e1]):
             #print(f"Assigning {value} to r1")
             self._relevantCall = True
             self._relevantArg = 1
          else:
             self._relevantCall = False
       if offset in self._project.arch.registers['r2']:
          value = state.solver.eval(state.inspect.reg_write_expr)
          if any([e1 for e1, e2, e3, e4, e5 in self._target_base_set if hex(value) == e1]):
             #print(f"Assigning {value} to r2")
             self._relevantCall = True
             self._relevantArg = 2
          else:
             self._relevantCall = False
       if offset in self._project.arch.registers['r3']:
          value = state.solver.eval(state.inspect.reg_write_expr)
          if any([e1 for e1, e2, e3, e4, e5 in self._target_base_set if hex(value) == e1]):
             #print(f"Assigning {value} to r3")
             self._relevantCall = True
             self._relevantArg = 3
          else:
             self._relevantCall = False

  
    def actionCallForHandlerReceiving(self, state):
       faddr = state.solver.eval(state.inspect.function_address)
       #print(f"Function {self.functionName(faddr)} relevant? {self._relevantCall}")
       if self._relevantCall:
          self._handlerReceivingFunctions.add((self._relevant_base,self._relevantFuncAddress, self._relevantArg, faddr))
          #print(f"Recording function {self.functionName(faddr)} at {hex(faddr)} as handler receiving")

    def actionInstruction(self, state):
        print(f"INSTRUCTION {hex(state.inspect.instruction)}")

    def actionSymVar(self, state):
        print(f"SYMBOLIC VAR {state.inspect.symbolic_name} and {state.inspect.symbolic_expr}")

    def ppCallArgPass(self, callTuple, start=""):
        print(f"{callTuple[0]} {callTuple[1]} {callTuple[2]} {callTuple[3]}")
        return "%s base %s function at %s name %s passes handle arg %d to function at %s name %s" % (start,callTuple[0],hex(callTuple[1]),self.functionName(callTuple[1]),callTuple[2],hex(callTuple[3]),self.functionName(callTuple[3]))


    def actionRegReadForArgReceivingTrans(self, state):
       #print(f"A1")
       offset = state.solver.eval(state.inspect.reg_read_offset)
       if self._relevantArg == 0 and offset in self._project.arch.registers['r0']:
          self._relevant_argexpr = state.solver.eval(state.inspect.reg_read_expr)
       if self._relevantArg == 1 and offset in self._project.arch.registers['r1']:
          self._relevant_argexpr = state.solver.eval(state.inspect.reg_read_expr)
       if self._relevantArg == 2 and offset in self._project.arch.registers['r2']:
          self._relevant_argexpr = state.solver.eval(state.inspect.reg_read_expr)

    def actionMemWriteForArgReceivingTrans(self, state):
       #print(f"A2")
       wexpr = state.solver.eval(state.inspect.mem_write_expr)
       if self._relevant_argexpr == wexpr:
          self._relevant_memaddr = state.solver.eval(state.inspect.mem_write_address)

    def actionMemReadForArgReceivingTrans(self, state):
        #print(f"A3")
        raddr = state.solver.eval(state.inspect.mem_read_address) 
        if raddr == self._relevant_memaddr:
           #print(f"{state.inspect.mem_read_expr}")
           #print(f"{self._relevant_targetexpr}")
           self._relevant_targetexpr = state.solver.eval(state.inspect.mem_read_expr)

    def actionRegWriteForArgReceivingTrans(self, state):
        #print(f"A4")
        offset = state.solver.eval(state.inspect.reg_write_offset)
        if offset in self._project.arch.registers['r0']:
           self._targetArg = 0
        if offset in self._project.arch.registers['r1']:
           self._targetArg = 1
        if offset in self._project.arch.registers['r3']:
           self._targetArg = 2

    def actionCallForArgReceivingTrans(self, state):
        #print(f"A5")
        if self._targetArg >= 0:
           fa = state.solver.eval(state.inspect.function_address)
           self._arg_receiving.add((self._relevant_base,self._relevantFuncAddr,self._targetArg,fa))

    def collectFunctionsReceivingArgNoOneStep(self, callers, all):
      cfg = self._current_cfg
      self._temp_frarg = set()
      self._arg_receiving = set()
      for fa, argno in callers:
            print(f"Function address {fa}")
            if fa == 0:
               continue 
            if not fa in cfg.functions:
               continue
            f = cfg.functions[fa]
            self._relevantFuncAddr = fa
            self._relevantArg = argno
            self._targetArg = -1
            self._relevant_argexpr = -1
            self._relevant_targetexpr = -1
            self._relevant_memaddr = -1
            self._relevantCall = False
            #print(f"Analyzing function {self.functionName(fa)}")
            for block_address in f.block_addrs:
                current_block = self._project.factory.block(block_address)
                #current_block.pp()
                #current_block.vex.pp()
                for ia in current_block.instruction_addrs:
                   s = self._project.factory.entry_state(
                       #remove_options={
                       #    angr.options.LAZY_SOLVES
                       #},
                       add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
                   )
                   s.ip = ia
                   #print(f"Stack pointer: {s.regs.sp}")
                   simgr = self._project.factory.simgr(s)      
                   s.inspect.b("call", when=angr.BP_BEFORE, action=self.actionCallForArgReceivingTrans)
                   s.inspect.b("mem_write", when=angr.BP_BEFORE, action=self.actionMemWriteForArgReceivingTrans)
                   s.inspect.b("mem_read", when=angr.BP_AFTER, action=self.actionMemReadForArgReceivingTrans)
                   s.inspect.b("reg_write", when=angr.BP_AFTER, action=self.actionRegWriteForArgReceivingTrans)
                   s.inspect.b("reg_read", when=angr.BP_AFTER, action=self.actionRegReadForArgReceivingTrans)
                   try:
                     simgr.step(num_inst=5)
                   except RuntimeError as e:
                     print(f"Possibly recursion depth issue, skipping {block_address} in function {f.name}")
      return self._arg_receiving

    def collectFunctionsReceivingArgNo(self, initialcallers):
        change = False
        i = 0
        all = initialcallers
        frontier = [(f2, a) for base, f1, a, f2 in initialcallers]
        while i == 0 or change:
            change = False
            i += 1
            stepr = self.collectFunctionsReceivingArgNoOneStep(frontier, all)
            frontier = set()
            for fr in stepr:
                if not fr  in all:
                   change = True
                   frontier.add((fr[2],fr[1]))
                all.add(fr)
        return all          

    def collectFunctionsReceivingHandlerAsArgRecursively(self, target_set):
        frontierhr = self.collectFunctionsReceivingHandlerAsArg(target_set)
        allhr = self.collectFunctionsReceivingArgNo(frontierhr)
        print(f"Number of handler passing tuples: {len(allhr)}")
        for hrt in allhr:
            print(f"{self.ppCallArgPass(hrt)}")

    def collectFunctionsReceivingHandlerAsArg(self, target_set):
        cfg = self._current_cfg
        self._handlerReceivingFunctions = set()
        for ha, d, ia, ba, fa in target_set:
            if fa == 0:
               continue
            # to do: check all blocks in the relevant function
            #if not self.getFirstArgSetting(ba):
            #   continue
            self._relevantFuncAddress = fa
            self._relevant_base = ha
            f = cfg.functions[fa]
            print(f"Analyzing function {self.functionName(fa)}")
            for block_address in f.block_addrs:
                self._relevantCall = False
                self._relevantArg = -1
                current_block = self._project.factory.block(block_address)
                #current_block.pp()
                #if f.name == "serialBegin":
                #   current_block.vex.pp()
                for ia in current_block.instruction_addrs:
                   s = self._project.factory.entry_state(
                       #remove_options={
                       #    angr.options.LAZY_SOLVES
                       #},
                       add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
                   )
                   s.ip = ia
                   #print(f"Stack pointer: {s.regs.sp}")
                   simgr = self._project.factory.simgr(s)
                   #print(f"Number of active {len(simgr.active)} at START")
                   #s.inspect.b("symbolic_variable", when=angr.BP_BEFORE, action=self.actionSymVar)
                   #s.inspect.b("instruction", when=angr.BP_BEFORE, action=self.actionInstruction)
                   s.inspect.b("call", when=angr.BP_BEFORE, action=self.actionCallForHandlerReceiving)
                   s.inspect.b("reg_write", when=angr.BP_AFTER, action=self.actionRegWriteForHandlerReceiving)
                   try:
                     simgr.step(num_inst=25)
                   except RuntimeError as e:
                     print(f"Possibly recursion depth issue, skipping {block_address} in function {f.name}")
                   #print(f"Number of active {len(simgr.active)} at END")
        print(f"Number of handler receiving functions: {len(self._handlerReceivingFunctions)}")
        hrfs = ""
        for base, cf, an, hrf in self._handlerReceivingFunctions:
           hrfs += "\nBase %s Caller at %s name %s argno %d callee at %s name %s\n" % (base,hex(cf),self.functionName(cf),an,hex(hrf),self.functionName(hrf))
        print(f"Handler receiving functions: {hrfs}")
        return self._handlerReceivingFunctions

    def ppCallbackAssignment(self, cbtuple, start=""):
       return "%s base %s callback %s %s assigned at instruction %s in context %s %s\n" % (start, hex(tuple[0]), hex(tuple[1]), self.functionName(tuple[1]),hex(tuple[2]), hex(tuple[3]),self.functionName(tuple[3]))

    def actionMMIOCallbackInstruction(self, state):
       self._relevant_instruction = state.inspect.instruction 

    def actionMMIOCallbackRegRead(self, state):
        #print(f"pc in cb read {hex(self._relevant_instruction)}")
        offset = state.solver.eval(state.inspect.reg_read_offset)
        #ia = state.solver.eval(state.regs.pc)
        ia = self._relevant_instruction
        if offset in self._project.arch.registers['r0'] or offset in self._project.arch.registers['r1'] or offset in self._project.arch.registers['r2']:
              if not offset in self._relevant_locals:
                 self._relevant_locals[offset] = (offset, ia, 0)
  

    def actionMMIOCallbackWrite(self, state):
        print(f"MMIO callback expression? {state.inspect.mem_write_expr} to address {state.inspect.mem_write_address}")
        print(f"noluyoruz")
        print(f"pc in cb write {hex(self._relevant_instruction)}")
        addr = state.solver.eval(state.inspect.mem_write_address)
        expr = state.solver.eval(state.inspect.mem_write_expr)
        print(f"MMIO callback expression? {expr} to address {hex(addr)}")
        #ia = state.solver.eval(state.regs.pc)
        ia = self._relevant_instruction
        self._relevant_instruction = 0 
        oc = 0
        iac = 0
        la = 0
        for o in self._relevant_locals:
            tuple = self._relevant_locals[o]
            print(f"Local tuple offset {tuple[0]} {hex(tuple[1])} vs {hex(ia)} {hex(tuple[2])}")
            if tuple[1] == ia:
               oc = o
               iac = ia
               la = addr
               break
        if not oc == 0 and not iac == 0 and not la == 0:
           self._relevant_locals[oc] = (oc, iac, la)
           print(f"Local address {hex(la)} expr for register offset {oc}")
        else:
           return
        fa = self.getFunctionAddress(expr)
        if fa:
           diff,base = self.isWithinRange(addr, self._target_base_set, self._handler_data_size)
           if not diff == -1:
              cfa = getFunctionFromInstruction(ia)
              tuple = (base,fa,ia,cfa)
              self._mmio_callback_assignments.add(tuple)
              print(f"self.ppCallbackAssignment(tuple,\"Detected callback assignment: \")")


    
    def matchIRLists(self, oneL, otherL): 
        if not len(oneL) == len(otherL):
           return False 
        match = True;
        index = 0
        num = len(oneL)
        while index < num:
           if not self.matchIR(oneL[index],otherL[index]):
              return False
           index += 1
        return True

    def matchIR(self, one, other):
        if isinstance(one,IRStmt) and isinstance(other,IRStmt):
           if isinstance(one,Put) and isinstance(other,Put):
              return one.offset == other.offset and self.matchIR(one.data,other.data) 
           if isinstance(one,PutI) and isinstance(other,PutI):
              return self.matchIR(one.ix,other.ix) and self.matchIR(one.data,other.data) 
           if isinstance(one,WrTmp) and isinstance(other,WrTmp):
              return self.matchIR(one.tmp,other.tmp) and self.matchIR(one.data,other.data) 
           if isinstance(one,Store) and isinstance(other,Store):
              return self.matchIR(one.addr,other.addr) and self.matchIR(one.data,other.data)
        if isinstance(one,IRExpr) and isinstance(other,IRExpr):
           if isinstance(one,GetI) and isinstance(other,GetI):
              return self.matchIR(one.index(),other.index())
           if isinstance(one,Get) and isinstance(other,Get):
              return self.matchIR(one.offset,other.offset)               
           if isinstance(one,RdTmp) and isinstance(other,RdTmp):
              return self.matchIR(one.tmp(),other.tmp())
           if isinstance(one,Binop) and isinstance(other,Binop):
              if one.op == other.op:
                 return self.matchIRLists(one.child_expressions(), other.child_expressions()) 
              else:
                 return False
           if isinstance(one,Unop) and isinstance(other,Unop):
              if one.op == other.op:
                 return self.matchIRLists(one.child_expressions(), other.child_expressions()) 
              else:
                 return False
           if isinstance(one,Load) and isinstance(other,Load):
              return self.matchIR(one.addr,other.addr)
           if isinstance(one,Const) and isinstance(other,Const):
              return one.con == other.con
        return False         


    def findCallbackAssignments(self, target_base_set, handler_recv_funcs, range=512):
        cfg = self._current_cfg
        candidateFuncs = set()
        # first summarize all base and candidate funcs
        for base, d, ia, ba, fa in target_base_set:
            candidateFuncs.add((base,fa))
        for base, cf, an, hrf in self._handlerReceivingFunctions:
            candidateFuncs.add((base, cf))
            candidateFuncs.add((base, hrf))
        for base, cf, an, hrf in handler_recv_funcs:
            candidateFuncs.add((base, cf))
            candidateFuncs.add((base, hrf))
        for base, fa in candidateFuncs:
             if fa == 0:
                continue
             print(f"Finding callback assignements in function at {hex(fa)} name {self.functionName(fa)}")
             f = None
             if fa in cfg.functions:
                f = cfg.functions[fa]
             else:
                continue
             self._relevant_locals = {}
             self._relevant_base = int(self._target_base,16)
             self._access_range = range
             self._relevantFuncAddress = fa
             print(f"Analyzing function {self.functionName(fa)}")
             for block_address in f.block_addrs:
                #print(f"\tBlock {hex(block_address)}")
                current_block = self._project.factory.block(block_address)
                stores = [x for x in current_block.vex.statements if x.tag == 'Ist_Store']
                for s in stores:
                    print(f"Block {hex(block_address)} Store address {s.addr} data {s.data}")
                    if s.addr.tmp:
                       print(f"\t temp {s.addr.tmp}")
                puts = [x for x in current_block.vex.statements if x.tag == 'Ist_Put']
                for p in puts:
                    if p.offset in self._project.arch.register_names:
                       print(f"Block {hex(block_address)} Put data {p.data} offset {p.offset} register name {self._project.arch.register_names[p.offset]}")
                gets = [x for x in current_block.vex.expressions if x.tag == 'Iex_Get']
                for g in gets:
                    if g.offset in self._project.arch.register_names:
                       print(f"Block {hex(block_address)} Get offset {g.offset} register name {self._project.arch.register_names[g.offset]}")
                #current_block.pp()
                #current_block.vex.pp()
                #for ia in current_block.instruction_addrs:
                #   self._relevant_instruction = 0
                   #print(f"\t\tInstruction at {hex(ia)} of function {hex(fa)} name {self.functionName(fa)}")
                #   s = self._project.factory.entry_state(
                       #remove_options={
                       #    angr.options.LAZY_SOLVES
                       #},
                #       add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                #                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
                #   )
                #   s.ip = fa
                   #s.ip = ia
                   #s.sp = 0x20005000
                #   simgr = self._project.factory.simgr(s)
                #   s.inspect.b("instruction", when=angr.BP_BEFORE, action=self.actionMMIOCallbackInstruction)
                #   s.inspect.b("reg_read", when=angr.BP_AFTER, action=self.actionMMIOCallbackRegRead)
                #   s.inspect.b("mem_write", when=angr.BP_AFTER, action=self.actionMMIOCallbackWrite)
                #   try:
                #     simgr.step()
                #   except RuntimeError as e:
                #     print(f"Possibly recursion depth issue, skipping {block_address} in function {f.name}")
       

    def actionMMIORead(self, state):
       addr = state.solver.eval(state.inspect.mem_read_address)
       if addr == self._MMIO_datareg:
          if addr in self._datareg_read:
             self._datareg_read[addr].add(self._relevantFuncAddress)
          else:
             self._datareg_read[addr] = set()
             self._datareg_read[addr].add(self._relevantFuncAddress) 
       else:
          if addr >= self._relevant_base and addr < self._relevant_base + self._access_range:
             if addr in self._otherreg_read:
                self._otherreg_read[addr].add(self._relevantFuncAddress)
             else:
                self._otherreg_read[addr] = set()
                self._otherreg_read[addr].add(self._relevantFuncAddress) 

    def actionMMIOWrite(self, state):
       addr = state.solver.eval(state.inspect.mem_write_address)
       if addr == self._MMIO_datareg:
          if addr in self._datareg_write:
             self._datareg_write[addr].add(self._relevantFuncAddress)
          else:
             self._datareg_write[addr] = set()
             self._datareg_write[addr].add(self._relevantFuncAddress) 
       else:
          if addr >= self._relevant_base and addr < self._relevant_base + self._access_range:
             if addr in self._otherreg_read:
                self._otherreg_write[addr].add(self._relevantFuncAddress)
             else:
                self._otherreg_write[addr] = set()
                self._otherreg_write[addr].add(self._relevantFuncAddress) 

    #def actionDummyCall(self, state):
    #    print(f"Call {state.inspect.function_address}")

    #def actionDummyInstruction(self, state):
        #print(f"Instruction {hex(state.inspect.instruction)}")

    def findRegisterAccess(self, target_base_set, handler_recv_funcs, callback_assignments):
        cfg = self._current_cfg
        candidateFuncs = set()
        # first summarize all base and candidate funcs
        for base, d, ia, ba, fa in target_base_set:
            candidateFuncs.add((base,fa))  
        for base, cf, an, hrf in self._handlerReceivingFunctions:
            candidateFuncs.add((base, cf))
            candidateFuncs.add((base, hrf))
        for base, cf, an, hrf in handler_recv_funcs:
            candidateFuncs.add((base, cf))
            candidateFuncs.add((base, hrf))
        for base, cb, ia, cf in callback_assignments:
            candidateFuncs.add((base, cb))   
            candidateFuncs.add((base, cf))   
        for base, fa in candidateFuncs:
            if fa == 0:
               continue
            print(f"Checking register accesses in function at {hex(fa)} name {self.functionName(fa)}")
            f = cfg.functions[fa]
            self._relevant_base = int(self._target_base,16)
            self._access_range = self._handler_data_size
            self._relevantFuncAddress = fa
            #print(f"Analyzing function {self.functionName(fa)}")
            for block_address in f.block_addrs:
                   #print(f"\tBlock {hex(block_address)}") 
                   current_block = self._project.factory.block(block_address)
                #current_block.pp()
                #current_block.vex.pp()
                #for ia in current_block.instruction_addrs:
                   #print(f"\t\tInstruction at {hex(ia)} of function {hex(fa)} name {self.functionName(fa)}")
                   s = self._project.factory.entry_state(
                       #remove_options={
                       #    angr.options.LAZY_SOLVES
                       #},
                       add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
                   )
                   #s.ip = ia
                   s.ip = block_address
                   #self.updateStateWithMMIOPointers(s,self._pointer_assignments)
                   #print(f"Stack pointer: {s.regs.sp}")
                   simgr = self._project.factory.simgr(s)
                   #print(f"Number of active {len(simgr.active)} at START")
                   #s.inspect.b("symbolic_variable", when=angr.BP_BEFORE, action=self.actionSymVar)
                   #s.inspect.b("instruction", when=angr.BP_BEFORE, action=self.actionInstruction)
                   #s.inspect.b("call", when=angr.BP_BEFORE, action=self.actionDummyCall)
                   #s.inspect.b("instruction", when=angr.BP_BEFORE, action=self.actionDummyInstruction)
                   s.inspect.b("mem_write", when=angr.BP_BEFORE, action=self.actionMMIOWrite)
                   s.inspect.b("mem_read", when=angr.BP_BEFORE, action=self.actionMMIORead)
                   try:
                     simgr.step(num_inst=10)
                   except RuntimeError as e:
                     print(f"Possibly recursion depth issue, skipping {block_address} in function {f.name}")
        print(f"MMIO data register reads:")                   
        for addr in self._datareg_read:
           print(f"\tFunctions that read from MMIO address {hex(addr)}")
           for fa in self._datareg_read[addr]: 
               print(f"\t\t Function at {hex(fa)} name {self.functionName(fa)}")
        print(f"MMIO data register writes:")                   
        for addr in self._datareg_write:
           print(f"\tFunctions that write to MMIO address {hex(addr)}")
           for fa in self._datareg_write[addr]: 
               print(f"\t\t Function at {hex(fa)} name {self.functionName(fa)}")
        print(f"MMIO non-data register reads:")                   
        for addr in self._otherreg_read:
           print(f"\tFunctions that read from MMIO address {hex(addr)}")
           for fa in self._otherreg_read[addr]: 
               print(f"\t\t Function at {hex(fa)} name {self.functionName(fa)}")
        print(f"MMIO non-data register writes:")                   
        for addr in self._otherreg_write:
           print(f"\tFunctions that write to MMIO address {hex(addr)}")
           for fa in self._otherreg_write[addr]: 
               print(f"\t\t Function at {hex(fa)} name {self.functionName(fa)}")

    def updateStateWithMMIOPointers(self, state, base_ptr_assignments):
        for base, pointer, addr in base_ptr_assignments:
            state.memory.store(pointer, addr, endness=state.arch.memory_endness)

    def findHandlerCallbackBufferAssignments(self, base_set, handlerRF):
        #for base, cf, an, hrf in handlerRF:
        for hrf, an in handlerRF:
            hrfFunc = self.getFunction(hrf)
            #cfFun = self.getFunction(cf)
            #print(f"Extract HAL for {hex(hrf)}")
            info = hex(hrf) if hrfFunc == None else hrfFunc.name
            print(f"Extracting callback and buffer assignments in {info} for argno {an}")
            res = self._iranalyzer.HALextract(hrfFunc, an)
            if res == None:
               continue
            cbres, bufres = res
            for cbcf, doff, cba in cbres:
                cbf = self.getFunction(cba)
                print(f"Callback {hex(cba)} name {cbf.name} set to handler at offset {doff}")
                self._callback_assignments.add((cbf, doff))
            for bufcf, doff, type, argreg in bufres:
                print(f"Buffer received from arg {argreg} set to handler at offset {doff}")
                self._buffer_assignments.add((bufcf, doff, type, argreg))

    def findAndCategorizeImplicitCallbacks(self):
        # will use self._buffer_assignments
        return 

    def categorizeCallbacks(self, callback_assignments):
        for cbf, cdoff in callback_assignments:
            roff = self._iranalyzer.HALreceivesFromDR(cbf, self._MMIO_base, self._MMIO_datareg)
            matchesR = False
            for bufcf, doff, type, argreg in self._buffer_assignments:
                if not isinstance(doff,int):
                   doff = int(doff,16)
                #print(f"{doff} found as a receive buffer offset?")
                if doff in roff:
                   matchesR = True
                   self._receiveBuffers.add(doff)
            if matchesR:
               self._receiveISRs.add((cbf,doff))
            toff = self._iranalyzer.HALtransmitsToDR(cbf, self._MMIO_base, self._MMIO_datareg)
            matchesT = False
            for bufcf, doff, type, argreg in self._buffer_assignments:
                if not isinstance(doff,int):
                   doff = int(doff,16)
                #print(f"{doff} found as a transmit buffer offset?")
                if doff in toff:
                   matchesT = True
                   self._transmitBuffers.add(doff)
            if matchesT:
               self._transmitISRs.add((cbf,doff))
        for cbf,doff in self._receiveISRs:
            print(f"Receive type ISR {hex(cbf.addr)} name {cbf.name}")
        for rbuf in self._receiveBuffers:
            print(f"Receive buffer offset {hex(rbuf)}")
        for cbf,doff in self._transmitISRs:
            print(f"Transmit type ISR {hex(cbf.addr)} name {cbf.name}")
        for tbuf in self._transmitBuffers:
            print(f"Transmit buffer offset {hex(tbuf)}")

    def generateDefUse(self, hrf):
        hf = [x for x, a in hrf]
        for ha in hf:
            hrfun = self.getFunction(ha) 
            self._iranalyzer.IRgenDefUse(hrfun)

    def ppTaintBufferInfo(self, tuple, receive, handler):
        if len(tuple) == 3:
           f, type, source = tuple
           if receive:
              print(f"Generic receive taint sink {f.name} {type} {source}") 
           else:
              print(f"Generic transmit taint source {f.name} {type} {source}") 
        elif len(tuple) == 4:
           f, type, source, dtsof = tuple
           if receive:
              print(f"Generic receive taint sink {f.name} {type} {source} handler {handler} field offset {dtsof}") 
           else:
              print(f"Generic transmit taint source {f.name} {type} {source} handler {handler} field offset {dtsof}") 

    def ppTaintBufferDetailedInfo(self, tuple, receive, handler=""):
        if len(tuple) == 3:
           f, type, source = tuple
           if receive:
              if type == "stack":
                 print(f"Function {hex(f.addr)} name {f.name} receives data from stack at offset {source} wrt stack pointer at function entry")
              if type == "argument":
                 print(f"Function {hex(f.addr)} name {f.name} receives data from arg {source} to directly taint data register")
              if type == "global" and source >= self._minRAM:
                 print(f"Function {hex(f.addr)} name {f.name} receives data from global address {hex(source)} to directly taint data register")
           else:
              if type == "stack":
                 print(f"Function {hex(f.addr)} name {f.name} transmits data from stack at offset {source} wrt stack pointer at function entry")
              if type == "argument":
                 print(f"Function {hex(f.addr)} name {f.name} transmits data from arg {source} to directly taint data register")
              if type == "global" and source >= self._minRAM:
                 print(f"Function {hex(f.addr)} name {f.name} transmits data from global address {hex(source)} to directly taint data register")
        elif len(tuple) == 4:
           f, type, source, dtsof = tuple
           if receive:
              if type == "stack":
                 print(f"Function {hex(f.addr)} name {f.name} receives data from stack at offset {source} handler {handler} field offset {dtsof} wrt stack pointer at function entry")
              if type == "argument":
                 print(f"Function {hex(f.addr)} name {f.name} receives data from arg {source} handler {handler} field offset {dtsof} to directly taint data register")
              if type == "global" and source >= self._minRAM:
                 print(f"Function {hex(f.addr)} name {f.name} receives data from global address {hex(source)} handler {handler} field offset {dtsof} to directly taint data register")
           else:
              if type == "stack":
                 print(f"Function {hex(f.addr)} name {f.name} transmits data from stack at offset {source} handler {handler} field offset {dtsof} wrt stack pointer at function entry")
              if type == "argument":
                 print(f"Function {hex(f.addr)} name {f.name} transmits data from arg {source} handler {handler} field offset {dtsof} to directly taint data register")
              if type == "global" and source >= self._minRAM:
                 print(f"Function {hex(f.addr)} name {f.name} transmits data from global address {hex(source)} handler {handler} field offset {dtsof} to directly taint data register")
        

    def findBufferAliases(self, halF):
        ralias = self._iranalyzer.HALfindBufferAliases(halF, self._receiveTaints)
        for ra in ralias:
            self._receiveBufferAliases.add(ra)
        talias = self._iranalyzer.HALfindBufferAliases(halF, self._transmitTaints)
        for ta in talias:
            self._transmitBufferAliases.add(ta)

    def findHALReceivingFunctionTaints(self, handlerReceivingFunctions, dataregoffset, receiveBuffers, transmitBuffers):
        receiveTaints = set()
        transmitTaints = set()
        directReceiveTaints = set()
        directTransmitTaints = set()
        genericReceiveTaints = set()
        genericTransmitTaints = set()
        #for base, cf, an, hrf in handlerReceivingFunctions:
        # case 1: direct taints from (to) data channel to (from) receive (transfer) buffers
        for hrf, an in handlerReceivingFunctions:
            hrfun = self.getFunction(hrf)
            if not hrfun.name == "UART_Receive_IT":
               continue
            print(f"Finding receive buffers for {hrfun.name} arg {an}")
            rt = self._iranalyzer.HALfindReceiveBufferAddressSource(hrfun, an, dataregoffset)
            for rtt in rt:
                self.ppTaintBufferInfo(rtt, True, an)
                #f, type, source = rtt
                #print(f"Generic receive taint sink {f.name} {type} {source}")
                genericReceiveTaints.add(rtt)
            print(f"Finding transmit buffers for {hrfun.name} arg {an}")
            tt = self._iranalyzer.HALfindTransmitBufferAddressSource(hrfun, an, dataregoffset)
            for ttt in tt:
                self.ppTaintBufferInfo(ttt, False, an)
                #f, type, source = ttt
                #print(f"Generic trainsmit taint source {f.name} {type} {source}")
                genericTransmitTaints.add(ttt)
        for rtt in genericReceiveTaints:
            if len(rtt) == 3:
               f, type, source = rtt
            elif len(rtt) == 4:
               f, type, source, dtoff = rtt
            self.ppTaintBufferDetailedInfo(rtt, True) 
            #if type == "stack":
            #   print(f"Function {hex(f.addr)} name {f.name} receives data from stack at offset {source} wrt stack pointer at function entry")
            #if type == "argument":
            #   print(f"Function {hex(f.addr)} name {f.name} receives data from arg {source} to directly taint data register")
            #if type == "global" and source >= self._minRAM:
            #   print(f"Function {hex(f.addr)} name {f.name} receives data from global address {hex(source)} to directly taint data register")
            if type == "stack" or type == "argument" or (type == "global" and source >= self._minRAM):
               self._receiveTaints.add(rtt)            
        for ttt in genericTransmitTaints:
            if len(ttt) == 3:
               f, type, source = ttt
            else:
               f, type, source, dtoff = ttt
            self.ppTaintBufferDetailedInfo(ttt, False) 
            #if type == "stack":
            #   print(f"Function {hex(f.addr)} name {f.name} transmits data from stack at offset {source} wrt stack pointer at function entry")
            #if type == "argument":
            #   print(f"Function {hex(f.addr)} name {f.name} transmits data from arg {source} to directly taint data register")
            #if type == "global" and source >= self._minRAM:
            #   print(f"Function {hex(f.addr)} name {f.name} transmits data from global address {hex(source)} to directly taint data register")
            if type == "stack" or type == "argument" or (type == "global" and source >= self._minRAM):
               self._transmitTaints.add(ttt)
        return 
        for hrf, an in handlerReceivingFunctions:
            hrfun = self.getFunction(hrf)
            print(f"Checking DIRECT taints for handler receiving function {hex(hrf)} name {self.functionName(hrf)} {hrfun}")
            if hrfun == None:
               continue
            rt = self._iranalyzer.HALfindDirectReceiveTaints(hrfun,an,self._datareg_offset)
            for rtt in rt:
                directReceiveTaints.add(rtt)         
            tt = self._iranalyzer.HALfindDirectTransmitTaints(hrfun,an,self._datareg_offset)
            for ttt in tt:
                directTransmitTaints.add(ttt)
        print(f"Number of direct receive taints {len(directReceiveTaints)} and direct transmit taints {len(directTransmitTaints)}")
        for rtt in directReceiveTaints:
            print(f"RT: {rtt}")  
            f, type, sink = rtt
            if type == "stack":
               print(f"Function {hex(f.addr)} name {f.name} taints stack at offset {sink} wrt stack pointer at function entry")
            if type == "argument":
               print(f"Function {hex(f.addr)} name {f.name} taints arg {sink} directly from data register")
            if type == "global" and sink >= self._minRAM:
               print(f"Function {hex(f.addr)} name {f.name} taints global address {hex(sink)} directly from data register")
            if type == "stack" or type == "argument" or (type == "global" and sink >= self._minRAM):
               self._directreceiveTaints.add(rtt)
        for ttt in directTransmitTaints:
            print(f"TT: {ttt}")  
            f, type, source = ttt
            if type == "stack":
               print(f"Function {hex(f.addr)} name {f.name} receives data from stack at offset {sink} wrt stack pointer at function entry")
            if type == "argument":
               print(f"Function {hex(f.addr)} name {f.name} receives data from arg {source} to directly taint data register")
            if type == "global" and source >= self._minRAM:
               print(f"Function {hex(f.addr)} name {f.name} receives data from global address {hex(source)} to directly taint data register")
            if type == "stack" or type == "argument" or (type == "global" and source >= self._minRAM):
               self._directtransmitTaints.add(ttt)
        # case 2: indirect taints through buffer pointer stored in the handler
        for hrf, an in handlerReceivingFunctions:
            hrfun = self.getFunction(hrf)
            print(f"Checking INDIRECT taints for handler receiving function {hex(hrf)} name {self.functionName(hrf)} {hrfun}")
            if hrfun == None:
               continue
            rt = self._iranalyzer.HALfindReceiveTaints(hrfun,an,receiveBuffers)
            for rtt in rt:
                receiveTaints.add(rtt)
            tt = self._iranalyzer.HALfindTransmitTaints(hrfun,an,transmitBuffers)
            for ttt in tt:
                transmitTaints.add(ttt)
        for rtt in receiveTaints:
            f, type, argno, dataoffset = rtt
            if type == "argument":
               print(f"Function {hex(f.addr)} name {f.name} taints arg {argno} with receive buffer at handler offset {dataoffset}")
            if type == "global" and argno >= self._minRAM:
               print(f"Function {hex(f.addr)} name {f.name} taints global address {hex(argno)} with receive buffer at handler offset {dataoffset}")
            if type == "argument" or (type == "global" and argno >= self._minRAM):
               self._directreceiveTaints.add(rtt)
        for ttt in transmitTaints:
            f, type, argno, dataoffset = ttt
            if type == "argument":
               print(f"Function {hex(f.addr)} name {f.name} arg {argno} taints transmit buffer at handler offset {dataoffset}")
            if type == "global" and argno >= self._minRAM:
               print(f"Function {hex(f.addr)} name {f.name} global address {hex(argno)} taints transmit buffer at handler offset {dataoffset}")
            if type == "argument" or (type == "global" and argno >= self._minRAM):
               self._directreceiveTaints.add(ttt)
            
    def propagateBufferTaints(self, receiveTaints, transmitTaints):
        newreceiveTaints = set()
        newtransmitTaints = set()
        for f, type, argno, dataoffset in receiveTaints:
            tr = self._iranalyzer.HALanalyzeCallingContextForTaint(f, argno, "receive")
            for f1, t1, a1 in tr:
                newreceiveTaints.add((f1, type, a1, f, argno))
        for f, type, argno, dataoffset in transmitTaints:
            tr = self._iranalyzer.HALanalyzeCallingContextForTaint(f, argno, "transmit")
            for f1, t1, a1 in tr:
                newtransmitTaints.add((f1, type, a1, f, argno))
        return (newreceiveTaints,newtransmitTaints)

    def propagateIndirectTaints(self, taints, type):
        result = set()
        for f1, type, argno, f2, argno2 in taints:
            tr = self._iranalyzer.HALanalyzeCallingContextForTaint(f1, argno, type)
            for f3, t3, a3 in tr:
                print(f"Indirect taint: {f3.name} {t3} {a3} {f1.name} {argno}")
                result.add((f3, t3, a3, f1, argno))
        return result

    def propagateTaints(self, receiveTaints, transmitTaints):
        rt, tt = self.propagateBufferTaints(self._receiveTaints, self._transmitTaints)
        changer = True
        changet = True
        nrt = rt
        ntt = tt
        while changer or changet:
              print(f"Propagate taint step!") 
              if changer:
                 r1 = self.propagateIndirectTaints(nrt, "receive")
                 changer = False
                 nrt = set()
                 for t in r1:
                     if not t in rt:
                        changer = True
                        nrt.add(t)
                 for t in nrt:
                     rt.add(t)
              if changet:
                 t1 =  self.propagateIndirectTaints(ntt, "transmit")
                 changet = False
                 ntt = set()
                 for t in t1:
                     if not t in tt:
                        changet = True
                        ntt.add(t)
                 for t in ntt:
                     tt.add(t)
        print(f"Indirect taints for receive buffers")
        for f1, type, a1, f2, a2 in rt:
            print(f"Function {hex(f1.addr)} name {f1.name} arg {a1} passed to arg {a2} function {hex(f2.addr)} name {f2.name}")
        print(f"Indirect taints for transmit buffers")
        for f1, type, a1, f2, a2 in tt:
            print(f"Function {hex(f1.addr)} name {f1.name} arg {a1} passed to arg {a2} function {hex(f2.addr)} name {f2.name}")
        self._receiveTaintPropagated = rt
        self._transmitTaintPropagated = tt

    def minimizeHalReceivingFunctions(self, halF):
        result = set()
        args = {}
        args[0] = 'r0'
        args[1] = 'r1'
        args[2] = 'r2'
        args[3] = 'r3'
        for f, ano in halF:
            if isinstance(ano, int):
               if ano in args.keys():
                  result.add((f, args[ano]))
            else:
               result.add((f,ano))
        return result

    def processPointsToInTrace(self):
        for addr in self._traceDef.keys():
            defs = self._traceDef[addr]
            for pc, index, data, size in defs:
                if data in self._traceLoads:
                   if not pc in self._tracePointsTo.keys():
                      self._tracePointsTo[pc] = set()
                   self._tracePointsTo[pc].add((pc, index, addr, data)) 
        for pc in self._tracePointsTo.keys():
            f = self._iranalyzer.IRgetFunctionOfInstruction(pc)
            if f == None:
               print(f"PointsTo for pc {hex(pc)}")
            else:
               print(f"PointsTo for pc {hex(pc)} f {f.name} {hex(f.addr)}")
            for pto in self._tracePointsTo[pc]:
                pc, index, addr, data = pto
                aons = ""
                dons = ""
                if addr in self._traceStackAddresses:
                   aons = " [STACK] "
                if data in self._traceStackAddresses:
                   dons = " [STACK] " 
                print(f"\t{hex(addr)} {aons} -> {hex(data)} {dons} at pc {hex(pc)} index {index}")

    def processDefPointsInTrace(self):
        for addr in self._traceDef.keys():
            for di in self._traceDef[addr]:
                pc, index, data, size = di
                f = self._iranalyzer.IRgetFunctionOfInstruction(pc)
                if not f == None:
                   if not f.addr in self._traceFunctionDefMap.keys():
                      self._traceFunctionDefMap[f.addr] = set()
                   self._traceFunctionDefMap[f.addr].add((pc, index, addr, data, size))
        for fa in self._traceFunctionDefMap.keys():
            f = self._iranalyzer.IRgetFunctionAtAddress(fa)
            print(f"Defs in function {f.name} {hex(fa)}")
            for pc, index, addr, data, size in self._traceFunctionDefMap[fa]:
                aons = ""
                dons = ""
                if addr in self._traceStackAddresses:
                   aons = " [STACK] "
                if data in self._traceStackAddresses:
                   dons = " [STACK] " 
                print(f"\t{hex(addr)} {aons} <- {hex(data)} {dons} at pc {hex(pc)} index {index}")


    def processWriteInTrace(self, addr, data, size, pc, index):
        if addr not in self._traceDef.keys():
           self._traceDef[addr] = []
        self._traceDef[addr].append((pc, index, data, size))
            

    def processReadInTrace(self, addr, data, size, pc, index):
        if addr not in self._traceUse.keys():
           self._traceUse[addr] = []
        self._traceUse[addr].append((pc, index, data, size))
        self._traceLoads.add(addr)
        if addr not in self._traceDef.keys():
           return
        defs = self._traceDef[addr]
        i = len(defs) - 1
        found = False
        while i >= 0:
              if i < index:
                 self._traceDefofUse[index] = i
                 found = True
                 break
              i -= 1

        
    def printStateMachine(self, edges, stateDesc, numStates):
        print(f"Number of states={numStates}")
        i = 0
        while i < numStates:
              print(f"State {i} size {len(stateDesc[i])}")
              i += 1
        for edge in edges:
            s1, d, s2 = edge
            print(f"Edge: ({s1},{d},{s2})")

    def findMMIORxBuffersFromTrace(self, mmioValueReadMap):
        values = set()
        index = 0
        while index < self._traceMaxIndex:
              if index in mmioValueReadMap.keys():
                 values.add(mmioValueReadMap[index])
              index += 1
        print(f"Number of MMIO values read: {len(values)}")
        print(f"Number of MMIO values read (from map): {len(mmioValueReadMap)}")
        index = 0
        while index < self._traceMaxIndex:
              if index in self._tracecallchain.keys():
                 tuple = self._tracecallchain[index]
                 if tuple[0] == 'write':
                    if tuple[2] > 9 and tuple[2] in values:
                       mindex = index
                       while mindex >= 0:
                             if mindex in mmioValueReadMap.keys():
                                if mmioValueReadMap[mindex] == tuple[2]:
                                   if not tuple[1] in self._rxbufsFromTrace:
                                      self._rxbufsFromTrace[tuple[1]] = 1
                                      if tuple[1] not in self._rxbufAccessesFromTrace.keys():
                                         self._rxbufAccessesFromTrace[tuple[1]] = set()
                                      self._rxbufAccessesFromTrace[tuple[1]].add(tuple[3])
                                   else:
                                      self._rxbufsFromTrace[tuple[1]] = self._rxbufsFromTrace[tuple[1]] + 1
                                      if tuple[1] not in self._rxbufAccessesFromTrace.keys():
                                         self._rxbufAccessesFromTrace[tuple[1]] = set()
                                      self._rxbufAccessesFromTrace[tuple[1]].add(tuple[3])
                                   break   
                             mindex -= 1
              index += 1
        sorted_dict = {key: value for key, value in sorted(self._rxbufsFromTrace.items(), key=lambda item: item[1])}
        self._rxbufsFromTrace = sorted_dict
        print(f"Candidate rx bufs num = {len(self._rxbufsFromTrace)}")
        for rb in self._rxbufsFromTrace.keys():
            print(f"rxbuf {hex(rb)} count {self._rxbufsFromTrace[rb]}")
            for pc in self._rxbufAccessesFromTrace[rb]:
                print(f"\t{hex(pc)}") 
 
    def TESTtrackMMIOTaints(self, fname=None):
        fd = None
        if not fname == None:
           if 'output' in self._config.keys():
              fname = self._config['output'] + "/" + fname
           fd = open(fname, "w")
        print(f"Trace max index: {self._traceMaxIndex}")
        #self._iranalyzer._comprehensiveDefUse = True
        taintList = self._iranalyzer.IRFindDataFlowsUsingTraceInfo(self._tracecallchain, self._traceMaxIndex, fd)
        fd.flush()
        # callchain depth of the taint location
        calldepth = 3
        # no limit 
        lastTaints = 0
        entryPoints = self._iranalyzer.IRfindTaintEntryPoints(self._tracecallchain, taintList, calldepth, lastTaints, self._trace_index, fd)
        #self._iranalyzer._comprehensiveDefUse = False
        if not fd == None:
           fd.close()

    def processCallChain(self):
        states = set()
        edges = set()
        stateDesc = {}
        numstates = 1
        state = set()
        mmiodata = 0
        index = 0
        indent = 0
        inisr = []
        previndent = [0]
        nummmioreads = 0
        mmioValueReadMap = {}
        while index < self._traceMaxIndex:
              if index in self._tracecallchain.keys():
                 tuple = self._tracecallchain[index]
                 if tuple[0] == 'readMMIO' or tuple[0] == 'enter' or tuple[0] == 'basicblock':
                    if tuple[0] == 'readMMIO':
                         type, addr, data1, data2 = tuple
                    else:
                         type, data1, data2 = tuple
                    if type == 'readMMIO':
                       nummmioreads += 1
                       mmioValueReadMap[index] = data1
                       if numstates == 1:
                          mmiodata = data1
                          if len(edges) == 0:
                             stateDesc[0] = state
                          numstates += 1
                       else:
                          oldmmiodata = mmiodata
                          mmiodata = data1                         
                          if stateDesc[numstates-2] == state:
                             edges.add((numstates-2, oldmmiodata, numstates -2))
                          else:
                             stateDesc[numstates-1] = state
                             edges.add((numstates-2, oldmmiodata, numstates-1))
                             numstates += 1
                       newstate = set()
                       for s in state:
                           newstate.add(s)
                       state = newstate 
                    pc = data1
                    lr = data2
                    f = self._iranalyzer.IRgetFunctionAtAddress(pc)
                    isr = lr == 0 or lr == 0xfffffff9   
                    if (type == 'enter' or type == 'basicblock') and not pc == 0:
                       state.add(pc)
                    if type == 'enter' or (type == 'basicblock' and pc == 0):                    
                       if isr:
                          inisr.append(True)
                       ret = pc == 0 
                       isrdesc = ""
                       if isr:
                          isrdesc = " ISR "
                          previndent.append(indent)
                       entdesc = ""
                       if isr:
                          indent = 0
                       else: 
                          indent = previndent.pop()
                       oldindent = indent
                       if not pc == 0 and not isr:
                          entdesc = " ENTERING "
                          inisr.append(False)
                       if not pc == 0:
                          indent += 1
                       retdesc = ""
                       if ret:
                          indent -= 1
                       if ret and not lr == 0xfffffff9:
                          retdesc = " RETURNING TO "
                          inisr.pop()
                       elif ret and lr == 0xfffffff9:
                          retdesc = " RETURNING TO "
                          inisr.pop()
                       else:
                          retdesc = " CALLSITE "
                       fdesc = ""
                       if not f == None:
                          fdesc = f.name
                       if lr == 0 or lr == 0xfffffff9:                    
                          indentstr = ""
                       else:
                          indentstr = ""
                          i = 0
                          while i < oldindent:
                                indentstr += " "
                                i += 1
                       print(f"[{index}] : {indentstr}{entdesc}{isrdesc}{fdesc} {hex(pc)} {retdesc} {hex(lr)}")
                       previndent.append(indent) 
              index += 1  
        if numstates > 1:
           if stateDesc[numstates-2] == state:
              edges.add((numstates-2, mmiodata, numstates -2))
              numstates -= 1  
           else:
              stateDesc[numstates-1] = state
              edges.add((numstates-2, oldmmiodata, numstates-1))
        print(f"MMIO data {mmiodata} numstates {numstates} num mmio reads {nummmioreads}")
        self.printStateMachine(edges, stateDesc, numstates)
        #self.findMMIORxBuffersFromTrace(mmioValueReadMap)

    def getBBForInstruction(self, f, ia):
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
        #print(f"BB none for ia {hex(ia)} in function {f.name}")
        return (None, None)


    def parseTraceFileUptoLimit(self, limit, mmioAddress):
        if self._trace == "":
           return 0
        fname = None
        if 'trace_path' in self._config:
           fname = self._config['trace_path'] 
        else:  
           if not self._fw_path == None:
              if not self._trace == None:
                 if self._trace_dir == None: 
                    fname = self._fw_path + "/" + self._trace
                 else:
                    fname = self._fw_path + "/" + self._trace_dir + "/" + self._trace
        if fname == None:
           print(f"Could not find trace file!")
           return 0
        # Open the file in read mode
        with open(fname, 'r') as file:
        # Read each line in the file
             print(f"Searching for entry at {str}")
             index = 0
             mhex = hex(mmioAddress)
             mmiostr = "Read: addr= 0x00000000%s" % (mhex.split('x')[1])
             print(f"searching for mmiostr {mmiostr}")
             mmioStartIndex = 0
             for line in file:
                 if mmiostr in line:
                    mmioindex = index
                    if mmioStartIndex == 0:
                       mmioStartIndex = index   
                       break
                 index += 1
             start = 0
             end = index
             #print(f"Getting initial memory snapshot upto first MMIO access at {mmioStartIndex}")
             #self.parseTraceFile(self._dyncallgraph, True, True, None, None, None, None, None, 0, mmioStartIndex)
             print(f"Getting memory snapshot up to index {limit}")
             return self.parseTraceFile(self._dyncallgraph, True, False, limit, None, None, None, None, None, None, None, None)

    def parseTraceFileUptoFunctionCall(self, fStop, mmioAddress, mmioStop, last, maxInstAddress, registerUpdates):
        if self._trace == "":
           return 0
        fname = None
        if 'trace_path' in self._config:
           fname = self._config['trace_path']
        else:
           if not self._fw_path == None:
              if not self._trace == None:
                 if self._trace_dir == None: 
                    fname = self._fw_path + "/" + self._trace
                 else:
                    fname = self._fw_path + "/" + self._trace_dir + "/" + self._trace
        if fname == None:
           print(f"Could not find trace file!")
           return 0
        # Open the file in read mode
        with open(fname, 'r') as file:
        # Read each line in the file
             str = "PC=%s" % (hex(fStop))
             print(f"Searching for entry at {str}")
             index = 0
             mhex = hex(mmioAddress)
             mmiostr = "Read: addr= 0x00000000%s" % (mhex.split('x')[1])
             print(f"searching for mmiostr {mmiostr}")
             mmioStartIndex = 0
             for line in file:
                 if mmiostr in line:
                    mmioindex = index
                    if mmioStartIndex == 0:
                       mmioStartIndex = index   
                 if str in line:
                    break
                 index += 1
             start = 0
             end = index
             if not mmioStop:
                 if index > last:
                    start = index - last
             else:
                start = mmioindex + 1
             print(f"Getting initial memory snapshot upto first MMIO access at {mmioStartIndex}")
             self.parseTraceFile(self._dyncallgraph, True, True, None, None, None, None, None, 0, mmioStartIndex)
             print(f"Getting memory snapshot between {start} and {end}")
             return self.parseTraceFile(self._dyncallgraph, True, True, None, None, None, None, None, start, end, maxInstAddress, registerUpdates)

    def parseTraceFileUptoPC(self, pcStop, mmioAddress):
        if self._trace == "":
           return 0
        fname = None
        if 'trace_path' in self._config:
           fname = self._config['trace_path']
        else:
           if not self._fw_path == None:
              if not self._trace == None:
                 if self._trace_dir == None: 
                    fname = self._fw_path + "/" + self._trace
                 else:
                    fname = self._fw_path + "/" + self._trace_dir + "/" + self._trace
        if fname == None:
           print(f"Could not find trace file!")
           return  
        # Open the file in read mode
        with open(fname, 'r') as file:
        # Read each line in the file
             str = "(pc "
             print(f"Searching for entry at {str}")
             index = 0
             mhex = hex(mmioAddress)
             mmiostr = "Read: addr= 0x00000000%s" % (mhex.split('x')[1])
             print(f"searching for mmiostr {mmiostr}")
             mmioStartIndex = 0
             for line in file:
                 if mmiostr in line:
                    mmioindex = index
                    if mmioStartIndex == 0:
                       mmioStartIndex = index
                       break
                 index += 1
             print(f"Getting initial memory snapshot upto first MMIO access at {mmioStartIndex}")
             self.parseTraceFile(self._dyncallgraph, True, True, None, None, None, None, None, 0, mmioStartIndex)
             print(f"Getting memory snapshot up to {hex(pcStop)}")
             return self.parseTraceFile(self._dyncallgraph, True, True, None, None, None, None, pcStop, None, None, None, None)

    def parseTraceFileExtractLoadAddressAtPC(self, pcLoad):
        if self._trace == "":
           return 0
        fname = None
        if 'trace_path' in self._config:
           fname = self._config['trace_path']
        else:
           if not self._fw_path == None:
              if not self._trace == None:
                 if self._trace_dir == None: 
                    fname = self._fw_path + "/" + self._trace
                 else:
                    fname = self._fw_path + "/" + self._trace_dir + "/" + self._trace
        if fname == None:
           print(f"Could not find trace file!")
           return 0
        # Open the file in read mode
        with open(fname, 'r') as file:
        # Read each line in the file
             str = "(pc "
             print(f"Searching for entry at {str}")
             for line in file:
                 if str in line and 'Read' in line:
                       tokens = line.split(' ')
                       ai = -1
                       si = -1
                       di = -1
                       pi = -1
                       i = 0
                       while i < len(tokens):
                           if 'addr' in tokens[i]:
                              ai = i + 1
                           if 'data' in tokens[i]:
                              di = i
                           if 'size' in tokens[i]:
                              si = i
                           if 'pc' in tokens[i]:
                              pi = i+1
                           i += 1
                       if ai > 0 and di > 0 and si > 0 and pi > 0:
                          at = tokens[ai].split('[')
                          addr = int(at[0],16)
                          pt = tokens[pi].split(')')
                          pc = int(pt[0], 16)
                          if pc == pcLoad:
                             return addr
        return None

    def parseTraceFilesForCallGraph(self, dyncg):
        if self._trace_dir == None:
           return
        oldtracefname = self._trace
        dirname = self._fw_path + "/" + self._trace_dir
        print(f"Reading trace files from directory {dirname} for call graph generation")
        flist = os.listdir(dirname)
        for fname in flist:
            if fname == "." or fname == ".." or not "trace" in fname:
               continue
            self._trace = fname
            print(f"Processing file {fname}")
            sp, lr, registerInitValues, mmioReadLocs, index = self.parseTraceFile(self._dyncallgraph, True, False, 75000)
        self._trace = oldtracefname
        
    def parseTraceFilesGenerateMap(self, returnValue, fd, limit_index, oneHopTaint):
        traceMap = {}
        if self._trace_dir == None:
           return traceMap
        oldtracefname = self._trace
        dirname = self._fw_path + "/" + self._trace_dir
        print(f"Reading trace files from directory {dirname} for trace map generation")
        flist = os.listdir(dirname)
        num = 0
        for fname in flist:
            if fname == "." or fname == ".." or not "trace" in fname:
               continue
            fd.write(f"Trace info from {fname}\n")
            self._traceMaxIndex = 0
            self._trace = fname
            self._tracecallchain = {}
            print(f"Processing file {fname}")
            sp, lr, registerInitValues, mmioReadLocs, stopIndex = self.parseTraceFileUptoLimit(limit_index, self._MMIO_datareg)
            print(f"Trace {fname} max index: {self._traceMaxIndex}")
            taintList, retBasedFlowMap, readtaintList = self._iranalyzer.IRFindDataFlowsUsingTraceInfo(self._tracecallchain, stopIndex, oneHopTaint, returnValue, fd)
            #taintList, retBasedFlowMap = self._iranalyzer.IRFindDataFlowsUsingTraceInfoForLastInstanceMMIOAccessAtPC(self._tracecallchain, stopIndex, oneHopTaint, 0x40a9ee, returnValue, fd)
            fd.flush()
            traceMap[fname] = (self._tracecallchain, taintList, retBasedFlowMap, readtaintList, stopIndex)
            num += 1
        if num == 0:
           print(f"WARNING: did not process any files under {dirname}. Make sure trance file names include the keyword trace!")
           sys.exit()
        self._trace = oldtracefname
        return traceMap

    # type: readMMIO/enter/basicblock
    # readMMIO: data, pc
    # enter: pc, lr
    # basicblock: addr, lr
    #def parseTraceFile(self, dyncg, dyncgwCallsite, full):
    def parseTraceFile(self, dyncg, full, updateMemory=False, limit=None, mmioStop=None, fStop=None, lrStop=None, pcStop=None, start=None, end=None, maxInstAddress=None, registerUpdates=None):
        # reset trace call chain
        del self._tracecallchain
        self._tracecallchain = {} 
        if self._trace == "":
           return 0
        fname = None
        if 'trace_path' in self._config:
           fname = self._config['trace_path']
        else:
           if not self._fw_path == None:
              if not self._trace == None:
                 if self._trace_dir == None: 
                    fname = self._fw_path + "/" + self._trace
                 else:
                    fname = self._fw_path + "/" + self._trace_dir + "/" + self._trace
        if fname == None:
           print(f"Could not find trace file!")
           return 0
        # Open the file in read mode
        lr = 0
        with open(fname, 'r') as file:
        # Read each line in the file
          stopPointReached = False
          spExtracted = False
          spFromDelta = 0
          lrAtEntry = 0
          lastpc = 0
          lastpcline = ""
          self._traceMaxMemIndex = 0
          self._traceMaxIndex = 0
          lindex = -1
          updatesCaptured = (maxInstAddress == None)
          registerInitValues = {}
          mmioReadLocs = set()
          for line in file:
            completed = updatesCaptured and stopPointReached and spExtracted
            if (not start == None or not end == None or not mmioStop == None or not fStop == None or not lrStop == None or not pcStop == None) and completed: 
               print(f"Breaking at {lindex}")
               break 
            lindex += 1
            if not start == None and not end == None:
               if lindex < start:
                  continue
               if lindex == end:
                  stopPointReached = True
            if not limit == None and lindex > limit:
               break
            self._traceMaxIndex = lindex
          # Print each line
            if 'lr=' in line:
               tokens = line.split('(')
               lrt = tokens[1].split('=')
               lrt2 = lrt[1].split(')')
               lrv = int(lrt2[0], 16)
               if not lrStop == None:
                  if lrv == lrStop:
                     stopPointReached = True 
               at = line.split(' ')
               addrs = at[-2]
               addr = int(addrs, 16)
               if lrv & ~1 == addr: 
                  self._tracecallchain[lindex] = ('basicblock', 0, lrv)
               else:
                  self._tracecallchain[lindex] = ('basicblock', addr, lrv)
               lastpc = addr       
            if 'LR=' in line:
               tokens = line.split('(')
               st = tokens[1].split(' ')
               pct = st[0].split('=')
               pct2 = pct[1].split(',')
               pcv = int(pct2[0], 16)
               lrt = st[1].split('=')
               lrt2 = lrt[1].split(')')
               lrv = int(lrt2[0], 16)
               self._tracecallchain[lindex] = ('enter', pcv, lrv) 
            if '(pc ' in line:
                self._traceMaxMemIndex = lindex 
                lastpcline = line
                if full:
                   if 'Write' in line or 'Read' in line:
                       tokens = line.split(' ')
                       ai = -1
                       si = -1
                       di = -1
                       pi = -1
                       i = 0
                       while i < len(tokens):
                           if 'addr' in tokens[i]:
                              ai = i + 1
                           if 'data' in tokens[i]:
                              di = i
                           if 'size' in tokens[i]:
                              si = i
                           if 'pc' in tokens[i]:
                              pi = i+1
                           i += 1
                       if ai > 0 and di > 0 and si > 0 and pi > 0:
                          at = tokens[ai].split('[')
                          addr = int(at[0],16)
                          if  stopPointReached and 'SP' in line:
                              spt = at[1].split(':')
                              if '+' in spt[1]:
                                 spdeltat = spt[1].split('+')
                                 spdeltat2 = spdeltat[1].split(']')
                                 spDelta = int(spdeltat2[0], 16)
                                 spFromDelta = addr - spDelta
                                 spExtracted = True
                                 print(f"SP is being extracted at index {lindex} delta {spDelta} addr {hex(addr)}")
                              if '-' in spt[1]:
                                 spdeltat = spt[1].split('-')
                                 spdeltat2 = spdeltat[1].split(']')
                                 spDelta = int(spdeltat2[0], 16)
                                 spFromDelta = addr + spDelta
                                 spExtracted = True                      
                          dt = tokens[di].split('=')
                          data = int(dt[1],16)
                          st = tokens[si].split('=')
                          size = int(st[1])
                          pt = tokens[pi].split(')')
                          pc = int(pt[0], 16)
                          if not maxInstAddress == None:
                             if stopPointReached and pc >= maxInstAddress:
                                updatesCaptured = True  
                          if not pcStop == None:
                             if pc == pcStop:
                                stopPointReached = True 
                          lastpc = pc
                          #print(f"Last pc updated to {hex(pc)}")
                          if 'SP' in line:
                              self._traceStackAddresses.add(addr)
                          if 'Write' in line:
                             self.processWriteInTrace(addr, data, size, pc, lindex)
                             self._tracecallchain[lindex] = ('write', addr, data, pc)
                             if updateMemory and (not stopPointReached or ((not maxInstAddress == None) and pc <= maxInstAddress)):
                                #print(f"lindex: {lindex} Write at pc={hex(pc)} addr={hex(addr)} size={size} data={hex(data)}")
                                try:
                                    self._project.loader.memory.store(addr, data.to_bytes(size,'little'))
                                except KeyError:
                                    oldaddr = addr
                                    addr = int.from_bytes(oldaddr.to_bytes(4,'little'),byteorder='big')
                                    #print(f"Adjusted address {hex(addr)}")
                                    try:  
                                        self._project.loader.memory.store(addr, data.to_bytes(size,'little'))
                                    except KeyError:
                                        ok = True
                                        #print(f"Skipping writing to address {hex(addr)}")
                          if 'Read' in line:
                             if not mmioStop == None:
                                if addr == mmioStop:
                                   stopPointReached = True
                             if stopPointReached and not registerUpdates == None and pc in registerUpdates.keys():
                                for reg in registerUpdates[pc]:
                                    registerInitValues[reg] = data
                                    print(f"Register {reg} value {data}") 
                             self.processReadInTrace(addr, data, size, pc, lindex)
                             if addr == self._MMIO_datareg:
                                self._tracecallchain[lindex] = ('readMMIO', addr, data, pc)
                                mmioReadLocs.add(pc)
                             else:
                                self._tracecallchain[lindex] = ('read', addr, data, pc)                                 
                             #print(f"Read at pc={hex(pc)} index={memindex} addr={hex(addr)} size={size} data={hex(data)}")
                          if updateMemory and stopPointReached and not maxInstAddress == None and pc == maxInstAddress:
                             updatesCaptured = True 
                          tokens = lastpcline.split('(') 
                          if not len(tokens) == 2:
                             continue
                          tokens2 = tokens[-1].split(')')
                          if len(tokens2) == 0:
                             continue
                          tokens3 = tokens2[0].split(' ')
                          if len(tokens3) < 2:
                             continue
                          #lastpc = int(tokens3[-1],16)        
            if 'Calling function:' in line and 'from' in line and not 'ffff' in line:
                #if 'spi' in line:
                #   print(f"{line}")
                tokens = line.split('(') 
                if not len(tokens) == 2:
                   continue
                tokens2 = tokens[-1].split(')')
                if len(tokens2) == 0:
                    continue  
                tokens3 = tokens2[0].split(',')
                if len(tokens3) < 2:
                   continue
                pct = tokens3[0].split('=')
                if not len(pct) == 2:
                   continue
                lrt = tokens3[1].split('=')
                if not len(lrt) == 2:
                   continue
                pc = int(pct[1],16)
                if not pcStop == None:
                   if pc == pcStop:
                      stopPointReached = True 
                lr = int(lrt[1],16)
                caller = 0
                othercaller = 0
                callerf = None
                othercallerf = None
                callee = 0
                calleef = None
                callsite = lr # approximate but fine for finding the bb
                if lastpc == 0:
                   caller = self.getFunctionAddressFromInstruction(lr)
                else:
                   caller = self.getFunctionAddressFromInstruction(lr)
                   #print(f"lastpc {hex(lastpc)}")
                   othercaller = self.getFunctionAddressFromInstruction(lastpc)
                #if 'Calling function: input from process_thread_cc2538_rf_process' in line:
                #   print(f"caller of input {hex(caller)}")
                #if 'spi' in line:
                #   print(f"{hex(caller)} {hex(othercaller)}")
                if caller == 0 and othercaller == 0:
                   continue
                callee = self.getFunctionAddressFromInstruction(pc)
                #if 'spi' in line:
                #   print(f"Callee {hex(callee)} pc {hex(pc)} lr {hex(lr)} lastpc {hex(lastpc)}")
                if not callee == 0:
                   continue
                calleef = self.getFunction(callee)
                if not fStop == None:
                   if caller == fStop:
                      stopPointReached = True
                      if ((not end == None and lindex == end) or end == None) and lrAtEntry == 0:
                         lrAtEntry = lr 
                if calleef == None:
                   continue
                if not caller == None:
                   callerf = self.getFunction(caller)
                if not othercaller == None:
                   othercallerf = self.getFunction(othercaller)
                if 'sub_' in calleef.name:
                   temp = calleef.name.split('_')
                   ca = int(temp[1], 16)
                   cf = self.getClosestFunctionForInstruction(ca)
                   if cf == None:
                      continue 
                   calleef = cf
                   callee = cf.addr     
                if not callee in dyncg.keys():
                   dyncg[callee] = set()
                   #dyncgwCallsite[callee] = set()
                if not caller == None and not callerf == None and not callsite == 0:
                   bb, bbi = self.getBBForInstruction(callerf, callsite)
                   if not bb == None:
                      dyncg[callee].add((caller, bb.addr))
                      #if 'Calling function: input from process_thread_cc2538_rf_process' in line:
                      #    print(f"Adding callee {hex(callee)} caller {hex(caller)} to dyncg")
                   #dyncgwCallsite[callee].add((caller, lr))
                   #if 'spi' in callerf.name or 'spi' in calleef.name:
                   #    print(f"[DYNCG] {callerf.name} {hex(caller)} calls {calleef.name} {hex(callee)}")
                if not othercaller == None and not othercallerf == None and not callsite == 0:
                   bb, bbi = self.getBBForInstruction(othercallerf, callsite)
                   if not bb == None:
                      dyncg[callee].add((othercaller, bb.addr))
                   #dyncgwCallsite[callee].add((othercaller, lastpc))
                   #if 'spi' in othercallerf.name or 'spi' in calleef.name:
                   #    print(f"[DYNCG] {othercallerf.name} {hex(othercaller)} calls {calleef.name} {hex(callee)}")
                lastpc = pc
        if not maxInstAddress == None:
           print(f"maxInstAddress {hex(maxInstAddress)}") 
        print(f"Stopped at index {lindex}") 
        return spFromDelta, lr, registerInitValues, mmioReadLocs, lindex
 
    def printBBs(self, f):
        print(f"BBs of function at {hex(f.addr)} {f.name}")
        for ba in f.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            bb.vex.pp()


    def printFirstBB(self, f):
        print(f"BBs of function at {hex(f.addr)} {f.name}")
        for ba in f.block_addrs:
            try:
               bb = self._project.factory.block(ba)
            except angr.errors.SimEngineError:
               continue
            bb.vex.pp()
            return

    #def TraceForwardRecordDefUse(self):
    def writePaths(self, fname, genpaths):
        fname = self._outputdir + "/" + fname
        fd = open(fname, "w")
        for pkey in genpaths.keys():
            path = genpaths[pkey]
            fd.write(f"== Path ==\n")
            i = len(path) - 1
            while i >= 0:
                  fa = path[i][0]
                  f = self._iranalyzer.IRgetFunctionAtAddress(fa)
                  min, max = self.getBBAddressRange(path[i][1])    
                  fd.write(f"Function={f.name},address={hex(fa)},bb_addr={hex(path[i][1].addr)}[{hex(min)},{hex(max)}],cfgnode_addr={hex(path[i][2].addr)}\n")
                  i -= 1
            fd.write(f"== End of path ==\n")
        fd.close()
   
    def writeCopyFunctionCallsites(self, fname, css):
        fname = self._outputdir + "/" + fname
        fd = open(fname, "w")
        for cs in css:
            caller, ia, callee = cs
            fd.write(f"caller_name={caller.name},caller_addr={hex(caller.addr)},callsite_addr={hex(ia)},callee_name={callee.name},callee_addr={hex(callee.addr)}\n")
        fd.close() 
         
    def writeLoadAddresses(self, fname, loadAddresses):
        fname = self._outputdir + "/" + fname
        fd = open(fname, "w")
        for l in loadAddresses:
            fd.write(f"{hex(l[0])},{l[1]}\n")
        fd.close()

    def getBBAddressRange(self, bb):
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
        return min, max

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

    # entryAddr should be the original function entry address
    def TESTreproduceDynFromEntry(self, entryAddr):
        entryAddr = 0x407918
        maxInstAddress, registerUpdates = self._iranalyzer.IRcaptureFromFunctionInit(entryAddr + 1)
        print(f"Max inst address {hex(maxInstAddress)}, Register updates from first bb:")
        for pc in registerUpdates.keys():
            for reg in registerUpdates[pc]:
                print(f"pc {hex(pc)} reg {reg}") 
        sp, lr, registerInitValues, mmioReadLocs, stopIndex = self.parseTraceFileUptoFunctionCall(entryAddr, self._MMIO_datareg, True, None, maxInstAddress, registerUpdates)
        #sp = self.parseTraceFile(self._dyncallgraph, True, True, None, self._MMIO_datareg, None, None, None)
        entryF = self._iranalyzer.IRgetFunctionAtAddress(entryAddr + 1)
        # find spoffset of function, assuming function entry
        offset = self._iranalyzer.IRcomputeStackOffsetAtEntry(entryF)
        spAtEntry = sp - offset
        print(f"Offset for stack in function {entryF.name} sp after entry {hex(sp)} {offset} sp at entry {hex(spAtEntry)} lr {hex(lr)}")
        self.printFirstBB(entryF)
        for reg in registerInitValues.keys():
            print(f"Register {reg} initial value {hex(registerInitValues[reg])}")
        entry_state = self._project.factory.blank_state(
                            remove_options={
                                             angr.options.LAZY_SOLVES
                                           }
        )
        entry_state.ip = maxInstAddress
        entry_state.regs.sp = spAtEntry
        entry_state.regs.lr = lr
        simgr = self._project.factory.simgr(entry_state,save_unconstrained=True)
        simgr.run()
        maxsteps = 10
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

        

    def ANATraceGuidedStaticAnalysisForTraceSet(self, returnValue, limit_index, entry_point_limit, oneHopTaint=True):
        if 'results_path' in self._config:
           fname = self._config['results_path']
        else:
           if oneHopTaint:
              if self._result_file_desc == "":
                 suffix = "alltraces_direct_taint.txt"
              else:
                 suffix = "alltraces_direct_taint_" + self._result_file_desc + ".txt"
              fname = self._fw_path + "/" + suffix
              self._default_config['results_file'] = suffix
           else:
              if self._result_file_desc == "":
                 suffix = "alltraces_indirect_taint.txt"
              else: 
                 suffix = "alltraces_indirect_taint_" + self._result_file_desc + ".txt"
              fname = self._fw_path + "/" + suffix
              self._default_config['results_file'] = suffix
        fd = open(fname, "w")
        traceMap = self.parseTraceFilesGenerateMap(returnValue, fd, limit_index, oneHopTaint)
        self._iranalyzer.DynfindCallingContextsForTaintPropagatingCopyFunctionsAcrossTraces(traceMap, self._callchain_depth_bound, fd)
        #self._iranalyzer.DynfindTaintCallChainsAcrossAllTraces(traceMap, self._callchain_depth_bound, self._MMIO_datareg, fd, entry_point_limit)
        fd.close()

    def ANATraceGuidedStaticAnalysis(self, returnValue, limit_index, entry_point_limit, oneHopTaint, taint_pc=None):
        sp, lr, registerInitValues, mmioReadLocs, stopIndex = self.parseTraceFileUptoLimit(limit_index, self._MMIO_datareg)
        fd = None
        if 'results_path' in self._config:
           fname = self._config['results_path']
        else:
           if oneHopTaint:
              if self._result_file_desc == "":
                 suffix = "singletrace_direct_taint.txt"
              else: 
                suffix = "singletrace_direct_taint_" + self._result_file_desc + ".txt"
              fname = self._fw_path + "/" + suffix
              self._default_config['results_file'] = suffix
           else:
              if self._result_file_desc == "":
                 suffix = "singletrace_indirect_taint.txt"
              else: 
                 suffix = "singletrace_indirect_taint_" + self._result_file_desc + ".txt"
              fname = self._fw_path + "/" + suffix
              self._default_config['results_file'] = suffix
        fd = open(fname, "w")
        print(f"Trace max index: {self._traceMaxIndex}")
        #self._iranalyzer._comprehensiveDefUse = True
        if taint_pc == None:
           taintList, retBasedFlowMap, readtaintList = self._iranalyzer.IRFindDataFlowsUsingTraceInfo(self._tracecallchain, limit_index, oneHopTaint, returnValue, fd)
        else:
           taintList, retBasedFlowMap, readtaintList = self._iranalyzer.IRFindDataFlowsUsingTraceInfoForLastInstanceMMIOAccessAtPC(self._tracecallchain, limit_index, oneHopTaint, taint_pc, returnValue, fd)
        fd.flush()
        # no limit
        self._iranalyzer.DynfindCallingContextsForTaintPropagatingCopyFunctions(self._tracecallchain, taintList, readtaintList, limit_index, self._callchain_depth_bound, fd)   
        lastTaints = 0
        #entryPoints = self._iranalyzer.IRfindTaintEntryPoints(self._tracecallchain, taintList, retBasedFlowMap, self._callchain_depth_bound, lastTaints, None, fd, entry_point_limit)
        #self._iranalyzer._comprehensiveDefUse = False
        if not fd == None:
           fd.close()

    def ANAreproduceDynFromPC(self, pc, maxbufsize, rxbuf=None, rxbufLoadPC=None):
        # CVE-2020-10064
        # pc = 0x401ca6
        # Use the load address after the top receive function returns (lr) 
        f = self._iranalyzer.IRgetFunctionOfInstruction(pc)
        maxInstAddress, registerUpdates = self._iranalyzer.IRcaptureFromFunctionInit(f.addr)
        print(f"Max inst address {hex(maxInstAddress)}, Register updates from first bb:")
        for tpc in registerUpdates.keys():
            for reg in registerUpdates[tpc]:
                print(f"pc {hex(tpc)} reg {reg}") 
        sp, lr, registerInitValues, mmioReadLocs, stopIndex = self.parseTraceFileUptoPC(pc, self._MMIO_datareg)
        self.TESTtrackMMIOTaints('dynamicTaintPropagation')
        return
        if rxbuf == None and not rxbufLoadPC == None:
           rxbuf = self.parseTraceFileExtractLoadAddressAtPC(rxbufLoadPC)
           print(f"Extracted rxbuf address {hex(rxbuf)}")
        #sp = self.parseTraceFile(self._dyncallgraph, True, True, None, self._MMIO_datareg, None, None, None)
        # find spoffset of function, assuming function entry
        # check symbolic with if state.solver.symbolic(
        size = 1
        while size <= maxbufsize:
              print(f"Symbolizing rx buf {hex(rxbuf)} {maxbufsize} bytes")
              entry_state = self._project.factory.blank_state(
                            remove_options={
                                             angr.options.LAZY_SOLVES
                                           }
              )
              entry_state.ip = maxInstAddress
              entry_state.regs.lr = lr
              sym = claripy.BVS("rxbuf",maxbufsize*8)
              entry_state.memory.store(rxbuf,sym,endness=self._project.arch.memory_endness)
              simgr = self._project.factory.simgr(entry_state,save_unconstrained=True)
              #simgr.run()
              maxsteps = 10
              stepno = 0
              while stepno < maxsteps and len(simgr.unconstrained)==0:
                    simgr.step()
                    if len(simgr.active) == 0:
                       print(f"No active states left after {stepno} steps!")
                       break
                    stepno += 1
                    print(f"At step {stepno} number of active states: {len(simgr.active)}")
              if len(simgr.unconstrained) > 0:
                 unconstrained_state = simgr.unconstrained[0]
                 fa = unconstrained_state.callstack.current_function_address
                 sp = unconstrained_state.callstack.current_stack_pointer
                 print(f"Memory error tainted function {hex(fa)} stack pointer {hex(sp)} and pc {unconstrained_state.regs.pc} ")
              else:
                 print(f"Analysis ended without an error after {stepno} steps")
              size += 1

    def SymexCVE202010064(self):
        self.ANAreproduceDynFromPC(0x401cf8, 4, None, 0x00401c8e)

    def TESTfindCopyFunctions(self):
        #offsets = [1, 4, 8, 16]
        offsets = [1]
        cf = set()
        for o in offsets:
            cfa = self._iranalyzer.IRfindCopyFunctions('r2', 'add', o)
            cfb = self._iranalyzer.IRfindCopyFunctions('r2', 'sub', o)
            for f in cfa:
                cf.add(f)
            for f in cfb:
                cf.add(f)
        for f in cf:
            print(f"Callsites for {f.name}:")
            css = self._iranalyzer.IRfindCallsitesWithNonConstantArg(f, 'r2')
            fname = "%s_%s" % ('copycallsites',f.name)
            self.writeCopyFunctionCallsites(fname, css) 
            for cs in css:
                caller, ia, callee = cs
                # CVE-2020-12140
                # if not ia == 0x205b24:
                #   continue
                # CVE-CVE-2021-10064
                #if not ia == 0x205b24:
                #   continue
                if not caller.name == 'net_6lo_uncompress':
                   continue
                bb, si = self._iranalyzer.IRgetBBForInstruction(caller, ia)
                paths = {} 
                loadAddresses = set() 
                genpaths = self._iranalyzer.IRenumeratePaths(paths, loadAddresses, caller, bb, si)
                #print(f"Path completed: {len(genpaths)}")
                #for pkey in genpaths.keys():
                #    path = genpaths[pkey]
                #    print(f"== Path ==") 
                #    self._iranalyzer.IRprintPath(path)
                #    print(f"== End of path ==")
                for l in loadAddresses:
                    print(f"Load address {hex(l[0])},{l[1]}")
                pname = "%s_%s_%s" % ('paths', caller.name, hex(ia))
                self.writePaths(pname, genpaths)
                laname = "%s_%s_%s" % ('loadAddresses', caller.name, hex(ia))
                self.writeLoadAddresses(laname, loadAddresses)

    def TESTIRisACopyFunction(self):
        #fa = 0x0020aa58
        #f, witness = self._iranalyzer.IRisACopyFunction(fa, 'r2', 'add', 4)
        fa = 0x0020ab44
        #f, witness = self._iranalyzer.IRisACopyFunction(fa, 'r2', 'sub', 4)
        f, witness = self._iranalyzer.IRisACopyFunction(fa, 'r2', 'sub', 16)
        if f:
           for wr in witness.keys():
               print(f"Copy semantics:")
               for w in witness[wr]:
                   f, bb, i, nc = w
                   st = bb.vex.statements[i]
                   print(f"\tFunction f {f.name} {hex(bb.addr)} statement {st} node {nc}")
                   paths = {} 
                   self._iranalyzer.IRenumeratePaths(paths, f, bb, i)
                   #print(f"Path completed: {len(paths)}")
                   #for pkey in paths.keys():
                   #    i = len(paths[pkey])
                   #    while i >= 0:
                   #          path = paths[pkey] 
                   #          f = self._iranalyzer.IRgetFunctionAtAddress(path[0])
                   #          print(f"Function {f.name} {hex(path[0])} {hex(path[1])} index {path[2]}")
                   #          i -= 1
                       

    def findMaxFunctionAddress(self):
        max = 0
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
                         if st.addr > max:
                            max = st.addr
                      index += 1
        return max

    def analyze(self):
        self._project = angr.Project(self._binary, auto_load_libs=False)
        self._current_cfg = self._project.analyses.CFG(collect_data_references=True,
                                                       extra_cross_references=True)
        #self._minRAM = 0x20000000
        #self._minRAM = self.findMaxFunctionAddress()
        #print(f"MinRAM based on max function address {hex(self._minRAM)}")
        for key in self._project.loader.main_object.sections_map.keys():
            print(f"Section {key} min addr {hex(self._project.loader.main_object.sections_map[key].min_addr)}") 
            print(f"\tmax addr {hex(self._project.loader.main_object.sections_map[key].max_addr)}") 
        self._minRAM = 0
        if "text" in self._project.loader.main_object.sections_map.keys():
            self._minRAM = self._project.loader.main_object.sections_map["text"].max_addr
        if ".text" in self._project.loader.main_object.sections_map.keys():
            self._minRAM = self._project.loader.main_object.sections_map[".text"].max_addr
        if self._minRAM == 0:
           self._minRAM = 0x20000000
        self._default_config['minRAM'] = self._minRAM
        print(f"MinRAM based on max addr {hex(self._minRAM)}")
        if 'start_address' in self._config.keys():
           self._start_addr = int(self._config['start_address'],16)
        else:
           self._start_addr = 0
        if self._start_addr == 0:
           self._start_addr =  self._project.entry
        self._default_config['start_addr'] = self._start_addr
        print(f"Start address: {hex(self._start_addr)}")
        self._MMIO_base = int(self._config['MMIO_base_addr'],16)
        print(f"MMIO base address={hex(self._MMIO_base)}")
        self._datareg_offset = int(self._config['data_reg_offset'],16)
        if 'status_reg_offset' in self._config.keys():
            self._statusreg_offset = int(self._config['status_reg_offset'],16)
        else:
            self._statusreg_offset = None 
            self._default_config['status_reg_offset'] = self._statusreg_offset 
        print(f"MMIO data register offset={hex(self._datareg_offset)}")
        self._MMIO_datareg = self._MMIO_base + self._datareg_offset
        print(f"MMIO data register address={hex(self._MMIO_datareg)}")
        if not self._statusreg_offset == None:   
           print(f"MMIO status register offset={hex(self._statusreg_offset)}")
        if 'trace' in self._config.keys():
           self._trace = self._config['trace']
        else:
           self._trace = None
           self._default_config['trace'] = self._trace
        if 'trace_path' in self._config.keys():
           self._trace_path = self._config['trace_path']
        else:
           self._trace_path = None
           self._default_config['trace_path'] = self._trace_path
        if 'trace_dir' in self._config.keys():
           self._trace_dir = self._config['trace_dir']
        else:
            self._trace_dir = None
            self._default_config['trace_dir'] = self._trace_dir
        if 'trace_index' in self._config.keys():
            self._trace_index = self._config['trace_index']
        else:
            self._trace_index = None
            self._default_config['trace_index'] = self._trace_index
        if 'taint_index' in self._config.keys():
            self._taint_index = self._config['taint_index']
        else:
            self._taint_index = None
            self._default_config['taint_index'] = self._taint_index
        if 'taint_pc' in self._config.keys():
            self._taint_pc = self._config['taint_pc']
        else:
            self._taint_pc = None
            self._default_config['taint_pc'] = self._taint_pc
        if 'callchain_depth_bound' in self._config.keys():
           self._callchain_depth_bound = self._config['callchain_depth_bound']
        else:
           self._callchain_depth_bound = 3
           self._default_config['callchain_depth_bound'] = self._callchain_depth_bound
        if 'entry_point_limit' in self._config.keys():
           self._entry_point_limit = self._config['entry_point_limit']
        else:
           self._entry_point_limit = None
           self._default_config['entry_point_limit'] = self._entry_point_limit
        if 'return_value_tracking' in self._config.keys():
           if self._config['return_value_tracking'] == "True":    
              self._return_value_tracking = True
           else:
              self._return_value_tracking = False
        else:
           self._return_value_tracking = False
           self._default_config['return_value_tracking'] = False 
        if 'multi_hop_taint' in self._config.keys():
           if self._config['multi_hop_taint'] == "True":
              self._one_hop_taint = False
           elif self._config['multi_hop_taint'] == "False":
              self._one_hop_taint = True
           else:
              print(f"Correct format for multi_hop_taint is True or False!")
              sys.exit()  
        else:
           self._one_hop_taint = False
           self._default_config['multi_hop_taint'] = not self._one_hop_taint
        self._analysis_type = self._config['analysis_type'] 
        if 'result_file_desc' in self._config.keys():
           self._result_file_desc = self._config['result_file_desc']
        else:
           self._result_file_desc = ""
           self._default_config['result_file_desc'] = self._result_file_desc 
        self._traceUse = {}
        self._traceDef = {}
        self._traceDefofUse = {}
        self._tracePointsTo = {}
        self._traceLoads = set()
        self._traceStackAddresses = set()
        self._traceFunctionDefMap = {}
        self._tracecallchain = {}
        self._dyncallgraph = {}
        self._rxbufsFromTrace = {}
        self._rxbufAccessesFromTrace = {}
        #self.parseTraceFile(self._dyncallgraph, True)
        #self.processPointsToInTrace()
        #self.processDefPointsInTrace()
        #self.processCallChain()
        #self.TESTIRisACopyFunction()
        #print(f"Max trace memory access index={self._traceMaxMemIndex}")
        #self.TESTreproduceDyn() 
        #self.TESTfindCopyFunctions()
        print(f"Created an angr project for {self._binary} arch {self._project.arch.name}")
        self._pointer_assignments = set()
        self._mmio_callback_assignments = set()
        self._target_base = hex(int(self._config['MMIO_base_addr'],16))
        self._target_addr = hex(int(self._config['MMIO_base_addr'],16) + int(self._config['data_reg_offset'],16))
        self._handler_data_size = self._config['handler_data_size']
        self._target_base_set = set()
        # base, depth, inst addr, block addr, func addr
        self._target_base_set.add((self._target_base,0,0,0,0))
        self._target_datareg_set = set()
        # base, depth, inst addr, block addr, func addr
        self._target_datareg_set.add((self._target_addr,0,0,0,0)) 
        # A dictionary of key: MMIO address to set of function addresses that read from them
        self._datareg_read = {}
        # A dictionary of key: MMIO address to set of function addresses that write to them
        self._datareg_write = {}
        self._otherreg_read = {}
        self._otherreg_write = {}
        self._MMIO_base_pointers = set()
        self._MMIO_base_accesses = set()
        self._MMIO_datareg_pointers = set()
        self._MMIO_datareg_accesses = set()
        self._MMIO_blocksWithConstants = set()
        self._functionEntry = set()
        self._callback_assignments = set()
        self._buffer_assignments = set() 
        self._receiveISRs = set()
        self._transmitISRs = set()
        self._receiveBuffers = set()
        self._transmitBuffers = set()
        self._receiveTaints = set()
        self._transmitTaints = set()
        self._receiveBufferAliases = set()
        self._transmitBufferAliases = set()
        self._directreceiveTaints = set()
        self._directtransmitTaints = set()
        self._receiveTaintPropagated = set()
        self._transmitTaintPropagated = set()
        self._halF = set()
        self._halCtx = set()
        self._halCB = set()
        self._halCandidates = set()
        self._bufferInfo = set()
        self._localbufferInfo = set()
        self._snapshotInfo = set()
        self._returnValueInfo = set()
        self._lastProcessingTime = time.time()
        self._statistics = {}
        self._numsteps = -1
        self._iranalyzer = HybridAnalyzer(self._project, self._current_cfg, self._minRAM, self._config, self._default_config, self._result_file_desc)
        self._iranalyzer.IRinitstats(self._fw_path, self._outputdir)
        if "trace_guided_analysis" in self._analysis_type or "HAL_API_Extraction_Complex_TraceGuided" in self._analysis_type:
           if not self._trace == None or not self._trace_path == None:
              sp, lr, registerInitValues, mmioReadLocs, index = self.parseTraceFile(self._dyncallgraph, True, False, 75000)
              self._iranalyzer.InitSetDynamicCallGraph(self._dyncallgraph)
              delta = self._iranalyzer.IRupdatestats("parse_trace_file_for_call_graph_generation")
              print(f"Trace processing time={delta}")
           elif not self._trace_dir == None:
              self.parseTraceFilesForCallGraph(self._dyncallgraph)           
              self._iranalyzer.InitSetDynamicCallGraph(self._dyncallgraph)
              delta = self._iranalyzer.IRupdatestats("parse_trace_file_for_call_graph_generation")
              print(f"Trace processing time={delta}")
        #if "find_copy_functions" in self._analysis_type or ("trace_guided_analysis" in self._analysis_type and not "read_copy_functions" in self._analysis_type):
        if "find_copy_functions" in self._analysis_type:
            self._iranalyzer.IRfindCopyFunctions(['r1','r2'], 'add', 1)
            delta = self._iranalyzer.IRupdatestats("find_copy_functions")
            print(f"Finding copy functions time={delta}")
        if "read_copy_functions" in self._analysis_type:
           self._iranalyzer.IRreadCopyFunctions()
           delta = self._iranalyzer.IRupdatestats("read_copy_functions")
           print(f"Reading copy functions time={delta}")           
        if "trace_guided_analysis" in self._analysis_type:
           if not self._trace == None or not self._trace_path == None:
              if not self._trace_index == None:  
                 self.ANATraceGuidedStaticAnalysis(self._return_value_tracking, self._trace_index, self._entry_point_limit, self._one_hop_taint, self._taint_pc)
                 delta = self._iranalyzer.IRupdatestats("trace_guided_analysis")
                 print(f"Trace guided analysis time={delta}") 
              else:
                 print(f"trace_index is not specified, required for trace_guided_analysis!")
           elif not self._trace_dir == None:
                 self.ANATraceGuidedStaticAnalysisForTraceSet(self._return_value_tracking, self._trace_index, self._entry_point_limit, self._one_hop_taint) 
                 delta = self._iranalyzer.IRupdatestats("trace_guided_analysis")
                 print(f"Trace guided analysis time={delta}") 
        if "HAL_API_Extraction_Simple" in self._analysis_type: 
           self._iranalyzer.HALfindSimpleMMIOAccesses(self._MMIO_base + self._datareg_offset, self._bufferInfo, self._localbufferInfo, self._snapshotInfo)
           self.writeBufferInfo('bufferInfo')
           self.writeSnapshotInfo('snapshotInfo')
           self.writeLocalBufferInfo('localbufferInfo')
           delta = self._iranalyzer.IRupdatestats("HAL_API_Extraction_Simple")
           print(f"HAL_API_Extraction_Simple analysis time={delta}")
        if "HAL_API_Extraction_Complex_StaticOnly" in self._analysis_type:
           if not self._statusreg_offset == None:
              # since pure static, not relying on dynamic information
              temp_mmioReadLocs = None
              self._iranalyzer.HALfilterFunctionsWithCommonSourceForPeripheralRegisters(self._datareg_offset, self._statusreg_offset, temp_mmioReadLocs, self._halCandidates)
              self._iranalyzer.HALfilterTransferBuffers(self._datareg_offset, self._halCandidates, self._bufferInfo, self._localbufferInfo, self._snapshotInfo, self._returnValueInfo)
              self.writeReturnValueInfo('returnValueInfo')
              self.writeSnapshotInfo('snapshotInfo')
              self.writeBufferInfo('bufferInfo')
              self.writeLocalBufferInfo('localbufferInfo')
              delta = self._iranalyzer.IRupdatestats("HAL_API_Extraction_Complex_StaticOnly")
              print(f"HAL_API_Extraction_Complex_StaticOnly time={delta}")
           else:
              print(f"Unable to perform HAL_API_Extraction_Complex_StaticOnly when status register offset is not specified!")
        if "HAL_API_Extraction_Complex_TraceGuided" in self._analysis_type:
           self._iranalyzer.HALfilterFunctionsBasedOnDynMMIOReads(mmioReadLocs, self._halCandidates)
           self._iranalyzer.HALfilterTransferBuffers(self._datareg_offset, self._halCandidates, self._bufferInfo, self._localbufferInfo, self._snapshotInfo, self._returnValueInfo)
           self.writeReturnValueInfo('returnValueInfo')
           self.writeSnapshotInfo('snapshotInfo')
           self.writeBufferInfo('bufferInfo')
           self.writeLocalBufferInfo('localbufferInfo')
           delta = self._iranalyzer.IRupdatestats("HAL_API_Extraction_Complex_TraceGuided")
           print(f"HAL_API_Extraction_Complex_TraceGuided time={delta}")
        self._iranalyzer.IRprintStats()
        return

    def serialize(self):
        self.writeBaseAliases('output_mmiobase_aliases.txt')
        self.writeDRAliases('output_mmiodr_aliases.txt')
        self.writeHandlerReceivingFunctions('output_handler_receiving.txt')
        self.writeHandlerReceivingFunctionContexts('output_handler_receiving_contexts.txt')
        self.writeReceiveBuffers('output_receive_buffers.txt')
        self.writeTransmitBuffers('output_transmit_buffers.txt')
        self.writeReceiveFunctions('output_receive_functions.txt')
        self.writeTransmitFunctions('output_transmit_functions.txt')
        self.writeMMIOReceiveTaints('output_receive_taints.txt')
        self.writeMMIOTransmitTaints('output_transmit_taints.txt')
        self.writeBaseAccesses('output_mmiobase_accesses.txt')
        self.writeDRAccesses('output_mmiodr_accesses.txt')
        self.writeReceiveAliases('output_receive_aliases.txt')
        self.writeTransmitAliases('output_transmit_aliases.txt')
 

    def run(self):
        print(f"Starting taint analysis\n")
        self.analyze()
        print(f"Finished taint analysis\n")

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print("Usage " + sys.argv[0] + " config_path")
        sys.exit(0)

    config = sys.argv[1]
    if len(sys.argv) == 3:
       if sys.argv[2] == "copy":
          base_dir = os.environ.get('HYFIVE_RESULTS', "")
          fwpath = base_dir + "/testreduced/46/"
          fw_path = fwpath 
          bin = fwpath + "binarydir/zephyr-CVE-2020-10064.elf"
          analysis_type = ["find_copy_functions"]
          copy_functions_path = fwpath + "copyfuncdir/copy_functions_generated.txt"
          statistics_path = fwpath + "/statsdir/statistics_for_copy_functions.txt"
          so = Tailor(config_path=None,
                   fw_path=fw_path,  
                   bin=bin, 
                   analysis_type=analysis_type,
                   copy_functions_path=copy_functions_path, 
                   statistics_path=statistics_path 
               )
          so.runSingle()
       elif sys.argv[2] == "trace_guided":
          base_dir = os.environ.get('HYFIVE_RESULTS', "")
          fwpath = base_dir + "/testreduced/46/"
          fw_path = fwpath 
          bin = fwpath + "binarydir/zephyr-CVE-2020-10064.elf"
          # MMIO_base_addr + data_reg_offset
          MMIO_datareg = 0x40088008
          result_file_desc = "poc_3_test_new_interface"
          results_path = fwpath + "/resultsdir/entry_points" + result_file_desc + ".txt"
          analysis_type = ["read_copy_functions","trace_guided_analysis"]
          callchain_depth_bound = 3
          taint_pc = 0x40a9ee 
          trace_index = 876821
          trace_path= fwpath + "/tracedir/trace.txt"
          statistics_path = fwpath + "/statsdir/statistics.txt"
          copy_functions_path = fwpath + "copyfuncdir/copy_functions"
          #output = "/testreduced/46/" 
          so = Tailor(config_path=None,
                   fw_path=fw_path,  
                   bin=bin, 
                   MMIO_datareg=MMIO_datareg,
                   taint_pc=taint_pc,  
                   copy_functions_path=copy_functions_path, 
                   #result_file_desc=result_file_desc, 
                   analysis_type=analysis_type,
                   callchain_depth_bound=callchain_depth_bound,
                   trace_index=trace_index,
                   results_path=results_path,
                   trace_path=trace_path, 
                   statistics_path=statistics_path 
                   #output=output    
                  ) 
          so.runSingle()
    else:
       so = Tailor(config_path=config)
       so.run()
