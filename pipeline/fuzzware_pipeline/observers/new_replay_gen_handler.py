from queue import Queue
from time import time
from .. import naming_conventions as nc
from watchdog.events import FileSystemEventHandler
import subprocess
from fuzzware_pipeline.logging_handler import logging_handler

logger = logging_handler().get_logger("pipeline")

class NewReplayGenHandler(FileSystemEventHandler):
    queue: Queue

    def __init__(self, queue):
        super(NewReplayGenHandler, self).__init__()
        self.queue = queue
        self.copy_functions = {}
        self.uniqueCopyFuncContexts = set()

    def filter(self,replay_file):
        if len(self.copy_functions) == 0:
           # init copy functions
           pos = replay_file.find(nc.DEFAULT_PROJECT_NAME)
           if pos > 0: 
              copy_functions_path = replay_file[:pos] + nc.PIPELINE_FILENAME_COPY_FUNCTIONS 
           with open(copy_functions_path, 'r') as cstream:
             for line in cstream:
                 fn, fa, fs = line.split(',')
                 self.copy_functions[fa] = (fn, fs)
        result = False
        for fa, ft in self.copy_functions.items():
            fn, fs = ft
            str = fn + " from"
            p1 = subprocess.Popen(["grep", str, replay_file], stdout=subprocess.PIPE)
            output = subprocess.check_output(["cut", "-d:", "-f2"], stdin=p1.stdout, text=True)
            p1.wait()
            ol = output.splitlines()
            logger.info(f"[REPLAY OBSERVER] Checking copy function {fn} using {str} contexts in {replay_file} output number of lines {len(ol)}")
            for line in output.splitlines():
                logger.info(f"[REPLAY OBSERVER] Processing {line}")
                if not line in self.uniqueCopyFuncContexts:
                   result = True 
                   self.uniqueCopyFuncContexts.add(line) 
        return result 
        

    def on_created(self, event):
        # we are storing some other file like mmio pc pairs,
        # but we want to notify when we see the replay file
        # if nc.PREFIX_REPLAY_GEN in event.src_path and self.filter(event.src_path):
        if nc.PREFIX_REPLAY_GEN in event.src_path:
           self.queue.put((time(), event.src_path))
