from queue import Queue
from time import time

from watchdog.events import FileSystemEventHandler

from .. import naming_conventions as nc

class NewEntryPointHandler(FileSystemEventHandler):
    queue: Queue

    def __init__(self, queue):
        super(NewEntryPointHandler, self).__init__()
        self.queue = queue

    def on_created(self, event):
        if not nc.TEMPORARY_PREFIX in event.src_path:
           self.queue.put((time(), event.src_path))
