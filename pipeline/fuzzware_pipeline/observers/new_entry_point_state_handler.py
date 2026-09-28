from queue import Queue
from time import time
import os
from fuzzware_pipeline.naming_conventions import PREFIX_ENTRY_POINT_STATEFILE

from watchdog.events import FileSystemEventHandler


class NewEntryPointStateHandler(FileSystemEventHandler):
    queue: Queue

    def __init__(self, queue):
        super(NewEntryPointStateHandler, self).__init__()
        self.queue = queue

    def on_created(self, event):
        self.queue.put((time(), event.src_path))
