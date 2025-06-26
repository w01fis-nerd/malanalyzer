from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import time

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self):
        self.changes = []

    def on_created(self, event):
        self.changes.append({
            'event_type': 'created',
            'path': event.src_path,
            'is_directory': event.is_directory,
            'timestamp': datetime.now().isoformat()
        })

    def on_modified(self, event):
        self.changes.append({
            'event_type': 'modified',
            'path': event.src_path,
            'is_directory': event.is_directory,
            'timestamp': datetime.now().isoformat()
        })

    def on_deleted(self, event):
        self.changes.append({
            'event_type': 'deleted',
            'path': event.src_path,
            'is_directory': event.is_directory,
            'timestamp': datetime.now().isoformat()
        })

    def on_moved(self, event):
        self.changes.append({
            'event_type': 'moved',
            'src_path': event.src_path,
            'dest_path': event.dest_path,
            'is_directory': event.is_directory,
            'timestamp': datetime.now().isoformat()
        })

class FileMonitor:
    def __init__(self, paths: Optional[List[str]] = None):
        self.paths = paths or ['C:\\Windows', 'C:\\Program Files', 'C:\\Users']
        self.event_handler = FileChangeHandler()
        self.observer = Observer()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_monitoring()

    def start_monitoring(self):
        """Start monitoring file system changes."""
        for path in self.paths:
            try:
                self.observer.schedule(self.event_handler, path, recursive=True)
            except Exception as e:
                print(f"Error monitoring {path}: {str(e)}")
        self.observer.start()

    def stop_monitoring(self):
        """Stop monitoring file system changes."""
        self.observer.stop()
        self.observer.join()

    def get_results(self) -> Dict:
        """Get monitoring results."""
        return {
            'monitored_paths': self.paths,
            'changes': self.event_handler.changes
        }