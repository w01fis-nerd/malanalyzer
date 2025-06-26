import psutil
import time
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

class ProcessMonitor:
    def __init__(self):
        self.processes: Dict[int, Dict] = {}
        self.monitoring: bool = False
        self.start_time: float = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_monitoring()

    def _capture_process_info(self, process: psutil.Process) -> Dict:
        """Capture detailed information about a process."""
        try:
            info = {
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'status': process.status(),
                'username': process.username(),
                'create_time': datetime.fromtimestamp(process.create_time()).isoformat(),
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent(),
                'open_files': [f.path for f in process.open_files()],
                'connections': [
                    {
                        'local_addr': f"{c.laddr.ip}:{c.laddr.port}",
                        'remote_addr': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                        'status': c.status
                    } for c in process.connections()
                ]
            }
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {}

    def start_monitoring(self):
        """Start monitoring processes."""
        self.monitoring = True
        self.start_time = time.time()
        
        # Capture initial process state
        for proc in psutil.process_iter(['pid']):
            try:
                self.processes[proc.pid] = self._capture_process_info(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def stop_monitoring(self):
        """Stop monitoring processes."""
        self.monitoring = False

    def get_results(self) -> Dict:
        """Get monitoring results."""
        return {
            'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
            'end_time': datetime.fromtimestamp(time.time()).isoformat(),
            'processes': self.processes
        }