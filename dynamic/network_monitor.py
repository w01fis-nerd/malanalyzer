from scapy.all import sniff, wrpcap
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
import threading
import time

class NetworkMonitor:
    def __init__(self, output_pcap: Optional[Path] = None):
        self.output_pcap = output_pcap or Path('capture.pcap')
        self.packets = []
        self.monitoring = False
        self.capture_thread = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_capturing()

    def packet_callback(self, packet):
        """Callback function for packet capture."""
        self.packets.append({
            'timestamp': datetime.now().isoformat(),
            'summary': packet.summary(),
            'src': packet.src if hasattr(packet, 'src') else None,
            'dst': packet.dst if hasattr(packet, 'dst') else None,
            'proto': packet.proto if hasattr(packet, 'proto') else None
        })

    def start_capture(self):
        """Start capturing network traffic."""
        def capture():
            sniff(prn=self.packet_callback, store=False)

        self.monitoring = True
        self.capture_thread = threading.Thread(target=capture)
        self.capture_thread.start()

    def stop_capturing(self):
        """Stop capturing network traffic."""
        self.monitoring = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=1)

        if self.packets and self.output_pcap:
            wrpcap(str(self.output_pcap), self.packets)

    def get_results(self) -> Dict:
        """Get capture results."""
        return {
            'packet_count': len(self.packets),
            'packets': self.packets,
            'pcap_file': str(self.output_pcap) if self.output_pcap else None
        }