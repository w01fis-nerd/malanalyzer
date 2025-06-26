import re
import ipaddress
from typing import Dict, List, Any, Set

class IOCExtractor:
    def __init__(self):
        # Regex patterns for IOC extraction
        self.ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        self.domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b'
        self.url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        self.email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        self.registry_pattern = r'HKEY_[A-Z_]+\\[A-Za-z0-9\\_ -]+'
        self.file_path_pattern = r'[C-Zc-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'
        
    def extract_ips(self, text: str) -> Set[str]:
        """Extract IP addresses from text."""
        ips = set(re.findall(self.ip_pattern, text))
        # Filter out local and private IPs
        return {ip for ip in ips if not self._is_local_ip(ip)}
    
    def extract_domains(self, text: str) -> Set[str]:
        """Extract domains from text."""
        return set(re.findall(self.domain_pattern, text))
    
    def extract_urls(self, text: str) -> Set[str]:
        """Extract URLs from text."""
        return set(re.findall(self.url_pattern, text))
    
    def extract_emails(self, text: str) -> Set[str]:
        """Extract email addresses from text."""
        return set(re.findall(self.email_pattern, text))
    
    def extract_registry_keys(self, text: str) -> Set[str]:
        """Extract Windows registry keys from text."""
        return set(re.findall(self.registry_pattern, text))
    
    def extract_file_paths(self, text: str) -> Set[str]:
        """Extract file paths from text."""
        return set(re.findall(self.file_path_pattern, text))
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if an IP address is local/private."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_link_local or 
                ip_obj.is_multicast
            )
        except ValueError:
            return False
    
    def extract_from_strings(self, strings: Dict[str, List[str]]) -> Dict[str, Set[str]]:
        """Extract IOCs from extracted strings."""
        all_text = ' '.join(strings.get('ascii', []) + strings.get('unicode', []))
        return self._extract_from_text(all_text)
    
    def extract_from_pe_info(self, pe_info: Dict[str, Any]) -> Dict[str, Set[str]]:
        """Extract IOCs from PE information."""
        iocs = {
            'ips': set(),
            'domains': set(),
            'urls': set(),
            'emails': set(),
            'registry_keys': set(),
            'file_paths': set()
        }
        
        # Convert imports and exports to text for extraction
        imports_text = ' '.join(pe_info.get('imports', []))
        exports_text = ' '.join(pe_info.get('exports', []))
        all_text = imports_text + ' ' + exports_text
        
        text_iocs = self._extract_from_text(all_text)
        for ioc_type, ioc_values in text_iocs.items():
            iocs[ioc_type].update(ioc_values)
        
        return iocs
    
    def extract_from_network(self, network_data: Dict[str, Any]) -> Dict[str, Set[str]]:
        """Extract IOCs from network capture data."""
        iocs = {
            'ips': set(),
            'domains': set(),
            'urls': set(),
            'emails': set(),
            'registry_keys': set(),
            'file_paths': set()
        }
        
        # Extract IPs from network packets
        for packet in network_data.get('packets', []):
            if packet.get('src') and not self._is_local_ip(packet.get('src')):
                iocs['ips'].add(packet.get('src'))
            if packet.get('dst') and not self._is_local_ip(packet.get('dst')):
                iocs['ips'].add(packet.get('dst'))
            
            # Extract from packet summary
            summary = packet.get('summary', '')
            text_iocs = self._extract_from_text(summary)
            for ioc_type, ioc_values in text_iocs.items():
                iocs[ioc_type].update(ioc_values)
        
        return iocs
    
    def extract_from_filesystem(self, filesystem_data: Dict[str, Any]) -> Dict[str, Set[str]]:
        """Extract IOCs from filesystem monitoring data."""
        iocs = {
            'ips': set(),
            'domains': set(),
            'urls': set(),
            'emails': set(),
            'registry_keys': set(),
            'file_paths': set()
        }
        
        # Extract file paths from changes
        for change in filesystem_data.get('changes', []):
            path = change.get('path', '')
            if path:
                iocs['file_paths'].add(path)
            
            # If it was a move, add destination path too
            if change.get('event_type') == 'moved' and change.get('dest_path'):
                iocs['file_paths'].add(change.get('dest_path'))
        
        return iocs
    
    def extract_from_processes(self, process_data: Dict[str, Any]) -> Dict[str, Set[str]]:
        """Extract IOCs from process monitoring data."""
        iocs = {
            'ips': set(),
            'domains': set(),
            'urls': set(),
            'emails': set(),
            'registry_keys': set(),
            'file_paths': set()
        }
        
        for pid, process in process_data.get('processes', {}).items():
            # Extract from command line
            cmdline = ' '.join(process.get('cmdline', []))
            text_iocs = self._extract_from_text(cmdline)
            for ioc_type, ioc_values in text_iocs.items():
                iocs[ioc_type].update(ioc_values)
            
            # Extract file paths
            if process.get('exe'):
                iocs['file_paths'].add(process.get('exe'))
            
            for file_path in process.get('open_files', []):
                iocs['file_paths'].add(file_path)
            
            # Extract IPs from connections
            for conn in process.get('connections', []):
                if conn.get('remote_addr'):
                    ip = conn.get('remote_addr').split(':')[0]
                    if ip and not self._is_local_ip(ip):
                        iocs['ips'].add(ip)
        
        return iocs
    
    def _extract_from_text(self, text: str) -> Dict[str, Set[str]]:
        """Extract all IOC types from a text."""
        return {
            'ips': self.extract_ips(text),
            'domains': self.extract_domains(text),
            'urls': self.extract_urls(text),
            'emails': self.extract_emails(text),
            'registry_keys': self.extract_registry_keys(text),
            'file_paths': self.extract_file_paths(text)
        }
    
    def extract_all(self, static_results: Dict[str, Any], dynamic_results: Dict[str, Any]) -> Dict[str, Set[str]]:
        """Extract all IOCs from analysis results."""
        combined_iocs = {
            'ips': set(),
            'domains': set(),
            'urls': set(),
            'emails': set(),
            'registry_keys': set(),
            'file_paths': set()
        }
        
        # Extract from static analysis
        if 'strings' in static_results:
            string_iocs = self.extract_from_strings(static_results['strings'])
            for ioc_type, ioc_values in string_iocs.items():
                combined_iocs[ioc_type].update(ioc_values)
        
        if 'pe_info' in static_results:
            pe_iocs = self.extract_from_pe_info(static_results['pe_info'])
            for ioc_type, ioc_values in pe_iocs.items():
                combined_iocs[ioc_type].update(ioc_values)
        
        # Extract from dynamic analysis
        if 'network' in dynamic_results:
            network_iocs = self.extract_from_network(dynamic_results['network'])
            for ioc_type, ioc_values in network_iocs.items():
                combined_iocs[ioc_type].update(ioc_values)
        
        if 'filesystem' in dynamic_results:
            filesystem_iocs = self.extract_from_filesystem(dynamic_results['filesystem'])
            for ioc_type, ioc_values in filesystem_iocs.items():
                combined_iocs[ioc_type].update(ioc_values)
        
        if 'processes' in dynamic_results:
            process_iocs = self.extract_from_processes(dynamic_results['processes'])
            for ioc_type, ioc_values in process_iocs.items():
                combined_iocs[ioc_type].update(ioc_values)
        
        # Convert sets to lists for easier serialization
        return {k: list(v) for k, v in combined_iocs.items()} 