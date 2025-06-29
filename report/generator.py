import json
import os
import datetime
from pathlib import Path
from typing import Dict, List, Any, Union, Optional
import jinja2
from tabulate import tabulate

class Report:
    def __init__(self, sample_path: Path, output_dir: Union[str, Path] = 'output'):
        """Initialize a new report.
        
        Args:
            sample_path (Path): Path to the analyzed sample
            output_dir (Union[str, Path], optional): Output directory. Defaults to 'output'.
        """
        self.sample_path = sample_path
        self.sample_name = sample_path.name
        
        if isinstance(output_dir, str):
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize report data
        self.report_data = {
            'sample_name': self.sample_name,
            'sample_path': str(sample_path),
            'analysis_time': datetime.datetime.now().isoformat(),
            'system_info': {},
            'static_analysis': {},
            'dynamic_analysis': {},
            'iocs': {}
        }
    
    def add_system_info(self, system_info: Dict[str, str]) -> None:
        """Add system information to the report.
        
        Args:
            system_info (Dict[str, str]): System information
        """
        self.report_data['system_info'] = system_info
    
    def add_static_analysis(self, static_results: Dict[str, Any]) -> None:
        """Add static analysis results to the report.
        
        Args:
            static_results (Dict[str, Any]): Static analysis results
        """
        self.report_data['static_analysis'] = static_results
    
    def add_dynamic_analysis(self, dynamic_results: Dict[str, Any]) -> None:
        """Add dynamic analysis results to the report.
        
        Args:
            dynamic_results (Dict[str, Any]): Dynamic analysis results
        """
        self.report_data['dynamic_analysis'] = dynamic_results
    
    def add_iocs(self, iocs: Dict[str, List[str]]) -> None:
        """Add extracted IOCs to the report.
        
        Args:
            iocs (Dict[str, List[str]]): Extracted IOCs
        """
        self.report_data['iocs'] = iocs
    
    def generate_json_report(self, output_path: Path) -> None:
        """Generate a JSON report.
        
        Args:
            output_path (Path): Path to save the JSON report
        """
        with open(output_path, 'w') as f:
            json.dump(self.report_data, f, indent=4)
    
    def generate_text_report(self, output_path: Path) -> None:
        """Generate a plain text report.
        
        Args:
            output_path (Path): Path to save the text report
        """
        with open(output_path, 'w') as f:
            # Sample information
            f.write(f"=== Malware Analysis Report ===\n\n")
            f.write(f"Sample: {self.report_data['sample_name']}\n")
            f.write(f"Path: {self.report_data['sample_path']}\n")
            f.write(f"Analysis Time: {self.report_data['analysis_time']}\n")
            
            # System information
            if self.report_data['system_info']:
                f.write(f"Platform: {self.report_data['system_info'].get('os', 'Unknown')}\n")
                f.write(f"Architecture: {self.report_data['system_info'].get('architecture', 'Unknown')}\n")
            f.write("\n")
            
            # Static Analysis
            f.write(f"=== Static Analysis ===\n\n")
            
            # File hashes
            if 'hashes' in self.report_data['static_analysis']:
                f.write("File Hashes:\n")
                for hash_type, hash_value in self.report_data['static_analysis']['hashes'].items():
                    f.write(f"  {hash_type.upper()}: {hash_value}\n")
                f.write("\n")
            
            # PE Info (Windows)
            if 'pe_info' in self.report_data['static_analysis']:
                pe_info = self.report_data['static_analysis']['pe_info']
                f.write("PE Information:\n")
                
                # Basic PE info
                for key in ['machine_type', 'timestamp', 'subsystem']:
                    if key in pe_info:
                        f.write(f"  {key}: {pe_info[key]}\n")
                
                # Sections
                if 'sections' in pe_info and pe_info['sections']:
                    f.write("\nSections:\n")
                    section_data = []
                    for section in pe_info['sections']:
                        section_data.append([
                            section.get('name', ''),
                            section.get('virtual_address', ''),
                            section.get('virtual_size', ''),
                            section.get('raw_size', ''),
                            section.get('characteristics', '')
                        ])
                    
                    f.write(tabulate(
                        section_data,
                        headers=['Name', 'VirtAddr', 'VirtSize', 'RawSize', 'Characteristics'],
                        tablefmt='plain'
                    ))
                    f.write("\n\n")
                
                # Imports
                if 'imports' in pe_info and pe_info['imports']:
                    f.write("\nImports:\n")
                    for imp in pe_info['imports'][:50]:  # Limit to first 50
                        f.write(f"  {imp}\n")
                    
                    if len(pe_info['imports']) > 50:
                        f.write(f"  ... and {len(pe_info['imports']) - 50} more\n")
                    
                    f.write("\n")
            
            # ELF Info (Linux)
            if 'elf_info' in self.report_data['static_analysis']:
                elf_info = self.report_data['static_analysis']['elf_info']
                f.write("ELF Information:\n")
                
                # Basic ELF info
                for key in ['elf_class', 'data_encoding', 'os_abi', 'machine_type', 'entry_point']:
                    if key in elf_info:
                        f.write(f"  {key}: {elf_info[key]}\n")
                
                # Dependencies
                if 'dependencies' in elf_info and elf_info['dependencies']:
                    f.write("\nDependencies:\n")
                    for dep in elf_info['dependencies']:
                        f.write(f"  {dep}\n")
                    f.write("\n")
                
                # Sections
                if 'sections' in elf_info and elf_info['sections']:
                    f.write("\nSections:\n")
                    section_data = []
                    for section in elf_info['sections']:
                        section_data.append([
                            section.get('name_offset', ''),
                            section.get('type', ''),
                            section.get('flags', ''),
                            section.get('address', ''),
                            section.get('size', '')
                        ])
                    
                    f.write(tabulate(
                        section_data,
                        headers=['Name Offset', 'Type', 'Flags', 'Address', 'Size'],
                        tablefmt='plain'
                    ))
                    f.write("\n\n")
            
            # Dynamic Analysis
            f.write(f"=== Dynamic Analysis ===\n\n")
            
            # Process activity
            if 'processes' in self.report_data['dynamic_analysis']:
                processes = self.report_data['dynamic_analysis']['processes'].get('processes', {})
                f.write(f"Process Activity:\n")
                f.write(f"  {len(processes)} processes monitored\n\n")
                
                # List top processes by memory usage
                process_list = []
                for pid, proc_info in processes.items():
                    if 'name' in proc_info and 'memory_percent' in proc_info:
                        process_list.append((
                            pid,
                            proc_info.get('name', ''),
                            proc_info.get('memory_percent', 0),
                            proc_info.get('cpu_percent', 0)
                        ))
                
                # Sort by memory usage
                process_list.sort(key=lambda x: x[2], reverse=True)
                
                if process_list:
                    f.write("Top processes by memory usage:\n")
                    f.write(tabulate(
                        process_list[:10],  # Top 10
                        headers=['PID', 'Name', 'Memory %', 'CPU %'],
                        tablefmt='plain'
                    ))
                    f.write("\n\n")
            
            # Network activity
            if 'network' in self.report_data['dynamic_analysis']:
                network = self.report_data['dynamic_analysis']['network']
                f.write(f"Network Activity:\n")
                f.write(f"  {network.get('packet_count', 0)} packets captured\n")
                if network.get('pcap_file'):
                    f.write(f"  PCAP file: {network.get('pcap_file')}\n")
                f.write("\n")
            
            # File system activity
            if 'filesystem' in self.report_data['dynamic_analysis']:
                filesystem = self.report_data['dynamic_analysis']['filesystem']
                changes = filesystem.get('changes', [])
                f.write(f"File System Activity:\n")
                f.write(f"  {len(changes)} file system changes detected\n\n")
                
                if changes:
                    # Group by event type
                    event_types = {}
                    for change in changes:
                        event_type = change.get('event_type', 'unknown')
                        if event_type not in event_types:
                            event_types[event_type] = 0
                        event_types[event_type] += 1
                    
                    for event_type, count in event_types.items():
                        f.write(f"  {event_type}: {count}\n")
                    f.write("\n")
            
            # IOCs
            f.write(f"=== Indicators of Compromise ===\n\n")
            
            for ioc_type, indicators in self.report_data['iocs'].items():
                if indicators:
                    f.write(f"{ioc_type.capitalize()}:\n")
                    for indicator in indicators:
                        f.write(f"  {indicator}\n")
                    f.write("\n")
    
    def generate_html_report(self, output_path: Path) -> None:
        """Generate an HTML report.
        
        Args:
            output_path (Path): Path to save the HTML report
        """
        # Create a Jinja2 template
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Malware Analysis Report: {{ report.sample_name }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1, h2, h3 { color: #333; }
                .container { max-width: 1200px; margin: 0 auto; }
                .section { margin-bottom: 30px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
                tr:hover { background-color: #f5f5f5; }
                .ioc-list { list-style-type: none; padding-left: 0; }
                .ioc-item { padding: 5px; border-bottom: 1px solid #eee; }
                .platform-info { background-color: #e8f4f8; padding: 10px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Malware Analysis Report</h1>
                
                <div class="section">
                    <h2>Sample Information</h2>
                    <table>
                        <tr><th>Name</th><td>{{ report.sample_name }}</td></tr>
                        <tr><th>Path</th><td>{{ report.sample_path }}</td></tr>
                        <tr><th>Analysis Time</th><td>{{ report.analysis_time }}</td></tr>
                    </table>
                    
                    {% if report.system_info %}
                    <div class="platform-info">
                        <h3>Platform Information</h3>
                        <table>
                            <tr><th>Operating System</th><td>{{ report.system_info.os }}</td></tr>
                            <tr><th>Architecture</th><td>{{ report.system_info.architecture }}</td></tr>
                            <tr><th>Platform</th><td>{{ report.system_info.platform }}</td></tr>
                        </table>
                    </div>
                    {% endif %}
                </div>
                
                <div class="section">
                    <h2>Static Analysis</h2>
                    
                    {% if report.static_analysis.hashes %}
                    <h3>File Hashes</h3>
                    <table>
                        {% for hash_type, hash_value in report.static_analysis.hashes.items() %}
                        <tr>
                            <th>{{ hash_type|upper }}</th>
                            <td>{{ hash_value }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% endif %}
                    
                    {% if report.static_analysis.pe_info %}
                    <h3>PE Information (Windows)</h3>
                    <table>
                        {% for key in ['machine_type', 'timestamp', 'subsystem'] %}
                            {% if key in report.static_analysis.pe_info %}
                            <tr>
                                <th>{{ key }}</th>
                                <td>{{ report.static_analysis.pe_info[key] }}</td>
                            </tr>
                            {% endif %}
                        {% endfor %}
                    </table>
                    
                    {% if report.static_analysis.pe_info.sections %}
                    <h4>Sections</h4>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Virtual Address</th>
                            <th>Virtual Size</th>
                            <th>Raw Size</th>
                            <th>Characteristics</th>
                        </tr>
                        {% for section in report.static_analysis.pe_info.sections %}
                        <tr>
                            <td>{{ section.name }}</td>
                            <td>{{ section.virtual_address }}</td>
                            <td>{{ section.virtual_size }}</td>
                            <td>{{ section.raw_size }}</td>
                            <td>{{ section.characteristics }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% endif %}
                    
                    {% if report.static_analysis.pe_info.imports %}
                    <h4>Imports</h4>
                    <div style="max-height: 300px; overflow-y: auto;">
                        <ul>
                        {% for imp in report.static_analysis.pe_info.imports %}
                            <li>{{ imp }}</li>
                        {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                    {% endif %}
                    
                    {% if report.static_analysis.elf_info %}
                    <h3>ELF Information (Linux)</h3>
                    <table>
                        {% for key in ['elf_class', 'data_encoding', 'os_abi', 'machine_type', 'entry_point'] %}
                            {% if key in report.static_analysis.elf_info %}
                            <tr>
                                <th>{{ key }}</th>
                                <td>{{ report.static_analysis.elf_info[key] }}</td>
                            </tr>
                            {% endif %}
                        {% endfor %}
                    </table>
                    
                    {% if report.static_analysis.elf_info.dependencies %}
                    <h4>Dependencies</h4>
                    <ul>
                        {% for dep in report.static_analysis.elf_info.dependencies %}
                            <li>{{ dep }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    
                    {% if report.static_analysis.elf_info.sections %}
                    <h4>Sections</h4>
                    <table>
                        <tr>
                            <th>Name Offset</th>
                            <th>Type</th>
                            <th>Flags</th>
                            <th>Address</th>
                            <th>Size</th>
                        </tr>
                        {% for section in report.static_analysis.elf_info.sections %}
                        <tr>
                            <td>{{ section.name_offset }}</td>
                            <td>{{ section.type }}</td>
                            <td>{{ section.flags }}</td>
                            <td>{{ section.address }}</td>
                            <td>{{ section.size }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% endif %}
                    {% endif %}
                </div>
                
                <div class="section">
                    <h2>Dynamic Analysis</h2>
                    
                    {% if report.dynamic_analysis.processes %}
                    <h3>Process Activity</h3>
                    <p>{{ report.dynamic_analysis.processes.processes|length }} processes monitored</p>
                    
                    <table>
                        <tr>
                            <th>PID</th>
                            <th>Name</th>
                            <th>Memory %</th>
                            <th>CPU %</th>
                        </tr>
                        {% for pid, proc in report.dynamic_analysis.processes.processes.items() %}
                            {% if loop.index <= 10 %}
                            <tr>
                                <td>{{ pid }}</td>
                                <td>{{ proc.name }}</td>
                                <td>{{ proc.memory_percent }}</td>
                                <td>{{ proc.cpu_percent }}</td>
                            </tr>
                            {% endif %}
                        {% endfor %}
                    </table>
                    {% endif %}
                    
                    {% if report.dynamic_analysis.network %}
                    <h3>Network Activity</h3>
                    <p>{{ report.dynamic_analysis.network.packet_count }} packets captured</p>
                    {% if report.dynamic_analysis.network.pcap_file %}
                    <p>PCAP file: {{ report.dynamic_analysis.network.pcap_file }}</p>
                    {% endif %}
                    {% endif %}
                    
                    {% if report.dynamic_analysis.filesystem %}
                    <h3>File System Activity</h3>
                    <p>{{ report.dynamic_analysis.filesystem.changes|length }} file system changes detected</p>
                    
                    {% if report.dynamic_analysis.filesystem.changes %}
                    <table>
                        <tr>
                            <th>Event Type</th>
                            <th>Path</th>
                            <th>Time</th>
                        </tr>
                        {% for change in report.dynamic_analysis.filesystem.changes %}
                            {% if loop.index <= 20 %}
                            <tr>
                                <td>{{ change.event_type }}</td>
                                <td>{{ change.path }}</td>
                                <td>{{ change.timestamp }}</td>
                            </tr>
                            {% endif %}
                        {% endfor %}
                    </table>
                    {% endif %}
                    {% endif %}
                </div>
                
                <div class="section">
                    <h2>Indicators of Compromise</h2>
                    
                    {% for ioc_type, indicators in report.iocs.items() %}
                        {% if indicators %}
                        <h3>{{ ioc_type|capitalize }}</h3>
                        <ul class="ioc-list">
                            {% for indicator in indicators %}
                            <li class="ioc-item">{{ indicator }}</li>
                            {% endfor %}
                        </ul>
                        {% endif %}
                    {% endfor %}
                </div>
            </div>
        </body>
        </html>
        """
        
        # Render the template
        template = jinja2.Template(template_str)
        html_content = template.render(report=self.report_data)
        
        # Write to file
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def generate(self, formats: List[str] = ['html', 'json']) -> Dict[str, Path]:
        """Generate reports in specified formats.
        
        Args:
            formats (List[str], optional): List of output formats. Defaults to ['html', 'json'].
        
        Returns:
            Dict[str, Path]: Dictionary mapping format to output file path
        """
        output_files = {}
        
        for fmt in formats:
            fmt = fmt.lower()
            if fmt == 'json':
                output_path = self.output_dir / f"{self.sample_name}_report.json"
                self.generate_json_report(output_path)
                output_files['json'] = output_path
            elif fmt == 'html':
                output_path = self.output_dir / f"{self.sample_name}_report.html"
                self.generate_html_report(output_path)
                output_files['html'] = output_path
            elif fmt == 'text':
                output_path = self.output_dir / f"{self.sample_name}_report.txt"
                self.generate_text_report(output_path)
                output_files['text'] = output_path
        
        return output_files
