import argparse
import sys
import os
import platform
from pathlib import Path
from typing import Optional

# Import our modules
from static import file_analysis, pe_analysis, yara_scanner
try:
    from static import elf_analysis
except ImportError:
    elf_analysis = None

from dynamic import process_monitor, file_monitor, network_monitor
from ioc import extractor, parser
from report import generator
from utils import logger, config

class MalwareAnalyzer:
    def __init__(self):
        self.logger = logger.setup_logger()
        self.config = config.load_config()
        self.system_info = config.get_system_info()
        self.logger.info(f"Initialized on {self.system_info['os']} platform")

    def run_static_analysis(self, file_path: Path) -> dict:
        """Run static analysis on the target file."""
        self.logger.info(f"Starting static analysis on {file_path}")
        results = {}
        
        # File hashes
        self.logger.info("Calculating file hashes...")
        results['hashes'] = file_analysis.calculate_hashes(file_path)
        
        # String extraction
        self.logger.info("Extracting strings...")
        results['strings'] = file_analysis.extract_strings(file_path)
        
        # Binary analysis based on file type and OS
        if self.system_info['os'] == 'windows':
            # PE analysis for Windows executables
            if file_path.suffix.lower() in ('.exe', '.dll', '.sys'):
                self.logger.info("Performing PE analysis...")
                results['pe_info'] = pe_analysis.analyze_pe(file_path)
        else:
            # ELF analysis for Linux executables
            if self._is_executable(file_path):
                self.logger.info("Performing ELF analysis...")
                if elf_analysis:
                    results['elf_info'] = elf_analysis.analyze_elf(file_path)
                else:
                    self.logger.warning("ELF analysis module not available")
        
        # YARA scanning
        self.logger.info("Scanning with YARA rules...")
        yara_rules_dir = Path(self.config['analysis']['static']['yara_rules_dir'])
        if yara_rules_dir.exists():
            scanner = yara_scanner.YaraScanner(yara_rules_dir)
            results['yara_matches'] = scanner.scan_file(file_path)
        else:
            self.logger.warning(f"YARA rules directory not found: {yara_rules_dir}")
            results['yara_matches'] = []
        
        self.logger.info("Static analysis completed")
        return results

    def _is_executable(self, file_path: Path) -> bool:
        """Check if file is an executable."""
        try:
            # Check file permissions on Unix-like systems
            if self.system_info['os'] != 'windows':
                import stat
                st = os.stat(file_path)
                return bool(st.st_mode & stat.S_IEXEC)
            else:
                # On Windows, check file extension
                return file_path.suffix.lower() in ('.exe', '.dll', '.sys')
        except:
            return False

    def run_dynamic_analysis(self, file_path: Path) -> dict:
        """Run dynamic analysis on the target file."""
        self.logger.info(f"Starting dynamic analysis on {file_path}")
        results = {}
        
        # Configure monitoring paths based on OS
        monitor_paths = self.config['analysis']['dynamic']['monitor_paths']
        
        # Set up monitoring
        self.logger.info("Setting up process, file system, and network monitoring...")
        with process_monitor.ProcessMonitor() as proc_mon:
            with file_monitor.FileMonitor(paths=monitor_paths) as file_mon:
                with network_monitor.NetworkMonitor(output_pcap=Path('output/capture.pcap')) as net_mon:
                    # Start monitoring
                    self.logger.info("Starting monitoring...")
                    proc_mon.start_monitoring()
                    file_mon.start_monitoring()
                    net_mon.start_capturing()
                    
                    # Execute the sample in controlled environment
                    self.logger.info(f"Executing sample: {file_path}")
                    
                    if self.system_info['os'] == 'windows':
                        self.logger.warning("Sample execution not implemented yet. Please run the sample manually.")
                    else:
                        # On Linux, we can try to execute the sample
                        if self._is_executable(file_path):
                            self.logger.info("Sample appears to be executable. Please run it manually in a controlled environment.")
                        else:
                            self.logger.info("Sample is not executable. No execution needed.")
                    
                    # Wait for user input to stop monitoring
                    input("Press Enter to stop monitoring and continue analysis...")
                    
                    # Stop monitoring and get results
                    self.logger.info("Stopping monitoring and collecting results...")
                    results['processes'] = proc_mon.get_results()
                    results['filesystem'] = file_mon.get_results()
                    results['network'] = net_mon.get_results()
        
        self.logger.info("Dynamic analysis completed")
        return results

    def extract_iocs(self, static_results: dict, dynamic_results: dict) -> dict:
        """Extract IOCs from analysis results."""
        self.logger.info("Extracting indicators of compromise...")
        ioc_extractor = extractor.IOCExtractor()
        iocs = ioc_extractor.extract_all(static_results, dynamic_results)
        
        # Save IOCs
        output_dir = Path(self.config['output']['dir'])
        ioc_formats = self.config['output']['ioc_formats']
        self.logger.info(f"Saving IOCs in formats: {', '.join(ioc_formats)}")
        parser.save_iocs(iocs, format=ioc_formats, output_dir=output_dir)
        
        self.logger.info(f"IOC extraction completed. Found: {sum(len(v) for v in iocs.values())} indicators")
        return iocs

    def generate_report(self, sample_path: Path, static_results: dict,
                       dynamic_results: dict, iocs: dict) -> None:
        """Generate analysis report."""
        self.logger.info("Generating analysis report...")
        output_dir = Path(self.config['output']['dir'])
        report_formats = self.config['output']['report_formats']
        
        report = generator.Report(sample_path, output_dir=output_dir)
        report.add_static_analysis(static_results)
        report.add_dynamic_analysis(dynamic_results)
        report.add_iocs(iocs)
        
        # Add system information to report
        report.add_system_info(self.system_info)
        
        output_files = report.generate(report_formats)
        
        for fmt, path in output_files.items():
            self.logger.info(f"Generated {fmt} report: {path}")

def main():
    parser = argparse.ArgumentParser(
        description='Malware Analysis and Incident Response Toolkit')
    parser.add_argument('sample', type=Path, help='Path to the sample for analysis')
    parser.add_argument('--static', action='store_true', help='Run static analysis')
    parser.add_argument('--dynamic', action='store_true', help='Run dynamic analysis')
    parser.add_argument('--ioc', action='store_true', help='Extract IOCs')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--all', action='store_true', help='Run full analysis chain')

    args = parser.parse_args()
    
    # Check if sample file exists
    if not args.sample.exists():
        print(f"Error: Sample file not found: {args.sample}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs('output', exist_ok=True)
    
    analyzer = MalwareAnalyzer()
    system_info = config.get_system_info()
    
    print(f"MalAnalyzer - Malware Analysis and Incident Response Toolkit")
    print(f"Platform: {system_info['os']} ({system_info['architecture']})")
    print(f"Analyzing sample: {args.sample}")

    static_results = {}
    dynamic_results = {}
    iocs = {}

    if args.all or args.static:
        static_results = analyzer.run_static_analysis(args.sample)

    if args.all or args.dynamic:
        dynamic_results = analyzer.run_dynamic_analysis(args.sample)

    if args.all or args.ioc:
        iocs = analyzer.extract_iocs(static_results, dynamic_results)

    if args.all or args.report:
        analyzer.generate_report(args.sample, static_results, dynamic_results, iocs)
    
    print("Analysis completed. Results saved to the output directory.")

if __name__ == '__main__':
    main()