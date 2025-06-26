# MalAnalyzer - Cross-Platform Malware Analysis and Incident Response Toolkit

MalAnalyzer is a comprehensive command-line tool for analyzing malware samples and aiding in incident response. Built with Python, it provides both static and dynamic analysis capabilities, extracts indicators of compromise (IOCs), and generates detailed reports following industry best practices. **Now supports both Windows and Linux!**

## 🚀 What This Tool Can Do

### **Static Analysis Capabilities**
- **File Hash Calculation**: Generate MD5, SHA1, and SHA256 hashes for file identification and integrity verification
- **String Extraction**: Extract both ASCII and Unicode strings to identify suspicious patterns, URLs, IPs, and other indicators
- **Binary Analysis**:
  - **Windows**: PE file structure analysis (executables, DLLs, system files)
  - **Linux**: ELF file structure analysis (executables, shared libraries)
- **YARA Rule Scanning**: Scan files against custom YARA rules to detect malware signatures and patterns

### **Dynamic Analysis Capabilities**
- **Process Monitoring**: Track all running processes, their memory usage, CPU usage, open files, and network connections
- **File System Monitoring**: Monitor file system changes in real-time (file creation, modification, deletion, moves)
- **Network Traffic Capture**: Capture network packets and save them as PCAP files for analysis

### **IOC (Indicators of Compromise) Extraction**
Automatically extract and categorize:
- **IP Addresses**: External IPs (filters out local/private IPs)
- **Domain Names**: Potential C2 servers or malicious domains
- **URLs**: Suspicious web addresses
- **Email Addresses**: Potential phishing or C2 communication
- **Registry Keys**: Windows registry modifications
- **File Paths**: Suspicious file locations and operations

### **Reporting and Output**
- **HTML Reports**: Beautiful, interactive web-based reports with tables and formatted data
- **JSON Reports**: Machine-readable structured data for integration with other tools
- **Text Reports**: Simple, readable console output
- **IOC Export**: Save indicators in multiple formats (JSON, CSV, STIX, MISP)

## 🖥️ **Cross-Platform Support**

### **Windows Features**
- ✅ PE file analysis (.exe, .dll, .sys)
- ✅ Windows registry monitoring
- ✅ Windows-specific process monitoring
- ✅ Windows file system paths

### **Linux Features**
- ✅ ELF file analysis (executables, shared libraries)
- ✅ Linux process monitoring
- ✅ Unix file system monitoring
- ✅ Library dependency analysis
- ✅ Linux-specific IOC extraction

### **Cross-Platform Features**
- ✅ File hash calculation
- ✅ String extraction
- ✅ YARA rule scanning
- ✅ Network traffic capture
- ✅ IOC extraction and reporting
- ✅ HTML/JSON/Text report generation

## 📋 Features

### **Rapid Triage**
- Quickly analyze suspicious files without execution
- Identify potential threats through static analysis
- Generate file fingerprints for threat intelligence

### **Behavioral Analysis**
- Monitor what malware does when it runs
- Track process creation and system changes
- Capture network communication patterns

### **IOC Generation**
- Automatically extract indicators for threat hunting
- Export in multiple formats for SIEM integration
- Categorize indicators by type for easy analysis

### **Professional Documentation**
- Generate comprehensive reports for stakeholders
- Multiple output formats for different audiences
- Detailed analysis logs for audit trails

### **Integration Ready**
- Output formats compatible with SIEMs and threat intelligence platforms
- JSON output for API integration
- STIX/MISP format support for threat sharing

## 🛠️ Installation

### **Prerequisites**
- **Python 3.6+**
- **Windows or Linux** (macOS support planned)
- **Administrative privileges** (for some dynamic analysis features)

### **Installation Steps**

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/malanalyzer.git
cd malanalyzer
```

2. **Create a virtual environment and activate it:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install the dependencies:**
```bash
pip install -r requirements.txt
```

### **Linux-Specific Setup**
For full functionality on Linux, install additional system packages:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install libpcap-dev tcpdump

# CentOS/RHEL/Fedora
sudo yum install libpcap-devel tcpdump
# or
sudo dnf install libpcap-devel tcpdump
```

## 🚀 Usage

### **Basic Usage**
```bash
# Full analysis (static + dynamic + IOC extraction + reporting)
python main.py path/to/sample.exe --all

# Static analysis only
python main.py path/to/sample.exe --static

# Dynamic analysis only
python main.py path/to/sample.exe --dynamic

# Extract IOCs only
python main.py path/to/sample.exe --ioc

# Generate reports only
python main.py path/to/sample.exe --report
```

### **Platform-Specific Examples**

#### **Windows Example**
```bash
# Create Windows test sample
python test_sample.py

# Analyze Windows executable
python main.py test_sample.exe --all
```

#### **Linux Example**
```bash
# Create Linux test sample
python test_linux_sample.py

# Analyze Linux executable
python main.py test_linux_sample --all
```

### **Example Workflow**
```bash
# 1. Create a test sample for your platform
python test_sample.py          # Windows
python test_linux_sample.py    # Linux

# 2. Run full analysis
python main.py test_sample.exe --all

# 3. Check output directory for results
ls output/
```

## 📁 Project Structure

```
MALANALYZER/
├── main.py                 # Main entry point
├── static/                 # Static analysis modules
│   ├── file_analysis.py    # File hashes and string extraction
│   ├── pe_analysis.py      # PE file structure analysis (Windows)
│   ├── elf_analysis.py     # ELF file structure analysis (Linux)
│   └── yara_scanner.py     # YARA rule scanning
├── dynamic/                # Dynamic analysis modules
│   ├── process_monitor.py  # Process monitoring
│   ├── file_monitor.py     # File system monitoring
│   └── network_monitor.py  # Network traffic capture
├── ioc/                    # IOC extraction modules
│   ├── extractor.py        # IOC extraction logic
│   └── parser.py           # IOC format conversion
├── report/                 # Reporting modules
│   └── generator.py        # Report generation
├── utils/                  # Utility modules
│   ├── logger.py           # Logging configuration
│   └── config.py           # Configuration management
├── rules/                  # YARA rules directory
│   └── yara/
│       └── malware_signatures.yar
├── output/                 # Analysis results
├── test_sample.py          # Windows test sample generator
├── test_linux_sample.py    # Linux test sample generator
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## ⚙️ Configuration

The tool automatically detects your operating system and uses appropriate configurations:

### **Windows Configuration**
```json
{
  "analysis": {
    "dynamic": {
      "monitor_paths": ["C:\\Windows", "C:\\Program Files", "C:\\Users"]
    }
  }
}
```

### **Linux Configuration**
```json
{
  "analysis": {
    "dynamic": {
      "monitor_paths": ["/usr", "/etc", "/home", "/var", "/tmp"]
    }
  }
}
```

## 🔧 Requirements

### **Cross-Platform**
- **Python 3.6+**
- **YARA rules** (optional, place in `rules/yara/` directory)

### **Windows-Specific**
- **Administrative privileges** (for some dynamic analysis features)

### **Linux-Specific**
- **libpcap-dev** (for packet capture)
- **tcpdump** (for network analysis)
- **Root privileges** (for some network monitoring features)

## ⚠️ Important Security Notes

**🚨 CRITICAL: Always analyze malware in a safe, isolated environment!**

- Use a virtual machine for malware analysis
- Ensure the VM is isolated from your network
- Take snapshots before analysis
- Never run malware on production systems
- Follow your organization's security policies

## 🎯 Use Cases

### **For Security Analysts**
- Rapid triage of suspicious files
- Behavioral analysis of malware samples
- IOC extraction for threat hunting
- Report generation for stakeholders

### **For Incident Response Teams**
- Quick assessment during security incidents
- Evidence collection and documentation
- IOC sharing with threat intelligence platforms
- Post-incident analysis and reporting

### **For Threat Hunters**
- Proactive malware analysis
- Pattern identification across samples
- IOC database building
- Threat intelligence gathering

### **For Security Researchers**
- Malware behavior study
- Family classification
- Capability analysis
- Academic research

## 📊 Output Examples

### **HTML Report**
- Professional web-based interface
- Interactive tables and sections
- Color-coded indicators
- Platform-specific information
- Exportable results

### **JSON Output**
```json
{
  "sample_name": "suspicious.exe",
  "analysis_time": "2024-01-15T10:30:00",
  "system_info": {
    "os": "linux",
    "architecture": "x86_64",
    "platform": "Linux-5.4.0-x86_64"
  },
  "static_analysis": {
    "hashes": {
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "elf_info": {
      "elf_class": "ELFCLASS32",
      "machine_type": "EM_386",
      "dependencies": ["libc.so.6", "libpthread.so.0"]
    }
  },
  "iocs": {
    "ips": ["192.168.1.100"],
    "domains": ["evil.com"],
    "urls": ["http://evil.com/c2"],
    "emails": ["malware@evil.com"]
  }
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by "Practical Malware Analysis" by Michael Sikorski and Andrew Honig
- Built with industry-standard tools and libraries
- Follows DFIR best practices and methodologies
- Cross-platform support for modern security analysis

## 📞 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check the documentation
- Review the code comments

---

**Remember: This tool is for educational and legitimate security research purposes only. Always follow ethical guidelines and legal requirements when analyzing malware.** #   m a l a n a l y z e r  
 