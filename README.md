# MalAnalyzer 🔍

**Cross-Platform Malware Analysis and Incident Response Toolkit**

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green.svg)](https://github.com/w01fis-nerd/malanalyzer)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A comprehensive command-line tool for analyzing malware samples and aiding in incident response. Built with Python, it provides both static and dynamic analysis capabilities, extracts indicators of compromise (IOCs), and generates detailed reports following industry best practices.

**Now supports both Windows and Linux!** 🖥️

---

## 📋 Table of Contents

- [Features](#-features)
- [Cross-Platform Support](#-cross-platform-support)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [Requirements](#-requirements)
- [Security Notes](#-security-notes)
- [Use Cases](#-use-cases)
- [Output Examples](#-output-examples)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

---

## ✨ Features

### 🔍 Static Analysis
- **File Hash Calculation**: MD5, SHA1, SHA256 hashes for file identification
- **String Extraction**: ASCII and Unicode strings to identify suspicious patterns
- **Binary Analysis**:
  - **Windows**: PE file structure analysis (`.exe`, `.dll`, `.sys`)
  - **Linux**: ELF file structure analysis (executables, shared libraries)
- **YARA Rule Scanning**: Custom malware signature detection

### 🚀 Dynamic Analysis
- **Process Monitoring**: Track running processes, memory usage, CPU usage
- **File System Monitoring**: Real-time file system changes
- **Network Traffic Capture**: PCAP file generation for analysis

### 🎯 IOC Extraction
Automatically extract and categorize:
- **IP Addresses**: External IPs (filters local/private IPs)
- **Domain Names**: Potential C2 servers or malicious domains
- **URLs**: Suspicious web addresses
- **Email Addresses**: Potential phishing or C2 communication
- **Registry Keys**: Windows registry modifications
- **File Paths**: Suspicious file locations and operations

### 📊 Reporting
- **HTML Reports**: Interactive web-based reports with tables
- **JSON Reports**: Machine-readable structured data
- **Text Reports**: Simple, readable console output
- **IOC Export**: Multiple formats (JSON, CSV, STIX, MISP)

---

## 🖥️ Cross-Platform Support

| Feature | Windows | Linux |
|---------|---------|-------|
| **PE Analysis** | ✅ | ❌ |
| **ELF Analysis** | ❌ | ✅ |
| **Process Monitoring** | ✅ | ✅ |
| **File System Monitoring** | ✅ | ✅ |
| **Network Capture** | ✅ | ✅ |
| **Registry Monitoring** | ✅ | ❌ |
| **Library Dependencies** | ❌ | ✅ |
| **String Extraction** | ✅ | ✅ |
| **YARA Scanning** | ✅ | ✅ |
| **Hash Calculation** | ✅ | ✅ |
| **IOC Extraction** | ✅ | ✅ |
| **Report Generation** | ✅ | ✅ |

---

## 🚀 Quick Start

### 1. Clone and Setup
```bash
git clone https://github.com/w01fis-nerd/malanalyzer
cd malanalyzer
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Create Test Sample
```bash
# Windows
python test_sample.py

# Linux
python test_linux_sample.py
```

### 3. Run Analysis
```bash
# Full analysis
python main.py test_sample.exe --all

# Static analysis only
python main.py test_sample.exe --static
```

---

## 📦 Installation

### Prerequisites
- **Python 3.6+**
- **Windows or Linux**
- **Administrative privileges** (for dynamic analysis)

### Step-by-Step Installation

#### 1. Clone Repository
```bash
git clone https://github.com/yourusername/malanalyzer.git
cd malanalyzer
```

#### 2. Create Virtual Environment
```bash
python -m venv venv
```

#### 3. Activate Environment
```bash
# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

#### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### Linux-Specific Setup
For full functionality on Linux, install additional packages:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install libpcap-dev tcpdump

# CentOS/RHEL/Fedora
sudo yum install libpcap-devel tcpdump
# or
sudo dnf install libpcap-devel tcpdump
```

---

## 💻 Usage

### Basic Commands

```bash
# Full analysis (static + dynamic + IOC + reporting)
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

### Platform-Specific Examples

#### Windows
```bash
# Create Windows test sample
python test_sample.py

# Analyze Windows executable
python main.py test_sample.exe --all
```

#### Linux
```bash
# Create Linux test sample
python test_linux_sample.py

# Analyze Linux executable
python main.py test_linux_sample --all
```

### Example Workflow
```bash
# 1. Create test sample for your platform
python test_sample.py          # Windows
python test_linux_sample.py    # Linux

# 2. Run full analysis
python main.py test_sample.exe --all

# 3. Check output directory for results
ls output/
```

---

## 📁 Project Structure

```
MALANALYZER/
├── 📄 main.py                    # Main entry point
├── 📁 static/                    # Static analysis modules
│   ├── 📄 file_analysis.py       # File hashes and string extraction
│   ├── 📄 pe_analysis.py         # PE file analysis (Windows)
│   ├── 📄 elf_analysis.py        # ELF file analysis (Linux)
│   └── 📄 yara_scanner.py        # YARA rule scanning
├── 📁 dynamic/                   # Dynamic analysis modules
│   ├── 📄 process_monitor.py     # Process monitoring
│   ├── 📄 file_monitor.py        # File system monitoring
│   └── 📄 network_monitor.py     # Network traffic capture
├── 📁 ioc/                       # IOC extraction modules
│   ├── 📄 extractor.py           # IOC extraction logic
│   └── 📄 parser.py              # IOC format conversion
├── 📁 report/                    # Reporting modules
│   └── 📄 generator.py           # Report generation
├── 📁 utils/                     # Utility modules
│   ├── 📄 logger.py              # Logging configuration
│   └── 📄 config.py              # Configuration management
├── 📁 rules/                     # YARA rules directory
│   └── 📁 yara/
│       └── 📄 malware_signatures.yar
├── 📁 output/                    # Analysis results
├── 📄 test_sample.py             # Windows test sample generator
├── 📄 test_linux_sample.py       # Linux test sample generator
├── 📄 requirements.txt           # Python dependencies
└── 📄 README.md                  # This file
```

---

## ⚙️ Configuration

The tool automatically detects your operating system and uses appropriate configurations:

### Windows Configuration
```json
{
  "analysis": {
    "dynamic": {
      "monitor_paths": ["C:\\Windows", "C:\\Program Files", "C:\\Users"]
    }
  }
}
```

### Linux Configuration
```json
{
  "analysis": {
    "dynamic": {
      "monitor_paths": ["/usr", "/etc", "/home", "/var", "/tmp"]
    }
  }
}
```

---

## 🔧 Requirements

### Cross-Platform
- **Python 3.6+**
- **YARA rules** (optional, place in `rules/yara/` directory)

### Windows-Specific
- **Administrative privileges** (for dynamic analysis features)

### Linux-Specific
- **libpcap-dev** (for packet capture)
- **tcpdump** (for network analysis)
- **Root privileges** (for some network monitoring features)

---

## ⚠️ Security Notes

**🚨 CRITICAL: Always analyze malware in a safe, isolated environment!**

### Best Practices
- ✅ Use a virtual machine for malware analysis
- ✅ Ensure the VM is isolated from your network
- ✅ Take snapshots before analysis
- ✅ Never run malware on production systems
- ✅ Follow your organization's security policies

### Safety Checklist
- [ ] Analysis environment is isolated
- [ ] Network access is restricted
- [ ] Snapshots are available
- [ ] Security policies are followed
- [ ] Legal requirements are met

---

## 🎯 Use Cases

### For Security Analysts
- 🔍 Rapid triage of suspicious files
- 📊 Behavioral analysis of malware samples
- 🎯 IOC extraction for threat hunting
- 📋 Report generation for stakeholders

### For Incident Response Teams
- ⚡ Quick assessment during security incidents
- 📁 Evidence collection and documentation
- 🔗 IOC sharing with threat intelligence platforms
- 📈 Post-incident analysis and reporting

### For Threat Hunters
- 🔍 Proactive malware analysis
- 🧩 Pattern identification across samples
- 📚 IOC database building
- 📊 Threat intelligence gathering

### For Security Researchers
- 🔬 Malware behavior study
- 🏷️ Family classification
- 💪 Capability analysis
- 📖 Academic research

---

## 📊 Output Examples

### HTML Report
- Professional web-based interface
- Interactive tables and sections
- Color-coded indicators
- Platform-specific information
- Exportable results


## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation as needed
- Ensure cross-platform compatibility

---



## 🙏 Acknowledgments

- Inspired by "Practical Malware Analysis" by Michael Sikorski and Andrew Honig
- Built with industry-standard tools and libraries
- Follows DFIR best practices and methodologies
- Cross-platform support for modern security analysis

---


### Resources
- [YARA Documentation](https://yara.readthedocs.io/)
- [PE File Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [ELF File Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [DFIR Best Practices](https://www.sans.org/white-papers/)



**⚠️ Remember: This tool is for educational and legitimate security research purposes only. Always follow ethical guidelines and legal requirements when analyzing malware.**



