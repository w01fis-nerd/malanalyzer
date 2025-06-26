#!/usr/bin/env python3
"""
This script creates a simple test file that contains suspicious strings
to test the malware analyzer without using actual malware.
"""

import os
import sys
import struct
from pathlib import Path

def create_test_sample(output_path: str = "test_sample.exe") -> None:
    """Create a test file with suspicious strings.
    
    Args:
        output_path (str, optional): Output path for the test file. Defaults to "test_sample.exe".
    """
    print(f"Creating test sample at: {output_path}")
    
    # Create a minimal PE file structure
    dos_header = b'MZ' + b'\x00' * 58 + struct.pack('<I', 0x80)  # e_lfanew = 0x80
    
    # Add some suspicious strings
    suspicious_strings = [
        b"cmd.exe /c whoami",
        b"powershell.exe -nop -w hidden -c",
        b"RegCreateKeyExA",
        b"RegSetValueExA",
        b"WSAStartup",
        b"InternetOpenA",
        b"VirtualAlloc",
        b"WriteProcessMemory",
        b"CreateRemoteThread",
        b"This file would encrypt your files",
        b"bitcoin wallet address: 1A2B3C4D5E6F7G8H9I0J",
        b"Send payment to decrypt your files",
        b"GetAsyncKeyState",
        b"SetWindowsHookEx",
        b"WH_KEYBOARD",
        b"keylogger.log",
        b"http://malicious.example.com/c2",
        b"evil@example.com",
        b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]
    
    # Create the file content
    content = dos_header
    
    # Add padding to reach e_lfanew
    padding_size = 0x80 - len(content)
    content += b'\x00' * padding_size
    
    # Add a minimal PE header
    content += b'PE\x00\x00' + b'\x00' * 20  # PE signature and COFF header
    
    # Add the suspicious strings
    for s in suspicious_strings:
        content += s + b'\x00'
    
    # Write the file
    with open(output_path, 'wb') as f:
        f.write(content)
    
    print(f"Test sample created successfully.")
    print(f"Run the analyzer with: python main.py {output_path} --all")

if __name__ == "__main__":
    output_path = "test_sample.exe"
    if len(sys.argv) > 1:
        output_path = sys.argv[1]
    
    create_test_sample(output_path) 