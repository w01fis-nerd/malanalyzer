import hashlib
import string
import re
from pathlib import Path
from typing import Dict, List, Union

def calculate_hashes(file_path: Path) -> Dict[str, str]:
    """Calculate MD5, SHA1, and SHA256 hashes of a file.

    Args:
        file_path (Path): Path to the target file

    Returns:
        Dict[str, str]: Dictionary containing hash values
    """
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
            hash_sha256.update(chunk)

    return {
        'md5': hash_md5.hexdigest(),
        'sha1': hash_sha1.hexdigest(),
        'sha256': hash_sha256.hexdigest()
    }

def is_printable(byte_str: bytes) -> bool:
    """Check if a byte string contains printable characters.

    Args:
        byte_str (bytes): Byte string to check

    Returns:
        bool: True if string is printable, False otherwise
    """
    try:
        decoded = byte_str.decode('ascii')
        return all(char in string.printable for char in decoded)
    except UnicodeDecodeError:
        return False

def extract_strings(file_path: Path, min_length: int = 4) -> Dict[str, List[str]]:
    """Extract ASCII and Unicode strings from a file.

    Args:
        file_path (Path): Path to the target file
        min_length (int, optional): Minimum string length. Defaults to 4.

    Returns:
        Dict[str, List[str]]: Dictionary containing ASCII and Unicode strings
    """
    ascii_strings = []
    unicode_strings = []
    
    with open(file_path, 'rb') as f:
        content = f.read()

    # Extract ASCII strings
    ascii_pattern = re.compile(b'[\x20-\x7E]{' + str(min_length).encode() + b',}')
    ascii_matches = ascii_pattern.finditer(content)
    ascii_strings = [m.group().decode('ascii') for m in ascii_matches]

    # Extract Unicode strings (UTF-16LE)
    unicode_pattern = re.compile(b'(?:[\x20-\x7E][\x00]){' + str(min_length).encode() + b',}')
    unicode_matches = unicode_pattern.finditer(content)
    unicode_strings = [m.group().decode('utf-16le').rstrip('\x00') for m in unicode_matches]

    return {
        'ascii': ascii_strings,
        'unicode': unicode_strings
    }

def analyze_file(file_path: Path) -> Dict[str, Union[Dict[str, str], Dict[str, List[str]]]]:
    """Perform complete file analysis including hashes and strings.

    Args:
        file_path (Path): Path to the target file

    Returns:
        Dict: Analysis results including hashes and extracted strings
    """
    results = {
        'file_name': file_path.name,
        'file_size': file_path.stat().st_size,
        'hashes': calculate_hashes(file_path),
        'strings': extract_strings(file_path)
    }
    return results