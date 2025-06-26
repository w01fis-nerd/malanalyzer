import pefile
from pathlib import Path
from typing import Dict, List, Optional, Union

def analyze_pe(file_path: Path) -> Dict[str, Union[str, List[str], Dict[str, str]]]:
    """Analyze PE file structure and characteristics.

    Args:
        file_path (Path): Path to the PE file

    Returns:
        Dict: PE analysis results
    """
    try:
        pe = pefile.PE(str(file_path))
        results = {
            'machine_type': hex(pe.FILE_HEADER.Machine),
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'dll_characteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'sections': [],
            'imports': [],
            'exports': []
        }

        # Get sections information
        for section in pe.sections:
            section_info = {
                'name': section.Name.decode().rstrip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'raw_size': hex(section.SizeOfRawData),
                'characteristics': hex(section.Characteristics)
            }
            results['sections'].append(section_info)

        # Get imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                for imp in entry.imports:
                    if imp.name:
                        results['imports'].append(f"{dll_name}:{imp.name.decode()}")
                    else:
                        results['imports'].append(f"{dll_name}:ordinal_{imp.ordinal}")

        # Get exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    results['exports'].append(exp.name.decode())

        pe.close()
        return results

    except pefile.PEFormatError as e:
        return {'error': f"Not a valid PE file: {str(e)}"}
    except Exception as e:
        return {'error': f"Analysis failed: {str(e)}"}