import struct
from pathlib import Path
from typing import Dict, List, Optional, Union
import platform

def analyze_elf(file_path: Path) -> Dict[str, Union[str, List[str], Dict[str, str]]]:
    """Analyze ELF file structure and characteristics.
    
    Args:
        file_path (Path): Path to the ELF file
    
    Returns:
        Dict: ELF analysis results
    """
    try:
        with open(file_path, 'rb') as f:
            # Read ELF header
            elf_header = f.read(64)
            
            if len(elf_header) < 64:
                return {'error': 'File too small to be a valid ELF file'}
            
            # Parse ELF header
            magic = elf_header[:4]
            if magic != b'\x7fELF':
                return {'error': 'Not a valid ELF file (wrong magic number)'}
            
            # Extract basic information
            elf_class = elf_header[4]
            data_encoding = elf_header[5]
            elf_version = elf_header[6]
            os_abi = elf_header[7]
            abi_version = elf_header[8]
            
            # Get machine type and entry point
            machine_type = struct.unpack('<H', elf_header[18:20])[0]
            entry_point = struct.unpack('<I', elf_header[24:28])[0]
            
            # Get section and program header info
            ph_offset = struct.unpack('<I', elf_header[28:32])[0]
            sh_offset = struct.unpack('<I', elf_header[32:36])[0]
            ph_num = struct.unpack('<H', elf_header[44:46])[0]
            sh_num = struct.unpack('<H', elf_header[46:48])[0]
            
            results = {
                'elf_class': _get_elf_class(elf_class),
                'data_encoding': _get_data_encoding(data_encoding),
                'os_abi': _get_os_abi(os_abi),
                'machine_type': _get_machine_type(machine_type),
                'entry_point': hex(entry_point),
                'sections': [],
                'symbols': [],
                'dependencies': []
            }
            
            # Read section headers
            f.seek(sh_offset)
            for i in range(sh_num):
                try:
                    section_header = f.read(40)
                    if len(section_header) == 40:
                        section_info = _parse_section_header(section_header)
                        results['sections'].append(section_info)
                except:
                    break
            
            # Try to extract dependencies using ldd-like approach
            results['dependencies'] = _extract_dependencies(file_path)
            
            return results
            
    except Exception as e:
        return {'error': f'ELF analysis failed: {str(e)}'}

def _get_elf_class(elf_class: int) -> str:
    """Get ELF class description."""
    classes = {
        0: 'ELFCLASSNONE',
        1: 'ELFCLASS32',
        2: 'ELFCLASS64'
    }
    return classes.get(elf_class, f'Unknown ({elf_class})')

def _get_data_encoding(encoding: int) -> str:
    """Get data encoding description."""
    encodings = {
        0: 'ELFDATANONE',
        1: 'ELFDATA2LSB',
        2: 'ELFDATA2MSB'
    }
    return encodings.get(encoding, f'Unknown ({encoding})')

def _get_os_abi(abi: int) -> str:
    """Get OS ABI description."""
    abis = {
        0: 'ELFOSABI_NONE',
        1: 'ELFOSABI_HPUX',
        2: 'ELFOSABI_NETBSD',
        3: 'ELFOSABI_LINUX',
        6: 'ELFOSABI_SOLARIS',
        7: 'ELFOSABI_AIX',
        8: 'ELFOSABI_IRIX',
        9: 'ELFOSABI_FREEBSD',
        10: 'ELFOSABI_TRU64',
        11: 'ELFOSABI_MODESTO',
        12: 'ELFOSABI_OPENBSD',
        13: 'ELFOSABI_OPENVMS',
        14: 'ELFOSABI_NSK',
        15: 'ELFOSABI_AROS',
        16: 'ELFOSABI_FENIXOS',
        17: 'ELFOSABI_CLOUDABI',
        18: 'ELFOSABI_OPENVOS'
    }
    return abis.get(abi, f'Unknown ({abi})')

def _get_machine_type(machine: int) -> str:
    """Get machine type description."""
    machines = {
        0: 'EM_NONE',
        1: 'EM_M32',
        2: 'EM_SPARC',
        3: 'EM_386',
        4: 'EM_68K',
        5: 'EM_88K',
        7: 'EM_860',
        8: 'EM_MIPS',
        9: 'EM_S370',
        10: 'EM_MIPS_RS3_LE',
        15: 'EM_PARISC',
        17: 'EM_VPP500',
        18: 'EM_SPARC32PLUS',
        19: 'EM_960',
        20: 'EM_PPC',
        21: 'EM_PPC64',
        22: 'EM_S390',
        23: 'EM_SPU',
        36: 'EM_V800',
        37: 'EM_FR20',
        38: 'EM_RH32',
        39: 'EM_RCE',
        40: 'EM_ARM',
        41: 'EM_FAKE_ALPHA',
        42: 'EM_SH',
        43: 'EM_SPARCV9',
        44: 'EM_TRICORE',
        45: 'EM_ARC',
        46: 'EM_H8_300',
        47: 'EM_H8_300H',
        48: 'EM_H8S',
        49: 'EM_H8_500',
        50: 'EM_IA_64',
        51: 'EM_MIPS_X',
        52: 'EM_COLDFIRE',
        53: 'EM_68HC12',
        54: 'EM_MMA',
        55: 'EM_PCP',
        56: 'EM_NCPU',
        57: 'EM_NDR1',
        58: 'EM_STARCORE',
        59: 'EM_ME16',
        60: 'EM_ST100',
        61: 'EM_TINYJ',
        62: 'EM_X86_64',
        63: 'EM_PDSP',
        66: 'EM_FX66',
        67: 'EM_ST9PLUS',
        68: 'EM_ST7',
        69: 'EM_68HC16',
        70: 'EM_68HC11',
        71: 'EM_68HC08',
        72: 'EM_68HC05',
        73: 'EM_SVX',
        74: 'EM_ST19',
        75: 'EM_VAX',
        76: 'EM_CRIS',
        77: 'EM_JAVELIN',
        78: 'EM_FIREPATH',
        79: 'EM_ZSP',
        80: 'EM_MMIX',
        81: 'EM_HUANY',
        82: 'EM_PRISM',
        83: 'EM_AVR',
        84: 'EM_FR30',
        85: 'EM_D10V',
        86: 'EM_D30V',
        87: 'EM_V850',
        88: 'EM_M32R',
        89: 'EM_MN10300',
        90: 'EM_MN10200',
        91: 'EM_PJ',
        92: 'EM_OPENRISC',
        93: 'EM_ARC_COMPACT',
        94: 'EM_XTENSA',
        95: 'EM_VIDEOCORE',
        96: 'EM_TMM_GPP',
        97: 'EM_NS32K',
        98: 'EM_TPC',
        99: 'EM_SNP1K',
        100: 'EM_ST200',
        101: 'EM_IP2K',
        102: 'EM_MAX',
        103: 'EM_CR',
        104: 'EM_F2MC16',
        105: 'EM_MSP430',
        106: 'EM_BLACKFIN',
        107: 'EM_SE_C33',
        108: 'EM_SEP',
        109: 'EM_ARCA',
        110: 'EM_UNICORE',
        111: 'EM_EXCESS',
        112: 'EM_DXP',
        113: 'EM_ALTERA_NIOS2',
        114: 'EM_CRX',
        115: 'EM_XGATE',
        116: 'EM_C166',
        117: 'EM_M16C',
        118: 'EM_DSPIC30F',
        119: 'EM_CE',
        120: 'EM_M32C',
        131: 'EM_TSK3000',
        132: 'EM_RS08',
        133: 'EM_SHARC',
        134: 'EM_ECOG2',
        135: 'EM_SCORE7',
        136: 'EM_DSP24',
        137: 'EM_VIDEOCORE3',
        138: 'EM_LATTICEMICO32',
        139: 'EM_SE_C17',
        140: 'EM_TI_C6000',
        141: 'EM_TI_C2000',
        142: 'EM_TI_C5500',
        143: 'EM_TI_ARP32',
        144: 'EM_TI_PRU',
        160: 'EM_MMDSP_PLUS',
        161: 'EM_CYPRESS_M8C',
        162: 'EM_R32C',
        163: 'EM_TRIMEDIA',
        164: 'EM_QDSP6',
        165: 'EM_8051',
        166: 'EM_STXP7X',
        167: 'EM_NDS32',
        168: 'EM_ECOG1X',
        169: 'EM_MAXQ30',
        170: 'EM_XIMO16',
        171: 'EM_MANIK',
        172: 'EM_CRAYNV2',
        173: 'EM_RX',
        174: 'EM_METAG',
        175: 'EM_MCST_ELBRUS',
        176: 'EM_ECOG16',
        177: 'EM_CR16',
        178: 'EM_ETPU',
        179: 'EM_SLE9X',
        180: 'EM_L10M',
        181: 'EM_K10M',
        183: 'EM_AARCH64',
        185: 'EM_AVR32',
        186: 'EM_STM8',
        187: 'EM_TILE64',
        188: 'EM_TILEPRO',
        189: 'EM_MICROBLAZE',
        190: 'EM_CUDA',
        191: 'EM_TILEGX',
        192: 'EM_CLOUDSHIELD',
        193: 'EM_COREA_1ST',
        194: 'EM_COREA_2ND',
        195: 'EM_ARC_COMPACT2',
        196: 'EM_OPEN8',
        197: 'EM_RL78',
        198: 'EM_VIDEOCORE5',
        199: 'EM_78KOR',
        200: 'EM_56800EX',
        201: 'EM_BA1',
        202: 'EM_BA2',
        203: 'EM_XCORE',
        204: 'EM_MCHP_PIC',
        205: 'EM_INTEL205',
        206: 'EM_INTEL206',
        207: 'EM_INTEL207',
        208: 'EM_INTEL208',
        209: 'EM_INTEL209',
        210: 'EM_KM32',
        211: 'EM_KMX32',
        212: 'EM_KMX16',
        213: 'EM_KMX8',
        214: 'EM_KVARC',
        215: 'EM_CDP',
        216: 'EM_COGE',
        217: 'EM_COOL',
        218: 'EM_NORC',
        219: 'EM_CSR_KALIMBA',
        220: 'EM_Z80',
        221: 'EM_VISIUM',
        222: 'EM_FT32',
        223: 'EM_MOXIE',
        224: 'EM_AMDGPU',
        243: 'EM_RISCV',
        247: 'EM_BPF',
        250: 'EM_CSKY',
        251: 'EM_LOONGARCH'
    }
    return machines.get(machine, f'Unknown ({machine})')

def _parse_section_header(header: bytes) -> Dict[str, str]:
    """Parse section header information."""
    try:
        name_offset = struct.unpack('<I', header[0:4])[0]
        section_type = struct.unpack('<I', header[4:8])[0]
        flags = struct.unpack('<I', header[8:12])[0]
        address = struct.unpack('<I', header[12:16])[0]
        offset = struct.unpack('<I', header[16:20])[0]
        size = struct.unpack('<I', header[20:24])[0]
        
        return {
            'name_offset': hex(name_offset),
            'type': hex(section_type),
            'flags': hex(flags),
            'address': hex(address),
            'offset': hex(offset),
            'size': hex(size)
        }
    except:
        return {'error': 'Failed to parse section header'}

def _extract_dependencies(file_path: Path) -> List[str]:
    """Extract library dependencies from ELF file.
    
    Args:
        file_path (Path): Path to the ELF file
    
    Returns:
        List[str]: List of library dependencies
    """
    dependencies = []
    
    try:
        # Try to use ldd command if available
        import subprocess
        result = subprocess.run(['ldd', str(file_path)], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if '=>' in line:
                    lib_name = line.split('=>')[0].strip()
                    if lib_name and not lib_name.startswith('linux-vdso'):
                        dependencies.append(lib_name)
    except:
        # Fallback: try to extract from dynamic section
        try:
            with open(file_path, 'rb') as f:
                # This is a simplified approach - in practice you'd need to
                # parse the dynamic section properly
                content = f.read()
                # Look for common library patterns
                import re
                lib_pattern = re.compile(rb'lib[a-zA-Z0-9_-]+\.so[0-9.]*')
                matches = lib_pattern.findall(content)
                dependencies = [m.decode('utf-8', errors='ignore') for m in matches]
        except:
            pass
    
    return dependencies 