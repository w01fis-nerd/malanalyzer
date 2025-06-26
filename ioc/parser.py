import json
import csv
import os
from pathlib import Path
from typing import Dict, List, Any, Union

def save_iocs_to_json(iocs: Dict[str, List[str]], output_path: Path) -> None:
    """Save IOCs to a JSON file.
    
    Args:
        iocs (Dict[str, List[str]]): Dictionary of IOCs
        output_path (Path): Path to save the JSON file
    """
    with open(output_path, 'w') as f:
        json.dump(iocs, f, indent=4)

def save_iocs_to_csv(iocs: Dict[str, List[str]], output_path: Path) -> None:
    """Save IOCs to a CSV file.
    
    Args:
        iocs (Dict[str, List[str]]): Dictionary of IOCs
        output_path (Path): Path to save the CSV file
    """
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Type', 'Indicator', 'Description'])
        
        for ioc_type, indicators in iocs.items():
            for indicator in indicators:
                writer.writerow([ioc_type, indicator, ''])

def save_iocs_to_stix(iocs: Dict[str, List[str]], output_path: Path) -> None:
    """Save IOCs to STIX format.
    
    Args:
        iocs (Dict[str, List[str]]): Dictionary of IOCs
        output_path (Path): Path to save the STIX file
    
    Note: This is a simplified version that doesn't create actual STIX objects.
    For real STIX implementation, use libraries like stix2.
    """
    # Map IOC types to STIX object types
    type_mapping = {
        'ips': 'ipv4-addr',
        'domains': 'domain-name',
        'urls': 'url',
        'emails': 'email-addr',
        'registry_keys': 'windows-registry-key',
        'file_paths': 'file'
    }
    
    stix_objects = []
    
    for ioc_type, indicators in iocs.items():
        stix_type = type_mapping.get(ioc_type, 'indicator')
        
        for indicator in indicators:
            stix_obj = {
                "type": stix_type,
                "spec_version": "2.1",
                "id": f"{stix_type}--{indicator.replace('.', '-').replace(':', '-')}",
                "value": indicator
            }
            stix_objects.append(stix_obj)
    
    with open(output_path, 'w') as f:
        json.dump({"type": "bundle", "objects": stix_objects}, f, indent=4)

def save_iocs_to_misp(iocs: Dict[str, List[str]], output_path: Path) -> None:
    """Save IOCs to MISP format.
    
    Args:
        iocs (Dict[str, List[str]]): Dictionary of IOCs
        output_path (Path): Path to save the MISP file
    
    Note: This is a simplified version that doesn't create actual MISP objects.
    For real MISP implementation, use PyMISP library.
    """
    # Map IOC types to MISP attribute types
    type_mapping = {
        'ips': 'ip-dst',
        'domains': 'domain',
        'urls': 'url',
        'emails': 'email',
        'registry_keys': 'regkey',
        'file_paths': 'filename'
    }
    
    misp_attributes = []
    
    for ioc_type, indicators in iocs.items():
        misp_type = type_mapping.get(ioc_type, 'other')
        
        for indicator in indicators:
            misp_attr = {
                "type": misp_type,
                "category": "Network activity",
                "to_ids": True,
                "value": indicator
            }
            misp_attributes.append(misp_attr)
    
    misp_event = {
        "Event": {
            "info": "Malware Analysis IOCs",
            "analysis": "2",
            "threat_level_id": "2",
            "Attribute": misp_attributes
        }
    }
    
    with open(output_path, 'w') as f:
        json.dump(misp_event, f, indent=4)

def save_iocs(iocs: Dict[str, List[str]], format: List[str] = ['json'], 
             output_dir: Union[str, Path] = 'output') -> Dict[str, Path]:
    """Save IOCs in multiple formats.
    
    Args:
        iocs (Dict[str, List[str]]): Dictionary of IOCs
        format (List[str], optional): List of output formats. Defaults to ['json'].
        output_dir (Union[str, Path], optional): Output directory. Defaults to 'output'.
    
    Returns:
        Dict[str, Path]: Dictionary mapping format to output file path
    """
    if isinstance(output_dir, str):
        output_dir = Path(output_dir)
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    output_files = {}
    
    for fmt in format:
        fmt = fmt.lower()
        if fmt == 'json':
            output_path = output_dir / 'iocs.json'
            save_iocs_to_json(iocs, output_path)
            output_files['json'] = output_path
        elif fmt == 'csv':
            output_path = output_dir / 'iocs.csv'
            save_iocs_to_csv(iocs, output_path)
            output_files['csv'] = output_path
        elif fmt == 'stix':
            output_path = output_dir / 'iocs.stix.json'
            save_iocs_to_stix(iocs, output_path)
            output_files['stix'] = output_path
        elif fmt == 'misp':
            output_path = output_dir / 'iocs.misp.json'
            save_iocs_to_misp(iocs, output_path)
            output_files['misp'] = output_path
    
    return output_files 