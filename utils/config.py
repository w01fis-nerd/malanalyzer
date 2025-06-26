import json
import os
import platform
from pathlib import Path
from typing import Dict, Any, Optional

# Detect operating system
SYSTEM = platform.system().lower()

# Default configurations for different operating systems
WINDOWS_CONFIG = {
    "analysis": {
        "static": {
            "enabled": True,
            "yara_rules_dir": "rules/yara",
            "min_string_length": 4
        },
        "dynamic": {
            "enabled": True,
            "monitor_paths": [
                "C:\\Windows",
                "C:\\Program Files",
                "C:\\Users"
            ],
            "capture_network": True,
            "sandbox_timeout": 60
        }
    },
    "output": {
        "dir": "output",
        "report_formats": ["html", "json"],
        "ioc_formats": ["json", "csv"]
    },
    "logging": {
        "level": "INFO",
        "file": "malanalyzer.log"
    }
}

LINUX_CONFIG = {
    "analysis": {
        "static": {
            "enabled": True,
            "yara_rules_dir": "rules/yara",
            "min_string_length": 4
        },
        "dynamic": {
            "enabled": True,
            "monitor_paths": [
                "/usr",
                "/etc",
                "/home",
                "/var",
                "/tmp"
            ],
            "capture_network": True,
            "sandbox_timeout": 60
        }
    },
    "output": {
        "dir": "output",
        "report_formats": ["html", "json"],
        "ioc_formats": ["json", "csv"]
    },
    "logging": {
        "level": "INFO",
        "file": "malanalyzer.log"
    }
}

def get_default_config() -> Dict[str, Any]:
    """Get default configuration based on operating system."""
    if SYSTEM == "windows":
        return WINDOWS_CONFIG
    elif SYSTEM == "linux":
        return LINUX_CONFIG
    else:
        # Fallback to Linux config for other Unix-like systems
        return LINUX_CONFIG

DEFAULT_CONFIG = get_default_config()

def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from file or use default.
    
    Args:
        config_path (Optional[Path], optional): Path to config file. Defaults to None.
    
    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    # If config path is provided and file exists, load it
    if config_path and config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                # Merge with default config to ensure all keys are present
                return _merge_configs(DEFAULT_CONFIG, config)
        except Exception as e:
            print(f"Error loading config file: {e}")
            return DEFAULT_CONFIG
    
    # If no config file or error, use default
    return DEFAULT_CONFIG

def save_config(config: Dict[str, Any], config_path: Path) -> bool:
    """Save configuration to file.
    
    Args:
        config (Dict[str, Any]): Configuration dictionary
        config_path (Path): Path to save config file
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(config_path.parent, exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving config file: {e}")
        return False

def _merge_configs(default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge user config with default config.
    
    Args:
        default (Dict[str, Any]): Default configuration
        user (Dict[str, Any]): User configuration
    
    Returns:
        Dict[str, Any]: Merged configuration
    """
    result = default.copy()
    
    for key, value in user.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_configs(result[key], value)
        else:
            result[key] = value
    
    return result

def get_system_info() -> Dict[str, str]:
    """Get system information for analysis context.
    
    Returns:
        Dict[str, str]: System information
    """
    return {
        "os": SYSTEM,
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "python_version": platform.python_version()
    } 