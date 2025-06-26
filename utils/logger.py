import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logger(log_file: Optional[Path] = None, log_level: int = logging.INFO) -> logging.Logger:
    """Set up and configure the logger.
    
    Args:
        log_file (Optional[Path], optional): Path to log file. Defaults to None.
        log_level (int, optional): Logging level. Defaults to logging.INFO.
    
    Returns:
        logging.Logger: Configured logger
    """
    # Create logger
    logger = logging.getLogger('malanalyzer')
    logger.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler if log file is specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger 