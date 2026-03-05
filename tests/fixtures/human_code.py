#!/usr/bin/env python3
"""
A simple file utilities module written by a human developer.
Contains common file operations with proper error handling.
"""

import os
import shutil
import json
from pathlib import Path
from typing import Optional, List, Dict, Any


def read_config(config_path: str) -> Dict[str, Any]:
    """
    Read configuration from a JSON file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Dictionary containing configuration data
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file is invalid JSON
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        return json.load(f)


def write_config(config_path: str, config_data: Dict[str, Any]) -> None:
    """Write configuration to a JSON file."""
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    with open(config_path, 'w') as f:
        json.dump(config_data, f, indent=2)


def backup_file(source_path: str, backup_dir: str) -> str:
    """
    Create a backup copy of a file.
    
    Args:
        source_path: Path to the file to backup
        backup_dir: Directory to store the backup
        
    Returns:
        Path to the backup file
    """
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source file not found: {source_path}")
    
    os.makedirs(backup_dir, exist_ok=True)
    
    source_file = Path(source_path)
    backup_path = Path(backup_dir) / f"{source_file.stem}_backup{source_file.suffix}"
    
    shutil.copy2(source_path, backup_path)
    return str(backup_path)


def find_files(directory: str, pattern: str = "*.txt") -> List[str]:
    """
    Find files matching a pattern in a directory.
    
    Args:
        directory: Directory to search in
        pattern: File pattern to match (e.g., "*.py")
        
    Returns:
        List of file paths matching the pattern
    """
    directory_path = Path(directory)
    if not directory_path.exists():
        return []
    
    return [str(p) for p in directory_path.glob(pattern) if p.is_file()]


def get_file_info(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Get information about a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary with file information or None if file doesn't exist
    """
    try:
        stat = os.stat(file_path)
        return {
            'size': stat.st_size,
            'modified': stat.st_mtime,
            'created': stat.st_ctime,
            'is_directory': os.path.isdir(file_path),
            'permissions': oct(stat.st_mode)[-3:]
        }
    except (OSError, FileNotFoundError):
        return None


def cleanup_temp_files(temp_dir: str, max_age_days: int = 7) -> int:
    """
    Clean up temporary files older than specified days.
    
    Args:
        temp_dir: Directory containing temporary files
        max_age_days: Maximum age in days before deletion
        
    Returns:
        Number of files deleted
    """
    if not os.path.exists(temp_dir):
        return 0
    
    import time
    current_time = time.time()
    max_age_seconds = max_age_days * 24 * 60 * 60
    deleted_count = 0
    
    for root, dirs, files in os.walk(temp_dir):
        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                file_age = current_time - os.path.getctime(file_path)
                if file_age > max_age_seconds:
                    os.remove(file_path)
                    deleted_count += 1
            except OSError:
                continue  # Skip files we can't access
    
    return deleted_count


if __name__ == "__main__":
    # Example usage
    test_config = {
        "app_name": "File Utils",
        "version": "1.0.0",
        "debug": False
    }
    
    # This is just for testing the module
    print("File utilities module loaded successfully")