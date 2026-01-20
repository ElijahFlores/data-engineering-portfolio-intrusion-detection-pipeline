"""
EXTRACT Module: Read raw log files
Part of the Intrusion Detection ETL Pipeline

Fixed:
- Relative path handling for flexible execution
- Memory-efficient streaming option
- Better error messages
"""
import os
from typing import List, Generator
from pathlib import Path

class LogExtractor:
    """Handles extraction of raw log files from source directories"""
    
    def __init__(self, log_directory: str = None):
        """
        Initialize extractor with log directory
        
        Args:
            log_directory: Path to log directory (relative or absolute)
                         If None, defaults to 'data/raw' from project root
        """
        if log_directory is None:
            # FIXED: Find project root dynamically
            project_root = Path(__file__).parent.parent
            log_directory = project_root / 'data' / 'raw'
        
        self.log_directory = Path(log_directory)
        
        if not self.log_directory.exists():
            print(f"⚠ Warning: Log directory does not exist: {self.log_directory}")
            print(f"  Creating directory...")
            self.log_directory.mkdir(parents=True, exist_ok=True)
        
    def extract_logs(self, filename: str) -> List[str]:
        """
        Extract log entries from a file
        
        Args:
            filename: Name of the log file to extract
            
        Returns:
            List of log lines as strings
            
        Raises:
            FileNotFoundError: If log file doesn't exist
        """
        filepath = self.log_directory / filename
        
        if not filepath.exists():
            raise FileNotFoundError(
                f"Log file not found: {filepath}\n"
                f"Current directory: {os.getcwd()}\n"
                f"Looking in: {self.log_directory}"
            )
        
        with open(filepath, 'r', encoding='utf-8') as f:
            logs = f.readlines()
        
        print(f"✓ Extracted {len(logs):,} log entries from {filename}")
        return logs
    
    def extract_logs_streaming(self, filename: str) -> Generator[str, None, None]:
        """
        Extract logs using generator for memory efficiency (large files)
        
        Args:
            filename: Name of the log file
            
        Yields:
            Individual log lines
        """
        filepath = self.log_directory / filename
        
        if not filepath.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                yield line.strip()
    
    def extract_multiple_logs(self, filenames: List[str]) -> List[str]:
        """
        Extract from multiple log files and combine
        
        Args:
            filenames: List of log filenames
            
        Returns:
            Combined list of all log lines
        """
        all_logs = []
        for filename in filenames:
            try:
                all_logs.extend(self.extract_logs(filename))
            except FileNotFoundError as e:
                print(f"⚠ Skipping {filename}: {e}")
        
        print(f"✓ Total extracted: {len(all_logs):,} entries from {len(filenames)} files")
        return all_logs
    
    def list_available_logs(self) -> List[str]:
        """List all .log files in the log directory"""
        log_files = list(self.log_directory.glob('*.log'))
        return [f.name for f in log_files]

if __name__ == "__main__":
    # Test the extractor
    extractor = LogExtractor()
    
    print(f"Log directory: {extractor.log_directory}")
    print(f"Available logs: {extractor.list_available_logs()}")
    
    if extractor.list_available_logs():
        logs = extractor.extract_logs('ssh_auth.log')
        print(f"\nSample log entry:\n  {logs[0]}")
    else:
        print("\n⚠ No log files found. Run generate_logs.py first.")
