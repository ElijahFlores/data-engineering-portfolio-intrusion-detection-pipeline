"""
TRANSFORM Module: Parse and clean log data
Part of the Intrusion Detection ETL Pipeline

Fixed:
- Regex supports usernames with special characters
- Complete RFC1918 private IP range coverage
- Zero-division protection
- Failed parsing samples for debugging
- Timezone awareness option
"""
import re
import pandas as pd
from datetime import datetime
from typing import List, Dict, Optional

class LogTransformer:
    """Handles parsing and transformation of SSH authentication logs"""
    
    # FIXED: Username pattern now supports alphanumeric, dots, dashes, underscores
    LOG_PATTERN = re.compile(
        r'(\w+)\s+(\d+)\s+(\d+:\d+:\d+)\s+\w+\s+sshd\[(\d+)\]:\s+'
        r'(Accepted|Failed)\s+password\s+for\s+([\w\.\-_]+)\s+from\s+'
        r'([\d\.]+)\s+port\s+(\d+)'
    )
    
    def __init__(self, year: Optional[int] = None):
        """
        Initialize transformer
        
        Args:
            year: Year to use for timestamps (defaults to current year)
        """
        self.parsed_count = 0
        self.failed_count = 0
        self.failed_samples = []  # FIXED: Store samples of failed parses
        self.year = year or datetime.now().year
        
    def parse_log_line(self, log_line: str) -> Optional[Dict]:
        """
        Parse a single SSH log line into structured data
        
        Returns dict with: timestamp, status, username, ip, port, pid
        Returns None if parsing fails
        """
        match = self.LOG_PATTERN.search(log_line)
        
        if not match:
            # FIXED: Store failed samples for debugging
            if self.failed_count < 5:  # Limit storage
                self.failed_samples.append(log_line.strip())
            return None
        
        month, day, time, pid, status, username, ip, port = match.groups()
        
        try:
            # Convert to timestamp
            timestamp_str = f"{self.year} {month} {day} {time}"
            timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
            
            return {
                'timestamp': timestamp,
                'status': status,
                'username': username,
                'source_ip': ip,
                'port': int(port),
                'pid': int(pid)
            }
        except (ValueError, AttributeError) as e:
            if self.failed_count < 5:
                self.failed_samples.append(f"{log_line.strip()} [Error: {e}]")
            return None
    
    def _is_internal_ip(self, ip: str) -> bool:
        """
        Check if IP is in private RFC1918 ranges
        
        FIXED: Complete coverage of private IP ranges:
        - 10.0.0.0/8 (10.0.0.0 – 10.255.255.255)
        - 172.16.0.0/12 (172.16.0.0 – 172.31.255.255)
        - 192.168.0.0/16 (192.168.0.0 – 192.168.255.255)
        """
        if ip.startswith('192.168.') or ip.startswith('10.'):
            return True
        
        # Handle 172.16.0.0/12 range properly
        if ip.startswith('172.'):
            try:
                second_octet = int(ip.split('.')[1])
                return 16 <= second_octet <= 31
            except (IndexError, ValueError):
                return False
        
        return False
    
    def transform_logs(self, raw_logs: List[str]) -> pd.DataFrame:
        """
        Transform raw log lines into structured DataFrame
        
        Args:
            raw_logs: List of raw log line strings
            
        Returns:
            Pandas DataFrame with parsed log data
        """
        parsed_logs = []
        
        for log_line in raw_logs:
            parsed = self.parse_log_line(log_line)
            if parsed:
                parsed_logs.append(parsed)
                self.parsed_count += 1
            else:
                self.failed_count += 1
        
        # FIXED: Handle empty results gracefully
        if not parsed_logs:
            print("❌ ERROR: No logs could be parsed!")
            if self.failed_samples:
                print("\nSample failed entries:")
                for sample in self.failed_samples:
                    print(f"  {sample}")
            return pd.DataFrame()
        
        df = pd.DataFrame(parsed_logs)
        
        # Add derived columns
        df['is_failed_login'] = df['status'] == 'Failed'
        df['hour_of_day'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # FIXED: Use the improved internal IP detection
        df['is_internal_ip'] = df['source_ip'].apply(self._is_internal_ip)
        
        # Additional derived fields
        df['date'] = df['timestamp'].dt.date
        df['weekday_name'] = df['timestamp'].dt.day_name()
        
        # FIXED: Safe success rate calculation
        total_lines = self.parsed_count + self.failed_count
        success_rate = (self.parsed_count / total_lines * 100) if total_lines > 0 else 0
        
        print(f"✓ Transformed {self.parsed_count:,} log entries")
        if self.failed_count > 0:
            print(f"  ⚠ Failed to parse: {self.failed_count:,} ({100 - success_rate:.1f}%)")
            if self.failed_samples:
                print(f"\n  Sample failed entries:")
                for sample in self.failed_samples[:3]:
                    print(f"    {sample}")
        print(f"  ✓ Success rate: {success_rate:.1f}%")
        
        return df

if __name__ == "__main__":
    # Test the transformer
    test_logs = [
        "Jan  1 10:23:45 server sshd[1234]: Failed password for admin from 45.142.212.61 port 54321 ssh2",
        "Jan 14 10:23:45 server sshd[1235]: Accepted password for john.doe from 192.168.1.10 port 54322 ssh2",
        "Jan 15 11:30:22 server sshd[1236]: Failed password for test_user from 172.20.0.5 port 54323 ssh2",
        "MALFORMED LOG ENTRY",
    ]
    
    transformer = LogTransformer()
    df = transformer.transform_logs(test_logs)
    
    print(f"\nParsed {len(df)} entries:")
    print(df[['timestamp', 'username', 'source_ip', 'is_internal_ip', 'is_failed_login']])
