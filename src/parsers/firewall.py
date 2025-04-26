import re
from datetime import datetime
import pandas as pd

class FirewallParser:
    """Basic parser for firewall logs (expand with your actual format)"""
    
    def __init__(self):
        # Example pattern - adjust based on your firewall's log format
        self.pattern = re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
            r' \[(?P<severity>\w+)\]'
            r' (?P<source_ip>\d+\.\d+\.\d+\.\d+)'
            r':(?P<source_port>\d+) ->'
            r' (?P<dest_ip>\d+\.\d+\.\d+\.\d+)'
            r':(?P<dest_port>\d+)'
            r' (?P<action>\w+)'
            r' (?P<rule>\w+)'
        )
    
    def parse_line(self, line: str) -> dict:
        """Parse single firewall log line"""
        match = self.pattern.match(line)
        if not match:
            return {}
            
        data = match.groupdict()
        
        # Convert timestamp
        try:
            data['timestamp'] = datetime.strptime(
                data['timestamp'], 
                '%Y-%m-%d %H:%M:%S'
            )
        except ValueError:
            data['timestamp'] = None
            
        return data

    def parse_to_df(self, logs: list) -> pd.DataFrame:
        """Convert multiple logs to DataFrame"""
        return pd.DataFrame([self.parse_line(line) for line in logs if line.strip()])