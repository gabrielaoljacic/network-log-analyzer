import pandas as pd
from .parsers.apache import ApacheParser
from .parsers.syslog import SyslogParser
from .parsers.firewall import FirewallParser

class LogParser:
    def __init__(self, log_type='auto'):
        self.parsers = {
            'apache': ApacheParser(),
            'syslog': SyslogParser(),
            'firewall': FirewallParser()
        }
        self.log_type = log_type
    
    def detect_log_type(self, line: str) -> str:
        """Auto-detect log format"""
        if 'apache' in line.lower() or 'GET' in line:
            return 'apache'
        elif '<' in line and '>' in line:  # Syslog priority
            return 'syslog'
        elif '->' in line and ('ALLOW' in line or 'DENY' in line):  # Firewall hints
            return 'firewall'
        return 'unknown'
    
    def parse_line(self, line):
        """Parse a single log line"""
        if isinstance(line, dict):
            return line  # Already parsed
            
        if self.log_type == 'auto':
            log_type = self.detect_log_type(line)
        else:
            log_type = self.log_type
            
        if log_type in self.parsers:
            return self.parsers[log_type].parse_line(line)
        return None
    
    def parse_logs(self, logs):
        """
        Parse multiple logs (accepts both raw lines and dictionaries)
        Returns a DataFrame
        """
        parsed_logs = []
        
        for log in logs:
            if isinstance(log, dict):
                parsed_logs.append(log)
            else:
                parsed = self.parse_line(log)
                if parsed:
                    parsed_logs.append(parsed)
        
        return pd.DataFrame(parsed_logs)
    
    def clean_logs(self, df):
        """Basic cleaning of log data"""
        if not isinstance(df, pd.DataFrame):
            return df
            
        # Convert timestamp to datetime if present
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        elif 'time' in df.columns:
            df['time'] = pd.to_datetime(df['time'], errors='coerce')
        
        # Add some derived features if timestamp exists
        time_col = 'timestamp' if 'timestamp' in df.columns else 'time' if 'time' in df.columns else None
        if time_col:
            df['hour'] = df[time_col].dt.hour
            df['day_of_week'] = df[time_col].dt.dayofweek
        
        return df