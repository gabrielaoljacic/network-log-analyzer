import re
from datetime import datetime

class SyslogParser:
    """Parse standard syslog messages"""
    
    SYSLOG_FORMAT = (
        r'^(?P<priority>\<(\d+)\>)?'
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})?'
        r'\s(?P<host>\S+)'
        r'\s(?P<process>\S+)(?:\[(?P<pid>\d+)\])?:'
        r'\s(?P<message>.*)$'
    )
    
    def __init__(self):
        self.pattern = re.compile(self.SYSLOG_FORMAT)
    
    def parse_line(self, line):
        match = self.pattern.match(line)
        if not match:
            return None
            
        data = match.groupdict()
        
        # Parse timestamp (assuming current year)
        try:
            timestamp_str = data['timestamp']
            if timestamp_str:
                current_year = datetime.now().year
                timestamp_str = f"{timestamp_str} {current_year}"
                data['timestamp'] = datetime.strptime(timestamp_str, '%b %d %H:%M:%S %Y')
        except (ValueError, TypeError):
            data['timestamp'] = None
            
        # Extract priority components
        if data.get('priority'):
            pri = int(data['priority'].strip('<>'))
            data['facility'] = pri // 8
            data['severity'] = pri % 8
            
        return data