import re
from datetime import datetime

class ApacheParser:
    """Parse Apache Common/Combined log format"""
    
    COMMON_LOG_FORMAT = (
        r'(?P<host>\S+) \S+ (?P<user>\S+) \[(?P<time>.+?)\] '
        r'"(?P<request>.+?)" (?P<status>\d+) (?P<size>\S+)'
    )
    
    def __init__(self):
        self.pattern = re.compile(self.COMMON_LOG_FORMAT)
    
    def parse_line(self, line):
        match = self.pattern.match(line)
        if not match:
            return None
            
        data = match.groupdict()
        
        # Convert timestamp
        try:
            data['time'] = datetime.strptime(data['time'], '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            data['time'] = None
            
        # Parse request into components
        request_parts = data['request'].split()
        if len(request_parts) >= 3:
            data['method'] = request_parts[0]
            data['path'] = request_parts[1]
            data['protocol'] = request_parts[2]
        else:
            data['method'] = data['path'] = data['protocol'] = None
            
        return data