import random
from datetime import datetime, timedelta

def generate_simple_logs(num_entries=100):
    """Generate basic network log entries"""
    log_levels = ['INFO', 'WARNING', 'ERROR']
    protocols = ['HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS']
    status_codes = [200, 301, 400, 401, 403, 404, 500]
    ips = ['192.168.1.' + str(i) for i in range(1, 50)]
    
    logs = []
    base_time = datetime.now()
    
    for i in range(num_entries):
        time = base_time - timedelta(minutes=random.randint(0, 1440))
        log = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': random.choice(ips),
            'dest_ip': random.choice(ips),
            'protocol': random.choice(protocols),
            'port': random.randint(1, 65535),
            'status': random.choice(status_codes),
            'bytes': random.randint(0, 10000),
            'level': random.choice(log_levels),
            'message': generate_log_message()
        }
        logs.append(log)
    
    return logs

def generate_log_message():
    messages = [
        "Connection established",
        "Connection terminated",
        "Authentication failed",
        "Access denied",
        "Request processed",
        "Timeout occurred",
        "Invalid protocol",
        "Port scan detected",
        "Brute force attempt",
        "Data transfer complete"
    ]
    return random.choice(messages)