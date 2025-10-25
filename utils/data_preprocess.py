import pandas as pd
import os
import json
import random
from datetime import datetime, timedelta

def preprocess_packet_data():
    input_file = 'data/packets_cleaned.csv'
    output_file = 'data/packets_features.csv'

    print("Loading packet data...")
    df = pd.read_csv(input_file)

    print(f"Loaded {len(df)} rows with columns: {list(df.columns)}")

    # Ensure ports are integers; fill NaN with 0
    df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0).astype(int)
    df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0).astype(int)

    # Ensure IPs are strings
    df['src_ip'] = df['src_ip'].astype(str).str.strip()
    df['dst_ip'] = df['dst_ip'].astype(str).str.strip()

    # Extract last octet safely
    def get_last_octet(ip):
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return int(parts[-1])
            return 0
        except:
            return 0

    df['src_last'] = df['src_ip'].apply(get_last_octet)
    df['dst_last'] = df['dst_ip'].apply(get_last_octet)

    # Flag local IPs (private 192.168.x.x range)
    df['src_local'] = df['src_ip'].apply(lambda x: 1 if x.startswith('192.168') else 0)
    df['dst_local'] = df['dst_ip'].apply(lambda x: 1 if x.startswith('192.168') else 0)

    # Save the processed features
    df.to_csv(output_file, index=False)
    print(f"Features saved to {output_file} ({len(df)} rows)")

def generate_sample_data(num_packets=100):
    """Generate sample packet data with CURRENT timestamps"""
    import random
    from datetime import datetime, timedelta
    
    os.makedirs('data', exist_ok=True)
    
    protocols = ['TCP', 'UDP', 'ICMP']
    ips = [
        '192.168.1.100', '192.168.1.101', '192.168.1.102',
        '8.8.8.8', '1.1.1.1', '172.217.164.46', '142.250.185.206',
        '104.244.42.129', '151.101.1.140', '13.107.42.14'
    ]
    
    packets = []
    now = datetime.now()
    
    for i in range(num_packets):
        # Generate timestamps within LAST 5 MINUTES (for Live Monitoring)
        time_offset = random.uniform(0, 300)  # 0-300 seconds ago
        timestamp = now - timedelta(seconds=time_offset)
        
        protocol = random.choice(protocols)
        src_ip = random.choice(ips)
        dst_ip = random.choice([ip for ip in ips if ip != src_ip])
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53, 22, 3389, 8080])
        size = random.randint(64, 1500)
        
        packets.append({
            'Timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Protocol': protocol,
            'Source Port': src_port,
            'Destination Port': dst_port,
            'Packet Size': size
        })
    
    # Sort by timestamp (newest first for dashboard)
    packets.sort(key=lambda x: x['Timestamp'], reverse=True)
    
    # Save to CSV
    df = pd.DataFrame(packets)
    df.to_csv('data/packets_log.csv', index=False)
    print(f"Generated {num_packets} sample packets with current timestamps")
    return True

def generate_sample_threats(num_threats=20):
    """Generate sample threat data"""
    import random
    from datetime import datetime, timedelta
    
    os.makedirs('data', exist_ok=True)
    
    threat_types = [
        'port_scan_detected', 'dos_attack', 'suspicious_traffic',
        'malware_detected', 'brute_force_attempt', 'data_exfiltration'
    ]
    
    ips = ['192.168.1.100', '192.168.1.101', '8.8.8.8', '1.1.1.1', '104.244.42.129']
    
    threats = []
    now = datetime.now()
    
    for i in range(num_threats):
        time_offset = random.uniform(0, 300)  # Last 5 minutes
        timestamp = now - timedelta(seconds=time_offset)
        
        threats.append({
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'type': random.choice(threat_types),
            'source_ip': random.choice(ips),
            'destination_ip': random.choice(ips),
            'severity': random.choice(['High', 'Medium', 'Low']),
            'description': f'Detected {random.choice(threat_types)} activity'
        })
    
    # Sort by timestamp (newest first)
    threats.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Save to JSON
    with open('data/threat_logs.json', 'w') as f:
        json.dump(threats, f, indent=2)
    
    print(f"Generated {num_threats} sample threats")
    return True

if __name__ == "__main__":
    preprocess_packet_data()
    generate_sample_data()
    generate_sample_threats()