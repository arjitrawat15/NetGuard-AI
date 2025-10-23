import pandas as pd
import os

def preprocess_packet_data():
    input_file = 'data/packets_cleaned.csv'
    output_file = 'data/packets_features.csv'

    print("🔄 Loading packet data...")
    df = pd.read_csv(input_file)

    print(f"✅ Loaded {len(df)} rows with columns: {list(df.columns)}")

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
    print(f"✅ Features saved to {output_file} ({len(df)} rows)")

if __name__ == "__main__":
    preprocess_packet_data()
