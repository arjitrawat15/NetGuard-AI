import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

def generate_synthetic_training_data(n_samples=1000):
    print("Generating synthetic training data...")
    
    np.random.seed(42)
    
    normal_samples = n_samples // 2
    normal_data = {
        'total_packets': np.random.randint(10, 100, normal_samples),
        'unique_src_ips': np.random.randint(1, 10, normal_samples),
        'unique_dst_ips': np.random.randint(1, 20, normal_samples),
        'unique_src_ports': np.random.randint(1, 50, normal_samples),
        'unique_dst_ports': np.random.randint(1, 30, normal_samples),
        'total_bytes': np.random.randint(1000, 50000, normal_samples),
        'mean_packet_size': np.random.randint(64, 1500, normal_samples),
        'max_packet_size': np.random.randint(500, 1500, normal_samples),
        'min_packet_size': np.random.randint(40, 100, normal_samples),
        'std_packet_size': np.random.uniform(10, 200, normal_samples),
        'tcp_packets': np.random.randint(5, 80, normal_samples),
        'udp_packets': np.random.randint(0, 20, normal_samples),
        'icmp_packets': np.random.randint(0, 5, normal_samples),
        'other_protocol_packets': np.random.randint(0, 3, normal_samples),
        'http_packets': np.random.randint(0, 30, normal_samples),
        'https_packets': np.random.randint(0, 40, normal_samples),
        'dns_packets': np.random.randint(0, 10, normal_samples),
        'ssh_packets': np.random.randint(0, 5, normal_samples),
        'mean_ttl': np.random.randint(50, 128, normal_samples),
        'min_ttl': np.random.randint(30, 64, normal_samples),
        'max_ttl': np.random.randint(64, 255, normal_samples),
        'duration': np.random.uniform(1, 10, normal_samples),
        'packets_per_second': np.random.uniform(1, 50, normal_samples),
        'max_src_ip_count': np.random.randint(1, 20, normal_samples),
        'max_dst_ip_count': np.random.randint(1, 20, normal_samples),
        'src_ip_entropy': np.random.uniform(0.5, 3.0, normal_samples),
        'dst_ip_entropy': np.random.uniform(0.5, 3.0, normal_samples),
    }
    
    threat_samples = n_samples // 2
    threat_data = {
        'total_packets': np.random.randint(100, 1000, threat_samples),  # More packets
        'unique_src_ips': np.random.randint(1, 5, threat_samples),  # Fewer sources
        'unique_dst_ips': np.random.randint(50, 200, threat_samples),  # Many destinations
        'unique_src_ports': np.random.randint(1, 20, threat_samples),
        'unique_dst_ports': np.random.randint(50, 200, threat_samples),  # Port scanning
        'total_bytes': np.random.randint(10000, 500000, threat_samples),  # More data
        'mean_packet_size': np.random.randint(64, 1500, threat_samples),
        'max_packet_size': np.random.randint(1000, 1500, threat_samples),
        'min_packet_size': np.random.randint(40, 100, threat_samples),
        'std_packet_size': np.random.uniform(50, 500, threat_samples),
        'tcp_packets': np.random.randint(80, 900, threat_samples),  # High TCP
        'udp_packets': np.random.randint(0, 50, threat_samples),
        'icmp_packets': np.random.randint(0, 20, threat_samples),
        'other_protocol_packets': np.random.randint(0, 10, threat_samples),
        'http_packets': np.random.randint(0, 50, threat_samples),
        'https_packets': np.random.randint(0, 50, threat_samples),
        'dns_packets': np.random.randint(0, 20, threat_samples),
        'ssh_packets': np.random.randint(0, 10, threat_samples),
        'mean_ttl': np.random.randint(50, 128, threat_samples),
        'min_ttl': np.random.randint(30, 64, threat_samples),
        'max_ttl': np.random.randint(64, 255, threat_samples),
        'duration': np.random.uniform(1, 20, threat_samples),
        'packets_per_second': np.random.uniform(50, 500, threat_samples),  # High rate
        'max_src_ip_count': np.random.randint(50, 200, threat_samples),
        'max_dst_ip_count': np.random.randint(1, 10, threat_samples),
        'src_ip_entropy': np.random.uniform(0.1, 1.0, threat_samples),  # Low entropy
        'dst_ip_entropy': np.random.uniform(2.0, 4.0, threat_samples),  # High entropy
    }
    
    df_normal = pd.DataFrame(normal_data)
    df_normal['label'] = 0  # Normal
    
    df_threat = pd.DataFrame(threat_data)
    df_threat['label'] = 1  # Threat
    
    # Combine and shuffle
    df = pd.concat([df_normal, df_threat], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"✅ Generated {len(df)} samples ({normal_samples} normal, {threat_samples} threats)")
    
    return df

def train_model(output_path='models/threat_detector.joblib'):
    """ Training a Random Forest model for threat detection """
    print("🤖 Training ML model for threat detection...")
    
    df = generate_synthetic_training_data(n_samples=2000)
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"📚 Training set: {len(X_train)} samples")
    print(f"🧪 Test set: {len(X_test)} samples")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    
    print("🔄 Training model...")
    model.fit(X_train, y_train)
    
    print("\n📊 Model Evaluation:")
    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Threat']))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\n Top 10 Important Features:")
    print(feature_importance.head(10).to_string(index=False))
    
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, output_path)
    print(f"\n✅ Model saved to {output_path}")
    
    return model

if __name__ == "__main__":
    train_model()
