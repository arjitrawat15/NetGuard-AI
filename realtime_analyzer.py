import time
import logging
import threading
import queue
import json
import os
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

class RealTimeAnalyzer:
    """
    Real-time network traffic analyzer with ML-based threat detection
    """
    
    def __init__(self, window_size=5, model_path=None):
        """
        Initialize the real-time analyzer
        
        Args:
            window_size: Time window in seconds for feature aggregation
            model_path: Path to the trained ML model (joblib format)
        """
        self.window_size = window_size
        self.model_path = model_path
        self.model = None
        
        # Thread-safe queue for packet storage
        self.packet_buffer = deque(maxlen=10000)
        self.prediction_queue = queue.Queue(maxsize=1000)
        
        # Statistics
        self.total_packets = 0
        self.total_predictions = 0
        self.threats_detected = 0
        
        # Control flags
        self.running = False
        self.capture_thread = None
        self.analysis_thread = None
        
        # Load ML model if provided
        if model_path:
            self._load_model(model_path)
        
        logging.info(f"🛡️ RealTimeAnalyzer initialized (window={window_size}s)")
    
    def _load_model(self, model_path: str):
        """Load the trained ML model"""
        try:
            import joblib
            self.model = joblib.load(model_path)
            logging.info(f"✅ ML model loaded from {model_path}")
        except Exception as e:
            logging.warning(f"+Could not load model: {e}")
            logging.warning("Using rule-based detection instead")
            self.model = None
    
    def _packet_callback(self, packet):
        """Callback function for each captured packet"""
        try:
            if IP not in packet:
                return
            
            # Extract packet information
            packet_data = {
                'timestamp': datetime.now(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'size': len(packet),
                'ttl': packet[IP].ttl if hasattr(packet[IP], 'ttl') else 0,
                'src_port': None,
                'dst_port': None,
                'flags': None
            }
            
            # TCP specific features
            if TCP in packet:
                packet_data['src_port'] = packet[TCP].sport
                packet_data['dst_port'] = packet[TCP].dport
                packet_data['flags'] = str(packet[TCP].flags)
            
            # UDP specific features
            elif UDP in packet:
                packet_data['src_port'] = packet[UDP].sport
                packet_data['dst_port'] = packet[UDP].dport
            
            # ICMP specific features
            elif ICMP in packet:
                packet_data['icmp_type'] = packet[ICMP].type
            
            # Add to buffer
            self.packet_buffer.append(packet_data)
            self.total_packets += 1
            
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    
    def _capture_packets(self, interface=None):
        """Continuous packet capture in a separate thread"""
        logging.info("📡 Starting packet capture thread...")
        try:
            sniff(
                prn=self._packet_callback,
                iface=interface,
                store=False,
                filter="ip",
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            logging.error(f"Packet capture error: {e}")
            self.running = False
    
    def extract_flow_features(self, packets: List[Dict]) -> Dict:
        """
        Extract aggregated flow-level features from packet window
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            Dictionary of extracted features
        """
        if not packets:
            return self._get_default_features()
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(packets)
        
        # Basic statistics
        features = {
            # Packet count features
            'total_packets': len(df),
            'unique_src_ips': df['src_ip'].nunique(),
            'unique_dst_ips': df['dst_ip'].nunique(),
            'unique_src_ports': df['src_port'].nunique() if 'src_port' in df else 0,
            'unique_dst_ports': df['dst_port'].nunique() if 'dst_port' in df else 0,
            
            # Size features
            'total_bytes': df['size'].sum(),
            'mean_packet_size': df['size'].mean(),
            'max_packet_size': df['size'].max(),
            'min_packet_size': df['size'].min(),
            'std_packet_size': df['size'].std() if len(df) > 1 else 0,
            
            # Protocol distribution
            'tcp_packets': (df['protocol'] == 6).sum(),
            'udp_packets': (df['protocol'] == 17).sum(),
            'icmp_packets': (df['protocol'] == 1).sum(),
            'other_protocol_packets': ((df['protocol'] != 6) & 
                                      (df['protocol'] != 17) & 
                                      (df['protocol'] != 1)).sum(),
            
            # Port analysis (common ports)
            'http_packets': ((df['dst_port'] == 80) | (df['src_port'] == 80)).sum() if 'dst_port' in df else 0,
            'https_packets': ((df['dst_port'] == 443) | (df['src_port'] == 443)).sum() if 'dst_port' in df else 0,
            'dns_packets': ((df['dst_port'] == 53) | (df['src_port'] == 53)).sum() if 'dst_port' in df else 0,
            'ssh_packets': ((df['dst_port'] == 22) | (df['src_port'] == 22)).sum() if 'dst_port' in df else 0,
            
            # TTL features
            'mean_ttl': df['ttl'].mean() if 'ttl' in df else 0,
            'min_ttl': df['ttl'].min() if 'ttl' in df else 0,
            'max_ttl': df['ttl'].max() if 'ttl' in df else 0,
            
            # Time-based features
            'duration': (df['timestamp'].max() - df['timestamp'].min()).total_seconds() if len(df) > 1 else 0,
            'packets_per_second': len(df) / max(1, (df['timestamp'].max() - df['timestamp'].min()).total_seconds()) if len(df) > 1 else 0,
        }
        
        # IP distribution analysis
        top_src_ip = df['src_ip'].value_counts().iloc[0] if len(df) > 0 else 0
        top_dst_ip = df['dst_ip'].value_counts().iloc[0] if len(df) > 0 else 0
        
        features['max_src_ip_count'] = top_src_ip
        features['max_dst_ip_count'] = top_dst_ip
        features['src_ip_entropy'] = self._calculate_entropy(df['src_ip'])
        features['dst_ip_entropy'] = self._calculate_entropy(df['dst_ip'])
        
        return features
    
    def _calculate_entropy(self, series):
        """Calculate Shannon entropy of a series"""
        try:
            value_counts = series.value_counts()
            probabilities = value_counts / len(series)
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-9))
            return entropy
        except:
            return 0
    
    def _get_default_features(self) -> Dict:
        """Return default features when no packets available"""
        return {
            'total_packets': 0, 'unique_src_ips': 0, 'unique_dst_ips': 0,
            'unique_src_ports': 0, 'unique_dst_ports': 0, 'total_bytes': 0,
            'mean_packet_size': 0, 'max_packet_size': 0, 'min_packet_size': 0,
            'std_packet_size': 0, 'tcp_packets': 0, 'udp_packets': 0,
            'icmp_packets': 0, 'other_protocol_packets': 0, 'http_packets': 0,
            'https_packets': 0, 'dns_packets': 0, 'ssh_packets': 0,
            'mean_ttl': 0, 'min_ttl': 0, 'max_ttl': 0, 'duration': 0,
            'packets_per_second': 0, 'max_src_ip_count': 0,
            'max_dst_ip_count': 0, 'src_ip_entropy': 0, 'dst_ip_entropy': 0
        }
    
    def predict_threat(self, features: Dict) -> Dict:
        """
        Predict if traffic is normal or threat using ML model or rules
        
        Args:
            features: Extracted features dictionary
            
        Returns:
            Prediction result dictionary
        """
        prediction = {
            'timestamp': datetime.now().isoformat(),
            'is_threat': False,
            'threat_type': 'normal',
            'confidence': 0.0,
            'features': features
        }
        
        if self.model is not None:
            # ML-based prediction
            try:
                # Prepare features for model (ensure correct order)
                feature_values = [features.get(k, 0) for k in sorted(features.keys())]
                X = np.array(feature_values).reshape(1, -1)
                
                # Get prediction
                y_pred = self.model.predict(X)[0]
                
                # Get probability if available
                if hasattr(self.model, 'predict_proba'):
                    y_proba = self.model.predict_proba(X)[0]
                    prediction['confidence'] = float(y_proba[1]) if y_pred == 1 else float(y_proba[0])
                
                prediction['is_threat'] = bool(y_pred == 1)
                prediction['threat_type'] = 'ml_detected_threat' if y_pred == 1 else 'normal'
                
            except Exception as e:
                logging.error(f"ML prediction error: {e}")
                # Fall back to rule-based
                prediction = self._rule_based_prediction(features)
        else:
            # Rule-based prediction
            prediction = self._rule_based_prediction(features)
        
        return prediction
    
    def _rule_based_prediction(self, features: Dict) -> Dict:
        """Rule-based threat detection as fallback"""
        is_threat = False
        threat_type = 'normal'
        confidence = 0.0
        
        # Rule 1: High packet rate (possible DoS)
        if features['packets_per_second'] > 100:
            is_threat = True
            threat_type = 'possible_dos_attack'
            confidence = min(features['packets_per_second'] / 200, 1.0)
        
        # Rule 2: Port scanning (many unique destination ports)
        elif features['unique_dst_ports'] > 50:
            is_threat = True
            threat_type = 'port_scan_detected'
            confidence = min(features['unique_dst_ports'] / 100, 1.0)
        
        # Rule 3: Suspicious large packets
        elif features['max_packet_size'] > 1400 and features['tcp_packets'] > 10:
            is_threat = True
            threat_type = 'suspicious_large_packets'
            confidence = 0.6
        
        # Rule 4: Low entropy (possible attack pattern)
        elif features['dst_ip_entropy'] < 0.5 and features['total_packets'] > 20:
            is_threat = True
            threat_type = 'suspicious_pattern'
            confidence = 0.5
        
        return {
            'timestamp': datetime.now().isoformat(),
            'is_threat': is_threat,
            'threat_type': threat_type,
            'confidence': confidence,
            'features': features
        }
    
    def _analysis_loop(self):
        """Continuous analysis loop in separate thread"""
        logging.info("🔍 Starting analysis thread...")
        
        while self.running:
            try:
                # Wait for window duration
                time.sleep(self.window_size)
                
                # Get packets from buffer
                packets = list(self.packet_buffer)
                
                if len(packets) == 0:
                    continue
                
                # Extract features
                features = self.extract_flow_features(packets)
                
                # Predict threat
                prediction = self.predict_threat(features)
                
                # Add to prediction queue
                try:
                    self.prediction_queue.put_nowait(prediction)
                except queue.Full:
                    # Remove oldest prediction and add new one
                    try:
                        self.prediction_queue.get_nowait()
                        self.prediction_queue.put_nowait(prediction)
                    except:
                        pass
                
                self.total_predictions += 1
                
                if prediction['is_threat']:
                    self.threats_detected += 1
                    logging.warning(
                        f"⚠️ THREAT DETECTED: {prediction['threat_type']} "
                        f"(confidence: {prediction['confidence']:.2%})"
                    )
                else:
                    logging.info(
                        f"✅ Normal traffic (packets: {features['total_packets']}, "
                        f"bytes: {features['total_bytes']})"
                    )
                
                # Save prediction to file for dashboard
                self._save_prediction_for_dashboard(prediction)
                
                # Update stats file for dashboard
                self._update_stats_for_dashboard()
                
            except Exception as e:
                logging.error(f"Analysis loop error: {e}")
    
    def _save_prediction_for_dashboard(self, prediction: Dict):
        """Save prediction to JSON file for dashboard consumption"""
        try:
            predictions_file = 'data/ml_predictions.json'
            os.makedirs('data', exist_ok=True)

            # Load existing predictions
            predictions = []
            if os.path.exists(predictions_file):
                try:
                    with open(predictions_file, 'r') as f:
                        predictions = json.load(f)
                except:
                    predictions = []

            # Add new prediction (keep last 1000)
            predictions.append(prediction)
            if len(predictions) > 1000:
                predictions = predictions[-1000:]

            # ✅ Fix: handle NumPy int/float types during JSON dump
            def convert_types(o):
                if isinstance(o, (np.integer, np.int64, np.int32)):
                    return int(o)
                if isinstance(o, (np.floating, np.float64, np.float32)):
                    return float(o)
                if isinstance(o, np.ndarray):
                    return o.tolist()
                return str(o)

            with open(predictions_file, 'w') as f:
                json.dump(predictions, f, indent=2, default=convert_types)

        except Exception as e:
            logging.error(f"Error saving prediction for dashboard: {e}")


    
    def _update_stats_for_dashboard(self):
        """Update statistics file for dashboard"""
        try:
            stats_file = 'data/ml_stats.json'
            os.makedirs('data', exist_ok=True)
            
            stats = {
                'running': self.running,
                'window_size': self.window_size,
                'total_packets': self.total_packets,
                'total_predictions': self.total_predictions,
                'threats_detected': self.threats_detected,
                'buffer_size': len(self.packet_buffer),
                'prediction_queue_size': self.prediction_queue.qsize(),
                'last_update': datetime.now().isoformat()
            }
            
            with open(stats_file, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            logging.error(f"Error updating stats for dashboard: {e}")
    
    def start(self, interface=None):
        """Start the real-time analysis pipeline"""
        if self.running:
            logging.warning("Analyzer already running")
            return
        
        self.running = True
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface,),
            daemon=True
        )
        self.capture_thread.start()
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True
        )
        self.analysis_thread.start()
        
        logging.info("🚀 Real-time analyzer started")
    
    def stop(self):
        """Stop the analysis pipeline gracefully"""
        logging.info("🛑 Stopping analyzer...")
        self.running = False
        
        # Wait for threads to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
        
        logging.info("✅ Analyzer stopped")
    
    def get_latest_prediction(self) -> Optional[Dict]:
        """Get the latest prediction from queue"""
        try:
            return self.prediction_queue.get_nowait()
        except queue.Empty:
            return None
    
    def get_statistics(self) -> Dict:
        """Get current statistics"""
        return {
            'total_packets': self.total_packets,
            'total_predictions': self.total_predictions,
            'threats_detected': self.threats_detected,
            'buffer_size': len(self.packet_buffer),
            'prediction_queue_size': self.prediction_queue.qsize()
        }


def main():
    """Main function to run the real-time analyzer"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Real-time Network Traffic Analyzer")
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface to capture packets (default: system default)"
    )
    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Time window in seconds for feature aggregation (default: 5)"
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Path to trained ML model (joblib format)"
    )
    args = parser.parse_args()
    
    # Create analyzer
    analyzer = RealTimeAnalyzer(
        window_size=args.window,
        model_path=args.model
    )
    
    try:
        # Start analyzer
        analyzer.start(interface=args.interface)
        
        logging.info("Press Ctrl+C to stop...")
        
        # Keep running and print statistics periodically
        while True:
            time.sleep(10)
            stats = analyzer.get_statistics()
            logging.info(
                f"📊 Stats - Packets: {stats['total_packets']}, "
                f"Predictions: {stats['total_predictions']}, "
                f"Threats: {stats['threats_detected']}"
            )
    
    except KeyboardInterrupt:
        logging.info("\n🛑 Stopping analyzer...")
    finally:
        analyzer.stop()
        logging.info("👋 Goodbye!")


if __name__ == "__main__":
    main()
