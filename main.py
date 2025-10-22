from packet_capture import capture_packets
from threat_model import ThreatDetector

if __name__ == "__main__":
    print("🚀 Starting NETGUARD-AI System...")
    
    # Initialize threat detector (model will be loaded later)
    detector = ThreatDetector()

    # Start live packet capture (placeholder for now)
    capture_packets(detector)
