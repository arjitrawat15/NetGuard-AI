def extract_features(packet):
    """
    Extract basic features from scapy packet (expand later for ML).
    """
    features = {
        "packet_length": len(packet),
        "protocol": packet.proto if hasattr(packet, "proto") else None,
    }
    return features