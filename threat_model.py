import time
import json
import os
import logging
from collections import defaultdict

# Setup logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [INFO] %(message)s")

class ThreatDetector:
    def __init__(self):
        self.packet_count = defaultdict(int)
        self.port_activity = defaultdict(set)
        self.last_reset = time.time()
        self.reset_interval = 60  # reset stats every 60 seconds
        self.threat_log_path = os.path.join("data", "threat_logs.json")

        if not os.path.exists("data"):
            os.makedirs("data")

        # Ensure file exists
        if not os.path.exists(self.threat_log_path):
            with open(self.threat_log_path, "w") as f:
                json.dump([], f)

        logging.info("🛡️ ThreatDetector initialized")

    def analyze_packet(self, packet_info):
        src = packet_info.get("src", "unknown")
        dst = packet_info.get("dst", "unknown")
        proto = packet_info.get("proto", "unknown")
        sport = packet_info.get("sport", None)
        dport = packet_info.get("dport", None)
        size = packet_info.get("size", 0)

        current_time = time.time()

        # Reset every minute
        if current_time - self.last_reset > self.reset_interval:
            self.packet_count.clear()
            self.port_activity.clear()
            self.last_reset = current_time

        # Count packets per source
        self.packet_count[src] += 1

        # Track distinct ports per source
        if dport:
            self.port_activity[src].add(dport)

        # ---- RULE 1: Basic DoS Detection ----
        if self.packet_count[src] > 100:
            self._log_threat("Possible DoS Attack", src, dst, proto, size)

        # ---- RULE 2: Port Scan Detection ----
        if len(self.port_activity[src]) > 10:
            self._log_threat("Port Scan Detected", src, dst, proto, size)

        # ---- RULE 3: Suspicious External IPs ----
        if not src.startswith("192.168.") and not src.startswith("10."):
            if proto == "TCP" and size > 1000:
                self._log_threat("Suspicious Large TCP Packet", src, dst, proto, size)

    def _log_threat(self, threat_type, src, dst, proto, size):
        threat_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": threat_type,
            "src": src,
            "dst": dst,
            "proto": proto,
            "size": size
        }

        logging.warning(f"⚠️ {threat_type} | Src: {src} -> Dst: {dst} | Proto: {proto} | Size: {size}")

        with open(self.threat_log_path, "r+") as f:
            data = json.load(f)
            data.append(threat_data)
            f.seek(0)
            json.dump(data, f, indent=4)
