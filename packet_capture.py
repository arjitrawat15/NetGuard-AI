# packet_capture.py
from scapy.all import sniff, IP, TCP, UDP
import logging
import csv
import os
from datetime import datetime

def capture_packets(detector=None, interface=None):
    logging.info("📡 Starting packet capture...")

    log_file = "data/packets_log.csv"
    os.makedirs("data", exist_ok=True)

    # Create CSV file if it doesn't exist
    if not os.path.exists(log_file):
        with open(log_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Src_IP", "Dst_IP", "Protocol", "Src_Port", "Dst_Port", "Size"])

    def process_packet(packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                size = len(packet)

                sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None)
                dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)

                # Save to CSV
                with open(log_file, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([datetime.now(), src_ip, dst_ip, proto, sport, dport, size])

                # Print live traffic info
                print(f"{src_ip}:{sport} -> {dst_ip}:{dport} | Proto: {proto} | Size: {size} bytes")

                # If detector provided, analyze packet
                if detector:
                    packet_info = {"src": src_ip, "dst": dst_ip, "proto": proto,
                                   "sport": sport, "dport": dport, "size": size}
                    detector.analyze_packet(packet_info)

        except Exception as e:
            logging.error(f"[!] Error analyzing packet: {e}")

    sniff(prn=process_packet, iface=interface, store=False, filter="ip", count=5000)
    logging.info("✅ Packet capture completed. Data saved in data/packets_log.csv.")
