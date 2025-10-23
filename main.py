import argparse
import logging
from packet_capture import capture_packets
from threat_model import ThreatDetector

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    logging.info("🚀 Starting NETGUARD-AI System...")

    parser = argparse.ArgumentParser(description="NETGUARD-AI Packet Capture and Threat Detection")
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface to capture packets (default: system default)"
    )
    args = parser.parse_args()

    detector = ThreatDetector()

    try:
        logging.info(f"📡 Capturing packets on interface: {args.interface or 'default'}")
        capture_packets(detector, interface=args.interface)
    except KeyboardInterrupt:
        logging.warning("🛑 Packet capture stopped by user.")
    except Exception as e:
        logging.error(f"[!] Error during packet capture: {e}")
    finally:
        logging.info("✅ NETGUARD-AI System stopped.")

if __name__ == "__main__":
    main()
