#!/usr/bin/env python3
import argparse
import json
from scapy.all import IP, TCP, wrpcap

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Convert Cowrie JSON logs to PCAP.")
parser.add_argument('--input', required=True, help='Path to input JSON log file')
parser.add_argument('--output', required=True, help='Path to output PCAP file')
args = parser.parse_args()

packets = []

# Load and process each JSON log line
with open(args.input, 'r') as f:
    for line in f:
        try:
            data = json.loads(line)

            # Minimal viable check for IP traffic
            if "src_ip" in data and "dst_ip" in data:
                ip = IP(src=data["src_ip"], dst=data["dst_ip"])
                tcp = TCP(dport=data.get("dst_port", 22), sport=data.get("src_port", 2222), flags="S")

                pkt = ip / tcp
                packets.append(pkt)
        except json.JSONDecodeError:
            continue
        except Exception as e:
            continue  # For now, skip any broken records

# Write PCAP output
if packets:
    wrpcap(args.output, packets)

