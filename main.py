#!/usr/bin/env python3
"""
main.py - Educational Network Packet Sniffer

Features:
- Captures packets using Scapy
- Displays timestamp, source IP, destination IP, protocol, and length
- Supports IPv4 packets
- Stops safely with Ctrl+C

Requirements:
    pip install scapy
"""

from scapy.all import sniff, IP
from datetime import datetime


def get_protocol_name(protocol_number):
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    return protocols.get(protocol_number, f"OTHER({protocol_number})")


def process_packet(packet):
    if IP in packet:
        ip = packet[IP]

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        source = ip.src
        destination = ip.dst
        protocol = get_protocol_name(ip.proto)
        length = len(packet)

        print("-" * 70)
        print(f"Time       : {timestamp}")
        print(f"Source IP  : {source}")
        print(f"Destination: {destination}")
        print(f"Protocol   : {protocol}")
        print(f"Packet Size: {length} bytes")


def main():
    print("=" * 70)
    print("      EDUCATIONAL NETWORK PACKET SNIFFER")
    print("=" * 70)
    print("Capturing packets... Press Ctrl+C to stop.\n")

    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")


if __name__ == "__main__":
    main()
