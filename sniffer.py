"""
sniffer.py
Educational Network Packet Sniffer Module
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime


class PacketSniffer:
    def __init__(self):
        self.packet_count = 0

    def get_protocol(self, packet):
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(IP):
            return "IP"
        else:
            return "OTHER"

    def process_packet(self, packet):
        self.packet_count += 1

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        protocol = self.get_protocol(packet)

        print("-" * 80)
        print(f"Packet #: {self.packet_count}")
        print(f"Time    : {timestamp}")
        print(f"Protocol: {protocol}")
        print(f"Length  : {len(packet)} bytes")

        if packet.haslayer(IP):
            ip = packet[IP]
            print(f"Source IP      : {ip.src}")
            print(f"Destination IP : {ip.dst}")
            print(f"TTL            : {ip.ttl}")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f"Source Port    : {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"Source Port    : {udp.sport}")
            print(f"Destination Port: {udp.dport}")

        elif packet.haslayer(ARP):
            arp = packet[ARP]
            print(f"Sender IP      : {arp.psrc}")
            print(f"Target IP      : {arp.pdst}")

    def start(self, interface=None, packet_filter=None):
        """
        Start packet capture.

        interface: Network interface name (optional)
        packet_filter: BPF filter (e.g., 'tcp', 'udp', 'icmp')
        """
        print("=" * 80)
        print("Network Packet Sniffer Started")
        print("Press Ctrl+C to stop")
        print("=" * 80)

        try:
            sniff(
                iface=interface,
                filter=packet_filter,
                prn=self.process_packet,
                store=False
            )
        except KeyboardInterrupt:
            print("\n\nCapture stopped.")
            print(f"Total Packets Captured: {self.packet_count}")
