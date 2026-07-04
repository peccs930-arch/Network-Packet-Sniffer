"""
logger.py
Educational Packet Logger

Logs packet information to:
1. packets.csv
2. packets.txt
"""

import csv
import os
from datetime import datetime


class PacketLogger:
    def __init__(self,
                 csv_file="packets.csv",
                 txt_file="packets.txt"):

        self.csv_file = csv_file
        self.txt_file = txt_file

        # Create CSV file with header if it doesn't exist
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow([
                    "Time",
                    "Protocol",
                    "Source IP",
                    "Destination IP",
                    "Source Port",
                    "Destination Port",
                    "Packet Length"
                ])

    def log_csv(self,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                length):

        with open(self.csv_file, "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                length
            ])

    def log_txt(self,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                length):

        with open(self.txt_file, "a") as file:
            file.write("=" * 60 + "\n")
            file.write(f"Time      : {datetime.now()}\n")
            file.write(f"Protocol  : {protocol}\n")
            file.write(f"Source IP : {src_ip}\n")
            file.write(f"Dest IP   : {dst_ip}\n")
            file.write(f"Src Port  : {src_port}\n")
            file.write(f"Dst Port  : {dst_port}\n")
            file.write(f"Length    : {length} bytes\n")
            file.write("\n")

    def log(self,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            length):
        """
        Write packet information to both CSV and TXT.
        """
        self.log_csv(
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            length
        )

        self.log_txt(
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            length
        )
