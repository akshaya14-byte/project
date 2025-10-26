from scapy.all import sniff, IP, TCP, UDP
import json
import logging
import csv
import os
from datetime import datetime

# Load rules from JSON
def load_rules(path='rules.json'):
    with open(path, 'r') as f:
        return json.load(f)

rules = load_rules()

# Setup logging
logging.basicConfig(filename='firewall.log', level=logging.INFO)

# Setup CSV logging
csv_file = 'firewall_log.csv'
csv_headers = ['Timestamp', 'Action', 'Source IP', 'Destination IP', 'Protocol', 'Reason']

if not os.path.exists(csv_file):
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(csv_headers)

def log_block(packet, reason):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    src_ip = packet[IP].src if IP in packet else 'N/A'
    dst_ip = packet[IP].dst if IP in packet else 'N/A'
    proto = packet.proto if IP in packet else 'N/A'

    print(f"[BLOCKED] {packet.summary()} | Reason: {reason}")
    logging.info(f"[{timestamp}] BLOCKED: {packet.summary()} | Reason: {reason}")

    with open(csv_file, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, 'BLOCKED', src_ip, dst_ip, proto, reason])

def log_allow(packet):
    print(f"[ALLOWED] {packet.summary()}")

def apply_rules(packet):
    if IP in packet:
        src_ip = packet[IP].src
        proto = packet.proto
        dst_port = None

        if TCP in packet:
            dst_port = packet[TCP].dport
        elif UDP in packet:
            dst_port = packet[UDP].dport

        if src_ip in rules["block_ips"]:
            log_block(packet, f"Blocked IP: {src_ip}")
            return False
        if dst_port and dst_port in rules["block_ports"]:
            log_block(packet, f"Blocked Port: {dst_port}")
            return False
        if proto in rules["block_protocols"]:
            log_block(packet, f"Blocked Protocol: {proto}")
            return False

    return True

def packet_callback(packet):
    if apply_rules(packet):
        log_allow(packet)

print("🔥 Personal Firewall Started. Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)

