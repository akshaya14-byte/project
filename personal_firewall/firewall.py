# firewall.py

from scapy.all import sniff, IP, TCP, UDP
import json
import logging
from datetime import datetime
import csv
import os
# Load rules from JSON
def load_rules(path='rules.json'):
    with open(path, 'r') as f:
        return json.load(f)

rules = load_rules()

# Setup logging
logging.basicConfig(filename='firewall.log', level=logging.INFO)
#Setup CSv logging
csv_file = 'firewall_log.csv'
csv_headers = ['Timestamp','Action','Source IP','Destination IP','Protocol','Reason']
def log_block(packet, reason):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    summary = packet.summary()
    logging.info(f"[{timestamp}] BLOCKED: {summary} | Reason: {reason}")
    print(f"[BLOCKED] {summary} | Reason: {reason}")

def log_allow(packet):
    print(f"[ALLOWED] {packet.summary()}")

# Apply rules to each packet
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

# Sniff packets and apply rules
def packet_callback(packet):
    if apply_rules(packet):
        log_allow(packet)

print("🔥 Personal Firewall Started. Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
