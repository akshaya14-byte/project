import json
import subprocess

def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)

def enforce_iptables():
    rules = load_rules()

    for ip in rules["block_ips"]:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        print(f"🔒 Blocked IP: {ip}")

    for port in rules["block_ports"]:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "udp", "--dport", str(port), "-j", "DROP"])
        print(f"🔒 Blocked Port: {port}")

    for proto in rules["block_protocols"]:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", str(proto), "-j", "DROP"])
        print(f"🔒 Blocked Protocol: {proto}")

enforce_iptables()
