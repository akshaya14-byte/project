# add_rule.py

import json

def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)

def save_rules(rules):
    with open("rules.json", "w") as f:
        json.dump(rules, f, indent=2)

def add_ip(ip):
    rules = load_rules()
    if ip not in rules["block_ips"]:
        rules["block_ips"].append(ip)
        save_rules(rules)
        print(f"✅ Added IP: {ip}")
    else:
        print(f"⚠️ IP already exists: {ip}")

def add_port(port):
    rules = load_rules()
    if port not in rules["block_ports"]:
        rules["block_ports"].append(port)
        save_rules(rules)
        print(f"✅ Added Port: {port}")
    else:
        print(f"⚠️ Port already exists: {port}")

def add_protocol(proto):
    rules = load_rules()
    if proto not in rules["block_protocols"]:
        rules["block_protocols"].append(proto)
        save_rules(rules)
        print(f"✅ Added Protocol: {proto}")
    else:
        print(f"⚠️ Protocol already exists: {proto}")

# Example usage
add_ip("192.168.1.200")
add_port(8080)
add_protocol(1)
