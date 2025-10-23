import tkinter as tk
from tkinter import scrolledtext
import json
import subprocess

# Load and save rules
def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)

def save_rules(rules):
    with open("rules.json", "w") as f:
        json.dump(rules, f, indent=2)

# GUI actions
def start_firewall():
    subprocess.Popen(["sudo", "python3", "firewall.py"])
    log_box.insert(tk.END, "🔥 Firewall started\n")

def view_logs():
    try:
        with open("firewall_log.csv", "r") as f:
            log_box.delete(1.0, tk.END)
            log_box.insert(tk.END, f.read())
    except FileNotFoundError:
        log_box.insert(tk.END, "⚠️ No log file found\n")

def add_ip_gui():
    ip = ip_entry.get()
    rules = load_rules()
    if ip and ip not in rules["block_ips"]:
        rules["block_ips"].append(ip)
        save_rules(rules)
        log_box.insert(tk.END, f"✅ Added IP: {ip}\n")
    else:
        log_box.insert(tk.END, f"⚠️ IP already exists or empty\n")

def add_port_gui():
    port = port_entry.get()
    rules = load_rules()
    if port and int(port) not in rules["block_ports"]:
        rules["block_ports"].append(int(port))
        save_rules(rules)
        log_box.insert(tk.END, f"✅ Added Port: {port}\n")
    else:
        log_box.insert(tk.END, f"⚠️ Port already exists or empty\n")

def add_proto_gui():
    proto = proto_entry.get()
    rules = load_rules()
    if proto and int(proto) not in rules["block_protocols"]:
        rules["block_protocols"].append(int(proto))
        save_rules(rules)
        log_box.insert(tk.END, f"✅ Added Protocol: {proto}\n")
    else:
        log_box.insert(tk.END, f"⚠️ Protocol already exists or empty\n")

# GUI setup
app = tk.Tk()
app.title("Personal Firewall Dashboard")

tk.Button(app, text="Start Firewall", command=start_firewall).pack(pady=5)
tk.Button(app, text="View Logs", command=view_logs).pack(pady=5)

tk.Label(app, text="Add IP").pack()
ip_entry = tk.Entry(app)
ip_entry.pack()
tk.Button(app, text="Add IP", command=add_ip_gui).pack()

tk.Label(app, text="Add Port").pack()
port_entry = tk.Entry(app)
port_entry.pack()
tk.Button(app, text="Add Port", command=add_port_gui).pack()

tk.Label(app, text="Add Protocol").pack()
proto_entry = tk.Entry(app)
proto_entry.pack()
tk.Button(app, text="Add Protocol", command=add_proto_gui).pack()

log_box = scrolledtext.ScrolledText(app, width=80, height=20)
log_box.pack(pady=10)

app.mainloop()
