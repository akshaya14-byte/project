import tkinter as tk
from tkinter import scrolledtext
import json
import subprocess

app = tk.Tk()
app.title("Personal Firewall Dashboard")
log_box = scrolledtext.ScrolledText(app, width=80, height=20)
log_box.pack(pady=10)

def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)

def save_rules(rules):
    with open("rules.json", "w") as f:
        json.dump(rules, f, indent=2)

def start_firewall():
    subprocess.Popen(["sudo", "python3", "firewall.py"])
    log_box.insert(tk.END, "🔥 Firewall started\n")

def stop_firewall():
    subprocess.run(["pkill", "-f", "firewall.py"])
    log_box.insert(tk.END, "🛑 Firewall stopped\n")

def auto_refresh_log():
    try:
        with open("firewall.log", "r") as f:
            content = f.read()
            log_box.delete(1.0, tk.END)
            log_box.insert(tk.END, content)
    except FileNotFoundError:
        log_box.insert(tk.END, "⚠️ No firewall.log found\n")
    app.after(3000, auto_refresh_log)

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

# Buttons and input fields
tk.Button(app, text="Start Firewall", command=start_firewall).pack(pady=5)
tk.Button(app, text="Stop Firewall", command=stop_firewall).pack(pady=5)

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

# Start auto-refresh and GUI loop
auto_refresh_log()
app.mainloop()

