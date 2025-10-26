> Secure File Storage System & Python Firewall

This repository contains two modular cybersecurity tools built in Python:

1. **Secure File Storage System with AES Encryption** – A PyQt5 GUI-based tool for encrypting, decrypting, and verifying file integrity.
2. **Python Firewall with Modular Rule Enforcement** – A CLI-based firewall for real-time packet inspection and rule-based traffic control.

# Project 1: Secure File Storage System

# Description
A GUI tool that allows users to:
- Upload files
- Encrypt them using AES-256 (Fernet)
- Store metadata (filename, timestamp, SHA256 hash, key)
- Decrypt files and verify integrity

# Features
- PyQt5 GUI with buttons for Upload, Encrypt, Decrypt, Verify
- Real-time status log
- '.enc' and '.meta' file generation
- SHA256-based integrity check

>>> Technologies
- Python 3
- PyQt5
- cryptography.fernet
- hashlib
- json

# Project 2: Python Firewall

# Description
A command-line firewall that:
- Captures packets using 'scapy'
- Applies custom rules (IP, port, protocol, payload)
- Enforces system-level blocking via 'iptables'
- Logs traffic and rule hits for forensic analysis

# Features
- Modular rule parser
- Real-time packet inspection
- CLI interface for rule management
- Forensic-grade logging

# Technologies
- Python 3
- scapy
- iptables
- subprocess
- logging

# Setup Instructions

> Add your setup commands here for each project. Example:

# Create virtual environment
python3 -m venv secure_storage_env
source secure_storage_env/bin/activate

# Install dependencies
pip install pyqt5 cryptography scapy
