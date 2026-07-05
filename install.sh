#!/bin/bash
# Installation script for Port Scanner

echo "Installing Nmap-Style Port Scanner for Kali Linux..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root: sudo ./install.sh"
    exit 1
fi

# Update system
echo "[+] Updating package lists..."
apt update

# Install Python3 and pip if not installed
echo "[+] Installing Python3 and pip..."
apt install -y python3 python3-pip

# Install required Python packages
echo "[+] Installing Python dependencies..."
pip3 install -r requirements.txt

# Install additional Kali tools (optional)
echo "[+] Installing optional Kali tools..."
apt install -y nmap net-tools

# Make scanner executable
chmod +x port_scanner.py

echo "[+] Installation complete!"
echo "[+] Run the scanner: sudo python3 port_scanner.py -t <target>"
