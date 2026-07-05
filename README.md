# Port_scanner_nmap

## Advanced Nmap-Style Port Scanner for Kali Linux

A comprehensive, multi-threaded port scanner with Nmap-style functionality, service detection, OS fingerprinting, and stealth scanning capabilities.

## Features

- **Multiple Scan Types**
  - TCP Connect Scanning
  - SYN Stealth Scanning (requires root)
  - UDP Scanning
  - Network Range Scanning

- **Advanced Capabilities**
  - Multi-threaded scanning (configurable threads)
  - Service detection and banner grabbing
  - OS fingerprinting via TTL analysis
  - Port range parsing (e.g., `22,80,443,8000-9000`)
  - Verbose output mode

- **Output Formats**
  - Colored terminal output
  - JSON export
  - Nmap-style format
  - Custom report generation

- **Performance**
  - Concurrent scanning with ThreadPoolExecutor
  - Progress tracking
  - Timeout configuration
  - Memory efficient

## Installation

### Quick Installation

git clone https://github.com/Kaintura-Priyanshu/Port_scanner_nmap.git

cd Port_scanner_nmap

sudo bash install.sh

## Manual Installation

# Install dependencies
pip3 install -r requirements.txt

# Make scripts executable
chmod +x port_scanner.py quick_scan.sh

## Basic Usage

# Scan common ports on a target
sudo python3 port_scanner.py -t [ip]

# Scan specific ports
sudo python3 port_scanner.py -t example.com -p 22,80,443,3306

# Scan port range
sudo python3 port_scanner.py -t [ip] -p 1-1000

# Verbose scan with progress
sudo python3 port_scanner.py -t [ip] -v

# Stealth SYN scan (requires root)
sudo python3 port_scanner.py -t [ip] --stealth

# High-performance scan
sudo python3 port_scanner.py -t [ip] -p 1-10000 -T 200

# Save results in multiple formats
sudo python3 port_scanner.py -t [ip] -o scan_results.json --nmap-output

# Using Quick Scan Menu
sudo bash quick_scan.sh

## Security Notes
Always obtain proper authorization before scanning any target

Use stealth scanning responsibly to avoid detection

Respect network policies and applicable laws

This tool is intended for educational and authorized testing purposes only

Not for use on systems you don't own or have permission to test

## Common Issues

# Permission Denied (Stealth Scan)
sudo python3 port_scanner.py -t [ip] 1 --stealth

# Scapy Not Found
pip3 install scapy
# or
sudo apt-get install python3-scapy

# Slow Scanning
# Increase threads
sudo python3 port_scanner.py -t [ip] -T 200
# Reduce timeout
sudo python3 port_scanner.py -t [ip] --timeout 1

## Development
# Running Tests
python3 -m pytest tests/

## Code Style

# Check with flake8
flake8 port_scanner.py

# Format with black
black port_scanner.py
