#!/bin/bash
# Quick scan script for common use cases

echo "Quick Port Scanner Menu"
echo "======================"
echo "1. Quick TCP Connect Scan (Common Ports)"
echo "2. Stealth SYN Scan (Requires Root)"
echo "3. Comprehensive Scan (1-10000 ports)"
echo "4. Service Version Detection"
echo "5. Network Range Scan"
echo "======================"
read -p "Select option (1-5): " option

case $option in
    1)
        read -p "Enter target IP/hostname: " target
        sudo python3 port_scanner.py -t $target -p 22,23,25,53,80,110,111,135,139,143,443,445,993,995,3306,3389,5900,8080
        ;;
    2)
        read -p "Enter target IP/hostname: " target
        sudo python3 port_scanner.py -t $target --stealth -p 1-1024
        ;;
    3)
        read -p "Enter target IP/hostname: " target
        sudo python3 port_scanner.py -t $target -p 1-10000 -T 200
        ;;
    4)
        read -p "Enter target IP/hostname: " target
        sudo python3 port_scanner.py -t $target -p 22,80,443,3306,3389 -v
        ;;
    5)
        read -p "Enter network range (e.g., 192.168.1.0/24): " range
        echo "Scanning network range: $range"
        for ip in $(nmap -sn $range | grep "Nmap scan" | cut -d " " -f5); do
            echo "Scanning $ip..."
            sudo python3 port_scanner.py -t $ip -p 22,80,443 -v
        done
        ;;
    *)
        echo "Invalid option!"
        ;;
esac
