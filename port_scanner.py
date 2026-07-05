#!/usr/bin/env python3
"""
Advanced Port Scanner - Nmap-style Scanner for Kali Linux
Version: 1.0.0
"""
import socket
import threading
import time
import sys
import argparse
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import json
import os
import re

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class PortScanner:
    def __init__(self, target, ports=None, timeout=2, threads=100, verbose=False):
        """
        Initialize the port scanner
        
        Args:
            target: Target IP or hostname
            ports: Port range or list
            timeout: Socket timeout in seconds
            threads: Number of threads
            verbose: Enable verbose output
        """
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.open_ports = []
        self.scan_results = {}
        
        # Parse ports
        if ports:
            self.ports = self.parse_ports(ports)
        else:
            self.ports = list(range(1, 1025))  # Default: common ports
        
        # Common services
        self.service_db = self.load_service_database()
        
        # Resolve target
        self.target_ip = self.resolve_target()
        
        # OS detection flags
        self.os_info = None
        
    def parse_ports(self, port_string):
        """Parse port range string (e.g., '80,443,8000-9000,22')"""
        ports = []
        parts = port_string.split(',')
        
        for part in parts:
            if '-' in part:
                start, end = part.split('-')
                start = int(start.strip())
                end = int(end.strip())
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part.strip()))
        
        return ports
    
    def load_service_database(self):
        """Load common port-to-service mappings"""
        return {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            111: 'RPCBIND', 135: 'MSRPC', 139: 'NETBIOS-SSN',
            143: 'IMAP', 443: 'HTTPS', 445: 'MICROSOFT-DS',
            993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP',
            3306: 'MYSQL', 3389: 'RDP', 5432: 'POSTGRESQL',
            5900: 'VNC', 6379: 'REDIS', 8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT', 27017: 'MONGODB'
        }
    
    def resolve_target(self):
        """Resolve hostname to IP address"""
        try:
            if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', self.target):
                return self.target
            
            ip = socket.gethostbyname(self.target)
            if self.verbose:
                print(f"{Colors.GREEN}[+] Resolved {self.target} to {ip}{Colors.END}")
            return ip
        except socket.gaierror:
            print(f"{Colors.RED}[-] Could not resolve hostname: {self.target}{Colors.END}")
            sys.exit(1)
    
    def scan_port(self, port):
        """Scan a single port using TCP connect scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            result = sock.connect_ex((self.target_ip, port))
            response_time = (time.time() - start_time) * 1000  # ms
            
            sock.close()
            
            if result == 0:
                service = self.service_db.get(port, 'UNKNOWN')
                return {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'response_time': f"{response_time:.2f}ms"
                }
            elif result == 111:
                return {'port': port, 'status': 'filtered', 'service': 'unknown'}
            else:
                return {'port': port, 'status': 'closed', 'service': 'unknown'}
                
        except socket.error:
            return {'port': port, 'status': 'error', 'service': 'unknown'}
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Error scanning port {port}: {e}{Colors.END}")
            return {'port': port, 'status': 'error', 'service': 'unknown'}
    
    def scan_ports_threaded(self):
        """Scan ports using thread pool"""
        print(f"{Colors.BLUE}[*] Starting scan on {self.target} ({self.target_ip}){Colors.END}")
        print(f"{Colors.BLUE}[*] Scanning {len(self.ports)} ports...{Colors.END}")
        
        start_time = time.time()
        results = []
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all scan tasks
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in self.ports
            }
            
            # Process results as they complete
            completed = 0
            for future in as_completed(future_to_port):
                completed += 1
                port = future_to_port[future]
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['status'] == 'open':
                        self.open_ports.append(result)
                        if self.verbose:
                            print(f"{Colors.GREEN}[+] Port {port} is OPEN ({result['service']}){Colors.END}")
                    elif result['status'] == 'filtered' and self.verbose:
                        print(f"{Colors.YELLOW}[!] Port {port} is FILTERED{Colors.END}")
                    elif result['status'] == 'closed' and self.verbose:
                        print(f"{Colors.CYAN}[-] Port {port} is CLOSED{Colors.END}")
                
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.RED}[-] Error processing port {port}: {e}{Colors.END}")
                
                # Show progress
                if completed % 100 == 0:
                    sys.stdout.write(f"\r[*] Progress: {completed}/{len(self.ports)} ports scanned")
                    sys.stdout.flush()
        
        end_time = time.time()
        self.scan_time = end_time - start_time
        self.scan_results = results
        
        print(f"\n{Colors.GREEN}[+] Scan completed in {self.scan_time:.2f} seconds{Colors.END}")
        
        return results
    
    def banner_grab(self, port):
        """Grab banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target_ip, port))
            
            # Send probe based on service
            probes = {
                80: b"HEAD / HTTP/1.0\r\n\r\n",
                443: b"HEAD / HTTP/1.0\r\n\r\n",
                22: b"SSH-2.0-OpenSSH\r\n",
                21: b"HELP\r\n",
                25: b"HELP\r\n",
                3306: b"\x05\x00\x00\x00\x0a\x35\x2e\x36\x2e\x34\x38\x00",
            }
            
            probe = probes.get(port, b"\r\n")
            sock.send(probe)
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Clean up banner
            banner = banner.replace('\n', ' ').replace('\r', ' ').strip()
            return banner[:200]  # Limit banner length
            
        except:
            return None
    
    def os_detection(self):
        """Basic OS detection using TTL and TCP stack fingerprinting"""
        try:
            # Send SYN packet to common ports
            import subprocess
            import re
            
            # Use ping to get TTL
            ping_cmd = f"ping -c 1 -W 2 {self.target_ip}"
            ping_result = subprocess.run(ping_cmd, shell=True, capture_output=True, text=True)
            
            if ping_result.returncode == 0:
                # Extract TTL from ping output
                ttl_match = re.search(r'ttl=(\d+)', ping_result.stdout, re.IGNORECASE)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    
                    # OS fingerprinting based on TTL
                    if ttl <= 64:
                        return "Linux/Unix-like (TTL: 64)"
                    elif ttl <= 128:
                        return "Windows (TTL: 128)"
                    elif ttl <= 255:
                        return "Cisco/Network device (TTL: 255)"
                    else:
                        return f"Unknown OS (TTL: {ttl})"
            
            return "Unknown"
            
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] OS detection failed: {e}{Colors.END}")
            return "Unknown"
    
    def service_version_detection(self, port):
        """Attempt to detect service version"""
        banner = self.banner_grab(port)
        if banner:
            return banner
        return "Unknown"
    
    def perform_stealth_scan(self):
        """Perform a SYN stealth scan using scapy (requires root)"""
        try:
            from scapy.all import IP, TCP, sr1
            results = []
            
            print(f"{Colors.BLUE}[*] Performing SYN stealth scan on {self.target_ip}{Colors.END}")
            
            for port in self.ports[:100]:  # Limit to first 100 ports for stealth
                try:
                    # Send SYN packet
                    syn_packet = IP(dst=self.target_ip)/TCP(dport=port, flags='S')
                    response = sr1(syn_packet, timeout=2, verbose=0)
                    
                    if response and response.haslayer(TCP):
                        if response[TCP].flags & 0x12:  # SYN-ACK
                            self.open_ports.append({
                                'port': port,
                                'status': 'open',
                                'service': self.service_db.get(port, 'UNKNOWN')
                            })
                            results.append(port)
                            # Send RST to close connection
                            rst_packet = IP(dst=self.target_ip)/TCP(dport=port, flags='R')
                            send(rst_packet, verbose=0)
                            
                            if self.verbose:
                                print(f"{Colors.GREEN}[+] Port {port} is OPEN (stealth){Colors.END}")
                        elif response[TCP].flags & 0x14:  # RST-ACK
                            if self.verbose:
                                print(f"{Colors.CYAN}[-] Port {port} is CLOSED (stealth){Colors.END}")
                    else:
                        if self.verbose:
                            print(f"{Colors.YELLOW}[!] Port {port} is FILTERED (stealth){Colors.END}")
                            
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.YELLOW}[!] Error scanning port {port}: {e}{Colors.END}")
            
            return results
            
        except ImportError:
            print(f"{Colors.YELLOW}[!] Scapy not installed. Use: pip install scapy{Colors.END}")
            return []
    
    def scan(self, scan_type='tcp_connect'):
        """Main scan function with various scan types"""
        
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}Nmap-Style Port Scanner{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"[*] Target: {self.target}")
        print(f"[*] IP Address: {self.target_ip}")
        print(f"[*] Ports: {self.ports[:10]}{'...' if len(self.ports) > 10 else ''}")
        print(f"[*] Scan Type: {scan_type}")
        print(f"[*] Threads: {self.threads}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}\n")
        
        # Start scan
        if scan_type == 'stealth' and os.geteuid() == 0:
            open_ports = self.perform_stealth_scan()
        else:
            self.scan_ports_threaded()
            open_ports = [p['port'] for p in self.open_ports]
        
        # OS Detection
        print(f"\n{Colors.BLUE}[*] Performing OS detection...{Colors.END}")
        self.os_info = self.os_detection()
        
        # Version detection on open ports
        if self.open_ports:
            print(f"\n{Colors.BLUE}[*] Performing version detection...{Colors.END}")
            for port_info in self.open_ports[:10]:  # Limit to first 10 ports
                banner = self.banner_grab(port_info['port'])
                if banner:
                    port_info['banner'] = banner
                    print(f"{Colors.GREEN}[+] Port {port_info['port']}: {banner}{Colors.END}")
        
        # Display results
        self.display_results()
        
        return self.open_ports
    
    def display_results(self):
        """Display scan results in a formatted table"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}Scan Results{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        
        if self.open_ports:
            print(f"\n{Colors.GREEN}[+] {len(self.open_ports)} open ports found:{Colors.END}")
            print(f"\n{'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'VERSION':<30}")
            print(f"{'-'*70}")
            
            for port_info in sorted(self.open_ports, key=lambda x: x['port']):
                port = port_info['port']
                status = port_info.get('status', 'open')
                service = port_info.get('service', 'unknown')
                banner = port_info.get('banner', '')
                
                version_display = banner[:30] if banner else 'unknown'
                print(f"{port:<10} {status:<10} {service:<15} {version_display:<30}")
        else:
            print(f"\n{Colors.YELLOW}[!] No open ports found{Colors.END}")
        
        # OS Detection Results
        if self.os_info:
            print(f"\n{Colors.BLUE}[*] OS Detection: {self.os_info}{Colors.END}")
        
        # Scan summary
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"[*] Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Total ports scanned: {len(self.ports)}")
        print(f"[*] Open ports found: {len(self.open_ports)}")
        print(f"[*] Scan duration: {self.scan_time:.2f} seconds")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}\n")
    
    def save_results(self, filename='scan_results.json'):
        """Save scan results to JSON file"""
        results = {
            'target': self.target,
            'target_ip': self.target_ip,
            'scan_date': datetime.now().isoformat(),
            'scan_duration': self.scan_time,
            'open_ports': self.open_ports,
            'total_ports_scanned': len(self.ports),
            'os_detection': self.os_info
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] Error saving results: {e}{Colors.END}")
    
    def export_nmap_format(self, filename='scan_output.nmap'):
        """Export results in Nmap-style format"""
        try:
            with open(filename, 'w') as f:
                f.write(f"# Nmap-style scan report for {self.target} ({self.target_ip})\n")
                f.write(f"# Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Scan duration: {self.scan_time:.2f} seconds\n\n")
                
                f.write(f"Nmap scan report for {self.target} ({self.target_ip})\n")
                f.write(f"Host is up (0.001s latency).\n\n")
                
                f.write("PORT     STATE    SERVICE    VERSION\n")
                f.write("------   -----    -------    -------\n")
                
                for port_info in sorted(self.open_ports, key=lambda x: x['port']):
                    port = port_info['port']
                    service = port_info.get('service', 'unknown')
                    banner = port_info.get('banner', '')
                    version = banner[:50] if banner else ''
                    
                    f.write(f"{port:<8} open     {service:<10} {version}\n")
                
                if self.os_info:
                    f.write(f"\nOS detection: {self.os_info}\n")
            
            print(f"{Colors.GREEN}[+] Nmap-style output saved to {filename}{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.RED}[-] Error exporting results: {e}{Colors.END}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner - Nmap-style scanner for Kali Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python port_scanner.py -t 192.168.1.1
  python port_scanner.py -t example.com -p 80,443,8080-8085
  python port_scanner.py -t 192.168.1.1 -p 1-1000 -T 200 -v
  python port_scanner.py -t 192.168.1.1 --stealth
  python port_scanner.py -t 192.168.1.1 -o results.json --nmap-output
        '''
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1024',
                       help='Port range (e.g., 80,443,8000-9000)')
    parser.add_argument('-T', '--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=2,
                       help='Socket timeout in seconds (default: 2)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--stealth', action='store_true',
                       help='Perform SYN stealth scan (requires root)')
    parser.add_argument('-o', '--output', default='scan_results.json',
                       help='Output file for JSON results')
    parser.add_argument('--nmap-output', action='store_true',
                       help='Generate Nmap-style output file')
    
    args = parser.parse_args()
    
    # Check for root privileges for stealth scan
    if args.stealth and os.geteuid() != 0:
        print(f"{Colors.RED}[-] Stealth scan requires root privileges. Use: sudo python {sys.argv[0]} [options]{Colors.END}")
        sys.exit(1)
    
    # Create scanner instance
    scanner = PortScanner(
        target=args.target,
        ports=args.ports,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose
    )
    
    # Perform scan
    scan_type = 'stealth' if args.stealth else 'tcp_connect'
    scanner.scan(scan_type=scan_type)
    
    # Save results
    scanner.save_results(args.output)
    
    if args.nmap_output:
        scanner.export_nmap_format()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.END}")
        sys.exit(1)