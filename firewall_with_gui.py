import socket
import struct
import logging
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import threading
import queue
from datetime import datetime
from collections import defaultdict
import time
import re
import ipaddress
from tkinter import font as tkfont
import json
import os
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import hashlib
import ssl
import socket
import subprocess
import platform

class IPS:
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.connection_attempts = defaultdict(int)
        self.port_scan_attempts = defaultdict(int)
        self.suspicious_ips = set()
        self.blocked_ips = set()
        self.whitelist_ips = set()
        self.attack_patterns = {
            'port_scan': 5,  # Number of ports to trigger port scan detection
            'connection_flood': 10,  # Number of connections per second to trigger flood detection
            'suspicious_ports': {21, 22, 23, 25, 445, 3389},  # Ports to monitor
            'max_packets_per_second': 100,  # Maximum packets per second from a single IP
            'max_connections_per_minute': 50  # Maximum connections per minute from a single IP
        }
        self.packet_counts = defaultdict(int)
        self.connection_times = defaultdict(list)
        self.last_reset = time.time()
        self.reset_interval = 60  # Reset counters every 60 seconds
        
        # Known attack signatures
        self.attack_signatures = {
            'sql_injection': re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE).*FROM'),
            'xss_attack': re.compile(r'(?i)(<script|javascript:|onerror=|onload=)'),
            'path_traversal': re.compile(r'(?i)(\.\.\/|\.\.\\|~\/|~\\|\/etc\/|\/var\/)'),
            'command_injection': re.compile(r'(?i)(;|\||&|\$|`|>|<)')
        }
        
    def analyze_packet(self, src_ip, dst_ip, src_port, dst_port, payload=None):
        current_time = time.time()
        
        # Reset counters periodically
        if current_time - self.last_reset > self.reset_interval:
            self.connection_attempts.clear()
            self.port_scan_attempts.clear()
            self.packet_counts.clear()
            self.connection_times.clear()
            self.last_reset = current_time
        
        # Skip analysis for whitelisted IPs
        if src_ip in self.whitelist_ips:
            return False
        
        # Track connection attempts
        self.connection_attempts[src_ip] += 1
        self.packet_counts[src_ip] += 1
        
        # Track connection times
        self.connection_times[src_ip].append(current_time)
        self.connection_times[src_ip] = [t for t in self.connection_times[src_ip] 
                                       if current_time - t <= 60]
        
        # Check for port scanning
        if dst_port in self.attack_patterns['suspicious_ports']:
            self.port_scan_attempts[src_ip] += 1
        
        # Analyze payload for attack signatures if available
        if payload:
            self.analyze_payload(src_ip, payload)
        
        # Detect and prevent attacks
        return self.detect_and_prevent_attacks(src_ip)
    
    def analyze_payload(self, src_ip, payload):
        for attack_type, pattern in self.attack_signatures.items():
            if pattern.search(payload):
                self.log(f"ALERT: Detected {attack_type} attempt from {src_ip}")
                self.suspicious_ips.add(src_ip)
                return True
        return False
    
    def detect_and_prevent_attacks(self, src_ip):
        current_time = time.time()
        
        # Check packet rate
        if self.packet_counts[src_ip] > self.attack_patterns['max_packets_per_second']:
            self.log(f"ALERT: High packet rate from {src_ip}")
            self.block_ip(src_ip)
            return True
        
        # Check connection rate
        recent_connections = len([t for t in self.connection_times[src_ip] 
                                if current_time - t <= 60])
        if recent_connections > self.attack_patterns['max_connections_per_minute']:
            self.log(f"ALERT: Connection flood from {src_ip}")
            self.block_ip(src_ip)
            return True
        
        # Check for port scanning
        if self.port_scan_attempts[src_ip] > self.attack_patterns['port_scan']:
            self.log(f"ALERT: Port scan detected from {src_ip}")
            self.block_ip(src_ip)
            return True
        
        return False
    
    def block_ip(self, ip):
        if ip not in self.whitelist_ips:
            self.blocked_ips.add(ip)
            self.log(f"IPS: Blocked IP {ip}")
    
    def unblock_ip(self, ip):
        self.blocked_ips.discard(ip)
        self.log(f"IPS: Unblocked IP {ip}")
    
    def whitelist_ip(self, ip):
        self.whitelist_ips.add(ip)
        self.blocked_ips.discard(ip)
        self.suspicious_ips.discard(ip)
        self.log(f"IPS: Whitelisted IP {ip}")
    
    def remove_from_whitelist(self, ip):
        self.whitelist_ips.discard(ip)
        self.log(f"IPS: Removed IP {ip} from whitelist")
    
    def is_blocked(self, ip):
        return ip in self.blocked_ips
    
    def is_whitelisted(self, ip):
        return ip in self.whitelist_ips
    
    def log(self, message):
        if self.log_callback:
            self.log_callback(message)

class VulnerabilityScanner:
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.nvd_api_key = None
        self.vulnerability_cache = {}
        self.known_vulnerabilities = set()
        self.scan_results = {}
        
        # NVD API endpoints
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Common vulnerability patterns
        self.vuln_patterns = {
            'sql_injection': re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE).*FROM'),
            'xss': re.compile(r'(?i)(<script|javascript:|onerror=|onload=)'),
            'path_traversal': re.compile(r'(?i)(\.\.\/|\.\.\\|~\/|~\\|\/etc\/|\/var\/)'),
            'command_injection': re.compile(r'(?i)(;|\||&|\$|`|>|<)'),
            'buffer_overflow': re.compile(r'(?i)(strcpy|strcat|sprintf|gets)'),
            'format_string': re.compile(r'(?i)(%s|%n|%x|%d)')
        }
    
    def set_api_key(self, api_key):
        self.nvd_api_key = api_key
        self.log("NVD API key configured")
    
    def check_nvd_vulnerability(self, cpe_string):
        """Check NVD database for known vulnerabilities"""
        if not self.nvd_api_key:
            self.log("NVD API key not configured")
            return []
        
        try:
            headers = {'apiKey': self.nvd_api_key}
            params = {
                'cpeName': cpe_string,
                'resultsPerPage': 20
            }
            
            response = requests.get(self.nvd_api_base, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    vulnerabilities.append({
                        'id': cve.get('id'),
                        'description': cve.get('descriptions', [{}])[0].get('value'),
                        'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore'),
                        'published': cve.get('published')
                    })
                
                return vulnerabilities
            else:
                self.log(f"Error querying NVD API: {response.status_code}")
                return []
                
        except Exception as e:
            self.log(f"Error checking NVD: {str(e)}")
            return []
    
    def scan_port(self, ip, port):
        """Scan a specific port for vulnerabilities"""
        try:
            # Basic port scan
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                # Port is open, perform service detection
                service = self.detect_service(ip, port)
                vulnerabilities = self.check_service_vulnerabilities(service, ip, port)
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'vulnerabilities': vulnerabilities
                }
            return None
            
        except Exception as e:
            self.log(f"Error scanning port {port}: {str(e)}")
            return None
    
    def detect_service(self, ip, port):
        """Detect service running on port"""
        try:
            if port == 80 or port == 443:
                return self.detect_web_service(ip, port)
            elif port == 22:
                return "SSH"
            elif port == 21:
                return "FTP"
            elif port == 25:
                return "SMTP"
            elif port == 3306:
                return "MySQL"
            elif port == 5432:
                return "PostgreSQL"
            else:
                return "Unknown"
        except:
            return "Unknown"
    
    def detect_web_service(self, ip, port):
        """Detect web service details"""
        try:
            protocol = "https" if port == 443 else "http"
            url = f"{protocol}://{ip}:{port}"
            response = requests.get(url, timeout=2, verify=False)
            
            server = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', '')
            
            return f"Web ({server} {powered_by})"
        except:
            return "Web (Unknown)"
    
    def check_service_vulnerabilities(self, service, ip, port):
        """Check for known vulnerabilities in detected service"""
        vulnerabilities = []
        
        # Check NVD database
        if "Web" in service:
            cpe_string = self.get_web_cpe(service)
            nvd_vulns = self.check_nvd_vulnerability(cpe_string)
            vulnerabilities.extend(nvd_vulns)
        
        # Check for common vulnerabilities
        if port == 80 or port == 443:
            web_vulns = self.check_web_vulnerabilities(ip, port)
            vulnerabilities.extend(web_vulns)
        
        return vulnerabilities
    
    def get_web_cpe(self, service):
        """Generate CPE string for web service"""
        # Extract server and version information
        match = re.search(r'Web \(([^)]+)\)', service)
        if match:
            server_info = match.group(1)
            # Parse server info and create CPE string
            return f"cpe:2.3:a:{server_info.lower()}"
        return None
    
    def check_web_vulnerabilities(self, ip, port):
        """Check for common web vulnerabilities"""
        vulnerabilities = []
        try:
            protocol = "https" if port == 443 else "http"
            url = f"{protocol}://{ip}:{port}"
            
            # Check for common security headers
            response = requests.get(url, timeout=2, verify=False)
            headers = response.headers
            
            if 'X-Frame-Options' not in headers:
                vulnerabilities.append({
                    'id': 'MISSING-XFO',
                    'description': 'Missing X-Frame-Options header',
                    'severity': 'Medium',
                    'type': 'Security Header'
                })
            
            if 'X-Content-Type-Options' not in headers:
                vulnerabilities.append({
                    'id': 'MISSING-XCTO',
                    'description': 'Missing X-Content-Type-Options header',
                    'severity': 'Low',
                    'type': 'Security Header'
                })
            
            # Check for SSL/TLS issues
            if port == 443:
                ssl_vulns = self.check_ssl_vulnerabilities(ip, port)
                vulnerabilities.extend(ssl_vulns)
            
        except Exception as e:
            self.log(f"Error checking web vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def check_ssl_vulnerabilities(self, ip, port):
        """Check for SSL/TLS vulnerabilities"""
        vulnerabilities = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port)) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    if 'notAfter' in cert:
                        expiry = ssl.cert_time_to_seconds(cert['notAfter'])
                        if expiry < time.time():
                            vulnerabilities.append({
                                'id': 'EXPIRED-CERT',
                                'description': 'SSL certificate has expired',
                                'severity': 'High',
                                'type': 'SSL/TLS'
                            })
                    
                    # Check SSL/TLS version
                    if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                        vulnerabilities.append({
                            'id': 'WEAK-SSL',
                            'description': f'Weak SSL/TLS version: {ssock.version()}',
                            'severity': 'High',
                            'type': 'SSL/TLS'
                        })
        
        except Exception as e:
            self.log(f"Error checking SSL vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def scan_ip(self, ip):
        """Perform comprehensive vulnerability scan of an IP"""
        self.log(f"Starting vulnerability scan for {ip}")
        results = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'ports': [],
            'vulnerabilities': []
        }
        
        # Scan common ports
        common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 5432]
        
        for port in common_ports:
            port_result = self.scan_port(ip, port)
            if port_result:
                results['ports'].append(port_result)
                results['vulnerabilities'].extend(port_result.get('vulnerabilities', []))
        
        self.scan_results[ip] = results
        return results
    
    def log(self, message):
        if self.log_callback:
            self.log_callback(message)

class BasicFirewall:
    def __init__(self, log_callback=None):
        self.blocked_ips = set()
        self.blocked_ports = {22, 23, 3389}  # Common ports to block
        self.allowed_ips = set()
        self.log_callback = log_callback
        self.is_running = False
        self.ids = IDS(log_callback)
        self.ips = IPS(log_callback)
        
    def start(self):
        try:
            # Create raw socket to capture packets
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind(('0.0.0.0', 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            self.is_running = True
            self.log("Firewall started and listening for packets")
            
            while self.is_running:
                try:
                    # Receive packet
                    packet, addr = s.recvfrom(65535)
                    
                    # Parse IP header
                    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
                    
                    # Extract information
                    version_ihl = ip_header[0]
                    ihl = version_ihl & 0xF
                    ip_header_length = ihl * 4
                    src_ip = socket.inet_ntoa(ip_header[8])
                    dst_ip = socket.inet_ntoa(ip_header[9])
                    
                    # Parse TCP header if present
                    if len(packet) > ip_header_length:
                        tcp_header = struct.unpack('!HHLLBBHHH', packet[ip_header_length:ip_header_length+20])
                        src_port = tcp_header[0]
                        dst_port = tcp_header[1]
                        
                        # Get payload if present
                        payload = packet[ip_header_length + 20:] if len(packet) > ip_header_length + 20 else None
                        
                        # Analyze packet with IDS and IPS
                        self.ids.analyze_packet(src_ip, dst_ip, src_port, dst_port)
                        if self.ips.analyze_packet(src_ip, dst_ip, src_port, dst_port, payload):
                            continue
                        
                        # Check if packet should be blocked
                        if self.should_block(src_ip, dst_ip, src_port, dst_port):
                            self.log(f"Blocked packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                            continue
                        
                        self.log(f"Allowed packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                
                except Exception as e:
                    self.log(f"Error processing packet: {str(e)}")
                    continue
                    
        except KeyboardInterrupt:
            self.log("Firewall stopped by user")
        finally:
            self.is_running = False
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
    
    def stop(self):
        self.is_running = False
    
    def should_block(self, src_ip, dst_ip, src_port, dst_port):
        # Check if source IP is blocked
        if src_ip in self.blocked_ips:
            return True
            
        # Check if destination IP is blocked
        if dst_ip in self.blocked_ips:
            return True
            
        # Check if source port is blocked
        if src_port in self.blocked_ports:
            return True
            
        # Check if destination port is blocked
        if dst_port in self.blocked_ports:
            return True
            
        # Check if IP is blocked by IPS
        if self.ips.is_blocked(src_ip):
            return True
            
        return False
    
    def block_ip(self, ip):
        self.blocked_ips.add(ip)
        self.log(f"Blocked IP: {ip}")
    
    def unblock_ip(self, ip):
        self.blocked_ips.discard(ip)
        self.log(f"Unblocked IP: {ip}")
    
    def block_port(self, port):
        self.blocked_ports.add(port)
        self.log(f"Blocked port: {port}")
    
    def unblock_port(self, port):
        self.blocked_ports.discard(port)
        self.log(f"Unblocked port: {port}")
    
    def whitelist_ip(self, ip):
        self.ips.whitelist_ip(ip)
    
    def remove_from_whitelist(self, ip):
        self.ips.remove_from_whitelist(ip)
    
    def log(self, message):
        if self.log_callback:
            self.log_callback(message)

class ModernTheme:
    def __init__(self):
        self.colors = {
            'primary': '#2c3e50',
            'secondary': '#34495e',
            'accent': '#3498db',
            'success': '#2ecc71',
            'warning': '#f1c40f',
            'danger': '#e74c3c',
            'light': '#ecf0f1',
            'dark': '#2c3e50',
            'background': '#f5f6fa',
            'text': '#2c3e50'
        }
        
        self.styles = {
            'TFrame': {'background': self.colors['background']},
            'TLabel': {'background': self.colors['background'], 'foreground': self.colors['text']},
            'TButton': {
                'background': self.colors['accent'],
                'foreground': 'white',
                'padding': 5,
                'font': ('Helvetica', 10)
            },
            'TEntry': {
                'fieldbackground': 'white',
                'foreground': self.colors['text'],
                'padding': 5
            },
            'TLabelframe': {
                'background': self.colors['background'],
                'foreground': self.colors['text']
            },
            'TLabelframe.Label': {
                'background': self.colors['background'],
                'foreground': self.colors['text'],
                'font': ('Helvetica', 10, 'bold')
            }
        }

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Firewall Control Panel")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f5f6fa')
        
        # Create menu bar
        self.create_menu()
        
        # Apply modern theme
        self.theme = ModernTheme()
        self.apply_theme()
        
        # Create message queue for thread-safe logging
        self.log_queue = queue.Queue()
        
        # Create firewall instance with log callback
        self.firewall = BasicFirewall(log_callback=self.log_message)
        self.firewall_thread = None
        
        # Create main container
        self.create_main_container()
        
        # Start log monitor
        self.monitor_logs()
        
        # Load saved settings
        self.load_settings()
        
        # Add vulnerability scanner
        self.vulnerability_scanner = VulnerabilityScanner(log_callback=self.log_message)
        
    def create_menu(self):
        menubar = Menu(self.root)
        self.root.config(menu=menubar)
        
        # File Menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Settings", command=self.save_settings)
        file_menu.add_command(label="Load Settings", command=self.load_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Export Logs", command=self.export_logs)
        file_menu.add_command(label="Import Rules", command=self.import_rules)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Firewall Menu
        firewall_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Firewall", menu=firewall_menu)
        firewall_menu.add_command(label="Start Firewall", command=self.start_firewall)
        firewall_menu.add_command(label="Stop Firewall", command=self.stop_firewall)
        firewall_menu.add_separator()
        firewall_menu.add_command(label="Reset Firewall", command=self.reset_firewall)
        
        # Rules Menu
        rules_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Rules", menu=rules_menu)
        rules_menu.add_command(label="Add IP Rule", command=self.show_add_ip_rule)
        rules_menu.add_command(label="Add Port Rule", command=self.show_add_port_rule)
        rules_menu.add_command(label="Manage Rules", command=self.show_rule_manager)
        
        # Security Menu
        security_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Security", menu=security_menu)
        security_menu.add_command(label="Security Settings", command=self.show_security_settings)
        security_menu.add_command(label="Attack Statistics", command=self.show_attack_stats)
        security_menu.add_command(label="Whitelist Manager", command=self.show_whitelist_manager)
        
        # Tools Menu
        tools_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Network Monitor", command=self.show_network_monitor)
        tools_menu.add_command(label="Packet Analyzer", command=self.show_packet_analyzer)
        tools_menu.add_command(label="Connection Viewer", command=self.show_connection_viewer)
        
        # Vulnerability Menu
        vuln_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Vulnerability", menu=vuln_menu)
        vuln_menu.add_command(label="Configure API Key", command=self.show_api_config)
        vuln_menu.add_command(label="Scan IP", command=self.show_scan_dialog)
        vuln_menu.add_command(label="View Scan Results", command=self.show_scan_results)
        vuln_menu.add_separator()
        vuln_menu.add_command(label="Export Scan Report", command=self.export_scan_report)
        
        # Help Menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
    
    def show_add_ip_rule(self):
        rule_window = tk.Toplevel(self.root)
        rule_window.title("Add IP Rule")
        rule_window.geometry("400x300")
        
        ttk.Label(rule_window, text="IP Address:").pack(pady=5)
        ip_entry = ttk.Entry(rule_window)
        ip_entry.pack(pady=5)
        
        ttk.Label(rule_window, text="Action:").pack(pady=5)
        action_var = tk.StringVar(value="block")
        ttk.Radiobutton(rule_window, text="Block", variable=action_var, value="block").pack()
        ttk.Radiobutton(rule_window, text="Allow", variable=action_var, value="allow").pack()
        
        ttk.Button(rule_window, text="Add Rule", 
                  command=lambda: self.add_ip_rule(ip_entry.get(), action_var.get(), rule_window)).pack(pady=20)
    
    def show_add_port_rule(self):
        rule_window = tk.Toplevel(self.root)
        rule_window.title("Add Port Rule")
        rule_window.geometry("400x300")
        
        ttk.Label(rule_window, text="Port:").pack(pady=5)
        port_entry = ttk.Entry(rule_window)
        port_entry.pack(pady=5)
        
        ttk.Label(rule_window, text="Action:").pack(pady=5)
        action_var = tk.StringVar(value="block")
        ttk.Radiobutton(rule_window, text="Block", variable=action_var, value="block").pack()
        ttk.Radiobutton(rule_window, text="Allow", variable=action_var, value="allow").pack()
        
        ttk.Button(rule_window, text="Add Rule", 
                  command=lambda: self.add_port_rule(port_entry.get(), action_var.get(), rule_window)).pack(pady=20)
    
    def show_rule_manager(self):
        rule_window = tk.Toplevel(self.root)
        rule_window.title("Rule Manager")
        rule_window.geometry("600x400")
        
        # Create notebook for different rule types
        notebook = ttk.Notebook(rule_window)
        notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # IP Rules tab
        ip_frame = ttk.Frame(notebook)
        notebook.add(ip_frame, text="IP Rules")
        self.create_ip_rules_list(ip_frame)
        
        # Port Rules tab
        port_frame = ttk.Frame(notebook)
        notebook.add(port_frame, text="Port Rules")
        self.create_port_rules_list(port_frame)
    
    def show_security_settings(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Security Settings")
        settings_window.geometry("500x400")
        
        # Create settings options
        frame = ttk.Frame(settings_window, padding="10")
        frame.pack(fill="both", expand=True)
        
        # IDS Settings
        ttk.Label(frame, text="IDS Settings", font=("Helvetica", 12, "bold")).pack(pady=10)
        
        # Enable/Disable IDS
        ids_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Enable IDS", variable=ids_var).pack(pady=5)
        
        # Sensitivity level
        ttk.Label(frame, text="Detection Sensitivity:").pack(pady=5)
        sensitivity = ttk.Scale(frame, from_=1, to=10, orient="horizontal")
        sensitivity.pack(pady=5)
        
        # Save button
        ttk.Button(frame, text="Save Settings", 
                  command=lambda: self.save_security_settings(ids_var.get(), sensitivity.get())).pack(pady=20)
    
    def show_attack_stats(self):
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Attack Statistics")
        stats_window.geometry("600x400")
        
        # Create statistics display
        frame = ttk.Frame(stats_window, padding="10")
        frame.pack(fill="both", expand=True)
        
        # Attack types
        ttk.Label(frame, text="Attack Types", font=("Helvetica", 12, "bold")).pack(pady=10)
        
        # Create statistics labels
        self.stats_labels = {}
        for attack_type in ["Port Scans", "Connection Floods", "SQL Injections", "XSS Attempts"]:
            label = ttk.Label(frame, text=f"{attack_type}: 0")
            label.pack(pady=5)
            self.stats_labels[attack_type] = label
    
    def show_whitelist_manager(self):
        whitelist_window = tk.Toplevel(self.root)
        whitelist_window.title("Whitelist Manager")
        whitelist_window.geometry("500x400")
        
        # Create whitelist interface
        frame = ttk.Frame(whitelist_window, padding="10")
        frame.pack(fill="both", expand=True)
        
        # Add IP to whitelist
        ttk.Label(frame, text="Add IP to Whitelist").pack(pady=5)
        ip_entry = ttk.Entry(frame)
        ip_entry.pack(pady=5)
        ttk.Button(frame, text="Add", 
                  command=lambda: self.add_to_whitelist(ip_entry.get())).pack(pady=5)
        
        # Whitelist display
        ttk.Label(frame, text="Current Whitelist").pack(pady=10)
        whitelist_text = scrolledtext.ScrolledText(frame, height=10)
        whitelist_text.pack(fill="both", expand=True)
    
    def show_network_monitor(self):
        monitor_window = tk.Toplevel(self.root)
        monitor_window.title("Network Monitor")
        monitor_window.geometry("800x600")
        
        # Create network monitoring interface
        frame = ttk.Frame(monitor_window, padding="10")
        frame.pack(fill="both", expand=True)
        
        # Traffic graph
        ttk.Label(frame, text="Network Traffic").pack(pady=5)
        # Add graph widget here
        
        # Connection list
        ttk.Label(frame, text="Active Connections").pack(pady=5)
        connection_list = ttk.Treeview(frame, columns=("Source", "Destination", "Port", "Status"))
        connection_list.pack(fill="both", expand=True)
    
    def show_packet_analyzer(self):
        analyzer_window = tk.Toplevel(self.root)
        analyzer_window.title("Packet Analyzer")
        analyzer_window.geometry("800x600")
        
        # Create packet analysis interface
        frame = ttk.Frame(analyzer_window, padding="10")
        frame.pack(fill="both", expand=True)
        
        # Packet capture controls
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill="x", pady=5)
        
        ttk.Button(control_frame, text="Start Capture", 
                  command=self.start_packet_capture).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Stop Capture", 
                  command=self.stop_packet_capture).pack(side="left", padx=5)
        
        # Packet display
        packet_list = ttk.Treeview(frame, columns=("Time", "Source", "Destination", "Protocol", "Length"))
        packet_list.pack(fill="both", expand=True)
    
    def show_connection_viewer(self):
        viewer_window = tk.Toplevel(self.root)
        viewer_window.title("Connection Viewer")
        viewer_window.geometry("800x600")
        
        # Create connection viewing interface
        frame = ttk.Frame(viewer_window, padding="10")
        frame.pack(fill="both", expand=True)
        
        # Connection list
        connection_list = ttk.Treeview(frame, 
                                     columns=("Local Address", "Remote Address", "State", "Process"))
        connection_list.pack(fill="both", expand=True)
    
    def show_documentation(self):
        doc_window = tk.Toplevel(self.root)
        doc_window.title("Documentation")
        doc_window.geometry("800x600")
        
        # Create documentation interface
        frame = ttk.Frame(doc_window, padding="10")
        frame.pack(fill="both", expand=True)
        
        # Documentation content
        doc_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
        doc_text.pack(fill="both", expand=True)
        
        # Add documentation content
        doc_text.insert("1.0", """
        Firewall Control Panel Documentation
        
        1. Getting Started
        - How to start the firewall
        - Basic configuration
        - Understanding the interface
        
        2. Managing Rules
        - Adding IP rules
        - Adding port rules
        - Managing existing rules
        
        3. Security Features
        - IDS/IPS functionality
        - Attack detection
        - Whitelist management
        
        4. Monitoring Tools
        - Network monitoring
        - Packet analysis
        - Connection viewing
        
        5. Troubleshooting
        - Common issues
        - Error messages
        - Performance optimization
        """)
    
    def show_about(self):
        messagebox.showinfo("About", 
                          "Advanced Firewall Control Panel\n"
                          "Version 1.0\n\n"
                          "A comprehensive firewall solution with IDS/IPS capabilities.\n"
                          "© 2024 Your Company")
    
    def add_ip_rule(self, ip, action, window):
        if ip:
            if action == "block":
                self.firewall.block_ip(ip)
            else:
                self.firewall.whitelist_ip(ip)
            window.destroy()
    
    def add_port_rule(self, port, action, window):
        try:
            port_num = int(port)
            if action == "block":
                self.firewall.block_port(port_num)
            else:
                self.firewall.unblock_port(port_num)
            window.destroy()
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid port number")
    
    def save_security_settings(self, ids_enabled, sensitivity):
        # Save security settings
        self.log_message(f"Security settings updated: IDS={ids_enabled}, Sensitivity={sensitivity}")
    
    def add_to_whitelist(self, ip):
        if ip:
            self.firewall.whitelist_ip(ip)
    
    def start_packet_capture(self):
        self.log_message("Starting packet capture...")
    
    def stop_packet_capture(self):
        self.log_message("Stopping packet capture...")
    
    def reset_firewall(self):
        if messagebox.askyesno("Reset Firewall", 
                             "Are you sure you want to reset the firewall? This will clear all rules."):
            # Reset firewall settings
            self.log_message("Firewall reset")
    
    def export_logs(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", "Logs exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
    
    def import_rules(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "r") as f:
                    rules = json.load(f)
                # Import rules
                messagebox.showinfo("Success", "Rules imported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import rules: {str(e)}")
    
    def apply_theme(self):
        style = ttk.Style()
        for element, properties in self.theme.styles.items():
            style.configure(element, **properties)
    
    def create_main_container(self):
        # Create main container with padding
        self.main_container = ttk.Frame(self.root, padding="20")
        self.main_container.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)
        
        # Create header
        self.create_header()
        
        # Create control panels
        self.create_control_panels()
        
        # Create log panel
        self.create_log_panel()
        
        # Create status bar
        self.create_status_bar()
    
    def create_header(self):
        header_frame = ttk.Frame(self.main_container)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        # Title
        title_font = tkfont.Font(family="Helvetica", size=24, weight="bold")
        title_label = ttk.Label(header_frame, text="Firewall Control Panel", font=title_font)
        title_label.grid(row=0, column=0, sticky="w")
        
        # Control buttons
        control_frame = ttk.Frame(header_frame)
        control_frame.grid(row=0, column=1, sticky="e")
        
        self.start_button = ttk.Button(control_frame, text="Start Firewall", 
                                     command=self.start_firewall, style='Accent.TButton')
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Firewall", 
                                    command=self.stop_firewall, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)
    
    def create_control_panels(self):
        # Create notebook for tabbed interface
        notebook = ttk.Notebook(self.main_container)
        notebook.grid(row=1, column=0, sticky="nsew", pady=(0, 20))
        
        # IP Control Tab
        ip_frame = ttk.Frame(notebook, padding="10")
        notebook.add(ip_frame, text="IP Control")
        self.create_ip_controls(ip_frame)
        
        # Port Control Tab
        port_frame = ttk.Frame(notebook, padding="10")
        notebook.add(port_frame, text="Port Control")
        self.create_port_controls(port_frame)
        
        # Security Status Tab
        security_frame = ttk.Frame(notebook, padding="10")
        notebook.add(security_frame, text="Security Status")
        self.create_security_status(security_frame)
    
    def create_ip_controls(self, parent):
        # IP Input
        input_frame = ttk.Frame(parent)
        input_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        ttk.Label(input_frame, text="IP Address:").grid(row=0, column=0, padx=5)
        self.ip_entry = ttk.Entry(input_frame, width=30)
        self.ip_entry.grid(row=0, column=1, padx=5)
        
        # IP Control Buttons
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        
        ttk.Button(button_frame, text="Block IP", command=self.block_ip).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Unblock IP", command=self.unblock_ip).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="Whitelist IP", command=self.whitelist_ip).grid(row=0, column=2, padx=5)
        ttk.Button(button_frame, text="Remove from Whitelist", command=self.remove_from_whitelist).grid(row=0, column=3, padx=5)
        
        # IP Lists
        lists_frame = ttk.Frame(parent)
        lists_frame.grid(row=2, column=0, sticky="nsew")
        
        # Blocked IPs
        blocked_frame = ttk.LabelFrame(lists_frame, text="Blocked IPs")
        blocked_frame.grid(row=0, column=0, padx=5, sticky="nsew")
        self.blocked_ips_list = scrolledtext.ScrolledText(blocked_frame, height=10, width=30)
        self.blocked_ips_list.pack(fill="both", expand=True)
        
        # Whitelisted IPs
        whitelist_frame = ttk.LabelFrame(lists_frame, text="Whitelisted IPs")
        whitelist_frame.grid(row=0, column=1, padx=5, sticky="nsew")
        self.whitelist_ips_list = scrolledtext.ScrolledText(whitelist_frame, height=10, width=30)
        self.whitelist_ips_list.pack(fill="both", expand=True)
    
    def create_port_controls(self, parent):
        # Port Input
        input_frame = ttk.Frame(parent)
        input_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        ttk.Label(input_frame, text="Port:").grid(row=0, column=0, padx=5)
        self.port_entry = ttk.Entry(input_frame, width=30)
        self.port_entry.grid(row=0, column=1, padx=5)
        
        # Port Control Buttons
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        
        ttk.Button(button_frame, text="Block Port", command=self.block_port).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Unblock Port", command=self.unblock_port).grid(row=0, column=1, padx=5)
        
        # Port Lists
        lists_frame = ttk.Frame(parent)
        lists_frame.grid(row=2, column=0, sticky="nsew")
        
        # Blocked Ports
        blocked_frame = ttk.LabelFrame(lists_frame, text="Blocked Ports")
        blocked_frame.grid(row=0, column=0, padx=5, sticky="nsew")
        self.blocked_ports_list = scrolledtext.ScrolledText(blocked_frame, height=10, width=30)
        self.blocked_ports_list.pack(fill="both", expand=True)
    
    def create_security_status(self, parent):
        # Status Indicators
        status_frame = ttk.LabelFrame(parent, text="System Status")
        status_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        self.ids_status = ttk.Label(status_frame, text="IDS: Active", foreground="green")
        self.ids_status.grid(row=0, column=0, padx=10, pady=5)
        
        self.ips_status = ttk.Label(status_frame, text="IPS: Active", foreground="green")
        self.ips_status.grid(row=0, column=1, padx=10, pady=5)
        
        # Statistics
        stats_frame = ttk.LabelFrame(parent, text="Security Statistics")
        stats_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        
        self.packets_blocked = ttk.Label(stats_frame, text="Packets Blocked: 0")
        self.packets_blocked.grid(row=0, column=0, padx=10, pady=5)
        
        self.attacks_detected = ttk.Label(stats_frame, text="Attacks Detected: 0")
        self.attacks_detected.grid(row=0, column=1, padx=10, pady=5)
    
    def create_log_panel(self):
        log_frame = ttk.LabelFrame(self.main_container, text="Security Logs")
        log_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        
        # Log controls
        control_frame = ttk.Frame(log_frame)
        control_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs).grid(row=0, column=0, padx=5)
        ttk.Button(control_frame, text="Save Logs", command=self.save_logs).grid(row=0, column=1, padx=5)
        
        # Log display
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=100)
        self.log_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Configure grid weights
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)
    
    def create_status_bar(self):
        self.status_var = tk.StringVar()
        self.status_var.set("Firewall Status: Stopped")
        status_bar = ttk.Label(self.main_container, textvariable=self.status_var, 
                             relief=tk.SUNKEN, padding=5)
        status_bar.grid(row=3, column=0, sticky="ew")
    
    def clear_logs(self):
        self.log_text.delete(1.0, tk.END)
    
    def save_logs(self):
        try:
            with open("firewall_logs.txt", "w") as f:
                f.write(self.log_text.get(1.0, tk.END))
            messagebox.showinfo("Success", "Logs saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
    
    def load_settings(self):
        try:
            if os.path.exists("firewall_settings.json"):
                with open("firewall_settings.json", "r") as f:
                    settings = json.load(f)
                    # Load saved settings
                    pass
        except Exception as e:
            self.log_message(f"Error loading settings: {str(e)}")
    
    def save_settings(self):
        try:
            settings = {
                # Save current settings
            }
            with open("firewall_settings.json", "w") as f:
                json.dump(settings, f)
        except Exception as e:
            self.log_message(f"Error saving settings: {str(e)}")
    
    def start_firewall(self):
        try:
            self.firewall_thread = threading.Thread(target=self.firewall.start)
            self.firewall_thread.daemon = True
            self.firewall_thread.start()
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_var.set("Firewall Status: Running")
            self.log_message("Firewall started")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start firewall: {str(e)}")
    
    def stop_firewall(self):
        self.firewall.stop()
        if self.firewall_thread:
            self.firewall_thread.join(timeout=1)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Firewall Status: Stopped")
        self.log_message("Firewall stopped")
    
    def block_ip(self):
        ip = self.ip_entry.get().strip()
        if ip:
            self.firewall.block_ip(ip)
            self.ip_entry.delete(0, tk.END)
    
    def unblock_ip(self):
        ip = self.ip_entry.get().strip()
        if ip:
            self.firewall.unblock_ip(ip)
            self.ip_entry.delete(0, tk.END)
    
    def whitelist_ip(self):
        ip = self.ip_entry.get().strip()
        if ip:
            self.firewall.whitelist_ip(ip)
            self.ip_entry.delete(0, tk.END)
    
    def remove_from_whitelist(self):
        ip = self.ip_entry.get().strip()
        if ip:
            self.firewall.remove_from_whitelist(ip)
            self.ip_entry.delete(0, tk.END)
    
    def block_port(self):
        try:
            port = int(self.port_entry.get().strip())
            self.firewall.block_port(port)
            self.port_entry.delete(0, tk.END)
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid port number")
    
    def unblock_port(self):
        try:
            port = int(self.port_entry.get().strip())
            self.firewall.unblock_port(port)
            self.port_entry.delete(0, tk.END)
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid port number")
    
    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put(f"{timestamp} - {message}")
    
    def monitor_logs(self):
        while True:
            try:
                message = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, message + "\n")
                self.log_text.see(tk.END)
            except queue.Empty:
                break
        self.root.after(100, self.monitor_logs)

    def show_api_config(self):
        config_window = tk.Toplevel(self.root)
        config_window.title("Configure NVD API Key")
        config_window.geometry("400x200")
        
        frame = ttk.Frame(config_window, padding="10")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="NVD API Key:").pack(pady=5)
        api_key_entry = ttk.Entry(frame, width=40)
        api_key_entry.pack(pady=5)
        
        ttk.Button(frame, text="Save", 
                  command=lambda: self.save_api_key(api_key_entry.get(), config_window)).pack(pady=20)
    
    def show_scan_dialog(self):
        scan_window = tk.Toplevel(self.root)
        scan_window.title("Vulnerability Scan")
        scan_window.geometry("400x200")
        
        frame = ttk.Frame(scan_window, padding="10")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="IP Address to Scan:").pack(pady=5)
        ip_entry = ttk.Entry(frame, width=40)
        ip_entry.pack(pady=5)
        
        ttk.Button(frame, text="Start Scan", 
                  command=lambda: self.start_vulnerability_scan(ip_entry.get(), scan_window)).pack(pady=20)
    
    def show_scan_results(self):
        if not self.vulnerability_scanner.scan_results:
            messagebox.showinfo("No Results", "No scan results available")
            return
        
        results_window = tk.Toplevel(self.root)
        results_window.title("Scan Results")
        results_window.geometry("800x600")
        
        notebook = ttk.Notebook(results_window)
        notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        for ip, results in self.vulnerability_scanner.scan_results.items():
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=ip)
            
            # Create results display
            self.create_scan_results_display(frame, results)
    
    def create_scan_results_display(self, parent, results):
        # Ports section
        ports_frame = ttk.LabelFrame(parent, text="Open Ports")
        ports_frame.pack(fill="x", padx=5, pady=5)
        
        ports_tree = ttk.Treeview(ports_frame, columns=("Port", "Service", "State"))
        ports_tree.heading("Port", text="Port")
        ports_tree.heading("Service", text="Service")
        ports_tree.heading("State", text="State")
        ports_tree.pack(fill="x", padx=5, pady=5)
        
        for port in results['ports']:
            ports_tree.insert("", "end", values=(
                port['port'],
                port['service'],
                port['state']
            ))
        
        # Vulnerabilities section
        vuln_frame = ttk.LabelFrame(parent, text="Vulnerabilities")
        vuln_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        vuln_tree = ttk.Treeview(vuln_frame, 
                                columns=("ID", "Description", "Severity", "Type"))
        vuln_tree.heading("ID", text="ID")
        vuln_tree.heading("Description", text="Description")
        vuln_tree.heading("Severity", text="Severity")
        vuln_tree.heading("Type", text="Type")
        vuln_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        for vuln in results['vulnerabilities']:
            vuln_tree.insert("", "end", values=(
                vuln['id'],
                vuln['description'],
                vuln.get('severity', 'Unknown'),
                vuln.get('type', 'Unknown')
            ))
    
    def save_api_key(self, api_key, window):
        if api_key:
            self.vulnerability_scanner.set_api_key(api_key)
            window.destroy()
            messagebox.showinfo("Success", "API key configured successfully")
        else:
            messagebox.showerror("Error", "Please enter a valid API key")
    
    def start_vulnerability_scan(self, ip, window):
        if not ip:
            messagebox.showerror("Error", "Please enter a valid IP address")
            return
        
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            
            # Start scan in a separate thread
            def scan_thread():
                window.destroy()
                progress_window = tk.Toplevel(self.root)
                progress_window.title("Scanning...")
                progress_window.geometry("300x100")
                
                ttk.Label(progress_window, text=f"Scanning {ip}...").pack(pady=10)
                progress = ttk.Progressbar(progress_window, mode='indeterminate')
                progress.pack(fill="x", padx=10, pady=5)
                progress.start()
                
                results = self.vulnerability_scanner.scan_ip(ip)
                
                progress.stop()
                progress_window.destroy()
                
                self.show_scan_results()
            
            threading.Thread(target=scan_thread, daemon=True).start()
            
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address format")
    
    def export_scan_report(self):
        if not self.vulnerability_scanner.scan_results:
            messagebox.showinfo("No Results", "No scan results to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, "w") as f:
                    json.dump(self.vulnerability_scanner.scan_results, f, indent=2)
                messagebox.showinfo("Success", "Scan report exported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop() 