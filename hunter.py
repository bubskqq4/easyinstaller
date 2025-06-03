#!/usr/bin/env python3

import os
import sys
import time
import socket
import subprocess
import requests
import platform
import json
import re
import threading
import queue
import datetime
import hashlib
import getpass
import ssl
import urllib.parse
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
import dns.resolver
import psutil
import netifaces
import ipaddress
import uuid
import random

init()

# -------------------- SETUP --------------------
CONFIG_DIR = "config"
CONFIG_FILES = {
    "ports.json": {"common_ports": [21, 22, 23, 25, 53, 80, 443, 8080], "extended_ports": list(range(1, 1001))},
    "settings.json": {"timeout": 0.5, "max_threads": 50, "log_file": "hutnter.log", "ddos_threshold": 100},
    "whitelist.json": {"allowed_ips": []},
    "users.json": {"users": [{"id": str(uuid.uuid4()), "username": "Ethan", "password": hashlib.sha256("Admin".encode()).hexdigest(), "role": "admin"}]}
}

if not os.path.exists(CONFIG_DIR):
    os.makedirs(CONFIG_DIR)
    print(Fore.GREEN + "[+] Created config folder." + Style.RESET_ALL)
for file_name, file_content in CONFIG_FILES.items():
    file_path = os.path.join(CONFIG_DIR, file_name)
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            json.dump(file_content, f, indent=4)
        print(Fore.GREEN + f"[+] Created {file_name} in config folder." + Style.RESET_ALL)

# Load configuration
with open(os.path.join(CONFIG_DIR, "ports.json"), "r") as f:
    PORTS_CONFIG = json.load(f)
with open(os.path.join(CONFIG_DIR, "settings.json"), "r") as f:
    SETTINGS = json.load(f)
with open(os.path.join(CONFIG_DIR, "users.json"), "r") as f:
    USERS = json.load(f)
with open(os.path.join(CONFIG_DIR, "whitelist.json"), "r") as f:
    WHITELIST = json.load(f)

# -------------------- LEGAL NOTICE --------------------
LEGAL = """
================== LEGAL NOTICE ==================
This tool (Hutnter) is for educational and ethical
penetration testing only. Unauthorized use of this
software against networks or systems you do not own
or have explicit permission to test is ILLEGAL.

The developer is not responsible for misuse or damage.
Users must comply with all applicable laws and regulations.
==================================================
"""

# -------------------- HEADER --------------------
def banner():
    os.system("cls" if platform.system() == "Windows" else "clear")
    print(Fore.GREEN + r"""
██╗  ██╗██╗   ██╗████████╗███╗   ██╗████████╗███████╗██████╗ 
██║  ██║██║   ██║╚══██╔══╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████║██║   ██║   ██║   ██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██║██║   ██║   ██║   ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝   ██║   ██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
""" + Style.RESET_ALL)
    print(Fore.CYAN + "                HUTNTER | Your Network, Your Rules" + Style.RESET_ALL)
    print(LEGAL)

# -------------------- LOGGING --------------------
def log_event(message):
    with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "a") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

# -------------------- NETWORK TOOLS --------------------
def ping_host():
    target = input(Fore.YELLOW + "[?] Enter host/IP to ping: " + Style.RESET_ALL)
    response = os.system(f"ping -c 4 {target}" if platform.system() != "Windows" else f"ping {target}")
    result = "Host is up." if response == 0 else "Host is down or unreachable."
    print(Fore.GREEN + f"[+] {result}" + Style.RESET_ALL)
    log_event(f"Pinged {target}: {result}")

def port_scan():
    target = input(Fore.YELLOW + "[?] Enter target IP: " + Style.RESET_ALL)
    ports = PORTS_CONFIG["common_ports"]
    print(Fore.CYAN + f"[~] Scanning {target}..." + Style.RESET_ALL)
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(SETTINGS["timeout"])
            s.connect((target, port))
            print(Fore.GREEN + f"[+] Port {port} is OPEN" + Style.RESET_ALL)
            s.close()
            log_event(f"Port scan: {target}:{port} is OPEN")
        except:
            pass

def extended_port_scan():
    target = input(Fore.YELLOW + "[?] Enter target IP: " + Style.RESET_ALL)
    ports = PORTS_CONFIG["extended_ports"]
    open_ports = []
    def scan_port(port):
        try:
            s = socket.socket()
            s.settimeout(SETTINGS["timeout"])
            s.connect((target, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    with ThreadPoolExecutor(max_workers=SETTINGS["max_threads"]) as executor:
        executor.map(scan_port, ports)
    for port in open_ports:
        print(Fore.GREEN + f"[+] Port {port} is OPEN" + Style.RESET_ALL)
        log_event(f"Extended port scan: {target}:{port} is OPEN")

def get_ip():
    hostname = input(Fore.YELLOW + "[?] Enter domain: " + Style.RESET_ALL)
    try:
        ip = socket.gethostbyname(hostname)
        print(Fore.GREEN + f"[+] IP of {hostname}: {ip}" + Style.RESET_ALL)
        log_event(f"Resolved {hostname} to {ip}")
    except socket.error:
        print(Fore.RED + "[-] Invalid hostname." + Style.RESET_ALL)
        log_event(f"Failed to resolve {hostname}")

def http_headers():
    url = input(Fore.YELLOW + "[?] Enter full URL (http://...): " + Style.RESET_ALL)
    try:
        r = requests.get(url)
        print(Fore.CYAN + "[~] HTTP Headers:" + Style.RESET_ALL)
        for k, v in r.headers.items():
            print(f"{k}: {v}")
        log_event(f"Retrieved HTTP headers for {url}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"HTTP headers error for {url}: {e}")

def reverse_ip():
    domain = input(Fore.YELLOW + "[?] Enter domain for Reverse IP: " + Style.RESET_ALL)
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"[+] IP: {ip}" + Style.RESET_ALL)
        print(Fore.CYAN + "[~] Domains hosted on this IP (mock):" + Style.RESET_ALL)
        print("example.com\nsub.example.com")
        log_event(f"Reverse IP lookup for {domain}: {ip}")
    except:
        print(Fore.RED + "[-] Reverse IP Lookup failed." + Style.RESET_ALL)
        log_event(f"Reverse IP lookup failed for {domain}")

def dns_lookup():
    domain = input(Fore.YELLOW + "[?] Enter domain for DNS Lookup: " + Style.RESET_ALL)
    try:
        result = socket.gethostbyname_ex(domain)
        print(Fore.GREEN + f"[+] DNS Info: {result}" + Style.RESET_ALL)
        log_event(f"DNS lookup for {domain}: {result}")
    except:
        print(Fore.RED + "[-] DNS Lookup failed." + Style.RESET_ALL)
        log_event(f"DNS lookup failed for {domain}")

def traceroute():
    target = input(Fore.YELLOW + "[?] Enter target for Traceroute: " + Style.RESET_ALL)
    try:
        if platform.system() == "Windows":
            os.system(f"tracert {target}")
        else:
            os.system(f"traceroute {target}")
        log_event(f"Traceroute performed for {target}")
    except:
        print(Fore.RED + "[-] Traceroute failed." + Style.RESET_ALL)
        log_event(f"Traceroute failed for {target}")

def whois_lookup():
    domain = input(Fore.YELLOW + "[?] Enter domain for WHOIS: " + Style.RESET_ALL)
    try:
        import whois
        data = whois.whois(domain)
        print(Fore.CYAN + "[~] WHOIS Data:" + Style.RESET_ALL)
        print(data)
        log_event(f"WHOIS lookup for {domain}")
    except:
        print(Fore.RED + "[-] Install `python-whois` module to use this feature." + Style.RESET_ALL)
        log_event(f"WHOIS lookup failed for {domain}: python-whois not installed")

def packet_sniffer():
    interface = input(Fore.YELLOW + "[?] Enter network interface (e.g., eth0): " + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        def process_packet(packet):
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                print(Fore.GREEN + f"[+] Packet: {src} -> {dst}" + Style.RESET_ALL)
                log_event(f"Sniffed packet: {src} -> {dst}")
        scapy.sniff(iface=interface, prn=process_packet, count=10)
    except:
        print(Fore.RED + "[-] Install `scapy` module to use this feature." + Style.RESET_ALL)
        log_event("Packet sniffer failed: scapy not installed")

def arp_spoof_detector():
    try:
        import scapy.all as scapy
        def detect_arp(packet):
            if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
                print(Fore.RED + f"[!] Possible ARP spoofing: {packet[scapy.ARP].psrc} claims {packet[scapy.ARP].hwsrc}" + Style.RESET_ALL)
                log_event(f"Detected possible ARP spoofing: {packet[scapy.ARP].psrc}")
        scapy.sniff(filter="arp", prn=detect_arp, count=10)
    except:
        print(Fore.RED + "[-] Install `scapy` module to use this feature." + Style.RESET_ALL)
        log_event("ARP spoof detector failed: scapy not installed")

def mac_address_lookup():
    ip = input(Fore.YELLOW + "[?] Enter IP to find MAC address: " + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        arp = scapy.ARP(pdst=ip)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = scapy.srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            print(Fore.GREEN + f"[+] IP: {ip}, MAC: {received.hwsrc}" + Style.RESET_ALL)
            log_event(f"MAC address lookup: {ip} -> {received.hwsrc}")
    except:
        print(Fore.RED + "[-] Install `scapy` module to use this feature." + Style.RESET_ALL)
        log_event(f"MAC address lookup failed for {ip}")

def bandwidth_monitor():
    print(Fore.CYAN + "[~] Monitoring bandwidth usage..." + Style.RESET_ALL)
    try:
        for _ in range(5):
            net_io = psutil.net_io_counters()
            print(Fore.GREEN + f"[+] Sent: {net_io.bytes_sent / 1024 / 1024:.2f} MB, Received: {net_io.bytes_recv / 1024 / 1024:.2f} MB" + Style.RESET_ALL)
            log_event(f"Bandwidth: Sent {net_io.bytes_sent / 1024 / 1024:.2f} MB, Received {net_io.bytes_recv / 1024 / 1024:.2f} MB")
            time.sleep(1)
    except:
        print(Fore.RED + "[-] Install `psutil` module to use this feature." + Style.RESET_ALL)
        log_event("Bandwidth monitor failed: psutil not installed")

def ssl_certificate_check():
    url = input(Fore.YELLOW + "[?] Enter URL (https://...): " + Style.RESET_ALL)
    try:
        hostname = urllib.parse.urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(Fore.GREEN + f"[+] SSL Certificate: {cert['subject']}" + Style.RESET_ALL)
                log_event(f"SSL certificate checked for {url}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"SSL certificate check failed for {url}: {e}")

def dns_enumeration():
    domain = input(Fore.YELLOW + "[?] Enter domain for DNS enumeration: " + Style.RESET_ALL)
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                print(Fore.GREEN + f"[+] {record}: {rdata}" + Style.RESET_ALL)
                log_event(f"DNS enumeration: {domain} {record} -> {rdata}")
        except:
            pass

def network_interfaces():
    interfaces = netifaces.interfaces()
    print(Fore.CYAN + "[~] Network Interfaces:" + Style.RESET_ALL)
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                print(Fore.GREEN + f"[+] {iface}: {addr['addr']}" + Style.RESET_ALL)
                log_event(f"Network interface: {iface} -> {addr['addr']}")

def file_integrity_check():
    file_path = input(Fore.YELLOW + "[?] Enter file path to check integrity: " + Style.RESET_ALL)
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        print(Fore.GREEN + f"[+] SHA256: {file_hash}" + Style.RESET_ALL)
        log_event(f"File integrity check: {file_path} -> {file_hash}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"File integrity check failed for {file_path}: {e}")

def vulnerability_scan():
    target = input(Fore.YELLOW + "[?] Enter target IP for vulnerability scan: " + Style.RESET_ALL)
    print(Fore.CYAN + "[~] Performing basic vulnerability scan (mock)..." + Style.RESET_ALL)
    vulnerabilities = ["Open port 23 (Telnet)", "Weak SSL version detected"]
    for vuln in vulnerabilities:
        print(Fore.RED + f"[!] {vuln}" + Style.RESET_ALL)
        log_event(f"Vulnerability scan: {target} -> {vuln}")

def packet_injection_test():
    print(Fore.YELLOW + "[?] Packet injection test (requires root/admin and scapy)." + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        dest_ip = input(Fore.YELLOW + "[?] Enter destination IP: " + Style.RESET_ALL)
        packet = scapy.IP(dst=dest_ip)/scapy.ICMP()
        scapy.send(packet, verbose=0)
        print(Fore.GREEN + "[+] Packet sent successfully." + Style.RESET_ALL)
        log_event(f"Packet injection test sent to {dest_ip}")
    except:
        print(Fore.RED + "[-] Install `scapy` module and run as root." + Style.RESET_ALL)
        log_event("Packet injection test failed")

def password_strength_checker():
    password = getpass.getpass(Fore.YELLOW + "[?] Enter password to check: " + Style.RESET_ALL)
    score = 0
    if len(password) >= 8:
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[@#$%^&+=]", password):
        score += 1
    strength = "Weak" if score < 3 else "Moderate" if score < 5 else "Strong"
    print(Fore.GREEN + f"[+] Password strength: {strength} (Score: {score}/5)" + Style.RESET_ALL)
    log_event(f"Password strength check: {strength}")

def network_traffic_analysis():
    print(Fore.CYAN + "[~] Analyzing network traffic (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Detected protocols: TCP, UDP, ICMP" + Style.RESET_ALL)
    log_event("Network traffic analysis performed")

def firewall_rule_check():
    print(Fore.CYAN + "[~] Checking firewall rules (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Firewall rules: Allow TCP 80, 443; Block UDP 53" + Style.RESET_ALL)
    log_event("Firewall rule check performed")

def os_fingerprinting():
    target = input(Fore.YELLOW + "[?] Enter target IP for OS fingerprinting: " + Style.RESET_ALL)
    print(Fore.CYAN + "[~] Performing OS fingerprinting (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + f"[+] OS: Linux/Windows (mock detection)" + Style.RESET_ALL)
    log_event(f"OS fingerprinting attempted on {target}")

def banner_grabbing():
    target = input(Fore.YELLOW + "[?] Enter target IP: " + Style.RESET_ALL)
    port = int(input(Fore.YELLOW + "[?] Enter port: " + Style.RESET_ALL))
    try:
        s = socket.socket()
        s.settimeout(SETTINGS["timeout"])
        s.connect((target, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode()
        print(Fore.GREEN + f"[+] Banner: {banner}" + Style.RESET_ALL)
        log_event(f"Banner grabbed from {target}:{port}")
        s.close()
    except:
        print(Fore.RED + "[-] Banner grabbing failed." + Style.RESET_ALL)
        log_event(f"Banner grabbing failed for {target}:{port}")

def subnet_calculator():
    ip = input(Fore.YELLOW + "[?] Enter IP (e.g., 192.168.1.0): " + Style.RESET_ALL)
    mask = int(input(Fore.YELLOW + "[?] Enter subnet mask bits (e.g., 24): " + Style.RESET_ALL))
    try:
        network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        print(Fore.GREEN + f"[+] Network: {network.network_address}/{mask}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Hosts: {network.num_addresses - 2}" + Style.RESET_ALL)
        log_event(f"Subnet calculated for {ip}/{mask}")
    except:
        print(Fore.RED + "[-] Invalid IP or mask." + Style.RESET_ALL)
        log_event(f"Subnet calculation failed for {ip}/{mask}")

def geo_ip_lookup():
    ip = input(Fore.YELLOW + "[?] Enter IP for GeoIP lookup: " + Style.RESET_ALL)
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data["status"] == "success":
            print(Fore.GREEN + f"[+] Location: {data['city']}, {data['country']}" + Style.RESET_ALL)
            log_event(f"GeoIP lookup for {ip}: {data['city']}, {data['country']}")
        else:
            print(Fore.RED + "[-] GeoIP lookup failed." + Style.RESET_ALL)
            log_event(f"GeoIP lookup failed for {ip}")
    except:
        print(Fore.RED + "[-] Error during GeoIP lookup." + Style.RESET_ALL)
        log_event(f"GeoIP lookup error for {ip}")

def http_method_test():
    url = input(Fore.YELLOW + "[?] Enter URL to test HTTP methods: " + Style.RESET_ALL)
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    for method in methods:
        try:
            r = requests.request(method, url)
            print(Fore.GREEN + f"[+] {method}: {r.status_code}" + Style.RESET_ALL)
            log_event(f"HTTP method test: {method} on {url} -> {r.status_code}")
        except:
            print(Fore.RED + f"[-] {method}: Failed" + Style.RESET_ALL)
            log_event(f"HTTP method test failed: {method} on {url}")

def dns_zone_transfer():
    domain = input(Fore.YELLOW + "[?] Enter domain for zone transfer: " + Style.RESET_ALL)
    try:
        answers = dns.resolver.resolve(domain, "NS")
        for ns in answers:
            ns = str(ns)
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                print(Fore.GREEN + f"[+] Zone transfer from {ns}:" + Style.RESET_ALL)
                for name, rdata in zone.iterate_rdatas():
                    print(f"{name}: {rdata}")
                log_event(f"DNS zone transfer from {ns} for {domain}")
            except:
                print(Fore.RED + f"[-] Zone transfer failed for {ns}" + Style.RESET_ALL)
                log_event(f"DNS zone transfer failed for {ns}")
    except:
        print(Fore.RED + "[-] DNS zone transfer failed." + Style.RESET_ALL)
        log_event(f"DNS zone transfer failed for {domain}")

def network_latency_test():
    target = input(Fore.YELLOW + "[?] Enter target IP/hostname: " + Style.RESET_ALL)
    try:
        start = time.time()
        socket.create_connection((target, 80), timeout=SETTINGS["timeout"])
        latency = (time.time() - start) * 1000
        print(Fore.GREEN + f"[+] Latency: {latency:.2f} ms" + Style.RESET_ALL)
        log_event(f"Network latency test to {target}: {latency:.2f} ms")
    except:
        print(Fore.RED + "[-] Latency test failed." + Style.RESET_ALL)
        log_event(f"Network latency test failed for {target}")

def protocol_analyzer():
    print(Fore.CYAN + "[~] Analyzing protocols (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Detected: HTTP, HTTPS, FTP, SSH" + Style.RESET_ALL)
    log_event("Protocol analysis performed")

def log_file_analyzer():
    log_file = os.path.join(CONFIG_DIR, SETTINGS["log_file"])
    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
        print(Fore.CYAN + "[~] Recent log entries:" + Style.RESET_ALL)
        for line in lines[-5:]:
            print(Fore.GREEN + f"[+] {line.strip()}" + Style.RESET_ALL)
        log_event("Log file analysis performed")
    except:
        print(Fore.RED + "[-] Log file not found." + Style.RESET_ALL)
        log_event("Log file analysis failed")

# -------------------- ETHICAL TOOLS --------------------
def ethical_dilemma_analyzer():
    print(Fore.CYAN + "[~] Ethical Dilemma Analyzer" + Style.RESET_ALL)
    action = input(Fore.YELLOW + "[?] Describe the network action (e.g., port scanning, packet sniffing): " + Style.RESET_ALL)
    target = input(Fore.YELLOW + "[?] Target (e.g., IP, domain): " + Style.RESET_ALL)
    permission = input(Fore.YELLOW + "[?] Do you have explicit permission? (yes/no): " + Style.RESET_ALL).lower()
    result = "Ethical" if permission == "yes" else "Unethical: Requires explicit permission"
    print(Fore.GREEN + f"[+] Analysis: {result}" + Style.RESET_ALL)
    log_event(f"Ethical dilemma analysis: {action} on {target} -> {result}")

def decision_making_framework():
    print(Fore.CYAN + "[~] Decision-Making Framework" + Style.RESET_ALL)
    action = input(Fore.YELLOW + "[?] Action to evaluate: " + Style.RESET_ALL)
    criteria = ["Legality", "Consent", "Impact", "Necessity"]
    scores = {}
    for criterion in criteria:
        score = int(input(Fore.YELLOW + f"[?] Score for {criterion} (1-5): " + Style.RESET_ALL))
        scores[criterion] = score
    avg_score = sum(scores.values()) / len(scores)
    result = "Proceed" if avg_score >= 3 else "Reconsider"
    print(Fore.GREEN + f"[+] Decision: {result} (Average Score: {avg_score:.2f})" + Style.RESET_ALL)
    log_event(f"Decision-making framework: {action} -> {result}")

def principles_manager():
    print(Fore.CYAN + "[~] Ethical Principles Manager" + Style.RESET_ALL)
    principles = ["Respect for autonomy", "Non-maleficence", "Beneficence", "Justice"]
    print(Fore.GREEN + "[+] Current principles: " + ", ".join(principles) + Style.RESET_ALL)
    new_principle = input(Fore.YELLOW + "[?] Add a new principle (or press Enter to skip): " + Style.RESET_ALL)
    if new_principle:
        principles.append(new_principle)
        print(Fore.GREEN + f"[+] Added: {new_principle}" + Style.RESET_ALL)
        log_event(f"Added ethical principle: {new_principle}")

def compliance_checker():
    print(Fore.CYAN + "[~] Compliance Checker" + Style.RESET_ALL)
    action = input(Fore.YELLOW + "[?] Action to check (e.g., port scanning): " + Style.RESET_ALL)
    standards = ["GDPR", "HIPAA", "PCI-DSS"]
    results = []
    for standard in standards:
        compliant = input(Fore.YELLOW + f"[?] Compliant with {standard}? (yes/no): " + Style.RESET_ALL).lower()
        results.append(f"{standard}: {'Compliant' if compliant == 'yes' else 'Non-compliant'}")
    print(Fore.GREEN + "[+] Compliance Results: " + "; ".join(results) + Style.RESET_ALL)
    log_event(f"Compliance check for {action}: {'; '.join(results)}")

def scenario_generator():
    print(Fore.CYAN + "[~] Ethical Scenario Generator" + Style.RESET_ALL)
    scenarios = [
        "Unauthorized port scan on a corporate network",
        "Packet sniffing on a public Wi-Fi",
        "Attempting to bypass authentication on a test server"
    ]
    scenario = random.choice(scenarios)
    print(Fore.GREEN + f"[+] Scenario: {scenario}" + Style.RESET_ALL)
    log_event(f"Generated scenario: {scenario}")

def decision_tree_builder():
    print(Fore.CYAN + "[~] Decision Tree Builder" + Style.RESET_ALL)
    action = input(Fore.YELLOW + "[?] Action to analyze: " + Style.RESET_ALL)
    tree = {"Action": action, "Steps": []}
    while True:
        step = input(Fore.YELLOW + "[?] Add decision step (or press Enter to finish): " + Style.RESET_ALL)
        if not step:
            break
        tree["Steps"].append(step)
    print(Fore.GREEN + f"[+] Decision Tree: {json.dumps(tree, indent=2)}" + Style.RESET_ALL)
    log_event(f"Built decision tree for {action}")

# -------------------- UTILITY TOOLS --------------------
def user_signup():
    print(Fore.CYAN + "[~] User Sign-Up" + Style.RESET_ALL)
    username = input(Fore.YELLOW + "[?] Enter username: " + Style.RESET_ALL)
    password = getpass.getpass(Fore.YELLOW + "[?] Enter password: " + Style.RESET_ALL)
    with open(os.path.join(CONFIG_DIR, "users.json"), "r") as f:
        users_data = json.load(f)
    if any(user['username'] == username for user in users_data['users']):
        print(Fore.RED + "[-] Username already exists." + Style.RESET_ALL)
        log_event(f"User sign-up failed: {username} already exists")
    else:
        user_id = str(uuid.uuid4())
        users_data['users'].append({"id": user_id, "username": username, "password": hashlib.sha256(password.encode()).hexdigest(), "role": "user"})
        with open(os.path.join(CONFIG_DIR, "users.json"), "w") as f:
            json.dump(users_data, f, indent=4)
        print(Fore.GREEN + "[+] User signed up successfully." + Style.RESET_ALL)
        log_event(f"User signed up: {username}")

def automated_backup():
    print(Fore.CYAN + "[~] Performing automated backup..." + Style.RESET_ALL)
    backup_dir = os.path.join(CONFIG_DIR, "backups")
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    for file_name in CONFIG_FILES.keys():
        src = os.path.join(CONFIG_DIR, file_name)
        dst = os.path.join(backup_dir, f"{file_name}.{timestamp}.bak")
        with open(src, "r") as f:
            data = f.read()
        with open(dst, "w") as f:
            f.write(data)
        print(Fore.GREEN + f"[+] Backed up {file_name} to {dst}" + Style.RESET_ALL)
        log_event(f"Backed up {file_name} to {dst}")

def multi_language_support():
    print(Fore.CYAN + "[~] Multi-Language Support" + Style.RESET_ALL)
    languages = {"en": "English", "es": "Spanish", "fr": "French"}
    lang = input(Fore.YELLOW + f"[?] Select language ({', '.join(languages.values())}): " + Style.RESET_ALL).lower()
    lang_code = next((code for code, name in languages.items() if name.lower() == lang), "en")
    try:
        from translate import Translator
        translator = Translator(to_lang=lang_code)
        message = translator.translate("Network scan completed")
        print(Fore.GREEN + f"[+] Translated: {message}" + Style.RESET_ALL)
        log_event(f"Translated message to {lang_code}")
    except:
        print(Fore.RED + "[-] Install `python-translate` module to use this feature." + Style.RESET_ALL)
        log_event("Multi-language support failed: python-translate not installed")

def report_generator():
    print(Fore.CYAN + "[~] Report Generator" + Style.RESET_ALL)
    report_type = input(Fore.YELLOW + "[?] Report type (summary/detailed): " + Style.RESET_ALL).lower()
    try:
        with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "r") as f:
            logs = f.readlines()
        report_file = os.path.join(CONFIG_DIR, f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(report_file, "w") as f:
            f.write("Hutnter Report\n")
            f.write(f"Generated: {datetime.datetime.now()}\n")
            f.write(f"Type: {report_type}\n\n")
            if report_type == "summary":
                f.write(f"Total Logs: {len(logs)}\n")
            else:
                for log in logs:
                    f.write(log)
        print(Fore.GREEN + f"[+] Report saved to {report_file}" + Style.RESET_ALL)
        log_event(f"Generated {report_type} report: {report_file}")
    except:
        print(Fore.RED + "[-] Report generation failed." + Style.RESET_ALL)
        log_event("Report generation failed")

# -------------------- HELP MENU --------------------
def help_menu():
    print(Fore.CYAN + "\n[ HUTNTER HELP MENU ]" + Style.RESET_ALL)
    print("""
1. Ping a Host                - Sends ICMP packets to check if the host is up.
2. Port Scanner              - Scans common ports to see which are open.
3. Get IP                    - Resolves a domain name to its IP address.
4. HTTP Headers              - Displays server response headers for a URL.
5. Reverse IP Lookup         - Finds domains sharing the same IP (mocked).
6. DNS Lookup                - Performs a DNS query to get records for a domain.
7. Traceroute                - Shows the route packets take to a target.
8. Whois Lookup              - Shows WHOIS registration info for a domain.
9. Extended Port Scan        - Scans a larger range of ports (1-1000).
10. Packet Sniffer           - Captures network packets (requires scapy).
11. ARP Spoof Detector       - Detects potential ARP spoofing attacks.
12. MAC Address Lookup       - Finds MAC address for an IP (requires scapy).
13. Bandwidth Monitor        - Monitors network bandwidth usage.
14. SSL Certificate Check    - Retrieves SSL certificate details.
15. DNS Enumeration          - Enumerates DNS records (A, MX, NS, etc.).
16. Network Interfaces       - Lists network interfaces and their IPs.
17. File Integrity Check     - Calculates SHA256 hash of a file.
18. Vulnerability Scan       - Performs a basic vulnerability scan (mock).
19. Packet Injection Test    - Sends test ICMP packet (requires scapy).
20. Password Strength Check  - Evaluates password strength.
21. Network Traffic Analysis - Analyzes network traffic (mock).
22. Firewall Rule Check      - Checks firewall rules (mock).
23. OS Fingerprinting        - Attempts OS detection (mock).
24. Banner Grabbing          - Retrieves service banners from open ports.
25. Subnet Calculator        - Calculates subnet details from IP and mask.
26. GeoIP Lookup             - Finds geographic location of an IP.
27. HTTP Method Test         - Tests supported HTTP methods on a URL.
28. DNS Zone Transfer        - Attempts DNS zone transfer.
29. Network Latency Test     - Measures network latency to a target.
30. Protocol Analyzer        - Analyzes network protocols (mock).
31. Log File Analyzer        - Analyzes Hutnter's log file.
32. User Sign-Up             - Register a new user.
33. Ethical Dilemma Analyzer - Analyzes ethical implications of network actions.
34. Decision-Making Framework - Evaluates actions based on ethical criteria.
35. Principles Manager       - Manages ethical principles.
36. Compliance Checker       - Checks compliance with standards like GDPR.
37. Scenario Generator       - Generates ethical scenarios for analysis.
38. Decision Tree Builder    - Builds decision trees for actions.
39. Automated Backup         - Backs up configuration files.
40. Multi-Language Support   - Translates messages to different languages.
41. Report Generator         - Generates summary or detailed reports.
42. Exit                     - Exits the tool.
h or help                    - Shows this help menu.

Admin Dashboard:
- Run `dashboard.py` to start the admin dashboard.
- Access at http://localhost:5000
- Login with username: Ethan, password: Admin
- Features: User management, DDoS whitelist, system metrics, exclusive tools
""")

# -------------------- MENU --------------------
def menu():
    while True:
        print(Fore.CYAN + "\n[ MENU ]" + Style.RESET_ALL)
        print("1. Ping a Host")
        print("2. Port Scanner (Common Ports)")
        print("3. Get IP from Hostname")
        print("4. View HTTP Headers")
        print("5. Reverse IP Lookup")
        print("6. DNS Lookup")
        print("7. Traceroute")
        print("8. Whois Lookup")
        print("9. Extended Port Scan")
        print("10. Packet Sniffer")
        print("11. ARP Spoof Detector")
        print("12. MAC Address Lookup")
        print("13. Bandwidth Monitor")
        print("14. SSL Certificate Check")
        print("15. DNS Enumeration")
        print("16. Network Interfaces")
        print("17. File Integrity Check")
        print("18. Vulnerability Scan")
        print("19. Packet Injection Test")
        print("20. Password Strength Check")
        print("21. Network Traffic Analysis")
        print("22. Firewall Rule Check")
        print("23. OS Fingerprinting")
        print("24. Banner Grabbing")
        print("25. Subnet Calculator")
        print("26. GeoIP Lookup")
        print("27. HTTP Method Test")
        print("28. DNS Zone Transfer")
        print("29. Network Latency Test")
        print("30. Protocol Analyzer")
        print("31. Log File Analyzer")
        print("32. User Sign-Up")
        print("33. Ethical Dilemma Analyzer")
        print("34. Decision-Making Framework")
        print("35. Principles Manager")
        print("36. Compliance Checker")
        print("37. Scenario Generator")
        print("38. Decision Tree Builder")
        print("39. Automated Backup")
        print("40. Multi-Language Support")
        print("41. Report Generator")
        print("42. Exit")
        print("h. Help")

        choice = input(Fore.YELLOW + "\nSelect an option: " + Style.RESET_ALL).strip().lower()

        if choice == "1":
            ping_host()
        elif choice == "2":
            port_scan()
        elif choice == "3":
            get_ip()
        elif choice == "4":
            http_headers()
        elif choice == "5":
            reverse_ip()
        elif choice == "6":
            dns_lookup()
        elif choice == "7":
            traceroute()
        elif choice == "8":
            whois_lookup()
        elif choice == "9":
            extended_port_scan()
        elif choice == "10":
            packet_sniffer()
        elif choice == "11":
            arp_spoof_detector()
        elif choice == "12":
            mac_address_lookup()
        elif choice == "13":
            bandwidth_monitor()
        elif choice == "14":
            ssl_certificate_check()
        elif choice == "15":
            dns_enumeration()
        elif choice == "16":
            network_interfaces()
        elif choice == "17":
            file_integrity_check()
        elif choice == "18":
            vulnerability_scan()
        elif choice == "19":
            packet_injection_test()
        elif choice == "20":
            password_strength_checker()
        elif choice == "21":
            network_traffic_analysis()
        elif choice == "22":
            firewall_rule_check()
        elif choice == "23":
            os_fingerprinting()
        elif choice == "24":
            banner_grabbing()
        elif choice == "25":
            subnet_calculator()
        elif choice == "26":
            geo_ip_lookup()
        elif choice == "27":
            http_method_test()
        elif choice == "28":
            dns_zone_transfer()
        elif choice == "29":
            network_latency_test()
        elif choice == "30":
            protocol_analyzer()
        elif choice == "31":
            log_file_analyzer()
        elif choice == "32":
            user_signup()
        elif choice == "33":
            ethical_dilemma_analyzer()
        elif choice == "34":
            decision_making_framework()
        elif choice == "35":
            principles_manager()
        elif choice == "36":
            compliance_checker()
        elif choice == "37":
            scenario_generator()
        elif choice == "38":
            decision_tree_builder()
        elif choice == "39":
            automated_backup()
        elif choice == "40":
            multi_language_support()
        elif choice == "41":
            report_generator()
        elif choice == "42":
            print(Fore.CYAN + "[*] Exiting Hutnter." + Style.RESET_ALL)
            log_event("Hutnter exited")
            break
        elif choice in ["h", "help"]:
            help_menu()
        else:
            print(Fore.RED + "Invalid option. Try again." + Style.RESET_ALL)
            log_event("Invalid menu option selected")

# -------------------- RUN --------------------
if __name__ == "__main__":
    try:
        banner()
        menu()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupted by user." + Style.RESET_ALL)
        log_event("Hutnter interrupted by user")
        sys.exit(0)
