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
import ssl
import urllib.parse
import random
import string
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
import dns.resolver
import psutil
import netifaces
import ipaddress
import uuid
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
import speedtest

init()

# -------------------- SETUP --------------------
CONFIG_DIR = "config"
CONFIG_FILES = {
    "ports.json": {"common_ports": [21, 22, 23, 25, 53, 80, 443, 8080], "extended_ports": list(range(1, 1001))},
    "settings.json": {"timeout": 0.5, "max_threads": 50, "log_file": "easyhex.log", "ddos_threshold": 100},
    "whitelist.json": {"allowed_ips": []},
    "users.json": {"users": [{"id": str(uuid.uuid4()), "username": "Ethan", "password": hashlib.sha256("Admin".encode()).hexdigest(), "role": "admin"}]},
    "keys.json": {
        "keys": [
            {"id": str(uuid.uuid4()), "key": hashlib.sha256("xAI-ADMIN-NEON-2025".encode()).hexdigest(), "role": "admin"}
        ]
    }
}

if not os.path.exists(CONFIG_DIR):
    os.makedirs(CONFIG_DIR)
    print(Fore.CYAN + "[+] Initialized config matrix." + Style.RESET_ALL)
for file_name, file_content in CONFIG_FILES.items():
    file_path = os.path.join(CONFIG_DIR, file_name)
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            json.dump(file_content, f, indent=4)
        print(Fore.CYAN + f"[+] Deployed {file_name} to matrix." + Style.RESET_ALL)

# Load configuration
with open(os.path.join(CONFIG_DIR, "ports.json"), "r") as f:
    PORTS_CONFIG = json.load(f)
with open(os.path.join(CONFIG_DIR, "settings.json"), "r") as f:
    SETTINGS = json.load(f)
with open(os.path.join(CONFIG_DIR, "keys.json"), "r") as f:
    KEYS = json.load(f)
with open(os.path.join(CONFIG_DIR, "whitelist.json"), "r") as f:
    WHITELIST = json.load(f)

# -------------------- LEGAL NOTICE --------------------
LEGAL = """
================== LEGAL MATRIX ==================
EASYHEX is for ethical penetration testing only.
Unauthorized access to networks or systems is ILLEGAL.
Comply with all laws. Developer not liable for misuse.
=================================================
"""

# -------------------- CYBERPUNK BANNER --------------------
def banner():
    os.system("cls" if platform.system() == "Windows" else "clear")
    print(Fore.MAGENTA + r"""
       ╔═╗╔═╗╔═══╗╦╦═╗ ╦════╗
       ║╩╠═╩╬══╦╦╗╠╩╩╩╠══╦╦╗
       ║╔╬═╗╠══╩╬╚╩╔╗║╔═╩╬╚╦═╦╦╦╗
       ╚╝╚═╩╩═══╩╩╩╩╩╩╩╚══╩╩═╩╩╩╩╩╩╩
    """ + Style.RESET_ALL)
    print(Fore.CYAN + "          EASYHEX | NEON MATRIX DOMINATOR" + Style.RESET_ALL)
    print(Fore.GREEN + LEGAL + Style.RESET_ALL)

# -------------------- LOGGING --------------------
def log_event(message):
    with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "a") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

# -------------------- PRODUCT KEY AUTHENTICATION --------------------
def product_key_auth():
    banner()
    print(Fore.MAGENTA + "=== ACCESS THE NEON MATRIX ===" + Style.RESET_ALL)
    while True:
        key = input(Fore.CYAN + "[NEONKEY] Enter product key: " + Style.RESET_ALL).strip()
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        with open(os.path.join(CONFIG_DIR, "keys.json"), "r") as f:
            keys_data = json.load(f)
        for stored_key in keys_data['keys']:
            if stored_key['key'] == key_hash:
                role = stored_key['role']
                log_event(f"{role.capitalize()} key authenticated: {key[:8]}...")
                return {"id": stored_key['id'], "key": key[:8] + "...", "role": role}
        print(Fore.RED + "[-] Invalid NEONKEY. Retry." + Style.RESET_ALL)
        log_event(f"Invalid key attempt: {key[:8]}...")
        print(Fore.CYAN + "[!] Generate a key via option 75 or use admin key: xAI-ADMIN-NEON-2025" + Style.RESET_ALL)
        input(Fore.CYAN + "[>] Press Enter to retry..." + Style.RESET_ALL)
        banner()

# -------------------- NETWORK TOOLS --------------------
def ping_host():
    target = input(Fore.CYAN + "[>] Target host/IP: " + Style.RESET_ALL)
    response = os.system(f"ping -c 4 {target}" if platform.system() != "Windows" else f"ping {target}")
    result = "Host is up." if response == 0 else "Host is down or unreachable."
    print(Fore.GREEN + f"[+] {result}" + Style.RESET_ALL)
    log_event(f"Pinged {target}: {result}")

def port_scan():
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    ports = PORTS_CONFIG["common_ports"]
    print(Fore.MAGENTA + f"[*] Scanning {target} on common ports..." + Style.RESET_ALL)
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(SETTINGS["timeout"])
            s.connect((target, port))
            print(Fore.GREEN + f"[+] Port {port} is OPEN" + Style.RESET_ALL)
            s.close()
            log_event(f"Port scan: {target}}:{port} is OPEN")
        except:
            pass

def extended_port_scan():
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
    ports = PORTS_CONFIG["extended_ports"]
    open_ports = []
    def scan_port(port)):
        try:
            s = socket.socket()
            s.settimeout(SETTINGS["timeout"])
            s.connect((target, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    print(Fore.MAGENTA + "[*] Initiating extended scan on {target}..." + Style.RESET_ALL)
    with ThreadPoolExecutor(max_workers=SETTINGS["max_threads"]) as executor:
        executor.map(scan_port, ports)
    for port in open_ports:
        print(Fore.GREEN + f"[+ Port {port}] is OPEN" + Style.RESET_ALL)
        log_event(f"Extended port scan: {target}:{port} is OPEN")

def get_ip():
    hostname = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        ip = socket.gethostbyname(hostname)
        print(Fore.GREEN + f"[+] IP of {hostname}: {ip}" + Style.RESET_ALL)
        log_event(f"Resolved {hostname} to {ip}")
    except socket.error:
        print(Fore.RED + "[-] Invalid hostname." + Style.RESET_ALL)
        log_event(f"Failed to resolve {hostname}")

def http_headers():
    url = input(Fore.CYAN + "[>] Enter full URL (http://...): " + Style.RESET_ALL)
    try:
        r = requests.get(url)
        print(Fore.MAGENTA + "[*] HTTP Headers:" + Style.RESET_ALL)
        for k, v in r.headers.items():
            print(Fore.GREEN + f"{k}: {v}" + Style.RESET_ALL)
        log_event(f"Retrieved HTTP headers for {url}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"HTTP headers error for {url}: {e}")

def reverse_ip():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"[+] IP: {ip}]" + Style.RESET_ALL)
        print(Fore.MAGENTA + "[*] Domains hosted (mock):" + Style.RESET_ALL)
        print(Fore.GREEN + "example.com\nsub.example.com" + Style.RESET_ALL)
        log_event(f"Reverse IP lookup for {domain}: {ip}")
    except:
        print(Fore.RED + "[-] Reverse IP Lookup failed." + Style.RESET_ALL)
        log_event(f"Reverse IP lookup failed for {domain}")

def dns_lookup():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        result = socket.gethostbyname_ex(domain)
        print(Fore.GREEN + f"[+] DNS Info: {result}" + Style.RESET_ALL)
        log_event(f"DNS lookup for {domain}: {result}")
    except:
        print(Fore.RED + "[-] DNS Lookup failed." + Style.RESET_ALL)
        log_event(f"DNS lookup failed for {domain}")

def traceroute():
    target = input(Fore.CYAN + "[>] Enter target: " + Style.RESET_ALL)
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
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        import whois
        data = whois.whois(domain)
        print(Fore.MAGENTA + "[*] WHOIS Data:" + Style.RESET_ALL)
        print(Fore.GREEN + str(data) + Style.RESET_ALL)
        log_event(f"WHOIS lookup for {domain}")
    except:
        print(Fore.RED + "[-] Install `python-whois` module." + Style.RESET_ALL)
        log_event(f"WHOIS lookup failed for {domain}: python-whois not installed")

def packet_sniffer():
    interface = input(Fore.CYAN + "[>] Enter interface (e.g., eth0): " + Style.RESET_ALL)
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
        print(Fore.RED + "[-] Install `scapy` module." + Style.RESET_ALL)
        log_event("Packet sniffer failed: scapy not installed")

def arp_spoof_detector():
    try:
        import scapy.all as scapy
        def detect_arp(packet):
            if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
                print(Fore.RED + f"[!] ARP spoofing: {packet[scapy.ARP].psrc} claims {packet[scapy.ARP].hwsrc}" + Style.RESET_ALL)
                log_event(f"Detected ARP spoofing: {packet[scapy.ARP].psrc}")
        scapy.sniff(filter="arp", prn=detect_arp, count=10)
    except:
        print(Fore.RED + "[-] Install `scapy` module." + Style.RESET_ALL)
        log_event("ARP spoof detector failed: scapy not installed")

def mac_address_lookup():
    ip = input(Fore.CYAN + "[>] Enter IP: " + Style.RESET_ALL)
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
        print(Fore.RED + "[-] Install `scapy` module." + Style.RESET_ALL)
        log_event(f"MAC address lookup failed for {ip}")

def bandwidth_monitor():
    print(Fore.MAGENTA + "[*] Monitoring bandwidth..." + Style.RESET_ALL)
    try:
        for _ in range(5):
            net_io = psutil.net_io_counters()
            print(Fore.GREEN + f"[+] Sent: {net_io.bytes_sent / 1024 / 1024:.2f} MB, Received: {net_io.bytes_recv / 1024 / 1024:.2f} MB" + Style.RESET_ALL)
            log_event(f"Bandwidth: Sent {net_io.bytes_sent / 1024 / 1024:.2f} MB, Received {net_io.bytes_recv / 1024 / 1024:.2f} MB")
            time.sleep(1)
    except:
        print(Fore.RED + "[-] Install `psutil` module." + Style.RESET_ALL)
        log_event("Bandwidth monitor failed: psutil not installed")

def ssl_certificate_check():
    url = input(Fore.CYAN + "[>] Enter URL (https://...): " + Style.RESET_ALL)
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
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[*] Network Interfaces:" + Style.RESET_ALL)
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                print(Fore.GREEN + f"[+] {iface}: {addr['addr']}" + Style.RESET_ALL)
                log_event(f"Network interface: {iface} -> {addr['addr']}")

def file_integrity_check():
    file_path = input(Fore.CYAN + "[>] Enter file path: " + Style.RESET_ALL)
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        print(Fore.GREEN + f"[+] SHA256: {file_hash}" + Style.RESET_ALL)
        log_event(f"File integrity check: {file_path} -> {file_hash}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"File integrity check failed for {file_path}: {e}")

def vulnerability_scan():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[*] Scanning vulnerabilities (mock)..." + Style.RESET_ALL)
    vulnerabilities = ["Open port 23 (Telnet)", "Weak SSL version detected"]
    for vuln in vulnerabilities:
        print(Fore.RED + f"[!] {vuln}" + Style.RESET_ALL)
        log_event(f"Vulnerability scan: {target} -> {vuln}")

def packet_injection_test():
    print(Fore.MAGENTA + "[*] Packet injection test (root required)." + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        dest_ip = input(Fore.CYAN + "[>] Enter destination IP: " + Style.RESET_ALL)
        packet = scapy.IP(dst=dest_ip)/scapy.ICMP()
        scapy.send(packet, verbose=0)
        print(Fore.GREEN + "[+] Packet sent." + Style.RESET_ALL)
        log_event(f"Packet injection test sent to {dest_ip}")
    except:
        print(Fore.RED + "[-] Install `scapy` and run as root." + Style.RESET_ALL)
        log_event("Packet injection test failed")

def password_strength_checker():
    password = getpass.getpass(Fore.CYAN + "[>] Enter password: " + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[*] Analyzing traffic (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Detected: TCP, UDP, ICMP" + Style.RESET_ALL)
    log_event("Network traffic analysis performed")

def firewall_rule_check():
    print(Fore.MAGENTA + "[*] Checking firewall (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Rules: Allow TCP 80, 443; Block UDP 53" + Style.RESET_ALL)
    log_event("Firewall rule check performed")

def os_fingerprinting():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[*] Fingerprinting OS (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] OS: Linux/Windows (mock)" + Style.RESET_ALL)
    log_event(f"OS fingerprinting attempted on {target}")

def banner_grabbing():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    port = int(input(Fore.CYAN + "[>] Enter port: " + Style.RESET_ALL))
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
    ip = input(Fore.CYAN + "[>] Enter IP (e.g., 192.168.1.0): " + Style.RESET_ALL)
    mask = int(input(Fore.CYAN + "[>] Enter mask bits (e.g., 24): " + Style.RESET_ALL))
    try:
        network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        print(Fore.GREEN + f"[+] Network: {network.network_address}/{mask}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Hosts: {network.num_addresses - 2}" + Style.RESET_ALL)
        log_event(f"Subnet calculated for {ip}/{mask}")
    except:
        print(Fore.RED + "[-] Invalid IP or mask." + Style.RESET_ALL)
        log_event(f"Subnet calculation failed for {ip}/{mask}")

def geo_ip_lookup():
    ip = input(Fore.CYAN + "[>] Enter IP: " + Style.RESET_ALL)
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
        print(Fore.RED + "[-] GeoIP lookup error." + Style.RESET_ALL)
        log_event(f"GeoIP lookup error for {ip}")

def http_method_test():
    url = input(Fore.CYAN + "[>] Enter URL: " + Style.RESET_ALL)
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
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    try:
        answers = dns.resolver.resolve(domain, "NS")
        for ns in answers:
            ns = str(ns)
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                print(Fore.GREEN + f"[+] Zone transfer from {ns}:" + Style.RESET_ALL)
                for name, rdata in zone.iterate_rdatas():
                    print(Fore.GREEN + f"{name}: {rdata}" + Style.RESET_ALL)
                log_event(f"DNS zone transfer from {ns} for {domain}")
            except:
                print(Fore.RED + f"[-] Zone transfer failed for {ns}" + Style.RESET_ALL)
                log_event(f"DNS zone transfer failed for {ns}")
    except:
        print(Fore.RED + "[-] DNS zone transfer failed." + Style.RESET_ALL)
        log_event(f"DNS zone transfer failed for {domain}")

def network_latency_test():
    target = input(Fore.CYAN + "[>] Enter target IP/hostname: " + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[*] Analyzing protocols (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Detected: HTTP, HTTPS, FTP, SSH" + Style.RESET_ALL)
    log_event("Protocol analysis performed")

def log_file_analyzer():
    log_file = os.path.join(CONFIG_DIR, SETTINGS["log_file"])
    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
        print(Fore.MAGENTA + "[*] Recent log entries:" + Style.RESET_ALL)
        for line in lines[-5:]:
            print(Fore.GREEN + f"[+] {line.strip()}" + Style.RESET_ALL)
        log_event("Log file analysis performed")
    except:
        print(Fore.RED + "[-] Log file not found." + Style.RESET_ALL)
        log_event("Log file analysis failed")

def web_crawler():
    url = input(Fore.CYAN + "[>] Enter URL: " + Style.RESET_ALL)
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        print(Fore.MAGENTA + "[*] Crawled Links:" + Style.RESET_ALL)
        for link in links[:10]:
            print(Fore.GREEN + f"[+] {link}" + Style.RESET_ALL)
        log_event(f"Web crawl performed on {url}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Web crawl failed for {url}: {e}")

def sql_injection_tester():
    url = input(Fore.CYAN + "[>] Enter URL (e.g., http://example.com?id=1): " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[*] Testing SQL injection (mock, ethical)..." + Style.RESET_ALL)
    payloads = ["' OR '1'='1", "'--"]
    for payload in payloads:
        test_url = f"{url}{payload}"
        try:
            r = requests.get(test_url)
            if "sql" in r.text.lower():
                print(Fore.RED + f"[!] Potential SQLi: {test_url}" + Style.RESET_ALL)
            else:
                print(Fore.GREEN + f"[+] Safe: {test_url}" + Style.RESET_ALL)
            log_event(f"SQLi test on {test_url}")
        except:
            print(Fore.RED + f"[-] Failed: {test_url}" + Style.RESET_ALL)
            log_event(f"SQLi test failed for {test_url}")

def wifi_scanner():
    print(Fore.MAGENTA + "[*] Scanning Wi-Fi networks..." + Style.RESET_ALL)
    try:
        import wifi
        networks = wifi.Cell.all('wlan0')
        for network in networks[:5]:
            print(Fore.GREEN + f"[+] SSID: {network.ssid}, Signal: {network.signal}" + Style.RESET_ALL)
            log_event(f"Wi-Fi scan: {network.ssid}")
    except:
        print(Fore.RED + "[-] Install `wifi` module and run as root." + Style.RESET_ALL)
        log_event("Wi-Fi scan failed: wifi module not installed")

def packet_crafter():
    print(Fore.MAGENTA + "[*] Crafting packet (root required)..." + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        dest_ip = input(Fore.CYAN + "[>] Destination IP: " + Style.RESET_ALL)
        payload = input(Fore.CYAN + "[>] Payload: " + Style.RESET_ALL)
        packet = scapy.IP(dst=dest_ip)/scapy.TCP(dport=80)/scapy.Raw(load=payload)
        scapy.send(packet, verbose=0)
        print(Fore.GREEN + "[+] Packet sent." + Style.RESET_ALL)
        log_event(f"Packet crafted and sent to {dest_ip}")
    except:
        print(Fore.RED + "[-] Install `scapy` and run as root." + Style.RESET_ALL)
        log_event("Packet crafting failed")

def network_topology_mapper():
    print(Fore.MAGENTA + "[*] Mapping topology (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Devices: Router (192.168.1.1), Host (192.168.1.100)" + Style.RESET_ALL)
    log_event("Network topology mapping performed")

def brute_force_tester():
    url = input(Fore.CYAN + "[>] Enter login URL: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[*] Testing brute force (mock, ethical)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Result: Login page rate-limits after 5 attempts." + Style.RESET_ALL)
    log_event(f"Brute force test on {url}")

def firewall_bypass_test():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[*] Testing firewall bypass (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Open ports detected: 80, 443" + Style.RESET_ALL)
    log_event(f"Firewall bypass test on {target}")

# -------------------- NEW NETWORK TOOLS --------------------
def advanced_packet_analyzer():
    interface = input(Fore.CYAN + "[>] Enter interface (e.g., eth0): " + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        def analyze_packet(packet):
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                proto = packet[scapy.IP].proto
                print(Fore.GREEN + f"[+] Packet: {src} -> {dst}, Protocol: {proto}" + Style.RESET_ALL)
                log_event(f"Analyzed packet: {src} -> {dst}, Proto: {proto}")
        scapy.sniff(iface=interface, prn=analyze_packet, count=10)
    except:
        print(Fore.RED + "[-] Install `scapy` module." + Style.RESET_ALL)
        log_event("Advanced packet analyzer failed: scapy not installed")

def vpn_detection():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[*] Detecting VPN (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] VPN detected: OpenVPN protocol" + Style.RESET_ALL)
    log_event(f"VPN detection on {target}")

def cloud_service_enumeration():
    target = input(Fore.CYAN + "[>] Enter target IP/domain: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[*] Enumerating cloud services (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Detected: AWS S3, Azure Blob Storage" + Style.RESET_ALL)
    log_event(f"Cloud service enumeration on {target}")

def port_knocking_simulator():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    ports = input(Fore.CYAN + "[>] Enter port sequence (e.g., 1000,2000,3000): " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[*] Simulating port knocking..." + Style.RESET_ALL)
    for port in ports.split(','):
        try:
            s = socket.socket()
            s.settimeout(SETTINGS["timeout"])
            s.connect((target, int(port)))
            s.close()
            print(Fore.GREEN + f"[+] Knocked port {port}" + Style.RESET_ALL)
            log_event(f"Port knock: {target}:{port}")
        except:
            print(Fore.RED + f"[-] Failed port {port}" + Style.RESET_ALL)
            log_event(f"Port knock failed: {target}:{port}")

def network_intrusion_detection():
    print(Fore.MAGENTA + "[*] Monitoring for intrusions (mock)..." + Style.RESET_ALL)
    print(Fore.RED + "[!] Suspicious traffic: Port scan detected" + Style.RESET_ALL)
    log_event("Network intrusion detection performed")

def ip_spoofing_test():
    print(Fore.MAGENTA + "[*] Testing IP spoofing (root required)..." + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        src_ip = input(Fore.CYAN + "[>] Source IP (spoofed): " + Style.RESET_ALL)
        dest_ip = input(Fore.CYAN + "[>] Destination IP: " + Style.RESET_ALL)
        packet = scapy.IP(src=src_ip, dst=dest_ip)/scapy.ICMP()
        scapy.send(packet, verbose=0)
        print(Fore.GREEN + "[+] Spoofed packet sent." + Style.RESET_ALL)
        log_event(f"IP spoofing test: {src_ip} -> {dest_ip}")
    except:
        print(Fore.RED + "[-] Install `scapy` and run as root." + Style.RESET_ALL)
        log_event("IP spoofing test failed")

def ssl_tls_version_scanner():
    url = input(Fore.CYAN + "[>] Enter URL (https://...): " + Style.RESET_ALL)
    try:
        hostname = urllib.parse.urlparse(url).hostname
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(Fore.GREEN + f"[+] TLS Version: {ssock.version()}" + Style.RESET_ALL)
                log_event(f"SSL/TLS scan for {url}: {ssock.version()}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"SSL/TLS scan failed for {url}: {e}")

def dns_cache_poisoning_test():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[*] Testing DNS cache poisoning (mock, ethical)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Result: DNS server not vulnerable" + Style.RESET_ALL)
    log_event(f"DNS cache poisoning test on {domain}")

def network_congestion_analyzer():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[*] Analyzing congestion (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Congestion: Moderate, 50ms delay" + Style.RESET_ALL)
    log_event(f"Network congestion analysis on {target}")

def iot_device_scanner():
    print(Fore.MAGENTA + "[*] Scanning IoT devices (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Devices: Smart Camera (192.168.1.50), Thermostat (192.168.1.51)" + Style.RESET_ALL)
    log_event("IoT device scan performed")

# -------------------- ETHICAL TOOLS --------------------
def ethical_dilemma_analyzer():
    print(Fore.MAGENTA + "[*] Ethical Dilemma Analyzer" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Network action: " + Style.RESET_ALL)
    target = input(Fore.CYAN + "[>] Target (IP/domain): " + Style.RESET_ALL)
    permission = input(Fore.CYAN + "[>] Explicit permission? (yes/no): " + Style.RESET_ALL).lower()
    result = "Ethical" if permission == "yes" else "Unethical: Requires permission"
    print(Fore.GREEN + f"[+] Analysis: {result}" + Style.RESET_ALL)
    log_event(f"Ethical dilemma analysis: {action} on {target} -> {result}")

def decision_making_framework():
    print(Fore.MAGENTA + "[*] Decision-Making Framework" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action to evaluate: " + Style.RESET_ALL)
    criteria = ["Legality", "Consent", "Impact", "Necessity"]
    scores = {}
    for criterion in criteria:
        score = int(input(Fore.CYAN + f"[>] Score for {criterion} (1-5): " + Style.RESET_ALL))
        scores[criterion] = score
    avg_score = sum(scores.values()) / len(scores)
    result = "Proceed" if avg_score >= 3 else "Reconsider"
    print(Fore.GREEN + f"[+] Decision: {result} (Score: {avg_score:.2f})" + Style.RESET_ALL)
    log_event(f"Decision-making framework: {action} -> {result}")

def principles_manager():
    print(Fore.MAGENTA + "[*] Ethical Principles Manager" + Style.RESET_ALL)
    principles = ["Respect for autonomy", "Non-maleficence", "Beneficence", "Justice"]
    print(Fore.GREEN + "[+] Principles: " + ", ".join(principles) + Style.RESET_ALL)
    new_principle = input(Fore.CYAN + "[>] Add principle (Enter to skip): " + Style.RESET_ALL)
    if new_principle:
        principles.append(new_principle)
        print(Fore.GREEN + f"[+] Added: {new_principle}" + Style.RESET_ALL)
        log_event(f"Added ethical principle: {new_principle}")

def compliance_checker():
    print(Fore.MAGENTA + "[*] Compliance Checker" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action to check: " + Style.RESET_ALL)
    standards = ["GDPR", "HIPAA", "PCI-DSS"]
    results = []
    for standard in standards:
        compliant = input(Fore.CYAN + f"[>] Compliant with {standard}? (yes/no): " + Style.RESET_ALL).lower()
        results.append(f"{standard}: {'Compliant' if compliant == 'yes' else 'Non-compliant'}")
    print(Fore.GREEN + "[+] Results: " + "; ".join(results) + Style.RESET_ALL)
    log_event(f"Compliance check for {action}: {'; '.join(results)}")

def scenario_generator():
    print(Fore.MAGENTA + "[*] Ethical Scenario Generator" + Style.RESET_ALL)
    scenarios = [
        "Unauthorized port scan on a corporate network",
        "Packet sniffing on a public Wi-Fi",
        "Bypassing authentication on a test server"
    ]
    scenario = random.choice(scenarios)
    print(Fore.GREEN + f"[+] Scenario: {scenario}" + Style.RESET_ALL)
    log_event(f"Generated scenario: {scenario}")

def decision_tree_builder():
    print(Fore.MAGENTA + "[*] Decision Tree Builder" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action to analyze: " + Style.RESET_ALL)
    tree = {"Action": action, "Steps": []}
    while True:
        step = input(Fore.CYAN + "[>] Add step (Enter to finish): " + Style.RESET_ALL)
        if not step:
            break
        tree["Steps"].append(step)
    print(Fore.GREEN + f"[+] Tree: {json.dumps(tree, indent=2)}" + Style.RESET_ALL)
    log_event(f"Built decision tree for {action}")

def risk_assessment():
    print(Fore.MAGENTA + "[*] Risk Assessment" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action to assess: " + Style.RESET_ALL)
    risks = ["Data breach", "Legal violation", "Reputation damage"]
    scores = {}
    for risk in risks:
        score = int(input(Fore.CYAN + f"[>] Risk level for {risk} (1-5): " + Style.RESET_ALL))
        scores[risk] = score
    avg_score = sum(scores.values()) / len(scores)
    result = "Low risk" if avg_score < 3 else "High risk"
    print(Fore.GREEN + f"[+] Risk: {result} (Score: {avg_score:.2f})" + Style.RESET_ALL)
    log_event(f"Risk assessment for {action}: {result}")

def ethics_report_generator():
    print(Fore.MAGENTA + "[*] Ethics Report Generator" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action analyzed: " + Style.RESET_ALL)
    report = f"Ethics Report\nAction: {action}\nEthical: Requires permission\nRecommendation: Obtain consent"
    print(Fore.GREEN + f"[+] {report}" + Style.RESET_ALL)
    log_event(f"Generated ethics report for {action}")

def stakeholder_analysis():
    print(Fore.MAGENTA + "[*] Stakeholder Analysis" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action to analyze: " + Style.RESET_ALL)
    stakeholders = ["Users", "Admins", "Clients"]
    impacts = {}
    for stakeholder in stakeholders:
        impact = input(Fore.CYAN + f"[>] Impact on {stakeholder}: " + Style.RESET_ALL)
        impacts[stakeholder] = impact
    print(Fore.GREEN + f"[+] Impacts: {json.dumps(impacts, indent=2)}" + Style.RESET_ALL)
    log_event(f"Stakeholder analysis for {action}")

def privacy_impact_assessment():
    print(Fore.MAGENTA + "[*] Privacy Impact Assessment" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action to assess: " + Style.RESET_ALL)
    data_types = ["Personal", "Financial", "Health"]
    risks = {}
    for data in data_types:
        risk = input(Fore.CYAN + f"[>] Privacy risk for {data} data (low/medium/high): " + Style.RESET_ALL)
        risks[data] = risk
    print(Fore.GREEN + f"[+] Risks: {json.dumps(risks, indent=2)}" + Style.RESET_ALL)
    log_event(f"Privacy impact assessment for {action}")

def ethical_ai_analysis():
    print(Fore.MAGENTA + "[*] Ethical AI Analysis" + Style.RESET_ALL)
    tool = input(Fore.CYAN + "[>] AI tool to analyze: " + Style.RESET_ALL)
    concerns = ["Bias", "Transparency", "Accountability"]
    results = {}
    for concern in concerns:
        level = input(Fore.CYAN + f"[>] Concern level for {concern} (low/medium/high): " + Style.RESET_ALL)
        results[concern] = level
    print(Fore.GREEN + f"[+] Results: {json.dumps(results, indent=2)}" + Style.RESET_ALL)
    log_event(f"Ethical AI analysis for {tool}")

def social_engineering_simulator():
    print(Fore.MAGENTA + "[*] Social Engineering Simulator (ethical)" + Style.RESET_ALL)
    scenario = random.choice(["Phishing email", "Phone scam", "USB drop"])
    print(Fore.GREEN + f"[+] Scenario: {scenario}" + Style.RESET_ALL)
    log_event(f"Social engineering scenario: {scenario}")

def bias_detection_framework():
    print(Fore.MAGENTA + "[*] Bias Detection Framework" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action to analyze: " + Style.RESET_ALL)
    biases = ["Selection bias", "Confirmation bias", "Automation bias"]
    detected = random.choice(biases)
    print(Fore.RED + f"[!] Detected: {detected}" + Style.RESET_ALL)
    log_event(f"Bias detection for {action}: {detected}")

def ethical_audit_trail():
    print(Fore.MAGENTA + "[*] Ethical Audit Trail" + Style.RESET_ALL)
    try:
        with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "r") as f:
            logs = [line for line in f if "ethical" in line.lower()]
        print(Fore.GREEN + "[+] Ethical actions:" + Style.RESET_ALL)
        for log in logs[-5:]:
            print(Fore.GREEN + f"{log.strip()}" + Style.RESET_ALL)
        log_event("Ethical audit trail reviewed")
    except:
        print(Fore.RED + "[-] Audit trail failed." + Style.RESET_ALL)
        log_event("Ethical audit trail failed")

# -------------------- UTILITY TOOLS --------------------
def user_signup():
    print(Fore.RED + "[!] Use option 64 to generate a new product key instead." + Style.RESET_ALL)
    log_event("User sign-up redirected to product key generation")

def automated_backup():
    print(Fore.MAGENTA + "[*] Initiating backup..." + Style.RESET_ALL)
    backup_dir = os.path.join(CONFIG_DIR, "backups")
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
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
    print(Fore.MAGENTA + "[*] Multi-Language Interface" + Style.RESET_ALL)
    languages = {"en": "English", "es": "Spanish", "fr": "French"}
    lang = input(Fore.CYAN + f"[>] Select language ({', '.join(languages.values())}): " + Style.RESET_ALL).lower()
    lang_code = next((code for code, name in languages.items() if name.lower() == lang), "en")
    try:
        from translate import Translator
        translator = Translator(to_lang(lang_code)
        message = translator.translate("Network scan completed")
        print(Fore.GREEN + f"[+] Translated: {message}" + Style.RESET_ALL)
        log_event(f"Translated message to {lang_code}")
    except ImportError:
        print(Fore.RED + "[-] Install `python-translate` module." + Style.RESET_ALL)
        log_event("Multi-language support failed: python-translate not installed")

def report_generator():
    print(Fore.MAGENTA + "[*] Generating Report" + Style.RESET_ALL)
    report_type = input(Fore.CYAN + "[>] Type (summary/detailed): " + Style.RESET_ALL).lower()
    try:
        with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "r") as f:
            logs = f.readlines()
        report_file = os.path.join(CONFIG_DIR, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(report_file, "w") as f:
            f.write("EASYHEX Report\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Type: {report_type}\n\n")
            if report_type == "summary":
                f.write(f"Total Logs: {len(logs)}\n")
            else:
                for log in logs:
                    f.write(log)
        print(Fore.GREEN + f"[+] Report saved: {report_file}" + Style.RESET_ALL)
        log_event(f"Generated {report_type} report: {report_file}")
    except:
        print(Fore.RED + "[-] Report generation failed." + Style.RESET_ALL)
        log_event("Report generation failed")

def file_encryptor():
    file_path = input(Fore.CYAN + "[>] Enter file path to encrypt: " + Style.RESET_ALL)
    try:
        key = Fernet.generate_key()
        fernet = Fernet(key)
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open(file_path + ".enc", "wb") as f:
            f.write(encrypted)
        with open(file_path + ".key", "wb") as f:
            f.write(key)
        print(Fore.GREEN + f"[+] Encrypted: {file_path}.enc, Key: {file_path}.key" + Style.RESET_ALL)
        log_event(f"Encrypted file: {file_path}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"File encryption failed for {file_path}: {e}")

def system_monitor():
    print(Fore.MAGENTA + "[*] System Monitor" + Style.RESET_ALL)
    try:
        for _ in range(5):
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            print(Fore.GREEN + f"[+] CPU: {cpu}%, Memory: {mem}%, Disk: {disk}%" + Style.RESET_ALL)
            log_event(f"System monitor: CPU {cpu}%, Memory {mem}%, Disk {disk}%")
            time.sleep(1)
    except:
        print(Fore.RED + "[-] Install `psutil` module." + Style.RESET_ALL)
        log_event("System monitor failed: psutil not installed")

def api_scanner():
    url = input(Fore.CYAN + "[>] Enter API URL: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[*] Scanning API (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Endpoints: /api/v1/users, /api/v1/data" + Style.RESET_ALL)
    log_event(f"API scan on {url}")

def password_generator():
    length = int(input(Fore.CYAN + "[>] Password length: " + Style.RESET_ALL))
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for _ in range(length))
    print(Fore.GREEN + f"[+] Password: {password}" + Style.RESET_ALL)
    log_event("Generated random password")

def log_cleaner():
    log_file = os.path.join(CONFIG_DIR, SETTINGS["log_file"])
    days = int(input(Fore.CYAN + "[>] Clear logs older than (days): " + Style.RESET_ALL))
    try:
        cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
        with open(log_file, "r") as f:
            lines = f.readlines()
        with open(log_file, "w") as f:
            for line in lines:
                timestamp = datetime.datetime.strptime(line[1:20], "%Y-%m-%d %H:%M:%S")
                if timestamp >= cutoff:
                    f.write(line)
        print(Fore.GREEN + "[+] Logs cleaned." + Style.RESET_ALL)
        log_event(f"Cleared logs older than {days} days")
    except Exception as e:
        print(Fore.RED + f"[-] Failed: {e}" + Style.RESET_ALL)
        log_event(f"Log cleaning failed: {e}")

def file_decrypt():
    file_path = input(Fore.CYAN + "[>] Enter encrypted file path: " + Style.RESET_ALL)
    key_file = input(Fore.CYAN + "[>] Enter key file path: " + Style.RESET_ALL)
    try:
        with open(key_file, "rb") as f:
            key = f.read()
        fernet = Fernet(key)
        with open(file_path, "rb") as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted)
        output_file = file_path.replace(".enc", "_decrypted")
        with open(output_file, "wb") as f:
            f.write(decrypted)
        print(Fore.GREEN + f"[+] Decrypted: {output_file}" + Style.RESET_ALL)
        log_event(f"Decrypted file: {file_path}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"File decryption failed: {file_path}")

def network_speed_test():
    print(Fore.MAGENTA + "[*] Testing network speed..." + Style.RESET_ALL)
    try:
        st = speedtest.Speedtest()
        st.download()
        st.upload()
        results = st.results.dict()
        print(Fore.GREEN + f"[+] Download: {results['download'] / 1000000:.2f} Mbps, Upload: {results['upload'] / 1000000:.2f} Mbps" + Style.RESET_ALL)
        log_event(f"Network speed: {results['download'] / 1000000:.2f} Mbps. down: Upload, Mbps: {results['upload'] / 1000000:.2f}")
    except:
        print(Fore.RED + "[-] Install `speedtest-cli` module." + Style.RESET_ALL)
        log_event("Network speed test failed: speedtest-cli not installed")

def dark_pool():
    print(Fore.MAGENTA + "[*] Scanning dark pool (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Activity: Tor node detected at 192.168.1.99" + Style.RESET_ALL)
    log_event("Dark pool scan performed")

def product_key_generator(session):
    if session["role"] != "admin":
        print(Fore.RED + "[-] Admin NEONKEY required!" + Style.RESET_ALL)
        log_event("Product key generation attempted by non-admin")
        return
    print(Fore.MAGENTA + "[*] Generating product key..." + Style.RESET_ALL)
    key = f"xAI-KEY-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    with open(os.path.join(CONFIG_DIR, "keys.json"), "r") as f:
        keys_data = json.load(f)
    keys_data["keys"].append({"id": str(uuid.uuid4()), "key": key_hash, "role": "public"})
    with open(os.path.join(CONFIG_DIR, "keys.json"), "w") as f:
        json.dump(keys_data, f, indent=4)
    print(Fore.GREEN + f"[+] Generated key: {key}" + Style.RESET_ALL)
    log_event(f"Generated product key: {key[:8]}...")

# -------------------- HELP MENU --------------------
def help_menu():
    print(Fore.YELLOW + "\n===== NEON MATRIX KEYS =====" + Style.RESET_ALL)
    print(Fore.CYAN + """
[NETWORK]
1. Ping Host                - Test connectivity
2. Port Scanner             - Scan common ports
3. Get IP                  - Resolve hostname
4. HTTP Headers           - Fetch headers
5. Reverse IP                - IP domain lookup (mock)
6. DNS Lookup               - DNS records
7. Traceroute              - Packet route
8. WHOIS                    - Domain info
9. Extended Port Scan      - Ports 1–1000
10. Packet Sniffer         - Capture packets (scapy)
11. ARP Spoofing          - Detect ARP spoofing
12. MAC Lookup             - Find MAC address
13. Bandwidth Monitor      - Track usage
14. SSL Certificate        - Check SSL certs
15. DNS Enumeration        - DNS record types
16. Network Interfaces      - List adapters
17. File Integrity         - SHA256 hash
18. Vulnerability Scan      - Basic vuln check (mock)
19. Packet Injection       - Test packet (scapy)
20. Password Strength      - Evaluate password
21. Traffic Analysis      - Analyze traffic (mock)
22. Firewall Rules         - Check firewall (mock)
23. OS Fingerprint         - Detect OS (mock)
24. Banner Grab            - Service banners
25. Subnet Calculator      - Subnet details
26. GeoIP Lookup           - IP geolocation
27. HTTP Methods           - Test HTTP methods
28. DNS Zone Transfer      - Zone transfer
29. Network Latency       - Measure latency
30. Protocol Analysis          - Protocols (mock)
31. Log Analyzer           - Review logs
32. Web Crawler             - Extract links
33. SQL Injection          - Test SQLi (mock)
34. Wi-Fi Scanner           - List Wi-Fi
35. Packet Crafter         - Custom packets
36. Topology Mapper      - Network map (mock)
37. Brute Force           - Login test (mock)
38. Firewall Bypass        - Test bypass (mock)
39. Packet Analyzer       - Detailed packet info
40. VPN Detection           - Detect VPN (mock)
41. Cloud Enumeration         - Cloud services (mock)
42. Port Knocking         - Simulate knocking
43. Intrusion Detection    - Monitor traffic (mock)
44. IP Spoofing           - Test spoofing (admin)
45. SSL/TLS Scanner        - TLS versions
46. DNS Poisoning        - Test poisoning (mock)
47. Network Congestion     - Analyze bottlenecks (mock)
48. IoT Scanner          - Detect IoT (mock)

[ETHICAL]
49. Ethical Dilemma        - Analyze ethics
50. Decision Framework   - Evaluate actions
51. Principles Manager     - Manage principles
52. Compliance Check       - Verify standards
53. Scenario Generator     - Ethical scenarios
54. Decision Tree        - Build trees
55. Risk Assessment        - Assess risks
56. Ethics Report           - Generate report
57. Stakeholder Analysis   - Impact analysis
58. Privacy Impact       - Data privacy
59. Ethical AI           - AI ethics
60. Social Engineering    - Phishing scenarios
61. Bias Detection        - Detect biases
62. Ethical Audit      - Audit trail

[UTILITY]
63. Auto Backup            - Backup config
64. Multi-Language          - Translate
65. Report Generator       - Log reports
66. File Encryptor         - AES-256 encryption
67. System Monitor        - CPU, memory
68. API Scanner           - Test APIs (mock)
69. File Decryptor        - AES decryption
70. Network Speed         - Speed test
71. Dark Pool            - Scan dark pool (mock)
72. Password Generator    - Random passwords
73. Log Cleaner                  - Clear logs
74. Product Key Gen           - Generate keys (admin)
75. User Sign-Up           - Deprecated, use key gen

[CONTROL]
76. Disconnect          - Exit CLI
h. Matrix Index         - Show this

Admin Tools:
- Run `dashboard.py` for admin controls
- URL: http://localhost:5000
- Features: User management, DDoS whitelist, metrics, admin stress test
- Admin key: xAI-ADMIN-NEON-2025
""" + Style.RESET_ALL)

# -------------------- MENU --------------------
def menu(session):
    while True:
        banner()
        print(Fore.MAGENTA + f"[NODE: {session['key']}] [ROLE: {session['role'].upper()}]" + Style.RESET_ALL)
        print(Fore.YELLOW + "\n===== NEON MATRIX COMMANDMENT =====" + Style.RESET_ALL)
        print(Fore.CYAN + """
[NETWORK]
1. Ping Host    2. Port Scan    3. Get IP    4. HTTP Headers    5. Reverse IP
6. DNS Lookup    7. Traceroute    8. WHOIS    9. Extended Scan    10. Hosts
11. ARP Spoof    12. MAC Lookup    13. Bandwidth    14. SSL Cert    15. DNS Enum
16. Interfaces    17. File Hash    18. Network    19. Packet Inject    20. Password
21. Traffic    22. Firewall    23. Encryption    22. OS Fingerprint    24. Banner Grab
25. Subnet    26. GeoIP    27. HTTP Methods    28. Zone Transfer    29. Network
30. Latency    31. Protocols    32. Log Analyzer    33. Web Crawler
34. SQLi Test    35. Wi-Fi Scan    36. Packet Craft    37. Topology
38. Brute Force    39. Firewall Bypass    40. Packet Analyze
45. VPN Detect    46. Cloud Enum    47. Port Knock    48. Intrusion
49. IP Spoof    50. SSL/TLS     51. DNS Poison    52. Congestion    53. IoT Scan

[ETHICAL]
54. Ethical Dilemma    55. Decision    53. Principles    54. Compliance
55. Scenarios    56. Decision Tree    57. Risk Assess    58. Ethics Report
59. Stakeholders    60. Privacy Impact    61. Ethical AI
62. Social Eng    63. Bias Detect    64. Audit Trail

[UTILITY]
65. Backup    66. Language    67. Report    68. Encrypt    69. Monitor
70. API Scan    71. Decrypt    72. Speed Test    73. Dark Pool
74. Password Gen    75. Log Clean    76. Key Gen

[CONTROL]
76. Exit    h. Help
""" + Style.RESET_ALL)
        choice = input(Fore.GREEN + "[>] Select: " + Style.RESET_ALL).strip().lower()
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
            web_crawler()
        elif choice == "33":
            sql_injection_tester()
        elif choice == "34":
            wifi_scanner()
        elif choice == "35":
            packet_crafter()
        elif choice == "36":
            network_topology_mapper()
        elif choice == "37":
            brute_force_tester()
        elif choice == "38":
            firewall_bypass_test()
        elif choice == "39":
            advanced_packet_analyzer()
        elif choice == "40":
            vpn_detection()
        elif choice == "41":
            cloud_service_enumeration()
        elif choice == "42":
            port_knocking_simulator()
        elif choice == "43":
            network_intrusion_detection()
        elif choice == "44":
            ip_spoofing_test()
        elif choice == "45":
            ssl_tls_version_scanner()
        elif choice == "46":
            dns_cache_poisoning_test()
        elif choice == "47":
            network_congestion_analyzer()
        elif choice == "48":
            iot_device_scanner()
        elif choice == "49":
            ethical_dilemma_analyzer()
        elif choice == "50":
            decision_making_framework()
        elif choice == "51":
            principles_manager()
        elif choice == "52":
            compliance_checker()
        elif choice == "53":
            scenario_generator()
        elif choice == "54":
            decision_tree_builder()
        elif choice == "55":
            risk_assessment()
        elif choice == "56":
            ethics_report_generator()
        elif choice == "57":
            stakeholder_analysis()
        elif choice == "58":
            privacy_impact_assessment()
        elif choice == "59":
            ethical_ai_analysis()
        elif choice == "60":
            social_engineering_simulator()
        elif choice == "61":
            bias_detection_framework()
        elif choice == "62":
            ethical_audit_trail()
        elif choice == "63":
            automated_backup()
        elif choice == "64":
            multi_language_support()
        elif choice == "65":
            report_generator()
        elif choice == "66":
            file_encryptor()
        elif choice == "67":
            system_monitor()
        elif choice == "68":
            api_scanner()
        elif choice == "69":
            file_decrypt()
        elif choice == "70":
            network_speed_test()
        elif choice == "71":
            dark_pool()
        elif choice == "72":
            password_generator()
        elif choice == "73":
            log_cleaner()
        elif choice == "74":
            product_key_generator(session)
        elif choice == "75":
            user_signup()
        elif choice == "76":
            print(Fore.RED + "[!] Disconnecting from NEON MATRIX..." + Style.RESET_ALL)
            log_event(f"{session['role']} key {session['key']} disconnected")
            break
        elif choice in ["h", "help"]:
            help_menu()
        else:
            print(Fore.RED + "[?] Invalid command. Check matrix index (h)." + Style.RESET_ALL)
            log_event("Invalid command selected")
        input(Fore.CYAN + "[>] Press Enter to continue..." + Style.RESET_ALL)

# -------------------- RUN --------------------
if __name__ == "__main__":
    try:
        session = product_key_auth()
        menu(session)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Matrix interrupted by user." + Style.RESET_ALL)
        log_event("EasyHex interrupted")
        sys.exit(1)
