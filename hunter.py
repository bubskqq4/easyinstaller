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
import csv

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

# -------------------- GLITCH EFFECT --------------------
def glitch_text(text, delay=0.05):
    for char in text:
        if random.random() < 0.1:
            print(Fore.RED + random.choice(string.ascii_letters), end='', flush=True)
            time.sleep(delay)
            print('\b' + char, end='', flush=True)
        else:
            print(char, end='', flush=True)
        time.sleep(delay)
    print()

# -------------------- CYBERPUNK BANNER --------------------
def banner():
    os.system("cls" if platform.system() == "Windows" else "clear")
    glitch_text(Fore.MAGENTA + r"""
       ╔═╗╔═╗╔═══╗╦╦═╗ ╦════╗
       ║╩╠═╩╬══╦╦╗╠╩╩╩╠══╦╦╗
       ║╔╬═╗╠══╩╬╚═╩═╗║╔═╩╬╚╦═╦╦╦╗
       ╚╝╩═══╩════╩╩╩╩╩╚══╩╩═╩╩╩╩╩
    """ + Style.RESET_ALL)
    print(Fore.CYAN + "[*] EASYHEX | NEON MATRIX DOMINATOR" + Style.RESET_ALL)
    print(Fore.GREEN + LEGAL + Style.RESET_ALL)

# -------------------- LOGGING --------------------
def log_event(message):
    with open(os.path.join(CONFIG_DIR, SETTINGS["log_file"]), "a") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

# -------------------- PRODUCT KEY AUTHENTICATION --------------------
def product_key_auth():
    banner()
    print(Fore.MAGENTA + "=== ACCESS NEON MATRIX ===" + Style.RESET_ALL)
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
        print(Fore.CYAN + "[!] Generate key via option 99 or use admin key: xAI-ADMIN-NEON-2025" + Style.RESET_ALL)
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
    print(Fore.MAGENTA + f"[~] Scanning {target} on common ports..." + Style.RESET_ALL)
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
    target = input(Fore.CYAN + "[>] Target IP: " + Style.RESET_ALL)
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
    print(Fore.MAGENTA + f"[~] Initiating extended scan on {target}..." + Style.RESET_ALL)
    with ThreadPoolExecutor(max_workers=SETTINGS["max_threads"]) as executor:
        executor.map(scan_port, ports)
    for port in open_ports:
        print(Fore.GREEN + f"[+] Port {port} is OPEN" + Style.RESET_ALL)
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
        print(Fore.MAGENTA + "[~] HTTP Headers:" + Style.RESET_ALL)
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
        print(Fore.GREEN + f"[+] IP: {ip}" + Style.RESET_ALL)
        print(Fore.MAGENTA + "[~] Domains hosted (mock):" + Style.RESET_ALL)
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
        print(Fore.MAGENTA + "[~] WHOIS Data:" + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[~] Monitoring bandwidth..." + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[~] Network Interfaces:" + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[~] Scanning vulnerabilities (mock)..." + Style.RESET_ALL)
    vulnerabilities = ["Open port 23 (Telnet)", "Weak SSL version detected"]
    for vuln in vulnerabilities:
        print(Fore.RED + f"[!] {vuln}" + Style.RESET_ALL)
        log_event(f"Vulnerability scan: {target} -> {vuln}")

def packet_injection_test():
    print(Fore.MAGENTA + "[~] Packet injection test (root required)." + Style.RESET_ALL)
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
    password = input(Fore.CYAN + "[>] Enter password: " + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[~] Analyzing traffic (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Detected: TCP, UDP, ICMP" + Style.RESET_ALL)
    log_event("Network traffic analysis performed")

def firewall_rule_check():
    print(Fore.MAGENTA + "[~] Checking firewall (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Rules: Allow TCP 80, 443; Block UDP 53" + Style.RESET_ALL)
    log_event("Firewall rule check performed")

def os_fingerprinting():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Fingerprinting OS (mock)..." + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[~] Analyzing protocols (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Detected: HTTP, HTTPS, FTP, SSH" + Style.RESET_ALL)
    log_event("Protocol analysis performed")

def log_file_analyzer():
    log_file = os.path.join(CONFIG_DIR, SETTINGS["log_file"])
    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
        print(Fore.MAGENTA + "[~] Recent log entries:" + Style.RESET_ALL)
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
        print(Fore.MAGENTA + "[~] Crawled Links:" + Style.RESET_ALL)
        for link in links[:10]:
            print(Fore.GREEN + f"[+] {link}" + Style.RESET_ALL)
        log_event(f"Web crawl performed on {url}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        log_event(f"Web crawl failed for {url}: {e}")

def sql_injection_tester():
    url = input(Fore.CYAN + "[>] Enter URL (e.g., http://example.com?id=1): " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Testing SQL injection (mock, ethical)..." + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[~] Scanning Wi-Fi networks..." + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[~] Crafting packet (root required)..." + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[~] Mapping topology (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Devices: Router (192.168.1.1), Host (192.168.1.100)" + Style.RESET_ALL)
    log_event("Network topology mapping performed")

def brute_force_tester():
    url = input(Fore.CYAN + "[>] Enter login URL: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Testing brute force (mock, ethical)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Result: Login page rate-limits after 5 attempts." + Style.RESET_ALL)
    log_event(f"Brute force test on {url}")

def firewall_bypass_test():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Testing firewall bypass (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Open ports detected: 80, 443" + Style.RESET_ALL)
    log_event(f"Firewall bypass test on {target}")

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
    print(Fore.MAGENTA + "[~] Detecting VPN (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] VPN detected: OpenVPN protocol" + Style.RESET_ALL)
    log_event(f"VPN detection on {target}")

def cloud_service_enumeration():
    target = input(Fore.CYAN + "[>] Enter target IP/domain: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Enumerating cloud services (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Detected: AWS S3, Azure Blob Storage" + Style.RESET_ALL)
    log_event(f"Cloud service enumeration on {target}")

def port_knocking_simulator():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    ports = input(Fore.CYAN + "[>] Enter port sequence (e.g., 1000,2000,3000): " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Simulating port knocking..." + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[~] Monitoring for intrusions (mock)..." + Style.RESET_ALL)
    print(Fore.RED + "[!] Suspicious traffic: Port scan detected" + Style.RESET_ALL)
    log_event("Network intrusion detection performed")

def ip_spoofing_test():
    print(Fore.MAGENTA + "[~] Testing IP spoofing (root required)..." + Style.RESET_ALL)
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
    print(Fore.MAGENTA + "[~] Testing DNS cache poisoning (mock, ethical)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Result: DNS server not vulnerable" + Style.RESET_ALL)
    log_event(f"DNS cache poisoning test on {domain}")

def network_congestion_analyzer():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Analyzing congestion (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Congestion: Moderate, 50ms delay" + Style.RESET_ALL)
    log_event(f"Network congestion analysis on {target}")

def iot_device_scanner():
    print(Fore.MAGENTA + "[~] Scanning IoT devices (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Devices: Smart Camera (192.168.1.50), Thermostat (192.168.1.51)" + Style.RESET_ALL)
    log_event("IoT device scan performed")

def proxy_detection():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Detecting proxy (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Proxy detected: HTTP proxy" + Style.RESET_ALL)
    log_event(f"Proxy detection on {target}")

def packet_replay():
    print(Fore.MAGENTA + "[~] Replaying packets (root required)..." + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        interface = input(Fore.CYAN + "[>] Enter interface: " + Style.RESET_ALL)
        packets = scapy.rdpcap("capture.pcap")[:5]
        for packet in packets:
            scapy.sendp(packet, iface=interface, verbose=0)
            print(Fore.GREEN + "[+] Packet replayed." + Style.RESET_ALL)
            log_event("Packet replayed")
    except:
        print(Fore.RED + "[-] Install `scapy` or provide `capture.pcap`." + Style.RESET_ALL)
        log_event("Packet replay failed")

def network_jamming_simulator():
    print(Fore.MAGENTA + "[~] Simulating network jamming (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Jamming: High packet loss simulated" + Style.RESET_ALL)
    log_event("Network jamming simulation performed")

def dns_spoofing_test():
    domain = input(Fore.CYAN + "[>] Enter domain: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Testing DNS spoofing (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Result: DNS spoofing not detected" + Style.RESET_ALL)
    log_event(f"DNS spoofing test on {domain}")

def ssl_stripping_test():
    url = input(Fore.CYAN + "[>] Enter URL: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Testing SSL stripping (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Result: HTTPS enforced" + Style.RESET_ALL)
    log_event(f"SSL stripping test on {url}")

def protocol_fuzzer():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Fuzzing protocols (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Fuzz results: No crashes detected" + Style.RESET_ALL)
    log_event(f"Protocol fuzzing on {target}")

def ip_fragmentation_test():
    print(Fore.MAGENTA + "[~] Testing IP fragmentation (root required)..." + Style.RESET_ALL)
    try:
        import scapy.all as scapy
        dest_ip = input(Fore.CYAN + "[>] Destination IP: " + Style.RESET_ALL)
        packet = scapy.IP(dst=dest_ip, flags="MF")/scapy.ICMP()
        scapy.send(packet, verbose=0)
        print(Fore.GREEN + "[+] Fragmented packet sent." + Style.RESET_ALL)
        log_event(f"IP fragmentation test to {dest_ip}")
    except:
        print(Fore.RED + "[-] Install `scapy` and run as root." + Style.RESET_ALL)
        log_event("IP fragmentation test failed")

def tor_network_scanner():
    print(Fore.MAGENTA + "[~] Scanning Tor network (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Tor nodes detected" + Style.RESET_ALL)
    log_event("Tor network scan performed")

def zero_day_scanner():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Scanning for zero-days (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] No zero-day vulnerabilities detected" + Style.RESET_ALL)
    log_event(f"Zero-day scan on {target}")

def websocket_scanner():
    url = input(Fore.CYAN + "[>] Enter WebSocket URL: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Scanning WebSocket (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] WebSocket endpoint active" + Style.RESET_ALL)
    log_event(f"WebSocket scan on {url}")

def bluetooth_scanner():
    print(Fore.MAGENTA + "[~] Scanning Bluetooth devices (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Devices: Headset (00:11:22)" + Style.RESET_ALL)
    log_event("Bluetooth scan performed")

def network_load_balancer_test():
    target = input(Fore.CYAN + "[>] Enter target IP: " + Style.RESET_ALL)
    print(Fore.MAGENTA + "[~] Testing load balancer (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Load balancer: Distributing traffic evenly" + Style.RESET_ALL)
    log_event(f"Load balancer test on {target}")

def vpn_leak_test():
    print(Fore.MAGENTA + "[~] Testing VPN leaks (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] No DNS/IP leaks detected" + Style.RESET_ALL)
    log_event("VPN leak test performed")

def firewall_rule_validator():
    print(Fore.MAGENTA + "[~] Validating firewall rules (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Rules valid: TCP 80, 443 allowed" + Style.RESET_ALL)
    log_event("Firewall rule validation performed")

def packet_latency_heatmap():
    print(Fore.MAGENTA + "[~] Generating latency heatmap (mock)..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Heatmap: High latency at 192.168.1.10" + Style.RESET_ALL)
    log_event("Packet latency heatmap generated")

# -------------------- ETHICAL TOOLS --------------------
def ethical_dilemma_analyzer():
    print(Fore.MAGENTA + "[~] Ethical Dilemma Analyzer" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Network action: " + Style.RESET_ALL)
    target = input(Fore.CYAN + "[>] Target (IP/domain): " + Style.RESET_ALL)
    permission = input(Fore.CYAN + "[>] Permission? (yes/no): " + Style.RESET_ALL).lower()
    result = "Ethical" if permission == "yes" else "Unethical: Requires permission"
    print(Fore.GREEN + f"[+] Analysis: {result}" + Style.RESET_ALL)
    log_event(f"Ethical dilemma: {action} on {target} -> {result}")

def decision_making_framework():
    print(Fore.MAGENTA + "[~] Decision Framework" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    criteria = ["Legality", "Consent", "Impact", "Necessity"]
    scores = {}
    for criterion in criteria:
        score = int(input(Fore.CYAN + f"[>] Score for {criterion} (1-5): " + Style.RESET_ALL))
        scores[criterion] = score
    avg_score = sum(scores.values()) / len(scores)
    result = "Proceed" if avg_score >= 3 else "Reconsider"
    print(Fore.GREEN + f"[+] Decision: {result} (Score: {avg_score:.2f})" + Style.RESET_ALL)
    log_event(f"Decision framework: {action} -> {result}")

def principles_manager():
    print(Fore.MAGENTA + "[~] Principles Manager" + Style.RESET_ALL)
    principles = ["Autonomy", "Non-maleficence", "Beneficence", "Justice"]
    print(Fore.GREEN + "[+] Principles: " + ", ".join(principles) + Style.RESET_ALL)
    new_principle = input(Fore.CYAN + "[>] Add principle: " + Style.RESET_ALL)
    if new_principle:
        principles.append(new_principle)
        print(Fore.GREEN + f"[+] Added: {new_principle}" + Style.RESET_ALL)
        log_event(f"Added principle: {new_principle}")

def compliance_checker():
    print(Fore.MAGENTA + "[~] Compliance Checker" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    standards = ["GDPR", "HIPAA", "PCI-DSS"]
    results = []
    for standard in standards:
        compliant = input(Fore.CYAN + f"[>] Compliant with {standard}? (yes/no): " + Style.RESET_ALL).lower()
        results.append(f"{standard}: {'Compliant' if compliant == 'yes' else 'Non-compliant'}")
    print(Fore.GREEN + "[+] Results: " + "; ".join(results) + Style.RESET_ALL)
    log_event(f"Compliance check: {'; '.join(results)}")

def scenario_generator():
    print(Fore.MAGENTA + "[~] Scenario Generator" + Style.RESET_ALL)
    scenarios = ["Unauthorized scan", "Public Wi-Fi sniff", "Test bypass"]
    scenario = random.choice(scenarios)
    print(Fore.GREEN + f"[+] Scenario: {scenario}" + Style.RESET_ALL)
    log_event(f"Generated scenario: {scenario}")

def decision_tree_builder():
    print(Fore.MAGENTA + "[~] Decision Tree Builder" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    tree = {"Action": action, "Steps": []}
    while True:
        step = input(Fore.CYAN + "[>] Step (Enter to finish): " + Style.RESET_ALL)
        if not step:
            break
        tree["Steps"].append(step)
    print(Fore.GREEN + f"[+] Tree: {json.dumps(tree, indent=2)}]" + Style.RESET_ALL)
    log_event(f"Built decision tree: {action}")

def risk_assessment():
    print(Fore.MAGENTA + "[~] Risk Assessment" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    risks = ["Data breach", "Legal violation", "Reputation damage"]
    scores = {}
    for risk in risks:
        score = int(input(Fore.CYAN + f"[>] Risk level for {risk} (1-5): " + Style.RESET_ALL))
        scores[risk] = score
    avg_score = sum(scores.values()) / len(scores)
    result = "Low risk" if avg_score < 0
3 else "High risk"
    print(Fore.GREEN + f"[+] Risk: {result} (Score: {avg_score:.2f})" + Style.RESET_ALL)
    log_event(f"Risk assessment: {action}: {result}")

def ethics_report_generator():
    print(Fore.MAGENTA + "[~] Ethics Report" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    report = f"Ethics Report\nAction: {action}\nEthical: Requires permission\nRecommendation: Obtain consent"
    print(Fore.GREEN + f"[+] {report}" + Style.RESET_ALL)
    log_event(f"Generated ethics report: {action}")

def stakeholder_analysis():
    print(Fore.MAGENTA + "[~] Stakeholder Analysis" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    stakeholders = ["Users", "Admins", "Clients"]
    impacts = {}
    for stakeholder in stakeholders:
        impact = input(Fore.CYAN + f"[>] Impact on {stakeholder}: " + Style.RESET_ALL)
        impacts[stakeholder] = impact
    print(Fore.GREEN + f"[+] Impacts: {json.dumps(impacts, indent=2)}" + Style.RESET_ALL)
    log_event(f"Stakeholder analysis: {action}")

def privacy_impact_assessment():
    print(Fore.MAGENTA + "[~] Privacy Impact Assessment" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    data_types = ["Personal", "Financial", "Health"]
    risks = {}
    for data in data_types:
        risk = input(Fore.CYAN + f"[>] Privacy risk for {data} (low/medium/high): " + Style.RESET_ALL)
        risks[data] = risk
    print(Fore.GREEN + f"[+] Risks: {json.dumps(risks, indent=2)}" + Style.RESET_ALL)
    log_event(f"Privacy impact: {action}")

def ethical_ai_analysis():
    print(Fore.MAGENTA + "[~] Ethical AI Analysis" + Style.RESET_ALL)
    tool = input(Fore.CYAN + "[>] AI tool: " + Style.RESET_ALL)
    concerns = ["Bias", "Transparency", "Accountability"]
    results = {}
    for concern in concerns:
        level = input(Fore.CYAN + f"[>] Concern level for {concern} (low/medium/high): " + Style.RESET_ALL)
        results[concern] = level
    print(Fore.GREEN + f"[+] Results: {json.dumps(results, indent=2)}" + Style.RESET_ALL)
    log_event(f"Ethical AI analysis: {tool}")

def social_engineering_simulator():
    print(Fore.MAGENTA + "[~] Social Engineering Simulator" + Style.RESET_ALL)
    scenario = random.choice(["Phishing email", "Phone scam", "USB drop"])
    print(Fore.GREEN + f"[+] Scenario: {scenario}" + Style.RESET_ALL)
    log_event(f"Social engineering: {scenario}")

def bias_detection_framework():
    print(Fore.MAGENTA + "[~] Bias Detection Framework" + Style.RESET_ALL)
    action = input(Fore.CYAN + "[>] Action: " + Style.RESET_ALL)
    biases = ["Selection", "Confirmation", "Automation"]
    detected = random.choice(biases)
    print(Fore.RED + f"[!] Detected: {detected}" + Style.RESET_ALL)
    log_event(f"Bias detection: {action}: {detected}")

def ethical_audit_trail():
    print(Fore.MAGENTA + "[~] Ethical Audit Trail" + Style.RESET_ALL)
    try:
        with open(os.path.join(CONFIG_DIR, SETTINGS["log"]
