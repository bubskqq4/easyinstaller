#!/usr/bin/env python3

import os
import sys
import time
import socket
import subprocess
import requests
import platform
import argparse
from colorama import Fore, Style, init

init()

# -------------------- LEGAL NOTICE --------------------
LEGAL = """
================== LEGAL NOTICE ==================
This tool (Hutnter) is for educational and ethical
penetration testing only. Unauthorized use of this
software against networks or systems you do not own
or have explicit permission to test is ILLEGAL.

The developer is not responsible for misuse or damage.
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

# -------------------- TOOLS --------------------

def ping_host():
    target = input(Fore.YELLOW + "[?] Enter host/IP to ping: " + Style.RESET_ALL)
    response = os.system(f"ping -c 4 {target}" if platform.system() != "Windows" else f"ping {target}")
    print(Fore.GREEN + "[+] Host is up." + Style.RESET_ALL if response == 0 else Fore.RED + "[-] Host is down or unreachable." + Style.RESET_ALL)

def port_scan():
    target = input(Fore.YELLOW + "[?] Enter target IP: " + Style.RESET_ALL)
    ports = [21, 22, 23, 25, 53, 80, 443, 8080]
    print(Fore.CYAN + f"[~] Scanning {target}..." + Style.RESET_ALL)
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((target, port))
            print(Fore.GREEN + f"[+] Port {port} is OPEN" + Style.RESET_ALL)
            s.close()
        except:
            pass

def get_ip():
    hostname = input(Fore.YELLOW + "[?] Enter domain: " + Style.RESET_ALL)
    try:
        ip = socket.gethostbyname(hostname)
        print(Fore.GREEN + f"[+] IP of {hostname}: {ip}" + Style.RESET_ALL)
    except socket.error:
        print(Fore.RED + "[-] Invalid hostname." + Style.RESET_ALL)

def http_headers():
    url = input(Fore.YELLOW + "[?] Enter full URL (http://...): " + Style.RESET_ALL)
    try:
        r = requests.get(url)
        print(Fore.CYAN + "[~] HTTP Headers:" + Style.RESET_ALL)
        for k, v in r.headers.items():
            print(f"{k}: {v}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)

def reverse_ip():
    domain = input(Fore.YELLOW + "[?] Enter domain for Reverse IP: " + Style.RESET_ALL)
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"[+] IP: {ip}" + Style.RESET_ALL)
        # Fake API placeholder (real service needed for live results)
        print(Fore.CYAN + "[~] Domains hosted on this IP (mock):" + Style.RESET_ALL)
        print("example.com\nsub.example.com")
    except:
        print(Fore.RED + "[-] Reverse IP Lookup failed." + Style.RESET_ALL)

def dns_lookup():
    domain = input(Fore.YELLOW + "[?] Enter domain for DNS Lookup: " + Style.RESET_ALL)
    try:
        result = socket.gethostbyname_ex(domain)
        print(Fore.GREEN + f"[+] DNS Info: {result}" + Style.RESET_ALL)
    except:
        print(Fore.RED + "[-] DNS Lookup failed." + Style.RESET_ALL)

def traceroute():
    target = input(Fore.YELLOW + "[?] Enter target for Traceroute: " + Style.RESET_ALL)
    try:
        if platform.system() == "Windows":
            os.system(f"tracert {target}")
        else:
            os.system(f"traceroute {target}")
    except:
        print(Fore.RED + "[-] Traceroute failed." + Style.RESET_ALL)

def whois_lookup():
    domain = input(Fore.YELLOW + "[?] Enter domain for WHOIS: " + Style.RESET_ALL)
    try:
        import whois
        data = whois.whois(domain)
        print(Fore.CYAN + "[~] WHOIS Data:" + Style.RESET_ALL)
        print(data)
    except:
        print(Fore.RED + "[-] Install `python-whois` module to use this feature." + Style.RESET_ALL)

def help_menu():
    print(Fore.CYAN + "\n[ HUTNTER HELP MENU ]" + Style.RESET_ALL)
    print("""
1. Ping a Host        - Sends ICMP packets to check if the host is up.
2. Port Scanner       - Scans common ports to see which are open.
3. Get IP             - Resolves a domain name to its IP address.
4. HTTP Headers       - Displays server response headers for a URL.
5. Reverse IP Lookup  - Finds domains sharing the same IP (mocked).
6. DNS Lookup         - Performs a DNS query to get records for a domain.
7. Traceroute         - Shows the route packets take to a target.
8. Whois Lookup       - Shows WHOIS registration info for a domain.
9. Exit               - Exits the tool.
h or help             - Shows this help menu.
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
        print("9. Exit")
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
            print(Fore.CYAN + "[*] Exiting Hutnter." + Style.RESET_ALL)
            break
        elif choice in ["h", "help"]:
            help_menu()
        else:
            print(Fore.RED + "Invalid option. Try again." + Style.RESET_ALL)

# -------------------- CLI MODE --------------------

def run_cli_mode():
    try:
        from tools.crash import CriticalError
        import tools.addons.clean
        import tools.addons.logo
        import tools.addons.winpcap
        from tools.method import AttackMethod
    except ImportError as err:
        print(Fore.RED + "[!] CLI Mode: Failed to import attack modules." + Style.RESET_ALL)
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Denial-of-service ToolKit")
    parser.add_argument("--target", type=str, metavar="<IP:PORT, URL, PHONE>", help="Target ip:port, url or phone")
    parser.add_argument("--method", type=str, metavar="<SMS/EMAIL/NTP/UDP/SYN/ICMP/POD/SLOWLORIS/MEMCACHED/HTTP>", help="Attack method")
    parser.add_argument("--time", type=int, default=10, help="Attack time in seconds")
    parser.add_argument("--threads", type=int, default=3, help="Thread count (1-200)")
    args = parser.parse_args()

    if not args.method or not args.target:
        parser.print_help()
        sys.exit(1)

    with AttackMethod(duration=args.time, name=args.method.upper(), threads=args.threads, target=args.target) as Flood:
        Flood.Start()

# -------------------- RUN --------------------

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_cli_mode()
    else:
        try:
            banner()
            menu()
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Interrupted by user." + Style.RESET_ALL)
            sys.exit(0)
