#!/usr/bin/env python3
# Created by LimerBoy

import os
import sys
import time
import socket
import requests
import platform
import argparse
from colorama import Fore, Style, init

init()
os.chdir(os.path.dirname(os.path.realpath(__file__)))

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

# -------------------- BANNER --------------------
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

# -------------------- INTERACTIVE TOOLS --------------------
def ping_host():
    target = input(Fore.YELLOW + "[?] Enter host/IP to ping: " + Style.RESET_ALL)
    response = os.system(f"ping -c 4 {target}")
    if response == 0:
        print(Fore.GREEN + "[+] Host is up." + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] Host is down or unreachable." + Style.RESET_ALL)

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

# -------------------- INTERACTIVE MENU --------------------
def menu():
    while True:
        print(Fore.CYAN + "\n[ MENU ]" + Style.RESET_ALL)
        print("1. Ping a Host")
        print("2. Port Scanner (Common Ports)")
        print("3. Get IP from Hostname")
        print("4. View HTTP Headers")
        print("5. Exit")

        choice = input(Fore.YELLOW + "\nSelect an option: " + Style.RESET_ALL)

        if choice == "1":
            ping_host()
        elif choice == "2":
            port_scan()
        elif choice == "3":
            get_ip()
        elif choice == "4":
            http_headers()
        elif choice == "5":
            print(Fore.CYAN + "[*] Exiting Hutnter." + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "Invalid option. Try again." + Style.RESET_ALL)

# -------------------- CLI ARGUMENT PARSER --------------------
def run_attack_from_args():
    try:
        from tools.crash import CriticalError
        import tools.addons.clean
        import tools.addons.logo
        import tools.addons.winpcap
        from tools.method import AttackMethod
    except ImportError as err:
        print(Fore.RED + "[!] Module import failed." + Style.RESET_ALL)
        from tools.crash import CriticalError
        CriticalError("Failed to import required modules.", err)
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Denial-of-service ToolKit")
    parser.add_argument("--target", type=str, metavar="<IP:PORT, URL, PHONE>",
                        help="Target IP:PORT, URL or phone")
    parser.add_argument("--method", type=str,
                        metavar="<SMS/EMAIL/NTP/UDP/SYN/ICMP/POD/SLOWLORIS/MEMCACHED/HTTP>",
                        help="Attack method")
    parser.add_argument("--time", type=int, default=10,
                        metavar="<time>", help="Attack time in seconds")
    parser.add_argument("--threads", type=int, default=3,
                        metavar="<threads>", help="Number of threads (1-200)")

    args = parser.parse_args()
    if args.target and args.method:
        with AttackMethod(
            duration=args.time,
            name=args.method.upper(),
            threads=args.threads,
            target=args.target
        ) as Flood:
            Flood.Start()
    else:
        parser.print_help()
        sys.exit(1)

# -------------------- MAIN --------------------
if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_attack_from_args()
    else:
        try:
            banner()
            menu()
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Interrupted by user." + Style.RESET_ALL)
            sys.exit(0)

