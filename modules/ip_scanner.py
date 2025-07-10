#!/usr/bin/env python3

import socket
import threading
from queue import Queue
from datetime import datetime
import sys

# === Configuration ===
THREADS = 100
TIMEOUT = 1
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 8080, 8443]
queue = Queue()
print_lock = threading.Lock()

# === Banner Grabbing ===
def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner
    except:
        return ""

# === Port Scanner Thread Worker ===
def port_scan(ip):
    while not queue.empty():
        port = queue.get()
        try:
            s = socket.socket()
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            with print_lock:
                banner = grab_banner(ip, port)
                print(f"[+] Open Port: {port}/TCP", end='')
                if banner:
                    print(f" | Service: {banner}")
                else:
                    print()
            s.close()
        except:
            pass
        finally:
            queue.task_done()

# === Scan Manager ===
def run_scan(ip, ports):
    print(f"\n[•] Scanning Target: {ip}")
    print(f"[•] Ports to Scan: {len(ports)}")
    print(f"[•] Threads: {THREADS}")
    print(f"[•] Time Started: {datetime.now().strftime('%H:%M:%S')}\n")

    for port in ports:
        queue.put(port)

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=port_scan, args=(ip,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"\n[✓] Scan Completed at {datetime.now().strftime('%H:%M:%S')}")
    sys.exit(0)

# === Port Parsing Logic ===
def parse_ports(port_input):
    if port_input.lower() == "top":
        return COMMON_PORTS
    elif "-" in port_input:
        start, end = map(int, port_input.split("-"))
        return list(range(start, end + 1))
    elif "," in port_input:
        return [int(p.strip()) for p in port_input.split(",")]
    elif port_input.isdigit():
        return [int(port_input)]
    else:
        raise ValueError("Invalid port input format.")

# === Friendly Entry Point ===
def run():
    print("┌────────────────────────────────────────────┐")
    print("│         KaliGPT Advanced IP Scanner        │")
    print("└────────────────────────────────────────────┘")
    target = input("🌍 Target IP or domain: ").strip()
    if not target:
        print("❌ No target provided.")
        sys.exit(1)

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("❌ Could not resolve host.")
        sys.exit(1)

    port_input = input("📦 Ports (top / 1-65535 / 22,80,443): ").strip() or "top"
    try:
        ports = parse_ports(port_input)
    except Exception as e:
        print(f"❌ Port error: {e}")
        sys.exit(1)

    run_scan(ip, ports)

# === Execution ===
if __name__ == "__main__":
    run()

