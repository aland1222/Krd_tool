#!/usr/bin/env python3

import requests
import threading
import re
from queue import Queue

# === Config ===
THREADS = 25
TIMEOUT = 5
USER_AGENT = {"User-Agent": "Mozilla/5.0 (KaliGPT-SmartSubFinder/3.0)"}
queue = Queue()
live_subs = []
found_subs = set()
lock = threading.Lock()

# === Data Sources ===
def from_crtsh(domain):
    try:
        print("[+] Checking crt.sh ...")
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, headers=USER_AGENT, timeout=10)
        entries = r.json()
        for entry in entries:
            name = entry.get("name_value")
            if name:
                for s in name.split('\n'):
                    if domain in s and "*" not in s:
                        found_subs.add(s.strip())
    except: pass

def from_hackertarget(domain):
    try:
        print("[+] Checking hackertarget.com ...")
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = requests.get(url, headers=USER_AGENT, timeout=10)
        lines = r.text.splitlines()
        for line in lines:
            sub = line.split(',')[0].strip()
            if domain in sub:
                found_subs.add(sub)
    except: pass

def from_c99(domain):
    try:
        print("[+] Checking subdomain-finder.c99.nl ...")
        url = f"https://subdomainfinder.c99.nl/scans/{domain}"
        r = requests.get(url, headers=USER_AGENT, timeout=10)
        matches = re.findall(rf"[a-zA-Z0-9_\-\.]*\.{re.escape(domain)}", r.text)
        for sub in matches:
            if domain in sub:
                found_subs.add(sub)
    except: pass

# === 200 OK Filter ===
def check_200():
    while not queue.empty():
        sub = queue.get()
        try:
            url = f"http://{sub}"
            r = requests.get(url, headers=USER_AGENT, timeout=TIMEOUT)
            if r.status_code == 200:
                with lock:
                    print(f"[200 OK] {sub}")
                    live_subs.append(sub)
        except:
            pass
        queue.task_done()

# === Run ===
def run():
    print("┌──────────────────────────────────────┐")
    print("│  KRD - Smart Subdomain 200 OK   │")
    print("└──────────────────────────────────────┘")
    domain = input("🌐 Enter target domain: ").strip()

    if not domain:
        print("❌ No domain entered.")
        return

    from_crtsh(domain)
    from_hackertarget(domain)
    from_c99(domain)

    if not found_subs:
        print("[!] No subdomains found from any source.")
        return

    print(f"\n[•] Total unique subdomains found: {len(found_subs)}")
    for sub in found_subs:
        queue.put(sub)

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=check_200)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if live_subs:
        print(f"\n[✓] {len(live_subs)} subdomains responded with HTTP 200:\n")
        for sub in live_subs:
            print("   └─ " + sub)
    else:
        print("[!] No subdomains responded with 200 OK.")

    print("\n[✓] Scan complete.")

# === Entry ===
if __name__ == "__main__":
    run()
