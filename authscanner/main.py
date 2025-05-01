--- a/authscanner/main.py
+++ b/authscanner/main.py
@@
-import dns.resolver
-import socket
-from scanner import check_spf, check_dmarc, check_dkim, check_mx, check_bimi, check_dnsbl, check_dnssec, check_mta_sts, check_tls_rpt, check_caa, check_ptr
-from scorer import calculate_score
-from logger import log_to_csv, log_to_json, send_slack_alert, upload_to_s3
-from config import DOMAINS_FILE, ALERT_SCORE_THRESHOLD, ENABLE_SLACK
+import argparse
+import logging
+from pathlib import Path
+
+from scanner import (
+    check_spf, check_dmarc, check_dkim,
+    check_mx, check_bimi, check_dnsbl,
+    check_dnssec, check_mta_sts, check_tls_rpt,
+    check_caa, check_ptr,
+)
+from scorer import calculate_score
+from logger import log_to_csv, log_to_json, send_slack_alert, upload_to_s3
+from config import DOMAINS_FILE, ALERT_SCORE_THRESHOLD, ENABLE_SLACK
@@
-# old one-off imports…
+# map all your check functions under friendly keys
+CHECKS = {
+    'spf':      check_spf,
+    'dmarc':    check_dmarc,
+    'dkim':     check_dkim,
+    'mx':       check_mx,
+    'bimi':     check_bimi,
+    'dnsbl':    check_dnsbl,
+    'dnssec':   check_dnssec,
+    'mta_sts':  check_mta_sts,
+    'tls_rpt':  check_tls_rpt,
+    'caa':      check_caa,
+    'ptr':      check_ptr,
+}
@@
-def scan_domain(domain):
-    spf_ok, spf_text = check_spf(domain)
-    dmarc_ok, dmarc_text = check_dmarc(domain)
-    dkim_ok, dkim_selector, dkim_text = check_dkim(domain)
-
-    checks = {
-        "spf_ok": spf_ok,
-        "spf_text": spf_text,
-        "dmarc_ok": dmarc_ok,
-        "dmarc_text": dmarc_text,
-        "dkim_ok": dkim_ok,
-        "dkim_selector": dkim_selector,
-        "dkim_status": "pass" if dkim_ok else "unknown",
-        "dkim_text": dkim_text,
-    }
-
-    score, reason = calculate_score(checks)
+def scan_domain(domain: str) -> dict:
+    """Run every check for a single domain, return a flat results dict."""
+    results = {}
+    for name, fn in CHECKS.items():
+        try:
+            ret = fn(domain)
+            # DKIM and BIMI return (ok, selector, text)
+            if name in ('dkim', 'bimi'):
+                ok, selector, txt = ret
+                results[f'{name}_ok']       = ok
+                results[f'{name}_selector'] = selector
+                results[f'{name}_text']     = txt
+            else:
+                ok, txt = ret
+                results[f'{name}_ok']   = ok
+                results[f'{name}_text'] = txt
+        except Exception as e:
+            # ensure one failure doesn’t crash the entire scan
+            results[f'{name}_ok']   = False
+            results[f'{name}_text'] = f'Error: {e}'
+
+    score, reason = calculate_score(results)
+    results.update({'score': score, 'reason': reason})
@@
-    log_to_csv(domain, checks, score, reason)
-    log_to_json(domain, checks, score, reason)
-    if ENABLE_SLACK and score < ALERT_SCORE_THRESHOLD:
-        send_slack_alert(domain, score, reason)
+    # centralize all side-effects
+    log_to_csv(domain, results, score, reason)
+    log_to_json(domain, results, score, reason)
+    if ENABLE_SLACK and score < ALERT_SCORE_THRESHOLD:
+        send_slack_alert(domain, score, reason)
+
+    return results
@@
-def main():
-    with open(DOMAINS_FILE) as f:
-        for line in f:
-            domain = line.strip()
-            if domain:
-                print(f"\\n🔍 Checking domain: {domain}")
-                scan_domain(domain)
-    upload_to_s3()
+def parse_args():
+    p = argparse.ArgumentParser(
+        description='AuthScanner: DNS checks for email health'
+    )
+    grp = p.add_mutually_exclusive_group(required=True)
+    grp.add_argument('-d', '--domain', help='Scan a single domain')
+    grp.add_argument(
+        '-f', '--file',
+        help='File containing newline-separated domains',
+        default=DOMAINS_FILE
+    )
+    return p.parse_args()
+
+def main():
+    logging.basicConfig(
+        level=logging.INFO,
+        format='%(asctime)s %(levelname)s:%(message)s'
+    )
+    args = parse_args()
+    domains = []
+    if args.domain:
+        domains = [args.domain]
+    else:
+        path = Path(args.file)
+        domains = [d.strip() for d in path.read_text().splitlines() if d.strip()]
+
+    for domain in domains:
+        logging.info(f'🔍 Scanning: {domain}')
+        try:
+            scan_domain(domain)
+        except Exception as e:
+            logging.error(f'Failed {domain}: {e}')
+
+    upload_to_s3()
+
+if __name__ == '__main__':
+    main()
