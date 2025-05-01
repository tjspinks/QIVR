import argparse
import logging
from pathlib import Path

from scanner import (
    check_spf, check_dmarc, check_dkim,
    check_mx, check_bimi, check_dnsbl,
    check_dnssec, check_mta_sts, check_tls_rpt,
    check_caa, check_ptr,
)
from scorer import calculate_score
from logger import log_to_csv, log_to_json, send_slack_alert, upload_to_s3
from config import DOMAINS_FILE, ALERT_SCORE_THRESHOLD, ENABLE_SLACK

# Mapping of check names to functions
CHECKS = {
    'spf':      check_spf,
    'dmarc':    check_dmarc,
    'dkim':     check_dkim,
    'mx':       check_mx,
    'bimi':     check_bimi,
    'dnsbl':    check_dnsbl,
    'dnssec':   check_dnssec,
    'mta_sts':  check_mta_sts,
    'tls_rpt':  check_tls_rpt,
    'caa':      check_caa,
    'ptr':      check_ptr,
}

# Suggestions for common failures
SUGGESTIONS = {
    'spf': "Ensure you have a 'v=spf1' TXT record listing your sending sources and an '-all' or '~all' qualifier.",
    'dmarc': "Publish a DMARC TXT record at '_dmarc.<your-domain>' with 'v=DMARC1; p=quarantine' or 'p=reject'.",
    'dkim': "DKIM may exist under non-standard selectors—consider adding custom selectors or checking with your MTA/ESP.",
    'mx': "Add MX records pointing at your mail servers to accept inbound mail.",
    'bimi': "For BIMI, publish a 'v=BIMI1' record and host a properly formatted SVG/logo per BIMI spec.",
}


def scan_domain(domain: str) -> dict:
    """
    Run all DNS/email auth checks for a domain. Returns results dict with raw data and a final score & reason.
    """
    results = {}
    for name, fn in CHECKS.items():
        try:
            ret = fn(domain)
            # DKIM & BIMI return three values: (ok, selector, text)
            if name in ('dkim', 'bimi'):
                ok, selector, txt = ret
                results[f'{name}_ok'] = ok
                results[f'{name}_selector'] = selector
                results[f'{name}_text'] = txt
            else:
                ok, txt = ret
                results[f'{name}_ok'] = ok
                results[f'{name}_text'] = txt
        except Exception as e:
            results[f'{name}_ok'] = False
            results[f'{name}_text'] = f'Error: {e}'
    score, reason = calculate_score(results)
    results['score'] = score
    results['reason'] = reason

    # Side-effects
    log_to_csv(domain, results, score, reason)
    log_to_json(domain, results, score, reason)
    if ENABLE_SLACK and score < ALERT_SCORE_THRESHOLD:
        send_slack_alert(domain, score, reason)

    return results


def parse_args():
    p = argparse.ArgumentParser(
        description='AuthScanner: DNS checks for email authentication health.'
    )
    p.add_argument(
        '-d', '--domain', help='Scan a single domain (overrides file)'
    )
    p.add_argument(
        '-f', '--file', default=DOMAINS_FILE,
        help='Path to newline-separated domains file'
    )
    return p.parse_args()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    args = parse_args()
    # Determine domains list
    domains = []
    if args.domain:
        domains = [args.domain.strip()]
    else:
        path = Path(args.file)
        if not path.is_file():
            logging.error(f"Domains file not found: {args.file}")
            return
        domains = [d.strip() for d in path.read_text().splitlines() if d.strip()]

    # Iterate and scan
    for domain in domains:
        logging.info(f"🔍 Scanning {domain}")
        results = scan_domain(domain)
        # Human-readable report
        print(f"\n=== Report for {domain} ===")
        for name in CHECKS.keys():
            ok = results.get(f'{name}_ok', False)
            text = results.get(f'{name}_text', '')
            status = 'PASS' if ok else 'FAIL'
            print(f"[{status}] {name.upper()}: {text or 'None'}")
            # Print suggestion if available
            if not ok and name in SUGGESTIONS:
                print(f"   Tip: {SUGGESTIONS[name]}")
        # Note for DKIM semantics
        if not results.get('dkim_ok'):
            print("   Note: DKIM check covers common selectors only; absence doesn't guarantee missing DKIM.")
        print(f"Score: {results['score']} | Reason: {results['reason']}")

    # Final side-effect after all
    upload_to_s3()


if __name__ == '__main__':
    main()
