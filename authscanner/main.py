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


def scan_domain(domain: str) -> dict:
    """
    Run all configured DNS/email auth checks for a domain.
    Returns a dict with all results and a final score + reason.
    """
    results = {}

    for name, fn in CHECKS.items():
        try:
            ret = fn(domain)
            # DKIM & BIMI return three values: (ok, selector, text)
            if name in ('dkim', 'bimi'):
                ok, selector, txt = ret
                results[f'{name}_ok']       = ok
                results[f'{name}_selector'] = selector
                results[f'{name}_text']     = txt
            else:
                ok, txt = ret
                results[f'{name}_ok']   = ok
                results[f'{name}_text'] = txt
        except Exception as e:
            results[f'{name}_ok']   = False
            results[f'{name}_text'] = f'Error: {e}'

    # Calculate final health score and reason
    score, reason = calculate_score(results)
    results['score']  = score
    results['reason'] = reason

    # Logging and alert side-effects
    log_to_csv(domain, results, score, reason)
    log_to_json(domain, results, score, reason)
    if ENABLE_SLACK and score < ALERT_SCORE_THRESHOLD:
        send_slack_alert(domain, score, reason)

    return results


def parse_args():
    p = argparse.ArgumentParser(
        description='AuthScanner: DNS checks for email authentication health.'
    )
    # Neither flag is strictly required; default file is used if domain omitted
    grp = p.add_mutually_exclusive_group()
    grp.add_argument(
        '-d', '--domain',
        help='Scan a single domain'
    )
    grp.add_argument(
        '-f', '--file',
        default=DOMAINS_FILE,
        help='Path to newline-separated domains file'
    )
    return p.parse_args()


def main():
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )

    args = parse_args()

    # Build the list of domains
    if args.domain:
        domains = [args.domain]
    else:
        path = Path(args.file)
        if not path.is_file():
            logging.error(f"Domains file not found: {args.file}")
            return
        domains = [d.strip() for d in path.read_text().splitlines() if d.strip()]

    # Scan each domain
    for domain in domains:
        logging.info(f"🔍 Scanning {domain}")
        try:
            scan_domain(domain)
        except Exception as e:
            logging.error(f"Unhandled error for {domain}: {e}")

    # After all domains, upload aggregated results
    upload_to_s3()


if __name__ == '__main__':
    main()
