import argparse
import logging
import json
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

SUGGESTIONS = {
    'spf': "Publish an SPF record (TXT) that specifies your authorized sending servers.",
    'dmarc': "Add a DMARC record to protect your domain from email spoofing.",
    'dkim': "Ensure DKIM selectors are correctly set. Check non-standard selectors if common ones are missing.",
    'mx': "Set MX records to route incoming mail properly.",
    'bimi': "Configure a BIMI record with a compliant SVG logo.",
}

def scan_domain(domain: str) -> dict:
    results = {}
    for name, fn in CHECKS.items():
        try:
            ret = fn(domain)
            if name in ('dkim', 'bimi'):
                ok, selector, txt = ret
                results[name] = {'ok': ok, 'selector': selector, 'text': txt}
            else:
                ok, txt = ret
                results[name] = {'ok': ok, 'text': txt}
        except Exception as e:
            results[name] = {'ok': False, 'text': f'Error: {e}'}

    score, reason = calculate_score(results)
    results['overall'] = {'score': score, 'reason': reason}

    log_to_csv(domain, results, score, reason)
    log_to_json(domain, results, score, reason)
    if ENABLE_SLACK and score < ALERT_SCORE_THRESHOLD:
        send_slack_alert(domain, score, reason)

    return results

def parse_args():
    parser = argparse.ArgumentParser(description='Email Authentication Scanner')
    parser.add_argument('-d', '--domain', help='Single domain to scan')
    parser.add_argument('-f', '--file', default=DOMAINS_FILE, help='File with domains to scan')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    return parser.parse_args()

def format_report(domain: str, results: dict) -> str:
    report_lines = [f"\n📊 Domain Scan Report: {domain}", '-'*50]
    for name, detail in results.items():
        if name == 'overall':
            continue
        status = '✅ PASS' if detail['ok'] else '❌ FAIL'
        selector = detail.get('selector', '')
        report_lines.append(f"{status} {name.upper():8} | Selector: {selector if selector else 'N/A'} | Detail: {detail['text']}")
        if not detail['ok'] and name in SUGGESTIONS:
            report_lines.append(f"   💡 Tip: {SUGGESTIONS[name]}")

    overall = results['overall']
    report_lines.extend([
        '-'*50,
        f"🏅 Overall Score: {overall['score']} ({overall['reason']})",
        '-'*50
    ])

    if not results.get('dkim', {}).get('ok', True):
        report_lines.append("⚠️ Note: DKIM check limited to common selectors. Additional selectors may exist.")

    return '\n'.join(report_lines)

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
    args = parse_args()

    if args.domain:
        domains = [args.domain.strip()]
    else:
        domains_file = Path(args.file)
        if not domains_file.exists():
            logging.error(f"File not found: {args.file}")
            return
        domains = [line.strip() for line in domains_file.read_text().splitlines() if line.strip()]

    all_results = {}
    for domain in domains:
        logging.info(f"Scanning domain: {domain}")
        result = scan_domain(domain)
        all_results[domain] = result

        if args.json:
            print(json.dumps({domain: result}, indent=2))
        else:
            print(format_report(domain, result))

    upload_to_s3()

if __name__ == '__main__':
    main()
