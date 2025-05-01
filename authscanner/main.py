import os
import json
from scanner import (
    check_spf, check_dmarc, check_dkim, check_mx, check_bimi, check_dnsbl,
    check_dnssec, check_mta_sts, check_tls_rpt, check_caa, check_ptr
)
from scorer import calculate_score
from logger import log_to_csv, log_to_json, send_slack_alert, upload_to_s3
from config import (
    DOMAINS_FILE, ALERT_SCORE_THRESHOLD, ENABLE_SLACK, ENABLE_S3
)

def scan_domain(domain):
    checks = {}
    
    # Core Checks
    checks['spf_ok'], checks['spf_text'] = check_spf(domain)
    checks['dmarc_ok'], checks['dmarc_text'] = check_dmarc(domain)
    checks['dkim_ok'], checks['dkim_text'] = check_dkim(domain)
    
    # Extended Checks
    checks['mx_ok'], checks['mx_text'] = check_mx(domain)
    checks['bimi_ok'], checks['bimi_text'] = check_bimi(domain)
    checks['dnsbl_ok'], checks['dnsbl_text'] = check_dnsbl(domain)
    checks['dnssec_ok'], checks['dnssec_text'] = check_dnssec(domain)
    checks['mta_sts_ok'], checks['mta_sts_text'] = check_mta_sts(domain)
    checks['tls_rpt_ok'], checks['tls_rpt_text'] = check_tls_rpt(domain)
    checks['caa_ok'], checks['caa_text'] = check_caa(domain)
    checks['ptr_ok'], checks['ptr_text'] = check_ptr(domain)
    
    score, reason = calculate_score(checks)

    print(f"\n🔍 Checking domain: {domain}")
    print(f"📊 Score: {score}/100")
    print(f"📝 Reason: {reason}")

    log_to_csv(domain, checks, score, reason)
    log_to_json(domain, checks, score, reason)

    if ENABLE_SLACK and score < ALERT_SCORE_THRESHOLD:
        send_slack_alert(domain, score, reason)

    return {
        "domain": domain,
        "checks": checks,
        "score": score,
        "reason": reason
    }

def main():
    results = []
    with open(DOMAINS_FILE, "r") as f:
        for line in f:
            domain = line.strip()
            if domain:
                results.append(scan_domain(domain))

    if ENABLE_S3:
        json_data = json.dumps(results, indent=4)
        upload_to_s3(json_data)

if __name__ == "__main__":
    main()

