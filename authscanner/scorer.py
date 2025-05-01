def calculate_score(results):
    score = 0
    total_possible = 0
    reasons = []

    scoring_weights = {
        "spf": 30,
        "dmarc": 30,
        "dkim": 10,
        "mx": 10,
        "dnsbl": 5,
        "dnssec": 5,
        "mta_sts": 3,
        "tls_rpt": 2,
        "caa": 3,
        "ptr": 2
    }

    for check, weight in scoring_weights.items():
        result = results.get(check, {})
        if result.get('ok'):
            score += weight
        else:
            reasons.append(f"{check.upper()} failed")
        total_possible += weight

    percent_score = int((score / total_possible) * 100)
    reason_text = "; ".join(reasons) if reasons else "All checks passed"
    return percent_score, reason_text
