def calculate_score(checks: dict) -> (int, str):
    """
    Calculate a normalized score out of 100 based on individual DNS/email checks.
    Expects `checks` dict with boolean values for *_ok keys.

    Returns:
        score (int): 0-100 score.
        reason (str): Semicolon-separated list of failed checks.
    """
    # Define weights for each check (total should sum to 100)
    weights = {
        'spf_ok': 15,
        'dmarc_ok': 20,
        'dkim_ok': 10,
        'mx_ok': 10,
        'bimi_ok': 5,
        'dnsbl_ok': 10,
        'dnssec_ok': 5,
        'mta_sts_ok': 5,
        'tls_rpt_ok': 5,
        'caa_ok': 5,
        'ptr_ok': 10,
    }
    total_weight = sum(weights.values())

    score_accum = 0
    failures = []
    for check, weight in weights.items():
        ok = checks.get(check, False)
        if ok:
            score_accum += weight
        else:
            # Humanize the failure reason
            label = check.replace('_ok', '').upper().replace('_', ' ')
            failures.append(f"{label} failed")

    # Normalize to 0-100
    score = int((score_accum / total_weight) * 100)
    reason = "; ".join(failures) if failures else "All checks passed ✅"
    return score, reason

