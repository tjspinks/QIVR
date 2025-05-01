from dns import resolver, exception

COMMON_DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "k1", "s1", "s1024", "s2048",
    "smtp", "mail", "dkim", "m1", "mx", "key1", "sendgrid", "sparkpost", "mandrill", "postfix", "amazon", "fastmail"
]

def check_spf(domain):
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            for txt in rdata.strings:
                decoded = txt.decode()
                if decoded.startswith("v=spf1"):
                    return True, decoded
        return False, "No SPF record found"
    except Exception as e:
        return False, f"Error checking SPF: {e}"

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            for txt in rdata.strings:
                decoded = txt.decode()
                if decoded.startswith("v=DMARC1"):
                    return True, decoded
        return False, "No DMARC record found"
    except Exception as e:
        return False, f"Error checking DMARC: {e}"

def check_dkim(domain):
    for selector in COMMON_DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = resolver.resolve(dkim_domain, "TXT")
            for rdata in answers:
                for txt in rdata.strings:
                    decoded = txt.decode()
                    if decoded.startswith("v=DKIM1"):
                        return "valid", f"{selector}: {decoded}"
        except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
            continue

    return "unknown", "❓ No DKIM found using common selectors; manual review recommended."

