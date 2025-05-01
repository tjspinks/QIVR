import dns.resolver
import socket
import ipaddress

# Utilities

def _extract_txt(rdata):
    """
    Join DNS TXT record segments into a single string.
    """
    try:
        parts = getattr(rdata, 'strings', None)
        if parts:
            return ''.join(seg.decode() for seg in parts)
        return rdata.to_text().strip('"')
    except Exception:
        return ''

# ---------------- SPFs ----------------
def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = _extract_txt(rdata)
            if txt.lower().startswith('v=spf1'):
                return True, txt
        return False, 'No SPF record found'
    except Exception as e:
        return False, f"Error: {e}"

# -------------- DMARC ----------------
def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt = _extract_txt(rdata)
            if txt.lower().startswith('v=dmarc1'):
                return True, txt
        return False, 'No DMARC record found'
    except Exception as e:
        return False, f"Error: {e}"

# --------------- DKIM ----------------
COMMON_DKIM_SELECTORS = [
    'default','selector1','selector2','google','k1','s1','s2',
    'smtp','mail','email','key1','key2','dkim','m1','mta1',
    'newsmtp','mx','cloud','mail1'
]

def check_dkim(domain):
    for sel in COMMON_DKIM_SELECTORS:
        try:
            answers = dns.resolver.resolve(f"{sel}._domainkey.{domain}", 'TXT')
            for rdata in answers:
                txt = _extract_txt(rdata)
                if txt.lower().startswith('v=dkim1'):
                    return True, sel, txt
        except Exception:
            continue
    return False, None, 'No DKIM record found'

# --------------- MX ------------------
def check_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        hosts = sorted(rdata.exchange.to_text().rstrip('.') for rdata in answers)
        if hosts:
            return True, hosts
        return False, 'No MX records'
    except Exception as e:
        return False, f"Error: {e}"

# -------------- BIMI ----------------
COMMON_BIMI_SELECTORS = ['default']

def check_bimi(domain):
    for sel in COMMON_BIMI_SELECTORS:
        try:
            answers = dns.resolver.resolve(f"{sel}._bimi.{domain}", 'TXT')
            for rdata in answers:
                txt = _extract_txt(rdata)
                if txt.lower().startswith('v=bimi1'):
                    return True, sel, txt
        except Exception:
            continue
    return False, None, 'No BIMI record found'

# ------------- DNSBL ---------------
DNSBL_PROVIDERS = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'b.barracudacentral.org'
]

def check_dnsbl(domain):
    """
    Returns (dnsbl_ok: bool, dnsbl_text: str).
    Checks each MX host's IP against DNSBLs, distinguishing actual listings
    from Spamhaus error codes (127.255.255.x), timeouts, and no-answer cases.
    """
    mx_ok, mx_hosts = check_mx(domain)
    if not mx_ok:
        return False, 'No MX records'

    ok = True
    notes = []
    for host in mx_hosts:
        try:
            ips = [r.to_text() for r in dns.resolver.resolve(host, 'A')]
        except Exception as e:
            notes.append(f'Error resolving MX host {host}: {e}')
            continue

        for ip in ips:
            rev_ip = '.'.join(reversed(ip.split('.')))
            for blk in DNSBL_PROVIDERS:
                query = f"{rev_ip}.{blk}"
                try:
                    answers = dns.resolver.resolve(query, 'A')
                    for ans in answers:
                        listed_ip = ipaddress.IPv4Address(ans.to_text())
                        # Skip Spamhaus error return codes 127.255.255.0/24
                        if listed_ip in ipaddress.IPv4Network('127.255.255.0/24'):
                            notes.append(f'Error code from {blk}: {listed_ip}')
                        # Treat true blacklist listings in 127.0.0.0/8 (excluding the error range)
                        elif listed_ip in ipaddress.IPv4Network('127.0.0.0/8'):
                            ok = False
                            notes.append(f'IP {ip} blacklisted by {blk} ({listed_ip})')
                except dns.resolver.NXDOMAIN:
                    # Not listed: expected
                    continue
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.Timeout:
                    notes.append(f'Timeout querying {blk} for {ip}')
                except dns.exception.DNSException as dns_e:
                    notes.append(f'DNS error querying {blk} for {ip}: {dns_e}')

    return (True, 'Clean') if ok else (False, '; '.join(notes))

# ------------- DNSSEC ---------------
def check_dnssec(domain):
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        return True, f"{len(answers)} DNSKEY records"
    except Exception:
        return False, ''

# ----------- MTA-STS ----------------
def check_mta_sts(domain):
    try:
        answers = dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        for rdata in answers:
            txt = _extract_txt(rdata)
            if 'v=stsv1' in txt.lower():
                return True, txt
        return False, 'No MTA-STS record'
    except Exception:
        return False, ''

# ---------- TLS-RPT -----------------
def check_tls_rpt(domain):
    try:
        answers = dns.resolver.resolve(f"_smtp._tls.{domain}", 'TXT')
        for rdata in answers:
            txt = _extract_txt(rdata)
            if 'v=tlsrptv1' in txt.lower():
                return True, txt
        return False, 'No TLS-RPT record'
    except Exception:
        return False, ''

# ------------- CAA ------------------
def check_caa(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CAA')
        recs = [f"{r.flags} {r.tag} {r.value}" for r in answers]
        return (True, '; '.join(recs)) if recs else (False, 'No CAA records')
    except Exception:
        return False, ''

# ------------ PTR -------------------
def check_ptr(domain):
    mx_ok, mx_hosts = check_mx(domain)
    if not mx_ok:
        return False, 'No MX records'
    host = mx_hosts[0]
    try:
        ip = dns.resolver.resolve(host, 'A')[0].to_text()
        name = socket.gethostbyaddr(ip)[0]
        return True, name
    except Exception as e:
        return False, f"Error: {e}"
