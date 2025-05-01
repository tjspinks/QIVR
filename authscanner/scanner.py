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
def check_dnsbl(domain):
    from authscanner.config import SPAMHAUS_DQS_KEY, USE_SPAMHAUS_DQS
    ok = True
    notes = []
    mx_ok, mx_hosts = check_mx(domain)
    if not mx_ok:
        return False, 'No MX records'

    for host in mx_hosts:
        try:
            ips = [a.to_text() for a in dns.resolver.resolve(host, 'A')]
        except Exception as e:
            notes.append(f'Error resolving MX host ({host}): {e}')
            continue

        for ip in ips:
            rev = '.'.join(reversed(ip.split('.')))
            providers = []

            if USE_SPAMHAUS_DQS:
                providers = [f"{rev}.{SPAMHAUS_DQS_KEY}.zen.dq.spamhaus.net"]
            else:
                providers = [f"{rev}.zen.spamhaus.org", f"{rev}.bl.spamcop.net", f"{rev}.b.barracudacentral.org"]

            for blk in providers:
                try:
                    answers = dns.resolver.resolve(blk, 'A')
                    for r in answers:
                        code = r.to_text()
                        # DQS error range (not a real listing)
                        if code.startswith("127.255.255."):
                            notes.append(f"Spamhaus query error from {blk}: {code}")
                            continue
                        notes.append(f"IP {ip} listed by {blk} ({code})")
                        ok = False
                except dns.resolver.NXDOMAIN:
                    continue
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.Timeout:
                    notes.append(f"Timeout querying {blk}")
                except dns.exception.DNSException as dns_e:
                    notes.append(f"DNS error ({blk}): {dns_e}")

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
