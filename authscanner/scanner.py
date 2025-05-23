import dns.resolver
import socket
import subprocess

# Utilities

def _extract_txt(rdata):
    try:
        parts = getattr(rdata, 'strings', None)
        if parts:
            return ''.join(seg.decode() for seg in parts)
        return rdata.to_text().strip('"')
    except Exception:
        return ''

# SPF Check
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

# DMARC Check
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

# DKIM Check
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

# MX Check
def check_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        hosts = sorted(rdata.exchange.to_text().rstrip('.') for rdata in answers)
        if hosts:
            return True, hosts
        return False, 'No MX records'
    except Exception as e:
        return False, f"Error: {e}"

# BIMI Check
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

# DNSBL Check
DNSBL_PROVIDERS = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'b.barracudacentral.org'
]

def check_dnsbl(domain):
    ok = True
    notes = []
    mx_ok, mx_hosts = check_mx(domain)
    if not mx_ok:
        return False, 'No MX records'

    try:
        for host in mx_hosts:
            try:
                ips = [a.to_text() for a in dns.resolver.resolve(host, 'A')]
            except Exception as e:
                notes.append(f'Error resolving MX host ({host}): {e}')
                continue

            for ip in ips:
                rev = '.'.join(reversed(ip.split('.')))
                for blk in DNSBL_PROVIDERS:
                    query = f"{rev}.{blk}"
                    try:
                        answers = dns.resolver.resolve(query, 'A')
                        for answer in answers:
                            ip_result = answer.to_text()
                            if ip_result.startswith("127.255.255."):
                                notes.append(f"Spamhaus error for {blk}: {ip_result}")
                            else:
                                ok = False
                                notes.append(f"IP {ip} listed by {blk} ({ip_result})")
                    except dns.resolver.NXDOMAIN:
                        continue
                    except dns.resolver.NoAnswer:
                        continue
                    except dns.resolver.Timeout:
                        notes.append(f"Timeout querying {blk}")
                    except dns.exception.DNSException as dns_e:
                        notes.append(f"DNS error ({query}): {dns_e}")
    except Exception as e:
        return False, f'Unexpected error: {e}'

    return (True, 'Clean') if ok else (False, '; '.join(notes))

# DNSSEC Check using native tool (drill)
def check_dnssec(domain):
    try:
        result = subprocess.run(["drill", "-D", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if "DNSSEC supported" in result.stdout:
            return True, "DNSSEC supported"
        else:
            return False, "DNSSEC not supported"
    except Exception as e:
        return False, f"Error: {e}"

# MTA-STS Check
def check_mta_sts(domain):
    try:
        answers = dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        for rdata in answers:
            txt = ''.join(seg.decode() for seg in getattr(rdata, 'strings', []))
            if 'v=STSv1' in txt:
                return True, txt
        return False, 'No MTA-STS record found'
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None, 'MTA-STS not implemented'
    except Exception as e:
        return False, f"Error: {e}"

# TLS-RPT Check
def check_tls_rpt(domain):
    try:
        answers = dns.resolver.resolve(f"_smtp._tls.{domain}", 'TXT')
        for rdata in answers:
            txt = ''.join(seg.decode() for seg in getattr(rdata, 'strings', []))
            if 'v=TLSRPTv1' in txt.lower():
                return True, txt
            else:
                return False, f"Invalid TLS-RPT format: {txt}"
        return None, 'TLS-RPT not implemented'
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None, 'TLS-RPT not implemented'
    except Exception as e:
        return False, f"Error: {e}"

# CAA Check
def check_caa(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CAA')
        recs = []
        for rdata in answers:
            recs.append(f"{rdata.flags} {rdata.tag} {rdata.value}")
        return (True, '; '.join(recs)) if recs else (False, 'No CAA records')
    except dns.resolver.NoAnswer:
        return None, 'CAA not implemented'
    except Exception as e:
        return False, f"Error: {e}"

# PTR Check
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
