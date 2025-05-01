import dns.resolver
import socket

# ---------------- SPFs ----------------
def check_spf(domain):
    """
    Returns (spf_ok: bool, spf_text: str)
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                txt_str = txt.decode()
                if txt_str.lower().startswith('v=spf1'):
                    return True, txt_str
        return False, ''
    except Exception as e:
        return False, f"Error: {e}"

# -------------- DMARC ----------------
def check_dmarc(domain):
    """
    Returns (dmarc_ok: bool, dmarc_text: str)
    """
    try:
        record = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(record, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                txt_str = txt.decode()
                if txt_str.lower().startswith('v=dmarc1'):
                    return True, txt_str
        return False, ''
    except Exception as e:
        return False, f"Error: {e}"

# --------------- DKIM ----------------
def check_dkim(domain, selector="default"):
    """
    Returns (dkim_ok: bool, dkim_text: str)
    """
    try:
        record = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(record, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                txt_str = txt.decode()
                if txt_str.lower().startswith('v=dkim1'):
                    return True, txt_str
        return False, ''
    except Exception as e:
        return False, f"Error: {e}"

# --------------- MX ------------------
def check_mx(domain):
    """
    Returns (mx_ok: bool, mx_text: str)
    """
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_hosts = sorted([rdata.exchange.to_text().rstrip('.') for rdata in answers])
        if not mx_hosts:
            return False, ''
        return True, ", ".join(mx_hosts)
    except Exception as e:
        return False, f"Error: {e}"

# -------------- BIMI ----------------
def check_bimi(domain, selector="default"):
    """
    Returns (bimi_ok: bool, bimi_text: str)
    """
    try:
        record = f"{selector}._bimi.{domain}"
        answers = dns.resolver.resolve(record, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                txt_str = txt.decode()
                if txt_str.lower().startswith('v=bimi1'):
                    return True, txt_str
        return False, ''
    except Exception as e:
        return False, f"Error: {e}"

# ------------- DNSBL ---------------
DNSBL_PROVIDERS = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'b.barracudacentral.org'
]

def check_dnsbl(domain):
    """
    Returns (dnsbl_ok: bool, dnsbl_text: str)
    Checks the first MX host's IP against common DNSBLs.
    """
    ok = True
    notes = []
    try:
        mx_ok, mx_text = check_mx(domain)
        if not mx_ok:
            return False, 'No MX records'
        host = mx_text.split(',')[0].strip()
        ips = [a.to_text() for a in dns.resolver.resolve(host, 'A')]
        for ip in ips:
            rev = '.'.join(reversed(ip.split('.')))
            for blk in DNSBL_PROVIDERS:
                try:
                    dns.resolver.resolve(f"{rev}.{blk}", 'A')
                    ok = False
                    notes.append(f"Blacklisted by {blk}")
                except dns.resolver.NXDOMAIN:
                    pass
        if ok:
            return True, 'Clean'
        return False, '; '.join(notes)
    except Exception as e:
        return False, f"Error: {e}"

# ------------- DNSSEC ---------------
def check_dnssec(domain):
    """
    Returns (dnssec_ok: bool, dnssec_text: str)
    Checks for DNSKEY records (indicating DNSSEC).
    """
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        return True, f"{len(answers)} DNSKEY records"
    except Exception:
        return False, ''

# ----------- MTA-STS ----------------
def check_mta_sts(domain):
    """
    Returns (mta_sts_ok: bool, mta_sts_text: str)
    Checks for MTA-STS policy record.
    """
    try:
        record = f"_mta-sts.{domain}"
        answers = dns.resolver.resolve(record, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                txt_str = txt.decode()
                if 'v=STSv1' in txt_str:
                    return True, txt_str
        return False, ''
    except Exception:
        return False, ''

# ---------- TLS-RPT -----------------
def check_tls_rpt(domain):
    """
    Returns (tls_rpt_ok: bool, tls_rpt_text: str)
    Checks for TLS reporting record.
    """
    try:
        record = f"_smtp._tls.{domain}"
        answers = dns.resolver.resolve(record, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                txt_str = txt.decode()
                if 'v=TLSRPTv1' in txt_str:
                    return True, txt_str
        return False, ''
    except Exception:
        return False, ''

# ------------- CAA ------------------
def check_caa(domain):
    """
    Returns (caa_ok: bool, caa_text: str)
    Checks for CAA records to restrict certificate issuance.
    """
    try:
        answers = dns.resolver.resolve(domain, 'CAA')
        records = []
        for rdata in answers:
            records.append(f"{rdata.flags} {rdata.tag} {rdata.value}")
        if records:
            return True, '; '.join(records)
        return False, ''
    except Exception:
        return False, ''

# ------------ PTR -------------------
def check_ptr(domain):
    """
    Returns (ptr_ok: bool, ptr_text: str)
    Performs reverse DNS on the first MX host's IP.
    """
    try:
        mx_ok, mx_text = check_mx(domain)
        if not mx_ok:
            return False, 'No MX records'
        host = mx_text.split(',')[0].strip()
        ip = dns.resolver.resolve(host, 'A')[0].to_text()
        names = socket.gethostbyaddr(ip)[0]
        return True, names
    except Exception as e:
        return False, f"Error: {e}"


