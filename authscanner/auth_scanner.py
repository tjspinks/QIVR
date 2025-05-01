import dns.resolver

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                if b"v=spf1" in txt:
                    print(f"✅ SPF found for {domain}: {txt.decode()}")
                    return True
        print(f"❌ No SPF found for {domain}")
        return False
    except Exception as e:
        print(f"Error checking SPF for {domain}: {e}")
        return False

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                if b"v=DMARC1" in txt:
                    print(f"✅ DMARC found for {domain}: {txt.decode()}")
                    return True
        print(f"❌ No DMARC found for {domain}")
        return False
    except Exception as e:
        print(f"Error checking DMARC for {domain}: {e}")
        return False

# Run the checks
domain = "example.com"
check_spf(domain)
check_dmarc(domain)
import dns.resolver

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                if b"v=spf1" in txt:
                    print(f"✅ SPF found for {domain}: {txt.decode()}")
                    return True
        print(f"❌ No SPF found for {domain}")
        return False
    except Exception as e:
        print(f"Error checking SPF for {domain}: {e}")
        return False

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                if b"v=DMARC1" in txt:
                    print(f"✅ DMARC found for {domain}: {txt.decode()}")
                    return True
        print(f"❌ No DMARC found for {domain}")
        return False
    except Exception as e:
        print(f"Error checking DMARC for {domain}: {e}")
        return False

# Run the checks
domain = "example.com"
check_spf(domain)
check_dmarc(domain)
import dns.resolver

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                if b"v=spf1" in txt:
                    print(f"✅ SPF found for {domain}: {txt.decode()}")
                    return True
        print(f"❌ No SPF found for {domain}")
        return False
    except Exception as e:
        print(f"Error checking SPF for {domain}: {e}")
        return False

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                if b"v=DMARC1" in txt:
                    print(f"✅ DMARC found for {domain}: {txt.decode()}")
                    return True
        print(f"❌ No DMARC found for {domain}")
        return False
    except Exception as e:
        print(f"Error checking DMARC for {domain}: {e}")
        return False

# Run the checks
domain = "example.com"
check_spf(domain)
check_dmarc(domain)
import dns.resolver

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                if b"v=spf1" in txt:
                    print(f"✅ SPF found for {domain}: {txt.decode()}")
                    return True
        print(f"❌ No SPF found for {domain}")
        return False
    except Exception as e:
        print(f"Error checking SPF for {domain}: {e}")
        return False

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                if b"v=DMARC1" in txt:
                    print(f"✅ DMARC found for {domain}: {txt.decode()}")
                    return True
        print(f"❌ No DMARC found for {domain}")
        return False
    except Exception as e:
        print(f"Error checking DMARC for {domain}: {e}")
        return False

# Run the checks
domain = "example.com"
check_spf(domain)
check_dmarc(domain)
import dns.resolver

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                if b"v=spf1" in txt:
                    print(f"✅ SPF found for {domain}: {txt.decode()}")
                    return True
        print(f"❌ No SPF found for {domain}")
        return False
    except Exception as e:
        print(f"Error checking SPF for {domain}: {e}")
        return False

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                if b"v=DMARC1" in txt:
                    print(f"✅ DMARC found for {domain}: {txt.decode()}")
                    return True
        print(f"❌ No DMARC found for {domain}")
        return False
    except Exception as e:
        print(f"Error checking DMARC for {domain}: {e}")
        return False

# Run the checks
domain = "example.com"
check_spf(domain)
check_dmarc(domain)

