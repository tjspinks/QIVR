# QIVR

**QIVR** (Queued Intelligence & Verification Relay) is a modular platform for monitoring, scoring, and improving email authentication and deliverability infrastructure.
--Email Deliverability but cool

This repository includes:

### 📦 Modules

- **`authscanner/`** — DNS-based authentication scanner (SPF, DKIM, DMARC)
- Future modules: BIMI, MTA-STS, DNSSEC, deliverability feedback integration, ML-powered send strategies

---

## Getting Started

```bash
git clone https://github.com/tjspinks/QIVR.git
cd QIVR/authscanner
python3 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt
python main.py
