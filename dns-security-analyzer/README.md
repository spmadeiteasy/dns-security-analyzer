# DomainScope — DNS Lookup & Domain Security Analyzer

A full-stack educational cybersecurity project. It combines a responsive browser dashboard with a Python FastAPI backend to inspect public DNS records, email-authentication signals and RDAP registration data.

## Features

- IPv4 / IPv6 and reverse PTR lookup
- DNS: A, AAAA, MX, NS, TXT, CNAME, SOA and CAA
- SPF and DMARC configuration analysis
- DKIM checks against a documented list of common selectors
- RDAP registration dates, registrar, status and nameservers
- New-domain age indicator (a weak signal, never a malware verdict)
- Batch analysis (up to 20 targets)
- Custom public DNS resolver
- JSON and text report export
- Built-in FastAPI API documentation at `/docs`
- Unit tests for validation and email-authentication parsing

## Requirements

- Python 3.10 or newer
- Internet connection for public DNS and RDAP queries

## Windows setup (PowerShell)

```powershell
cd dns-security-analyzer
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000** in your browser. API docs: **http://127.0.0.1:8000/docs**.

## Linux / macOS setup

```bash
cd dns-security-analyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Run tests

```bash
pytest -q
```

## API examples

Single lookup:

```bash
curl -X POST http://127.0.0.1:8000/api/lookup \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","include_records":true,"include_email":true,"include_rdap":true}'
```

Batch lookup:

```bash
curl -X POST http://127.0.0.1:8000/api/batch \
  -H 'Content-Type: application/json' \
  -d '{"targets":["example.com","cloudflare.com","8.8.8.8"]}'
```

Health check: `GET /api/health`.

## Project structure

```text
dns-security-analyzer/
├── app/
│   ├── __init__.py
│   ├── analyzer.py       # DNS, SPF/DMARC/DKIM and RDAP logic
│   ├── main.py           # FastAPI endpoints
│   └── static/
│       ├── index.html    # Dashboard
│       ├── style.css     # Responsive dark UI
│       └── app.js        # API calls, rendering and exports
├── tests/
│   └── test_analyzer.py
├── requirements.txt
└── README.md
```

## Important technical notes

- DNS answers are dependent on resolver, cache, DNSSEC configuration and time.
- The custom resolver field accepts public IP addresses only. Private/reserved resolver addresses are rejected.
- DKIM selector names are not published in a universal directory. This tool checks common selectors only. No match does **not** mean DKIM is absent.
- SPF/DMARC grades are simplified educational indicators, not full RFC compliance validators. SPF flattening, the 10-DNS-lookup SPF limit, macro expansion, DMARC organizational-domain discovery and alignment evaluation are not fully implemented.
- RDAP data can be redacted, rate-limited or unavailable. RDAP replaced many traditional WHOIS use cases, but the exact response differs by registry.
- A newly registered domain is not automatically malicious. A good SPF/DMARC setup does not prove that a domain is safe.
- Use this tool for learning and authorized defensive investigation. It performs passive public-data lookups, not port scanning or exploitation.

## Presentation outline

1. Problem: users cannot easily see how a domain is configured.
2. DNS basics: A/AAAA map names to IPs; MX routes email; NS identifies authoritative nameservers.
3. Email authentication: SPF, DKIM and DMARC reduce spoofing risks.
4. Registration intelligence: RDAP exposes registration events and registrar data.
5. Architecture: browser UI → FastAPI → DNS resolver / RDAP service.
6. Demonstration: analyze a domain, inspect records, compare email-authentication results, run a batch and export JSON.
7. Limitations: public data is incomplete; security indicators are not a verdict.

## License

MIT. Educational class project.
