# CV and Interview Material

## Short CV bullet

Built a browser-based phishing email analyzer that parses `.eml` files, extracts IOCs, scores phishing risk, maps likely MITRE ATT&CK techniques, and enriches domains, URLs, IPs and attachment hashes through a Cloudflare Worker integration with VirusTotal API v3.

## Stronger CV bullet

Developed PhishGuard AI, a bilingual phishing email analysis tool using HTML, CSS and JavaScript. The tool parses `.eml` files locally, extracts IOCs, detects risky URL and attachment patterns, evaluates SPF/DKIM/DMARC evidence, generates a 0–100 risk score, maps likely MITRE ATT&CK techniques, exports analyst-ready reports and optionally verifies indicators online through a serverless VirusTotal proxy without exposing API keys in the frontend.

## Skills to list

- Phishing Analysis
- Email Header Analysis
- IOC Extraction
- MITRE ATT&CK
- VirusTotal API v3
- Cloudflare Workers
- Serverless API Proxy
- JavaScript
- Secure Frontend Design
- GitHub Pages
- Incident Response Documentation

## Interview explanation

I built PhishGuard AI as a practical phishing email triage project. The core analyzer runs in the browser: it parses `.eml` files, extracts URLs, domains, attachment names and authentication results, and then applies a transparent scoring model. The output is designed for analyst workflow: executive summary, risk evidence, indicators, MITRE mapping, recommended actions and Markdown/JSON export.

The second design decision was to add online reputation without exposing secrets. A static GitHub Pages app cannot safely store private API keys, so I implemented a Cloudflare Worker proxy. The frontend sends only extracted IOCs and optional SHA-256 file hashes to the Worker, and the Worker queries VirusTotal API v3 using a secret stored in Cloudflare.
