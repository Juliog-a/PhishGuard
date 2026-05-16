# CV and Interview Material

## Short CV bullet

Built a browser-based phishing email analyzer that parses `.eml` files, extracts URLs and attachment indicators, evaluates sender-authentication signals, scores phishing risk, maps likely MITRE ATT&CK techniques, and exports SOC-style triage reports.

## Stronger CV bullet

Developed PhishGuard AI, a privacy-first phishing triage tool for SOC workflows using HTML, CSS and JavaScript. The tool parses `.eml` files locally, extracts IOCs, detects risky URL and attachment patterns, evaluates SPF/DKIM/DMARC evidence, generates a 0–100 risk score, maps likely MITRE ATT&CK techniques and exports analyst-ready Markdown/JSON reports.

## Skills to list

- Phishing Analysis
- Email Header Analysis
- IOC Extraction
- MITRE ATT&CK
- SOC Triage
- JavaScript
- Secure Frontend Design
- GitHub Pages
- Incident Response Documentation

## Interview explanation

I built PhishGuard AI as a privacy-first SOC triage tool. The main design decision was to avoid sending suspicious email content to a backend. The app parses `.eml` files directly in the browser, extracts URLs, domains, attachment names and authentication results, then applies a transparent scoring model. The output is designed for a junior SOC analyst: executive summary, evidence, indicators, MITRE mapping and recommended actions.

I intentionally did not expose an LLM API key in the frontend because a static GitHub Pages application cannot protect secrets. Instead, the tool generates an AI enrichment prompt that can be used in an approved environment after validating data-handling rules.
