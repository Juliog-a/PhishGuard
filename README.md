# PhishGuard AI — Phishing Email Analyzer

PhishGuard AI is a privacy-first phishing email analyzer built as a cybersecurity portfolio project. It runs entirely in the browser and can be deployed as a static website using GitHub Pages.

## What it does

- Uploads and parses `.eml` email files locally in the browser.
- Supports manual input for subject, sender, Reply-To, body and attachment names.
- Extracts URLs, domains, attachment names and authentication signals.
- Scores phishing risk from 0 to 100.
- Generates SOC-style triage output:
  - Executive summary
  - Risk evidence
  - Extracted indicators
  - Suggested MITRE ATT&CK mapping
  - Recommended analyst actions
  - AI enrichment prompt
- Exports results to JSON and Markdown.

## Why this project exists

This project is designed to support a cybersecurity CV/portfolio by showing practical knowledge of:

- phishing triage;
- email header analysis;
- IOC extraction;
- risk scoring;
- MITRE ATT&CK mapping;
- browser-based secure-by-design tooling;
- SOC analyst workflows.

## Live deployment with GitHub Pages

1. Create a new public GitHub repository, for example: `phishguard-ai`.
2. Upload all project files to the repository root:
   - `index.html`
   - `styles.css`
   - `app.js`
   - `assets/`
   - `examples/`
   - `docs/`
3. Go to **Settings → Pages**.
4. Under **Build and deployment**, choose **Deploy from a branch**.
5. Select:
   - Branch: `main`
   - Folder: `/root`
6. Save.
7. Your site should become available at:

```text
https://YOUR_USERNAME.github.io/phishguard-ai/
```

## Local usage

Open `index.html` directly in a browser, or run a simple local server:

```bash
python -m http.server 8000
```

Then open:

```text
http://localhost:8000
```

## Example CV bullet

```text
Built PhishGuard AI, a browser-based phishing email analyzer that parses .eml files, extracts IOCs, scores phishing risk, maps likely MITRE ATT&CK techniques, and generates SOC-style investigation guidance without sending email data to a backend.
```

## Example LinkedIn/GitHub description

```text
PhishGuard AI is a privacy-first phishing triage tool for SOC workflows. It analyzes suspicious emails locally in the browser, extracts URLs and attachment indicators, evaluates sender-authentication signals, produces a phishing risk score, and exports a structured analyst report.
```

## Technical design

The project is intentionally static:

- No backend.
- No database.
- No API key exposed in the frontend.
- No email content uploaded to third-party services.

The analyzer uses deterministic heuristics rather than a hosted LLM. This is deliberate: a pure GitHub Pages deployment cannot securely protect private API keys. The app therefore generates an **AI enrichment prompt** that an analyst can copy into an approved AI tool after reviewing data-handling requirements.

## Risk checks included

| Category | Examples |
|---|---|
| Authentication | SPF, DKIM, DMARC failures when present in headers |
| Sender anomalies | From / Reply-To domain mismatch |
| URL risk | shorteners, IP-based URLs, punycode, suspicious TLDs, excessive subdomains |
| Attachment risk | executable, script, ISO, HTML, compressed and macro-enabled files |
| Social engineering | urgency, credential prompts, payment pressure, impersonation language |
| SOC output | recommended actions, MITRE mapping, Markdown/JSON export |

## Limitations

This is an educational and portfolio-grade project, not a secure email gateway or enterprise detection product.

Known limitations:

- MIME parsing is intentionally lightweight.
- It does not detonate attachments.
- It does not query live threat-intelligence feeds.
- It does not verify domain reputation online.
- It cannot guarantee that an email is benign or malicious.
- MITRE mapping is indicative and should be reviewed by a human analyst.

## Safe handling note

Do not upload real confidential emails to public websites or paste sensitive email data into public AI tools. This app processes files locally, but the deployed GitHub Pages website itself is public.

## Suggested improvements

Future extensions:

- Add VirusTotal or URLScan integration through a secure backend.
- Add proper MIME parsing with a vetted parser.
- Add mailbox-provider-specific header interpretation.
- Add screenshot rendering for HTML emails in a sandbox.
- Add YARA/Sigma-inspired rule packs.
- Add LLM summarization through a backend that protects API keys.

## License

MIT License. See `LICENSE`.
