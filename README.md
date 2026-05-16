# PhishGuard AI — Phishing Email Analyzer

PhishGuard AI is a browser-based phishing email analyzer designed as a practical cybersecurity portfolio project and a usable triage assistant for suspicious emails.

The core analyzer runs locally in the browser. Optional online reputation verification is available through a Cloudflare Worker proxy that queries VirusTotal without exposing the API key in the frontend.

## Main features

- Upload and parse `.eml` files.
- Paste email evidence manually: subject, sender, Reply-To, body, headers and attachment names.
- Load 10 realistic demo `.eml` examples from benign to suspicious, spam, BEC and phishing.
- Extract URLs, domains, IP-based URLs and attachment names.
- Check SPF, DKIM and DMARC evidence when present in headers.
- Detect phishing signals: urgency, credential harvesting, payment pressure, impersonation, URL shorteners, punycode, suspicious TLDs and risky attachment extensions.
- Score phishing risk from `0/100` to `100/100`.
- Map likely behavior to MITRE ATT&CK techniques.
- Export analyst reports as JSON or Markdown.
- Switch interface language between English and Spanish.
- Optional VirusTotal enrichment for:
  - domains;
  - URLs;
  - IP addresses;
  - SHA-256 hashes of attachment samples.

## Online reputation architecture

The frontend is still deployable on GitHub Pages:

```text
GitHub Pages frontend
        ↓
Cloudflare Worker proxy
        ↓
VirusTotal API v3
```

The API key is stored as a Cloudflare Worker secret, not inside `app.js`.

The Worker only receives indicators selected by the app:

- domains;
- URLs;
- IP addresses;
- optional SHA-256 file hashes.

It does **not** receive the full `.eml` file or email body.

## Attachment handling

PhishGuard AI does not detonate attachments and does not upload files to VirusTotal.

For attachment enrichment, the user can select local attachment samples. The browser calculates SHA-256 locally using the Web Crypto API, and only the hash is sent to the Worker for a VirusTotal file report lookup.

This gives a realistic “attachment reputation” workflow without uploading potentially sensitive samples.

## Deploy frontend with GitHub Pages

1. Create a GitHub repository, for example:

```text
phishguard-ai
```

2. Upload all project files to the repository root.
3. Go to **Settings → Pages**.
4. Under **Build and deployment**, choose **Deploy from a branch**.
5. Select:
   - Branch: `main`
   - Folder: `/root`
6. Save.
7. Your site will be published at:

```text
https://YOUR_USERNAME.github.io/phishguard-ai/
```

## Configure VirusTotal enrichment

See [`VIRUSTOTAL_SETUP.md`](VIRUSTOTAL_SETUP.md).

Short version:

```bash
cd worker
npm install
npx wrangler login
npx wrangler secret put VT_API_KEY
npm run deploy
```

Then copy the deployed Worker URL into the **Online reputation verification** field inside the app.

## Local development

Run a local static server:

```bash
python -m http.server 8000
```

Open:

```text
http://localhost:8000
```

For the Worker:

```bash
cd worker
npm install
cp .dev.vars.example .dev.vars
# edit .dev.vars with your VirusTotal key
npm run dev
```

## Demo examples included

The `examples/` folder includes 10 synthetic `.eml` files:

1. Legitimate internal security update.
2. Legitimate supplier invoice with PDF.
3. Marketing newsletter.
4. Spam discount offer with multiple links.
5. Suspicious invoice with Reply-To mismatch.
6. Microsoft 365 credential phishing.
7. Parcel delivery lure with IP-based URL.
8. BEC wire transfer with no URL.
9. Macro-enabled invoice attachment.
10. Punycode/homograph security alert.

## Example CV bullet

```text
Built PhishGuard AI, a browser-based phishing email analyzer that parses .eml files, extracts IOCs, scores phishing risk, maps likely MITRE ATT&CK techniques, and enriches domains, URLs, IPs and attachment hashes through a Cloudflare Worker integration with VirusTotal API v3.
```

## Example technical description

```text
PhishGuard AI performs client-side phishing triage by extracting IOCs from email evidence, evaluating authentication headers and social-engineering signals, assigning a risk score, generating analyst actions and optionally querying VirusTotal through a serverless proxy so API keys are not exposed in the browser.
```

## Limitations

This is a portfolio/demo-grade analyzer, not an enterprise email security gateway.

Known limitations:

- MIME parsing is lightweight.
- It does not render HTML emails in a sandbox.
- It does not upload or detonate attachments.
- VirusTotal lookups depend on your API plan, quota and available reports.
- URL lookups use existing VirusTotal reports; the Worker does not submit URLs for active scanning by default.
- MITRE ATT&CK mapping is indicative and requires analyst review.
- A low score does not prove that a message is benign.

## License

MIT License. See `LICENSE`.
