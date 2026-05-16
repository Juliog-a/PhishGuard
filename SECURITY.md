# Security Policy

PhishGuard AI is an educational and portfolio-grade phishing analysis tool.

## Data handling

The default analyzer processes `.eml` files locally in the browser.

When online reputation verification is enabled, the app sends only extracted indicators to the configured Cloudflare Worker:

- domains;
- URLs;
- IP addresses;
- optional SHA-256 hashes of selected attachment samples.

The app does not intentionally send full email bodies, full headers or attachment file contents to VirusTotal.

## API key handling

Do not place a VirusTotal API key inside frontend JavaScript.

Use the included Cloudflare Worker and store the key as a Worker secret:

```bash
npx wrangler secret put VT_API_KEY
```

## Attachment handling

The tool does not detonate files and does not upload attachments.

If attachment files are selected, the browser computes SHA-256 locally and sends only the hash for reputation lookup.

## Limitations

- Do not use this as the only source for incident-response decisions.
- Do not upload confidential emails to public environments unless your organization allows it.
- Do not paste sensitive email content into public AI tools.
- VirusTotal lookups may disclose queried IOCs to VirusTotal according to its service terms and API behavior.
- Public GitHub Pages deployments are visible on the internet.

## Reporting issues

Open an issue with:

- reproduction steps;
- browser and operating system;
- whether the issue affects parsing, scoring, VirusTotal enrichment or export.
