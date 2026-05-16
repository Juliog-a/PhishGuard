# VirusTotal Online Verification Setup

PhishGuard AI supports optional online verification through VirusTotal API v3.

Because GitHub Pages is static, the VirusTotal API key must not be stored in `app.js`. This project includes a Cloudflare Worker proxy in the `worker/` folder.

## What the Worker checks

The Worker supports these VirusTotal lookups:

| Indicator | VirusTotal object |
|---|---|
| Domain | `/api/v3/domains/{domain}` |
| IP address | `/api/v3/ip_addresses/{ip}` |
| URL | `/api/v3/urls/{url_id}` |
| File SHA-256 | `/api/v3/files/{hash}` |

URL lookups use existing VirusTotal reports. This template does not submit URLs for active scanning by default.

## 1. Get a VirusTotal API key

Create a VirusTotal account and copy your API key from your user settings.

## 2. Deploy the Worker

From the project root:

```bash
cd worker
npm install
npx wrangler login
npx wrangler secret put VT_API_KEY
npm run deploy
```

Wrangler will return a URL similar to:

```text
https://phishguard-vt-worker.YOUR_SUBDOMAIN.workers.dev
```

## 3. Connect the frontend

Open PhishGuard AI in the browser.

1. Expand **Online reputation verification**.
2. Paste the Worker URL.
3. Click **Save endpoint**.
4. Load or paste an email.
5. Click **Verify IOCs online**.

## 4. Optional local Worker testing

Create a local `.dev.vars` file:

```bash
cp .dev.vars.example .dev.vars
```

Edit `.dev.vars`:

```text
VT_API_KEY=your_key_here
ALLOWED_ORIGIN=*
```

Run:

```bash
npm run dev
```

Then use the local Worker URL in the app.

## 5. Security notes

- Do not commit `.dev.vars`.
- Do not paste the VirusTotal API key into the frontend.
- Do not upload confidential email evidence to public repositories.
- Hash lookup is safer than sample upload, but queried hashes are still shared with VirusTotal.
