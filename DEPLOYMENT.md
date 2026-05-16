# Deployment Guide

## Frontend: GitHub Pages

1. Unzip the project.
2. Create a GitHub repository, for example `phishguard-ai`.
3. Upload the project files to the repository root.
4. Go to `Settings` → `Pages`.
5. Under `Build and deployment`, select `Deploy from a branch`.
6. Select:
   - Branch: `main`
   - Folder: `/root`
7. Save.
8. Open the published URL when GitHub finishes the deployment.

Expected URL:

```text
https://YOUR_USERNAME.github.io/phishguard-ai/
```

## Backend proxy: Cloudflare Worker

The frontend works without the Worker. The Worker is only needed for online reputation verification.

1. Create a free Cloudflare account.
2. Install dependencies:

```bash
cd worker
npm install
```

3. Login:

```bash
npx wrangler login
```

4. Add your VirusTotal API key as a secret:

```bash
npx wrangler secret put VT_API_KEY
```

5. Deploy:

```bash
npm run deploy
```

6. Copy the Worker URL, for example:

```text
https://phishguard-vt-worker.YOUR_SUBDOMAIN.workers.dev
```

7. Paste it into the PhishGuard AI interface under **Online reputation verification** and click **Save endpoint**.

## CORS restriction

By default, the Worker template uses `ALLOWED_ORIGIN = *` unless configured.

For a cleaner deployment, restrict it to your GitHub Pages origin in `worker/wrangler.toml`:

```toml
[vars]
ALLOWED_ORIGIN = "https://YOUR_USERNAME.github.io"
```

Then redeploy:

```bash
npm run deploy
```

## Privacy note

The local analyzer does not send full email content to any backend. Online verification sends extracted IOCs and optional SHA-256 hashes to your Worker, which queries VirusTotal.

Do not commit real emails, customer data or malware samples into the repository.
