const VT_BASE = 'https://www.virustotal.com/api/v3';
const MAX_PER_TYPE = 8;

export default {
  async fetch(request, env) {
    const cors = corsHeaders(env);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return json({ ok: true, service: 'phishguard-vt-worker' }, cors);
    }

    if (url.pathname !== '/lookup' || request.method !== 'POST') {
      return json({ ok: false, error: 'Use POST /lookup' }, cors, 404);
    }

    if (!env.VT_API_KEY) {
      return json({ ok: false, error: 'Missing VT_API_KEY secret in Worker environment' }, cors, 500);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, error: 'Invalid JSON body' }, cors, 400);
    }

    const indicators = sanitizeIndicators(body.indicators || {});
    const results = [];

    for (const domain of indicators.domains) {
      results.push(await lookupDomain(domain, env));
    }
    for (const ip of indicators.ips) {
      results.push(await lookupIp(ip, env));
    }
    for (const urlValue of indicators.urls) {
      results.push(await lookupUrl(urlValue, env));
    }
    for (const file of indicators.fileHashes) {
      results.push(await lookupFileHash(file, env));
    }

    return json({
      ok: true,
      source: 'VirusTotal API v3',
      generatedAt: new Date().toISOString(),
      counts: {
        domains: indicators.domains.length,
        ips: indicators.ips.length,
        urls: indicators.urls.length,
        fileHashes: indicators.fileHashes.length,
      },
      results,
      note: 'URL lookups use existing VirusTotal reports. This Worker does not upload email bodies or attachment contents.',
    }, cors);
  },
};

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, cors, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      ...cors,
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

function sanitizeIndicators(raw) {
  return {
    domains: unique(raw.domains).map(cleanDomain).filter(Boolean).slice(0, MAX_PER_TYPE),
    ips: unique(raw.ips).filter(isIp).slice(0, MAX_PER_TYPE),
    urls: unique(raw.urls).filter((value) => /^https?:\/\//i.test(value)).slice(0, MAX_PER_TYPE),
    fileHashes: normalizeHashes(raw.fileHashes).slice(0, MAX_PER_TYPE),
  };
}

function unique(values) {
  return [...new Set((Array.isArray(values) ? values : []).map((value) => String(value || '').trim()).filter(Boolean))];
}

function cleanDomain(domain) {
  const value = String(domain || '').toLowerCase().replace(/^www\./, '').replace(/[)>.,;]+$/g, '');
  if (!/^[a-z0-9.-]+\.[a-z0-9-]{2,}$/i.test(value)) return '';
  if (isIp(value)) return '';
  return value;
}

function isIp(value) {
  const parts = String(value || '').split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function normalizeHashes(items) {
  const normalized = [];
  for (const item of Array.isArray(items) ? items : []) {
    if (typeof item === 'string') {
      const sha256 = item.toLowerCase();
      if (/^[a-f0-9]{64}$/.test(sha256)) normalized.push({ sha256 });
    } else if (item && typeof item === 'object') {
      const sha256 = String(item.sha256 || '').toLowerCase();
      if (/^[a-f0-9]{64}$/.test(sha256)) {
        normalized.push({ sha256, filename: String(item.filename || ''), size: Number(item.size || 0) });
      }
    }
  }
  return normalized;
}

async function lookupDomain(domain, env) {
  const path = `/domains/${encodeURIComponent(domain)}`;
  return vtLookup({ type: 'domain', indicator: domain, path, guiUrl: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`, env });
}

async function lookupIp(ip, env) {
  const path = `/ip_addresses/${encodeURIComponent(ip)}`;
  return vtLookup({ type: 'ip', indicator: ip, path, guiUrl: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`, env });
}

async function lookupUrl(urlValue, env) {
  const id = base64Url(urlValue);
  const path = `/urls/${id}`;
  return vtLookup({ type: 'url', indicator: urlValue, path, guiUrl: `https://www.virustotal.com/gui/url/${id}`, env });
}

async function lookupFileHash(file, env) {
  const path = `/files/${encodeURIComponent(file.sha256)}`;
  const result = await vtLookup({ type: 'file', indicator: file.sha256, path, guiUrl: `https://www.virustotal.com/gui/file/${encodeURIComponent(file.sha256)}`, env });
  if (file.filename) result.filename = file.filename;
  if (file.size) result.size = file.size;
  return result;
}

async function vtLookup({ type, indicator, path, guiUrl, env }) {
  try {
    const response = await fetch(`${VT_BASE}${path}`, {
      headers: { 'x-apikey': env.VT_API_KEY, 'Accept': 'application/json' },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      return {
        type,
        indicator,
        found: false,
        verdict: response.status === 404 ? 'unknown' : 'error',
        stats: {},
        guiUrl,
        error: payload?.error?.message || `VirusTotal HTTP ${response.status}`,
      };
    }
    const stats = payload?.data?.attributes?.last_analysis_stats || {};
    return {
      type,
      indicator,
      found: true,
      verdict: verdictFromStats(stats),
      stats: normalizeStats(stats),
      reputation: payload?.data?.attributes?.reputation ?? null,
      lastAnalysisDate: payload?.data?.attributes?.last_analysis_date ?? null,
      guiUrl,
    };
  } catch (error) {
    return { type, indicator, found: false, verdict: 'error', stats: {}, guiUrl, error: error.message || 'Lookup failed' };
  }
}

function normalizeStats(stats) {
  return {
    malicious: Number(stats.malicious || 0),
    suspicious: Number(stats.suspicious || 0),
    harmless: Number(stats.harmless || 0),
    undetected: Number(stats.undetected || 0),
    timeout: Number(stats.timeout || 0),
  };
}

function verdictFromStats(stats) {
  if (Number(stats.malicious || 0) > 0) return 'malicious';
  if (Number(stats.suspicious || 0) > 0) return 'suspicious';
  if (Number(stats.harmless || 0) > 0) return 'clean';
  return 'unknown';
}

function base64Url(value) {
  return btoa(unescape(encodeURIComponent(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
