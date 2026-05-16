'use strict';

const RISK_WEIGHTS = {
  authFail: 18,
  dmarcFail: 22,
  dkimFail: 12,
  spfFail: 12,
  replyToMismatch: 14,
  suspiciousAttachmentCritical: 24,
  suspiciousAttachmentHigh: 16,
  suspiciousAttachmentMedium: 9,
  credentialLanguage: 14,
  urgencyLanguage: 10,
  paymentLanguage: 8,
  impersonationLanguage: 12,
  suspiciousUrlHigh: 18,
  suspiciousUrlMedium: 10,
  suspiciousUrlLow: 5,
  noUrlNoAttachmentReduction: -6,
};

const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'work', 'support', 'quest', 'country', 'kim', 'gq', 'tk', 'ml', 'cf']);
const SHORTENERS = new Set(['bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly', 's.id', 'lnkd.in']);
const CRITICAL_EXT = new Set(['exe', 'scr', 'js', 'jse', 'vbs', 'vbe', 'bat', 'cmd', 'ps1', 'hta', 'lnk', 'msi', 'dll', 'com']);
const HIGH_EXT = new Set(['iso', 'img', 'jar', 'chm', 'reg', 'wsf', 'wsh', 'xll']);
const MEDIUM_EXT = new Set(['html', 'htm', 'shtml', 'docm', 'xlsm', 'pptm', 'zip', 'rar', '7z', 'gz']);

const state = {
  extracted: {},
  lastResult: null,
};

const els = {
  file: document.getElementById('emlFile'),
  dropzone: document.getElementById('dropzone'),
  subject: document.getElementById('subject'),
  from: document.getElementById('from'),
  replyTo: document.getElementById('replyTo'),
  attachments: document.getElementById('attachments'),
  body: document.getElementById('body'),
  rawHeaders: document.getElementById('rawHeaders'),
  analyzeBtn: document.getElementById('analyzeBtn'),
  clearBtn: document.getElementById('clearBtn'),
  loadSampleBtn: document.getElementById('loadSampleBtn'),
  emptyState: document.getElementById('emptyState'),
  results: document.getElementById('results'),
  statusPill: document.getElementById('statusPill'),
  scoreCard: document.getElementById('scoreCard'),
  scoreValue: document.getElementById('scoreValue'),
  scoreClass: document.getElementById('scoreClass'),
  summaryText: document.getElementById('summaryText'),
  evidenceList: document.getElementById('evidenceList'),
  indicatorTables: document.getElementById('indicatorTables'),
  actionList: document.getElementById('actionList'),
  mitreList: document.getElementById('mitreList'),
  aiPrompt: document.getElementById('aiPrompt'),
  copyPromptBtn: document.getElementById('copyPromptBtn'),
  downloadJsonBtn: document.getElementById('downloadJsonBtn'),
  downloadMdBtn: document.getElementById('downloadMdBtn'),
};

function init() {
  els.file.addEventListener('change', handleFileSelection);
  els.analyzeBtn.addEventListener('click', runAnalysis);
  els.clearBtn.addEventListener('click', clearAll);
  els.loadSampleBtn.addEventListener('click', loadSample);
  els.copyPromptBtn.addEventListener('click', copyAiPrompt);
  els.downloadJsonBtn.addEventListener('click', downloadJson);
  els.downloadMdBtn.addEventListener('click', downloadMarkdown);
  document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', switchTab));
  setupDragAndDrop();
}

function setupDragAndDrop() {
  ['dragenter', 'dragover'].forEach((eventName) => {
    els.dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      els.dropzone.classList.add('dragover');
    });
  });
  ['dragleave', 'drop'].forEach((eventName) => {
    els.dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      els.dropzone.classList.remove('dragover');
    });
  });
  els.dropzone.addEventListener('drop', (event) => {
    const file = event.dataTransfer.files?.[0];
    if (file) readEmlFile(file);
  });
}

function handleFileSelection(event) {
  const file = event.target.files?.[0];
  if (file) readEmlFile(file);
}

function readEmlFile(file) {
  const reader = new FileReader();
  reader.onload = () => {
    const raw = String(reader.result || '');
    state.extracted = parseEml(raw);
    hydrateFields(state.extracted);
    els.statusPill.textContent = `Loaded: ${file.name}`;
  };
  reader.onerror = () => alert('Could not read the file. Try another .eml file or paste the email manually.');
  reader.readAsText(file);
}

function parseEml(raw) {
  const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const splitIndex = normalized.search(/\n\s*\n/);
  const headerText = splitIndex >= 0 ? normalized.slice(0, splitIndex) : '';
  const bodyText = splitIndex >= 0 ? normalized.slice(splitIndex).trim() : normalized;
  const unfolded = headerText.replace(/\n[\t ]+/g, ' ');
  const headers = {};
  unfolded.split('\n').forEach((line) => {
    const idx = line.indexOf(':');
    if (idx > 0) {
      const key = line.slice(0, idx).trim();
      const value = line.slice(idx + 1).trim();
      const lower = key.toLowerCase();
      headers[lower] = headers[lower] ? `${headers[lower]}\n${value}` : value;
    }
  });

  const filenames = extractAttachmentNames(normalized);
  const cleanBody = simplifyMimeBody(bodyText);

  return {
    subject: decodeMimeWords(headers.subject || ''),
    from: decodeMimeWords(headers.from || ''),
    replyTo: decodeMimeWords(headers['reply-to'] || ''),
    attachments: filenames,
    body: cleanBody,
    rawHeaders: headerText,
    headers,
    raw,
  };
}

function decodeMimeWords(value) {
  return value.replace(/=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g, (_, charset, encoding, encoded) => {
    try {
      if (encoding.toUpperCase() === 'B') {
        const binary = atob(encoded.replace(/\s/g, ''));
        const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
        return new TextDecoder(charset || 'utf-8').decode(bytes);
      }
      const qp = encoded.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      const bytes = Uint8Array.from(qp, (char) => char.charCodeAt(0));
      return new TextDecoder(charset || 'utf-8').decode(bytes);
    } catch {
      return encoded;
    }
  });
}

function extractAttachmentNames(raw) {
  const names = new Set();
  const patterns = [
    /filename\*?=(?:UTF-8''|"?)([^";\n]+)/gi,
    /name\*?=(?:UTF-8''|"?)([^";\n]+)/gi,
  ];
  patterns.forEach((pattern) => {
    let match;
    while ((match = pattern.exec(raw)) !== null) {
      const decoded = decodeURIComponentSafe(match[1].replace(/^"|"$/g, '').trim());
      if (decoded && looksLikeFilename(decoded)) names.add(decoded);
    }
  });
  return [...names];
}

function decodeURIComponentSafe(value) {
  try { return decodeURIComponent(value); } catch { return value; }
}

function looksLikeFilename(value) {
  return /\.[a-z0-9]{2,5}$/i.test(value) && value.length < 180;
}

function simplifyMimeBody(bodyText) {
  const withoutBoundaryLines = bodyText
    .split('\n')
    .filter((line) => !/^--[A-Za-z0-9'_()+_,.\/:=?-]+(--)?\s*$/.test(line.trim()))
    .join('\n');
  const withoutPartHeaders = withoutBoundaryLines.replace(/(?:^|\n)(Content-Type|Content-Transfer-Encoding|Content-Disposition):[^\n]*(\n\s+[^\n]*)*/gi, '');
  return stripHtml(withoutPartHeaders).replace(/\n{3,}/g, '\n\n').trim();
}

function stripHtml(input) {
  return input
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&#39;/g, "'")
    .replace(/&quot;/gi, '"')
    .replace(/[ \t]{2,}/g, ' ');
}

function hydrateFields(data) {
  if (data.subject) els.subject.value = data.subject;
  if (data.from) els.from.value = data.from;
  if (data.replyTo) els.replyTo.value = data.replyTo;
  if (data.attachments?.length) els.attachments.value = data.attachments.join(', ');
  if (data.body) els.body.value = data.body;
  if (data.rawHeaders) els.rawHeaders.value = data.rawHeaders;
}

function collectInput() {
  return {
    subject: els.subject.value.trim(),
    from: els.from.value.trim(),
    replyTo: els.replyTo.value.trim(),
    attachments: splitAttachments(els.attachments.value),
    body: els.body.value.trim(),
    rawHeaders: els.rawHeaders.value.trim(),
  };
}

function splitAttachments(value) {
  return value
    .split(/[,;\n]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function runAnalysis() {
  const input = collectInput();
  const result = analyzeEmail(input);
  state.lastResult = result;
  renderResult(result);
}

function analyzeEmail(input) {
  const combinedText = `${input.subject}\n${input.from}\n${input.replyTo}\n${input.body}\n${input.rawHeaders}`;
  const lower = combinedText.toLowerCase();
  const urls = analyzeUrls(extractUrls(combinedText));
  const attachments = analyzeAttachments(input.attachments);
  const domains = extractEmailDomains(input.from, input.replyTo);
  const evidence = [];
  let score = 0;

  const auth = parseAuthentication(input.rawHeaders);
  if (auth.dmarc === 'fail') addEvidence('critical', RISK_WEIGHTS.dmarcFail, 'DMARC authentication failed in message headers.', evidence);
  if (auth.spf === 'fail') addEvidence('high', RISK_WEIGHTS.spfFail, 'SPF authentication failed in message headers.', evidence);
  if (auth.dkim === 'fail' || auth.dkim === 'none') addEvidence('medium', RISK_WEIGHTS.dkimFail, 'DKIM is missing or failed in message headers.', evidence);
  if (auth.anyFail) addEvidence('high', RISK_WEIGHTS.authFail, 'At least one sender-authentication control failed.', evidence);

  if (domains.fromDomain && domains.replyToDomain && domains.fromDomain !== domains.replyToDomain) {
    addEvidence('high', RISK_WEIGHTS.replyToMismatch, `Reply-To domain (${domains.replyToDomain}) differs from From domain (${domains.fromDomain}).`, evidence);
  }

  const textSignals = analyzeTextSignals(lower);
  textSignals.forEach((signal) => addEvidence(signal.severity, signal.weight, signal.message, evidence));

  urls.forEach((url) => {
    url.findings.forEach((finding) => addEvidence(finding.severity, finding.weight, `${finding.message}: ${url.url}`, evidence));
  });

  attachments.forEach((attachment) => {
    attachment.findings.forEach((finding) => addEvidence(finding.severity, finding.weight, `${finding.message}: ${attachment.name}`, evidence));
  });

  if (!urls.length && !attachments.length && evidence.length) {
    addEvidence('low', RISK_WEIGHTS.noUrlNoAttachmentReduction, 'No URLs or attachments were extracted, reducing immediate exploitation likelihood.', evidence);
  }

  score = clamp(evidence.reduce((sum, item) => sum + item.weight, 0), 0, 100);
  const classification = classifyScore(score);
  const mitre = mapMitre({ urls, attachments, textSignals, auth, domains, score });
  const actions = buildActions(classification, { urls, attachments, auth, domains });
  const summary = buildSummary(input, score, classification, evidence, urls, attachments);
  const prompt = buildAiPrompt(input, { score, classification, evidence, urls, attachments, mitre, actions, summary });

  return {
    generatedAt: new Date().toISOString(),
    inputSummary: {
      subject: input.subject,
      from: input.from,
      replyTo: input.replyTo,
      attachmentCount: input.attachments.length,
    },
    score,
    classification,
    summary,
    evidence: evidence.sort((a, b) => b.weight - a.weight),
    indicators: { urls, attachments, domains, authentication: auth },
    mitre,
    actions,
    aiPrompt: prompt,
  };
}

function addEvidence(severity, weight, message, evidence) {
  evidence.push({ severity, weight, message });
}

function clamp(value, min, max) { return Math.max(min, Math.min(max, value)); }

function parseAuthentication(headers) {
  const lower = headers.toLowerCase();
  const get = (name) => {
    const match = lower.match(new RegExp(`${name}=(pass|fail|softfail|neutral|none|temperror|permerror)`, 'i'));
    return match ? match[1].toLowerCase() : 'unknown';
  };
  const spf = get('spf');
  const dkim = get('dkim');
  const dmarc = get('dmarc');
  return {
    spf,
    dkim,
    dmarc,
    anyFail: [spf, dkim, dmarc].some((value) => ['fail', 'softfail', 'permerror'].includes(value)),
  };
}

function extractEmailDomains(from, replyTo) {
  return {
    fromDomain: extractDomainFromEmail(from),
    replyToDomain: extractDomainFromEmail(replyTo),
  };
}

function extractDomainFromEmail(value) {
  const match = value.match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/i);
  return match ? normalizeDomain(match[1]) : '';
}

function normalizeDomain(domain) {
  return domain.toLowerCase().replace(/^www\./, '').replace(/[)>.,;]+$/g, '');
}

function analyzeTextSignals(lower) {
  const signals = [];
  const credentialTerms = ['password', 'contraseña', 'login', 'verify your account', 'verifica tu cuenta', 'account locked', 'cuenta bloqueada', 'sign in', 'iniciar sesión', 'mfa', '2fa', 'credential', 'credenciales'];
  const urgencyTerms = ['urgent', 'urgente', 'immediately', 'inmediatamente', 'within 24 hours', '24 horas', 'final notice', 'último aviso', 'action required', 'acción requerida'];
  const paymentTerms = ['invoice', 'factura', 'payment', 'pago', 'bank', 'transfer', 'wire', 'iban', 'refund', 'reembolso'];
  const impersonationTerms = ['microsoft', 'office 365', 'paypal', 'dhl', 'ups', 'amazon', 'google', 'apple', 'it support', 'soporte técnico', 'security team'];

  if (containsAny(lower, credentialTerms)) {
    signals.push({ severity: 'high', weight: RISK_WEIGHTS.credentialLanguage, message: 'Credential-harvesting or account-verification language detected.' });
  }
  if (containsAny(lower, urgencyTerms)) {
    signals.push({ severity: 'medium', weight: RISK_WEIGHTS.urgencyLanguage, message: 'Urgency or pressure language detected.' });
  }
  if (containsAny(lower, paymentTerms)) {
    signals.push({ severity: 'medium', weight: RISK_WEIGHTS.paymentLanguage, message: 'Payment, invoice or financial language detected.' });
  }
  if (containsAny(lower, impersonationTerms)) {
    signals.push({ severity: 'medium', weight: RISK_WEIGHTS.impersonationLanguage, message: 'Brand, IT support or service impersonation language detected.' });
  }
  return signals;
}

function containsAny(text, terms) { return terms.some((term) => text.includes(term)); }

function extractUrls(text) {
  const matches = text.match(/\b(?:https?:\/\/|www\.)[^\s<>'")]+/gi) || [];
  return [...new Set(matches.map((url) => url.replace(/[.,;:!?]+$/g, '')))].slice(0, 50);
}

function analyzeUrls(urls) {
  return urls.map((rawUrl) => {
    const findings = [];
    const parsed = parseUrl(rawUrl);
    const domain = parsed?.hostname ? normalizeDomain(parsed.hostname) : '';
    const tld = domain.split('.').pop() || '';
    const labels = domain.split('.').filter(Boolean);

    if (!parsed) findings.push({ severity: 'medium', weight: RISK_WEIGHTS.suspiciousUrlMedium, message: 'Malformed or unusual URL structure' });
    if (domain && /^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) findings.push({ severity: 'high', weight: RISK_WEIGHTS.suspiciousUrlHigh, message: 'IP-based URL detected' });
    if (domain.includes('xn--')) findings.push({ severity: 'high', weight: RISK_WEIGHTS.suspiciousUrlHigh, message: 'Punycode domain detected, possible homograph attack' });
    if (domain && SHORTENERS.has(domain)) findings.push({ severity: 'medium', weight: RISK_WEIGHTS.suspiciousUrlMedium, message: 'URL shortener detected' });
    if (SUSPICIOUS_TLDS.has(tld)) findings.push({ severity: 'medium', weight: RISK_WEIGHTS.suspiciousUrlMedium, message: `Suspicious or frequently abused TLD .${tld} detected` });
    if (labels.length >= 5) findings.push({ severity: 'low', weight: RISK_WEIGHTS.suspiciousUrlLow, message: 'Excessive subdomain depth detected' });
    if (rawUrl.includes('@')) findings.push({ severity: 'medium', weight: RISK_WEIGHTS.suspiciousUrlMedium, message: 'URL contains @ symbol, which can obscure the real host' });

    return { url: rawUrl, domain, findings };
  });
}

function parseUrl(rawUrl) {
  try {
    const normalized = rawUrl.startsWith('www.') ? `https://${rawUrl}` : rawUrl;
    return new URL(normalized);
  } catch {
    return null;
  }
}

function analyzeAttachments(attachments) {
  return attachments.map((name) => {
    const ext = (name.split('.').pop() || '').toLowerCase();
    const findings = [];
    if (CRITICAL_EXT.has(ext)) findings.push({ severity: 'critical', weight: RISK_WEIGHTS.suspiciousAttachmentCritical, message: `Executable or script attachment (.${ext})` });
    else if (HIGH_EXT.has(ext)) findings.push({ severity: 'high', weight: RISK_WEIGHTS.suspiciousAttachmentHigh, message: `High-risk attachment type (.${ext})` });
    else if (MEDIUM_EXT.has(ext)) findings.push({ severity: 'medium', weight: RISK_WEIGHTS.suspiciousAttachmentMedium, message: `Potentially risky attachment type (.${ext})` });
    return { name, extension: ext || 'unknown', findings };
  });
}

function classifyScore(score) {
  if (score >= 80) return { label: 'Critical', tone: 'critical', recommendation: 'Treat as likely phishing until proven otherwise.' };
  if (score >= 60) return { label: 'High', tone: 'high', recommendation: 'Investigate urgently and consider containment if delivered internally.' };
  if (score >= 35) return { label: 'Medium', tone: 'medium', recommendation: 'Requires analyst review and indicator validation.' };
  return { label: 'Low', tone: 'low', recommendation: 'Low risk based on available evidence, but not guaranteed benign.' };
}

function mapMitre(context) {
  const mappings = [];
  if (context.urls.length || context.textSignals.some((s) => s.message.includes('Credential'))) {
    mappings.push({ id: 'T1566.002', name: 'Phishing: Spearphishing Link', rationale: 'Message contains links and/or credential-harvesting language.' });
    mappings.push({ id: 'T1110', name: 'Brute Force / Credential Access context', rationale: 'Credential theft may support later unauthorized access.' });
  }
  if (context.attachments.length) {
    mappings.push({ id: 'T1566.001', name: 'Phishing: Spearphishing Attachment', rationale: 'Message contains attachment-based delivery opportunity.' });
    if (context.attachments.some((a) => a.findings.length)) {
      mappings.push({ id: 'T1204.002', name: 'User Execution: Malicious File', rationale: 'Risky attachment types may require user execution.' });
    }
  }
  if (context.auth.anyFail || context.domains.replyToDomain) {
    mappings.push({ id: 'T1585/T1586', name: 'Establish Accounts / Compromise Accounts', rationale: 'Sender anomalies may indicate spoofing or abused infrastructure.' });
  }
  return dedupeBy(mappings, 'id');
}

function dedupeBy(items, key) {
  const seen = new Set();
  return items.filter((item) => {
    if (seen.has(item[key])) return false;
    seen.add(item[key]);
    return true;
  });
}

function buildActions(classification, context) {
  const actions = [
    'Preserve the original email with full headers for evidence handling.',
    'Validate sender domain, Reply-To domain, and authentication results using mail gateway logs.',
    'Check whether the same subject, sender, URLs or attachment hashes were delivered to other users.',
  ];
  if (context.urls.length) actions.push('Open URLs only in a controlled sandbox or URL analysis platform; do not browse from a production endpoint.');
  if (context.attachments.length) actions.push('Detonate attachments only in a sandbox and calculate hashes before broader hunting.');
  if (context.auth.anyFail) actions.push('Review SPF, DKIM and DMARC alignment failures and compare with legitimate sender infrastructure.');
  if (['High', 'Critical'].includes(classification.label)) actions.push('If delivered internally, consider quarantine, mailbox purge and user notification.');
  actions.push('Document final analyst verdict: benign, suspicious, confirmed phishing, or false positive.');
  return actions;
}

function buildSummary(input, score, classification, evidence, urls, attachments) {
  const top = evidence.slice(0, 3).map((item) => item.message).join(' ');
  const subject = input.subject ? `Subject "${input.subject}"` : 'The submitted message';
  const indicatorText = `${urls.length} URL(s) and ${attachments.length} attachment(s) extracted`;
  return `${subject} received a ${classification.label.toLowerCase()} phishing-risk rating (${score}/100). ${indicatorText}. Main drivers: ${top || 'no strong phishing indicators were found in the supplied data.'} ${classification.recommendation}`;
}

function buildAiPrompt(input, result) {
  const evidenceLines = result.evidence.map((item) => `- [${item.severity.toUpperCase()}] ${item.message}`).join('\n') || '- No major evidence detected.';
  const urls = result.indicators?.urls?.map((item) => `- ${item.url} | domain=${item.domain || 'unknown'} | findings=${item.findings.map((f) => f.message).join('; ') || 'none'}`).join('\n') || '- None';
  const attachments = result.indicators?.attachments?.map((item) => `- ${item.name} | ext=${item.extension} | findings=${item.findings.map((f) => f.message).join('; ') || 'none'}`).join('\n') || '- None';
  return `Act as a SOC Tier 2 phishing analyst. Review the email evidence below and produce a concise triage report. Do not invent indicators. Clearly separate observed facts from hypotheses.\n\nSubject: ${input.subject || 'N/A'}\nFrom: ${input.from || 'N/A'}\nReply-To: ${input.replyTo || 'N/A'}\n\nRisk score from local analyzer: ${result.score}/100 (${result.classification.label})\n\nObserved evidence:\n${evidenceLines}\n\nExtracted URLs:\n${urls}\n\nExtracted attachments:\n${attachments}\n\nEmail body excerpt:\n${truncate(input.body || 'N/A', 1800)}\n\nReturn:\n1. Executive summary\n2. Verdict: benign / suspicious / confirmed phishing / insufficient evidence\n3. MITRE ATT&CK mapping\n4. Recommended investigation steps\n5. User-friendly explanation in non-technical language`;
}

function truncate(value, length) {
  return value.length > length ? `${value.slice(0, length)}... [truncated]` : value;
}

function renderResult(result) {
  els.emptyState.classList.add('hidden');
  els.results.classList.remove('hidden');
  els.statusPill.textContent = `${result.classification.label} risk`;
  els.statusPill.style.color = getToneColor(result.classification.tone);

  els.scoreValue.textContent = result.score;
  els.scoreClass.textContent = result.classification.label;
  els.scoreClass.style.color = getToneColor(result.classification.tone);
  els.summaryText.textContent = result.summary;

  els.evidenceList.innerHTML = result.evidence.length
    ? result.evidence.map((item) => `<li><span class="severity-tag tag-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>${escapeHtml(item.message)} <strong>(+${item.weight})</strong></li>`).join('')
    : '<li>No strong phishing indicators detected from the supplied data.</li>';

  els.indicatorTables.innerHTML = buildIndicatorHtml(result.indicators);
  els.actionList.innerHTML = result.actions.map((action) => `<li>${escapeHtml(action)}</li>`).join('');
  els.mitreList.innerHTML = result.mitre.length
    ? result.mitre.map((item) => `<div class="mitre-item"><strong>${escapeHtml(item.id)} — ${escapeHtml(item.name)}</strong><br>${escapeHtml(item.rationale)}</div>`).join('')
    : '<p class="muted">No MITRE mapping generated from current evidence.</p>';
  els.aiPrompt.value = result.aiPrompt;
}

function getToneColor(tone) {
  return {
    low: 'var(--low)',
    medium: 'var(--medium)',
    high: 'var(--high)',
    critical: 'var(--critical)',
  }[tone] || 'var(--muted)';
}

function buildIndicatorHtml(indicators) {
  const urlRows = indicators.urls.length
    ? indicators.urls.map((item) => `<tr><td>${escapeHtml(item.url)}</td><td>${escapeHtml(item.domain || 'unknown')}</td><td>${escapeHtml(item.findings.map((f) => f.message).join('; ') || 'No specific URL risk signal')}</td></tr>`).join('')
    : '<tr><td colspan="3">No URLs extracted.</td></tr>';
  const attachmentRows = indicators.attachments.length
    ? indicators.attachments.map((item) => `<tr><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.extension)}</td><td>${escapeHtml(item.findings.map((f) => f.message).join('; ') || 'No specific attachment risk signal')}</td></tr>`).join('')
    : '<tr><td colspan="3">No attachments extracted.</td></tr>';
  return `
    <h4>URLs</h4>
    <div class="table-wrap"><table><thead><tr><th>URL</th><th>Domain</th><th>Findings</th></tr></thead><tbody>${urlRows}</tbody></table></div>
    <h4>Attachments</h4>
    <div class="table-wrap"><table><thead><tr><th>Name</th><th>Extension</th><th>Findings</th></tr></thead><tbody>${attachmentRows}</tbody></table></div>
    <h4>Authentication</h4>
    <div class="table-wrap"><table><thead><tr><th>SPF</th><th>DKIM</th><th>DMARC</th><th>Any fail</th></tr></thead><tbody><tr><td>${escapeHtml(indicators.authentication.spf)}</td><td>${escapeHtml(indicators.authentication.dkim)}</td><td>${escapeHtml(indicators.authentication.dmarc)}</td><td>${indicators.authentication.anyFail ? 'Yes' : 'No'}</td></tr></tbody></table></div>
  `;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
}

function switchTab(event) {
  const target = event.currentTarget.dataset.tab;
  document.querySelectorAll('.tab').forEach((tab) => tab.classList.toggle('active', tab.dataset.tab === target));
  document.querySelectorAll('.tab-panel').forEach((panel) => panel.classList.add('hidden'));
  document.getElementById(`tab-${target}`).classList.remove('hidden');
}

function copyAiPrompt() {
  els.aiPrompt.select();
  navigator.clipboard?.writeText(els.aiPrompt.value).then(() => {
    els.copyPromptBtn.textContent = 'Copied';
    setTimeout(() => { els.copyPromptBtn.textContent = 'Copy prompt'; }, 1400);
  }).catch(() => document.execCommand('copy'));
}

function downloadJson() {
  if (!state.lastResult) return;
  downloadFile('phishing-analysis.json', JSON.stringify(state.lastResult, null, 2), 'application/json');
}

function downloadMarkdown() {
  if (!state.lastResult) return;
  downloadFile('phishing-analysis.md', resultToMarkdown(state.lastResult), 'text/markdown');
}

function resultToMarkdown(result) {
  const evidence = result.evidence.map((item) => `- **${item.severity.toUpperCase()}**: ${item.message} (+${item.weight})`).join('\n') || '- No strong evidence.';
  const urls = result.indicators.urls.map((item) => `- ${item.url} — ${item.findings.map((f) => f.message).join('; ') || 'No specific finding'}`).join('\n') || '- None';
  const attachments = result.indicators.attachments.map((item) => `- ${item.name} — ${item.findings.map((f) => f.message).join('; ') || 'No specific finding'}`).join('\n') || '- None';
  const mitre = result.mitre.map((item) => `- **${item.id} ${item.name}**: ${item.rationale}`).join('\n') || '- None';
  const actions = result.actions.map((action, index) => `${index + 1}. ${action}`).join('\n');
  return `# Phishing Email Analysis\n\nGenerated: ${result.generatedAt}\n\n## Verdict\n\nScore: **${result.score}/100**\n\nClassification: **${result.classification.label}**\n\n${result.summary}\n\n## Evidence\n\n${evidence}\n\n## URLs\n\n${urls}\n\n## Attachments\n\n${attachments}\n\n## MITRE ATT&CK\n\n${mitre}\n\n## Recommended Actions\n\n${actions}\n`;
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function clearAll() {
  [els.subject, els.from, els.replyTo, els.attachments, els.body, els.rawHeaders].forEach((el) => { el.value = ''; });
  els.file.value = '';
  state.extracted = {};
  state.lastResult = null;
  els.results.classList.add('hidden');
  els.emptyState.classList.remove('hidden');
  els.statusPill.textContent = 'Waiting for input';
  els.statusPill.style.color = 'var(--muted)';
}

function loadSample() {
  els.subject.value = 'Urgent: verify your Microsoft 365 account within 24 hours';
  els.from.value = 'Microsoft Security <security@microsoft-alerts-support.com>';
  els.replyTo.value = 'helpdesk@account-review-center.top';
  els.attachments.value = 'Account_Verification.html, MFA_Instructions.zip';
  els.body.value = 'Your Office 365 account has been locked due to unusual activity. Verify your account immediately within 24 hours to avoid permanent suspension. Sign in here: https://login.microsoft-security.account-review-center.top/session?id=9321 or use https://bit.ly/verify-m365-now';
  els.rawHeaders.value = 'Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=microsoft-alerts-support.com; dkim=none; dmarc=fail header.from=microsoft-alerts-support.com';
  runAnalysis();
  document.getElementById('analyzer').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

init();
