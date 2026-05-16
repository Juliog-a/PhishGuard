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

const UI_TEXT = {
  en: {
    'nav.analyzer': 'Analyzer',
    'nav.features': 'Features',
    'hero.eyebrow': 'Email threat analyzer',
    'hero.title': 'Detect suspicious signals in emails before opening links or attachments.',
    'hero.copy': 'Upload an .eml file or paste email details manually. The analyzer extracts IOCs, checks sender-authentication evidence, scores phishing risk and generates a structured report.',
    'hero.start': 'Start analysis',
    'hero.sample': 'Load sample',
    'hero.noteStrong': 'Privacy note:',
    'hero.note': 'the analysis runs in your browser. Do not use real confidential emails in public demonstrations.',
    'metric.eml': 'email parsing',
    'metric.ioc': 'indicator extraction',
    'metric.score': 'risk score',
    'analyzer.eyebrow': 'Email analyzer',
    'analyzer.title': 'Input suspicious email evidence',
    'analyzer.copy': 'Use either an uploaded .eml file or manual fields. Manual data overrides extracted values when filled.',
    'input.title': 'Email input',
    'input.clear': 'Clear',
    'input.uploadStrong': 'Upload .eml',
    'input.uploadRest': 'or drag it here',
    'input.uploadSmall': 'Headers, body, URLs and attachment names are parsed locally.',
    'field.subject': 'Subject',
    'field.from': 'From',
    'field.attachments': 'Attachments',
    'field.body': 'Email body / visible text',
    'field.advanced': 'Advanced headers',
    'field.rawHeaders': 'Raw headers or Authentication-Results',
    'input.analyze': 'Analyze email',
    'result.title': 'Analysis result',
    'status.waiting': 'Waiting for input',
    'empty.text': 'Upload an email or paste details, then run the analysis.',
    'score.label': 'Risk score',
    'score.classification': 'Classification',
    'summary.title': 'Executive summary',
    'tab.evidence': 'Evidence',
    'tab.indicators': 'Indicators',
    'tab.actions': 'Actions',
    'tab.ai': 'AI prompt',
    'evidence.title': 'Risk evidence',
    'indicators.title': 'Extracted indicators',
    'actions.title': 'Recommended actions',
    'mitre.title': 'Likely MITRE ATT&CK mapping',
    'ai.title': 'AI enrichment prompt',
    'ai.copy': 'Copy this prompt into your preferred AI assistant for human-reviewed enrichment. Do not paste real confidential data into public tools.',
    'ai.copyButton': 'Copy prompt',
    'ai.copied': 'Copied',
    'export.json': 'Download JSON',
    'export.md': 'Download Markdown',
    'features.eyebrow': 'What it checks',
    'features.title': 'Suspicious signals and IOCs',
    'card.auth.title': 'Header authentication',
    'card.auth.copy': 'Flags SPF, DKIM and DMARC failures when present in the .eml headers.',
    'card.url.title': 'URL risk',
    'card.url.copy': 'Detects shorteners, IP-based URLs, punycode domains, suspicious TLDs and excessive subdomains.',
    'card.attach.title': 'Attachment risk',
    'card.attach.copy': 'Highlights executable, script, macro-enabled and HTML attachments commonly abused in phishing.',
    'card.social.title': 'Social engineering',
    'card.social.copy': 'Scores urgency, credential-harvesting language, payment pressure and impersonation patterns.',
    'footer.left': 'PhishGuard AI — phishing email risk analyzer.',
    'footer.right': 'Use this tool as decision support, not as the only source for response decisions.',
    'ph.subject': 'Urgent: verify your account',
    'ph.from': 'Security Team <security@example.com>',
    'ph.attachments': 'invoice.html, payment.zip, report.pdf',
    'ph.body': 'Paste the message body, URLs, instructions, signatures or any suspicious text here.',
    'ph.rawHeaders': 'Authentication-Results: spf=fail dkim=none dmarc=fail...',
    'status.loaded': 'Loaded: {name}',
    'status.risk': '{classification} risk',
    'error.file': 'Could not read the file. Try another .eml file or paste the email manually.',
    'sev.low': 'low',
    'sev.medium': 'medium',
    'sev.high': 'high',
    'sev.critical': 'critical',
    'class.low': 'Low',
    'class.medium': 'Medium',
    'class.high': 'High',
    'class.critical': 'Critical',
    'rec.low': 'Low risk based on available evidence, but not guaranteed benign.',
    'rec.medium': 'Requires analyst review and indicator validation.',
    'rec.high': 'Investigate urgently and consider containment if delivered internally.',
    'rec.critical': 'Treat as likely phishing until proven otherwise.',
    'ev.dmarcFail': 'DMARC authentication failed in message headers.',
    'ev.spfFail': 'SPF authentication failed in message headers.',
    'ev.dkimFail': 'DKIM is missing or failed in message headers.',
    'ev.authAnyFail': 'At least one sender-authentication control failed.',
    'ev.replyMismatch': 'Reply-To domain ({reply}) differs from From domain ({from}).',
    'ev.credential': 'Credential-harvesting or account-verification language detected.',
    'ev.urgency': 'Urgency or pressure language detected.',
    'ev.payment': 'Payment, invoice or financial language detected.',
    'ev.impersonation': 'Brand, IT support or service impersonation language detected.',
    'ev.noUrlAttachmentReduction': 'No URLs or attachments were extracted, reducing immediate exploitation likelihood.',
    'url.malformed': 'Malformed or unusual URL structure',
    'url.ip': 'IP-based URL detected',
    'url.punycode': 'Punycode domain detected, possible homograph attack',
    'url.shortener': 'URL shortener detected',
    'url.tld': 'Suspicious or frequently abused TLD .{tld} detected',
    'url.subdomains': 'Excessive subdomain depth detected',
    'url.at': 'URL contains @ symbol, which can obscure the real host',
    'att.critical': 'Executable or script attachment (.{ext})',
    'att.high': 'High-risk attachment type (.{ext})',
    'att.medium': 'Potentially risky attachment type (.{ext})',
    'summary.subject': 'Subject "{subject}"',
    'summary.noSubject': 'The submitted message',
    'summary.indicators': '{urls} URL(s) and {attachments} attachment(s) extracted',
    'summary.noDrivers': 'no strong phishing indicators were found in the supplied data.',
    'summary.full': '{subject} received a {classification} phishing-risk rating ({score}/100). {indicators}. Main drivers: {drivers} {recommendation}',
    'mitre.link.rationale': 'Message contains links and/or credential-harvesting language.',
    'mitre.credential.rationale': 'Credential theft may support later unauthorized access.',
    'mitre.attachment.rationale': 'Message contains attachment-based delivery opportunity.',
    'mitre.execution.rationale': 'Risky attachment types may require user execution.',
    'mitre.sender.rationale': 'Sender anomalies may indicate spoofing or abused infrastructure.',
    'action.preserve': 'Preserve the original email with full headers for evidence handling.',
    'action.validate': 'Validate sender domain, Reply-To domain, and authentication results using mail gateway logs.',
    'action.hunt': 'Check whether the same subject, sender, URLs or attachment hashes were delivered to other users.',
    'action.urls': 'Open URLs only in a controlled sandbox or URL analysis platform; do not browse from a production endpoint.',
    'action.attachments': 'Detonate attachments only in a sandbox and calculate hashes before broader hunting.',
    'action.auth': 'Review SPF, DKIM and DMARC alignment failures and compare with legitimate sender infrastructure.',
    'action.containment': 'If delivered internally, consider quarantine, mailbox purge and user notification.',
    'action.verdict': 'Document final verdict: benign, suspicious, confirmed phishing, or false positive.',
    'empty.evidence': 'No strong phishing indicators detected from the supplied data.',
    'empty.mitre': 'No MITRE mapping generated from current evidence.',
    'table.urls': 'URLs',
    'table.attachments': 'Attachments',
    'table.authentication': 'Authentication',
    'table.url': 'URL',
    'table.domain': 'Domain',
    'table.findings': 'Findings',
    'table.name': 'Name',
    'table.extension': 'Extension',
    'table.anyFail': 'Any fail',
    'table.noUrls': 'No URLs extracted.',
    'table.noAttachments': 'No attachments extracted.',
    'table.noUrlFinding': 'No specific URL risk signal',
    'table.noAttachmentFinding': 'No specific attachment risk signal',
    'yes': 'Yes',
    'no': 'No',
    'none': 'None',
    'unknown': 'unknown',
    'md.title': 'Phishing Email Analysis',
    'md.generated': 'Generated',
    'md.verdict': 'Verdict',
    'md.score': 'Score',
    'md.classification': 'Classification',
    'md.evidence': 'Evidence',
    'md.attachments': 'Attachments',
    'md.actions': 'Recommended Actions',
    'prompt': 'Act as a phishing email analyst. Review the email evidence below and produce a concise triage report. Do not invent indicators. Clearly separate observed facts from hypotheses.\n\nSubject: {subject}\nFrom: {from}\nReply-To: {replyTo}\n\nRisk score from local analyzer: {score}/100 ({classification})\n\nObserved evidence:\n{evidence}\n\nExtracted URLs:\n{urls}\n\nExtracted attachments:\n{attachments}\n\nEmail body excerpt:\n{body}\n\nReturn:\n1. Executive summary\n2. Verdict: benign / suspicious / confirmed phishing / insufficient evidence\n3. MITRE ATT&CK mapping\n4. Recommended investigation steps\n5. User-friendly explanation in non-technical language',
  },
  es: {
    'nav.analyzer': 'Analizador',
    'nav.features': 'Funciones',
    'hero.eyebrow': 'Analizador de amenazas en email',
    'hero.title': 'Detecta señales sospechosas en correos antes de abrir enlaces o adjuntos.',
    'hero.copy': 'Sube un archivo .eml o pega los datos del correo manualmente. El analizador extrae IOCs, revisa evidencias de autenticación del remitente, calcula el riesgo de phishing y genera un informe estructurado.',
    'hero.start': 'Empezar análisis',
    'hero.sample': 'Cargar ejemplo',
    'hero.noteStrong': 'Nota de privacidad:',
    'hero.note': 'el análisis se ejecuta en tu navegador. No uses correos confidenciales reales en demostraciones públicas.',
    'metric.eml': 'lectura de email',
    'metric.ioc': 'extracción de indicadores',
    'metric.score': 'puntuación de riesgo',
    'analyzer.eyebrow': 'Analizador de email',
    'analyzer.title': 'Introduce la evidencia del correo sospechoso',
    'analyzer.copy': 'Puedes subir un .eml o rellenar los campos manualmente. Los datos manuales sustituyen a los extraídos cuando se completan.',
    'input.title': 'Entrada del correo',
    'input.clear': 'Limpiar',
    'input.uploadStrong': 'Sube un .eml',
    'input.uploadRest': 'o arrástralo aquí',
    'input.uploadSmall': 'Cabeceras, cuerpo, URLs y nombres de adjuntos se procesan localmente.',
    'field.subject': 'Asunto',
    'field.from': 'Remitente',
    'field.attachments': 'Adjuntos',
    'field.body': 'Cuerpo del correo / texto visible',
    'field.advanced': 'Cabeceras avanzadas',
    'field.rawHeaders': 'Cabeceras completas o Authentication-Results',
    'input.analyze': 'Analizar correo',
    'result.title': 'Resultado del análisis',
    'status.waiting': 'Esperando entrada',
    'empty.text': 'Sube un correo o pega los datos y ejecuta el análisis.',
    'score.label': 'Puntuación de riesgo',
    'score.classification': 'Clasificación',
    'summary.title': 'Resumen ejecutivo',
    'tab.evidence': 'Evidencias',
    'tab.indicators': 'Indicadores',
    'tab.actions': 'Acciones',
    'tab.ai': 'Prompt IA',
    'evidence.title': 'Evidencias de riesgo',
    'indicators.title': 'Indicadores extraídos',
    'actions.title': 'Acciones recomendadas',
    'mitre.title': 'Mapeo MITRE ATT&CK probable',
    'ai.title': 'Prompt de enriquecimiento con IA',
    'ai.copy': 'Copia este prompt en tu asistente de IA preferido para enriquecer el análisis con revisión humana. No pegues datos confidenciales reales en herramientas públicas.',
    'ai.copyButton': 'Copiar prompt',
    'ai.copied': 'Copiado',
    'export.json': 'Descargar JSON',
    'export.md': 'Descargar Markdown',
    'features.eyebrow': 'Qué comprueba',
    'features.title': 'Señales sospechosas e IOCs',
    'card.auth.title': 'Autenticación de cabeceras',
    'card.auth.copy': 'Marca fallos SPF, DKIM y DMARC cuando aparecen en las cabeceras del .eml.',
    'card.url.title': 'Riesgo en URLs',
    'card.url.copy': 'Detecta acortadores, URLs basadas en IP, dominios punycode, TLDs sospechosos y exceso de subdominios.',
    'card.attach.title': 'Riesgo en adjuntos',
    'card.attach.copy': 'Resalta adjuntos ejecutables, scripts, documentos con macros y HTML usados frecuentemente en phishing.',
    'card.social.title': 'Ingeniería social',
    'card.social.copy': 'Puntúa urgencia, robo de credenciales, presión de pago y patrones de suplantación.',
    'footer.left': 'PhishGuard AI — analizador de riesgo de phishing en email.',
    'footer.right': 'Usa esta herramienta como apoyo, no como única fuente para tomar decisiones de respuesta.',
    'ph.subject': 'Urgente: verifica tu cuenta',
    'ph.from': 'Equipo de Seguridad <security@example.com>',
    'ph.attachments': 'factura.html, pago.zip, informe.pdf',
    'ph.body': 'Pega aquí el cuerpo del mensaje, URLs, instrucciones, firmas o cualquier texto sospechoso.',
    'ph.rawHeaders': 'Authentication-Results: spf=fail dkim=none dmarc=fail...',
    'status.loaded': 'Cargado: {name}',
    'status.risk': 'Riesgo {classification}',
    'error.file': 'No se pudo leer el archivo. Prueba con otro .eml o pega el correo manualmente.',
    'sev.low': 'bajo',
    'sev.medium': 'medio',
    'sev.high': 'alto',
    'sev.critical': 'crítico',
    'class.low': 'Bajo',
    'class.medium': 'Medio',
    'class.high': 'Alto',
    'class.critical': 'Crítico',
    'rec.low': 'Riesgo bajo según la evidencia disponible, aunque no garantiza que el correo sea benigno.',
    'rec.medium': 'Requiere revisión manual y validación de indicadores.',
    'rec.high': 'Investigar con prioridad y considerar contención si se ha entregado internamente.',
    'rec.critical': 'Tratar como phishing probable hasta demostrar lo contrario.',
    'ev.dmarcFail': 'La autenticación DMARC falla en las cabeceras del mensaje.',
    'ev.spfFail': 'La autenticación SPF falla en las cabeceras del mensaje.',
    'ev.dkimFail': 'DKIM no está presente o falla en las cabeceras del mensaje.',
    'ev.authAnyFail': 'Al menos un control de autenticación del remitente ha fallado.',
    'ev.replyMismatch': 'El dominio Reply-To ({reply}) no coincide con el dominio From ({from}).',
    'ev.credential': 'Se detecta lenguaje orientado al robo o verificación de credenciales.',
    'ev.urgency': 'Se detecta lenguaje de urgencia o presión.',
    'ev.payment': 'Se detecta lenguaje financiero, de pago o factura.',
    'ev.impersonation': 'Se detecta posible suplantación de marca, soporte IT o servicio.',
    'ev.noUrlAttachmentReduction': 'No se han extraído URLs ni adjuntos, reduciendo la probabilidad de explotación inmediata.',
    'url.malformed': 'Estructura de URL malformada o inusual',
    'url.ip': 'URL basada en dirección IP detectada',
    'url.punycode': 'Dominio punycode detectado, posible ataque homográfico',
    'url.shortener': 'Acortador de URL detectado',
    'url.tld': 'TLD .{tld} sospechoso o usado frecuentemente en abuso',
    'url.subdomains': 'Profundidad excesiva de subdominios detectada',
    'url.at': 'La URL contiene el símbolo @, que puede ocultar el host real',
    'att.critical': 'Adjunto ejecutable o script (.{ext})',
    'att.high': 'Tipo de adjunto de alto riesgo (.{ext})',
    'att.medium': 'Tipo de adjunto potencialmente riesgoso (.{ext})',
    'summary.subject': 'El asunto "{subject}"',
    'summary.noSubject': 'El mensaje analizado',
    'summary.indicators': 'se han extraído {urls} URL(s) y {attachments} adjunto(s)',
    'summary.noDrivers': 'no se han encontrado indicadores fuertes de phishing en los datos aportados.',
    'summary.full': '{subject} recibe una clasificación de riesgo de phishing {classification} ({score}/100). {indicators}. Factores principales: {drivers} {recommendation}',
    'mitre.link.rationale': 'El mensaje contiene enlaces y/o lenguaje orientado al robo de credenciales.',
    'mitre.credential.rationale': 'El robo de credenciales puede facilitar accesos no autorizados posteriores.',
    'mitre.attachment.rationale': 'El mensaje incluye una posible vía de entrega mediante adjunto.',
    'mitre.execution.rationale': 'Los tipos de adjunto de riesgo pueden requerir ejecución por parte del usuario.',
    'mitre.sender.rationale': 'Las anomalías del remitente pueden indicar suplantación o infraestructura abusada.',
    'action.preserve': 'Conservar el correo original con cabeceras completas como evidencia.',
    'action.validate': 'Validar dominio del remitente, dominio Reply-To y resultados de autenticación en los logs de la pasarela de correo.',
    'action.hunt': 'Comprobar si el mismo asunto, remitente, URLs o hashes de adjuntos llegaron a otros usuarios.',
    'action.urls': 'Abrir URLs solo en sandbox o plataforma de análisis; no navegar desde un equipo de producción.',
    'action.attachments': 'Analizar adjuntos solo en sandbox y calcular hashes antes de ampliar la búsqueda.',
    'action.auth': 'Revisar fallos de alineación SPF, DKIM y DMARC y compararlos con la infraestructura legítima del remitente.',
    'action.containment': 'Si se entregó internamente, considerar cuarentena, purga de buzones y aviso a usuarios.',
    'action.verdict': 'Documentar el veredicto final: benigno, sospechoso, phishing confirmado o falso positivo.',
    'empty.evidence': 'No se han detectado indicadores fuertes de phishing con los datos aportados.',
    'empty.mitre': 'No se ha generado mapeo MITRE con la evidencia actual.',
    'table.urls': 'URLs',
    'table.attachments': 'Adjuntos',
    'table.authentication': 'Autenticación',
    'table.url': 'URL',
    'table.domain': 'Dominio',
    'table.findings': 'Hallazgos',
    'table.name': 'Nombre',
    'table.extension': 'Extensión',
    'table.anyFail': 'Algún fallo',
    'table.noUrls': 'No se han extraído URLs.',
    'table.noAttachments': 'No se han extraído adjuntos.',
    'table.noUrlFinding': 'Sin señal específica de riesgo en URL',
    'table.noAttachmentFinding': 'Sin señal específica de riesgo en adjunto',
    'yes': 'Sí',
    'no': 'No',
    'none': 'Ninguno',
    'unknown': 'desconocido',
    'md.title': 'Análisis de phishing en email',
    'md.generated': 'Generado',
    'md.verdict': 'Veredicto',
    'md.score': 'Puntuación',
    'md.classification': 'Clasificación',
    'md.evidence': 'Evidencias',
    'md.attachments': 'Adjuntos',
    'md.actions': 'Acciones recomendadas',
    'prompt': 'Actúa como analista de phishing por email. Revisa la evidencia inferior y genera un informe de triaje conciso. No inventes indicadores. Separa claramente hechos observados de hipótesis.\n\nAsunto: {subject}\nFrom: {from}\nReply-To: {replyTo}\n\nPuntuación del analizador local: {score}/100 ({classification})\n\nEvidencias observadas:\n{evidence}\n\nURLs extraídas:\n{urls}\n\nAdjuntos extraídos:\n{attachments}\n\nExtracto del cuerpo del correo:\n{body}\n\nDevuelve:\n1. Resumen ejecutivo\n2. Veredicto: benigno / sospechoso / phishing confirmado / evidencia insuficiente\n3. Mapeo MITRE ATT&CK\n4. Pasos recomendados de investigación\n5. Explicación sencilla para usuario no técnico',
  },
};

const state = {
  extracted: {},
  lastResult: null,
  loadedFileName: '',
  lang: getInitialLanguage(),
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
  langButtons: document.querySelectorAll('.lang-button'),
};

function getInitialLanguage() {
  const saved = localStorage.getItem('phishguard-lang');
  if (saved === 'en' || saved === 'es') return saved;
  return navigator.language?.toLowerCase().startsWith('es') ? 'es' : 'en';
}

function t(key, vars = {}) {
  const raw = UI_TEXT[state.lang]?.[key] || UI_TEXT.en[key] || key;
  return raw.replace(/\{(\w+)\}/g, (_, name) => vars[name] ?? '');
}

function init() {
  applyLanguage(false);
  els.file.addEventListener('change', handleFileSelection);
  els.analyzeBtn.addEventListener('click', runAnalysis);
  els.clearBtn.addEventListener('click', clearAll);
  els.loadSampleBtn.addEventListener('click', loadSample);
  els.copyPromptBtn.addEventListener('click', copyAiPrompt);
  els.downloadJsonBtn.addEventListener('click', downloadJson);
  els.downloadMdBtn.addEventListener('click', downloadMarkdown);
  els.langButtons.forEach((button) => button.addEventListener('click', switchLanguage));
  document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', switchTab));
  setupDragAndDrop();
}

function applyLanguage(rerun = true) {
  document.documentElement.lang = state.lang;
  document.querySelectorAll('[data-i18n]').forEach((node) => { node.textContent = t(node.dataset.i18n); });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((node) => { node.placeholder = t(node.dataset.i18nPlaceholder); });
  els.langButtons.forEach((button) => button.classList.toggle('active', button.dataset.lang === state.lang));
  if (state.loadedFileName && !state.lastResult) {
    els.statusPill.textContent = t('status.loaded', { name: state.loadedFileName });
  } else if (!state.lastResult) {
    els.statusPill.textContent = t('status.waiting');
  }
  if (rerun && state.lastResult) runAnalysis();
}

function switchLanguage(event) {
  const next = event.currentTarget.dataset.lang;
  if (!['en', 'es'].includes(next) || next === state.lang) return;
  state.lang = next;
  localStorage.setItem('phishguard-lang', next);
  applyLanguage(true);
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
    state.loadedFileName = file.name;
    hydrateFields(state.extracted);
    els.statusPill.textContent = t('status.loaded', { name: file.name });
  };
  reader.onerror = () => alert(t('error.file'));
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

  const auth = parseAuthentication(input.rawHeaders);
  if (auth.dmarc === 'fail') addEvidence('critical', RISK_WEIGHTS.dmarcFail, t('ev.dmarcFail'), evidence);
  if (auth.spf === 'fail') addEvidence('high', RISK_WEIGHTS.spfFail, t('ev.spfFail'), evidence);
  if (auth.dkim === 'fail' || auth.dkim === 'none') addEvidence('medium', RISK_WEIGHTS.dkimFail, t('ev.dkimFail'), evidence);
  if (auth.anyFail) addEvidence('high', RISK_WEIGHTS.authFail, t('ev.authAnyFail'), evidence);

  if (domains.fromDomain && domains.replyToDomain && domains.fromDomain !== domains.replyToDomain) {
    addEvidence('high', RISK_WEIGHTS.replyToMismatch, t('ev.replyMismatch', { reply: domains.replyToDomain, from: domains.fromDomain }), evidence);
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
    addEvidence('low', RISK_WEIGHTS.noUrlNoAttachmentReduction, t('ev.noUrlAttachmentReduction'), evidence);
  }

  const score = clamp(evidence.reduce((sum, item) => sum + item.weight, 0), 0, 100);
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
  const impersonationTerms = ['microsoft', 'office 365', 'paypal', 'dhl', 'ups', 'amazon', 'google', 'apple', 'it support', 'soporte técnico', 'security team', 'equipo de seguridad'];

  if (containsAny(lower, credentialTerms)) {
    signals.push({ type: 'credential', severity: 'high', weight: RISK_WEIGHTS.credentialLanguage, message: t('ev.credential') });
  }
  if (containsAny(lower, urgencyTerms)) {
    signals.push({ type: 'urgency', severity: 'medium', weight: RISK_WEIGHTS.urgencyLanguage, message: t('ev.urgency') });
  }
  if (containsAny(lower, paymentTerms)) {
    signals.push({ type: 'payment', severity: 'medium', weight: RISK_WEIGHTS.paymentLanguage, message: t('ev.payment') });
  }
  if (containsAny(lower, impersonationTerms)) {
    signals.push({ type: 'impersonation', severity: 'medium', weight: RISK_WEIGHTS.impersonationLanguage, message: t('ev.impersonation') });
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

    if (!parsed) findings.push({ severity: 'medium', weight: RISK_WEIGHTS.suspiciousUrlMedium, message: t('url.malformed') });
    if (domain && /^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) findings.push({ severity: 'high', weight: RISK_WEIGHTS.suspiciousUrlHigh, message: t('url.ip') });
    if (domain.includes('xn--')) findings.push({ severity: 'high', weight: RISK_WEIGHTS.suspiciousUrlHigh, message: t('url.punycode') });
    if (domain && SHORTENERS.has(domain)) findings.push({ severity: 'medium', weight: RISK_WEIGHTS.suspiciousUrlMedium, message: t('url.shortener') });
    if (SUSPICIOUS_TLDS.has(tld)) findings.push({ severity: 'medium', weight: RISK_WEIGHTS.suspiciousUrlMedium, message: t('url.tld', { tld }) });
    if (labels.length >= 5) findings.push({ severity: 'low', weight: RISK_WEIGHTS.suspiciousUrlLow, message: t('url.subdomains') });
    if (rawUrl.includes('@')) findings.push({ severity: 'medium', weight: RISK_WEIGHTS.suspiciousUrlMedium, message: t('url.at') });

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
    if (CRITICAL_EXT.has(ext)) findings.push({ severity: 'critical', weight: RISK_WEIGHTS.suspiciousAttachmentCritical, message: t('att.critical', { ext }) });
    else if (HIGH_EXT.has(ext)) findings.push({ severity: 'high', weight: RISK_WEIGHTS.suspiciousAttachmentHigh, message: t('att.high', { ext }) });
    else if (MEDIUM_EXT.has(ext)) findings.push({ severity: 'medium', weight: RISK_WEIGHTS.suspiciousAttachmentMedium, message: t('att.medium', { ext }) });
    return { name, extension: ext || t('unknown'), findings };
  });
}

function classifyScore(score) {
  if (score >= 80) return { level: 'critical', label: t('class.critical'), tone: 'critical', recommendation: t('rec.critical') };
  if (score >= 60) return { level: 'high', label: t('class.high'), tone: 'high', recommendation: t('rec.high') };
  if (score >= 35) return { level: 'medium', label: t('class.medium'), tone: 'medium', recommendation: t('rec.medium') };
  return { level: 'low', label: t('class.low'), tone: 'low', recommendation: t('rec.low') };
}

function mapMitre(context) {
  const mappings = [];
  if (context.urls.length || context.textSignals.some((s) => s.type === 'credential')) {
    mappings.push({ id: 'T1566.002', name: 'Phishing: Spearphishing Link', rationale: t('mitre.link.rationale') });
    mappings.push({ id: 'T1110', name: 'Brute Force / Credential Access context', rationale: t('mitre.credential.rationale') });
  }
  if (context.attachments.length) {
    mappings.push({ id: 'T1566.001', name: 'Phishing: Spearphishing Attachment', rationale: t('mitre.attachment.rationale') });
    if (context.attachments.some((a) => a.findings.length)) {
      mappings.push({ id: 'T1204.002', name: 'User Execution: Malicious File', rationale: t('mitre.execution.rationale') });
    }
  }
  if (context.auth.anyFail || context.domains.replyToDomain) {
    mappings.push({ id: 'T1585/T1586', name: 'Establish Accounts / Compromise Accounts', rationale: t('mitre.sender.rationale') });
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
    t('action.preserve'),
    t('action.validate'),
    t('action.hunt'),
  ];
  if (context.urls.length) actions.push(t('action.urls'));
  if (context.attachments.length) actions.push(t('action.attachments'));
  if (context.auth.anyFail) actions.push(t('action.auth'));
  if (['high', 'critical'].includes(classification.level)) actions.push(t('action.containment'));
  actions.push(t('action.verdict'));
  return actions;
}

function buildSummary(input, score, classification, evidence, urls, attachments) {
  const top = evidence.slice(0, 3).map((item) => item.message).join(' ');
  const subject = input.subject ? t('summary.subject', { subject: input.subject }) : t('summary.noSubject');
  const indicatorText = t('summary.indicators', { urls: urls.length, attachments: attachments.length });
  return t('summary.full', {
    subject,
    classification: classification.label.toLowerCase(),
    score,
    indicators: indicatorText,
    drivers: top || t('summary.noDrivers'),
    recommendation: classification.recommendation,
  });
}

function buildAiPrompt(input, result) {
  const evidenceLines = result.evidence.map((item) => `- [${t(`sev.${item.severity}`).toUpperCase()}] ${item.message}`).join('\n') || `- ${t('empty.evidence')}`;
  const urls = result.indicators?.urls?.map((item) => `- ${item.url} | domain=${item.domain || t('unknown')} | findings=${item.findings.map((f) => f.message).join('; ') || t('none')}`).join('\n') || `- ${t('none')}`;
  const attachments = result.indicators?.attachments?.map((item) => `- ${item.name} | ext=${item.extension} | findings=${item.findings.map((f) => f.message).join('; ') || t('none')}`).join('\n') || `- ${t('none')}`;
  return t('prompt', {
    subject: input.subject || 'N/A',
    from: input.from || 'N/A',
    replyTo: input.replyTo || 'N/A',
    score: result.score,
    classification: result.classification.label,
    evidence: evidenceLines,
    urls,
    attachments,
    body: truncate(input.body || 'N/A', 1800),
  });
}

function truncate(value, length) {
  return value.length > length ? `${value.slice(0, length)}... [truncated]` : value;
}

function renderResult(result) {
  els.emptyState.classList.add('hidden');
  els.results.classList.remove('hidden');
  els.statusPill.textContent = t('status.risk', { classification: result.classification.label });
  els.statusPill.style.color = getToneColor(result.classification.tone);

  els.scoreValue.textContent = result.score;
  els.scoreClass.textContent = result.classification.label;
  els.scoreClass.style.color = getToneColor(result.classification.tone);
  els.summaryText.textContent = result.summary;

  els.evidenceList.innerHTML = result.evidence.length
    ? result.evidence.map((item) => `<li><span class="severity-tag tag-${escapeHtml(item.severity)}">${escapeHtml(t(`sev.${item.severity}`))}</span>${escapeHtml(item.message)} <strong>(+${item.weight})</strong></li>`).join('')
    : `<li>${escapeHtml(t('empty.evidence'))}</li>`;

  els.indicatorTables.innerHTML = buildIndicatorHtml(result.indicators);
  els.actionList.innerHTML = result.actions.map((action) => `<li>${escapeHtml(action)}</li>`).join('');
  els.mitreList.innerHTML = result.mitre.length
    ? result.mitre.map((item) => `<div class="mitre-item"><strong>${escapeHtml(item.id)} — ${escapeHtml(item.name)}</strong><br>${escapeHtml(item.rationale)}</div>`).join('')
    : `<p class="muted">${escapeHtml(t('empty.mitre'))}</p>`;
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
    ? indicators.urls.map((item) => `<tr><td>${escapeHtml(item.url)}</td><td>${escapeHtml(item.domain || t('unknown'))}</td><td>${escapeHtml(item.findings.map((f) => f.message).join('; ') || t('table.noUrlFinding'))}</td></tr>`).join('')
    : `<tr><td colspan="3">${escapeHtml(t('table.noUrls'))}</td></tr>`;
  const attachmentRows = indicators.attachments.length
    ? indicators.attachments.map((item) => `<tr><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.extension)}</td><td>${escapeHtml(item.findings.map((f) => f.message).join('; ') || t('table.noAttachmentFinding'))}</td></tr>`).join('')
    : `<tr><td colspan="3">${escapeHtml(t('table.noAttachments'))}</td></tr>`;
  return `
    <h4>${escapeHtml(t('table.urls'))}</h4>
    <div class="table-wrap"><table><thead><tr><th>${escapeHtml(t('table.url'))}</th><th>${escapeHtml(t('table.domain'))}</th><th>${escapeHtml(t('table.findings'))}</th></tr></thead><tbody>${urlRows}</tbody></table></div>
    <h4>${escapeHtml(t('table.attachments'))}</h4>
    <div class="table-wrap"><table><thead><tr><th>${escapeHtml(t('table.name'))}</th><th>${escapeHtml(t('table.extension'))}</th><th>${escapeHtml(t('table.findings'))}</th></tr></thead><tbody>${attachmentRows}</tbody></table></div>
    <h4>${escapeHtml(t('table.authentication'))}</h4>
    <div class="table-wrap"><table><thead><tr><th>SPF</th><th>DKIM</th><th>DMARC</th><th>${escapeHtml(t('table.anyFail'))}</th></tr></thead><tbody><tr><td>${escapeHtml(indicators.authentication.spf)}</td><td>${escapeHtml(indicators.authentication.dkim)}</td><td>${escapeHtml(indicators.authentication.dmarc)}</td><td>${indicators.authentication.anyFail ? escapeHtml(t('yes')) : escapeHtml(t('no'))}</td></tr></tbody></table></div>
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
    els.copyPromptBtn.textContent = t('ai.copied');
    setTimeout(() => { els.copyPromptBtn.textContent = t('ai.copyButton'); }, 1400);
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
  const evidence = result.evidence.map((item) => `- **${t(`sev.${item.severity}`).toUpperCase()}**: ${item.message} (+${item.weight})`).join('\n') || `- ${t('empty.evidence')}`;
  const urls = result.indicators.urls.map((item) => `- ${item.url} — ${item.findings.map((f) => f.message).join('; ') || t('table.noUrlFinding')}`).join('\n') || `- ${t('none')}`;
  const attachments = result.indicators.attachments.map((item) => `- ${item.name} — ${item.findings.map((f) => f.message).join('; ') || t('table.noAttachmentFinding')}`).join('\n') || `- ${t('none')}`;
  const mitre = result.mitre.map((item) => `- **${item.id} ${item.name}**: ${item.rationale}`).join('\n') || `- ${t('none')}`;
  const actions = result.actions.map((action, index) => `${index + 1}. ${action}`).join('\n');
  return `# ${t('md.title')}\n\n${t('md.generated')}: ${result.generatedAt}\n\n## ${t('md.verdict')}\n\n${t('md.score')}: **${result.score}/100**\n\n${t('md.classification')}: **${result.classification.label}**\n\n${result.summary}\n\n## ${t('md.evidence')}\n\n${evidence}\n\n## URLs\n\n${urls}\n\n## ${t('md.attachments')}\n\n${attachments}\n\n## MITRE ATT&CK\n\n${mitre}\n\n## ${t('md.actions')}\n\n${actions}\n`;
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
  state.loadedFileName = '';
  els.results.classList.add('hidden');
  els.emptyState.classList.remove('hidden');
  els.statusPill.textContent = t('status.waiting');
  els.statusPill.style.color = 'var(--muted)';
}

function loadSample() {
  if (state.lang === 'es') {
    els.subject.value = 'Urgente: verifica tu cuenta de Microsoft 365 en 24 horas';
    els.from.value = 'Microsoft Security <security@microsoft-alerts-support.com>';
    els.replyTo.value = 'helpdesk@account-review-center.top';
    els.attachments.value = 'Verificacion_Cuenta.html, Instrucciones_MFA.zip';
    els.body.value = 'Tu cuenta de Office 365 ha sido bloqueada por actividad inusual. Verifica tu cuenta inmediatamente en menos de 24 horas para evitar una suspensión permanente. Inicia sesión aquí: https://login.microsoft-security.account-review-center.top/session?id=9321 o usa https://bit.ly/verify-m365-now';
  } else {
    els.subject.value = 'Urgent: verify your Microsoft 365 account within 24 hours';
    els.from.value = 'Microsoft Security <security@microsoft-alerts-support.com>';
    els.replyTo.value = 'helpdesk@account-review-center.top';
    els.attachments.value = 'Account_Verification.html, MFA_Instructions.zip';
    els.body.value = 'Your Office 365 account has been locked due to unusual activity. Verify your account immediately within 24 hours to avoid permanent suspension. Sign in here: https://login.microsoft-security.account-review-center.top/session?id=9321 or use https://bit.ly/verify-m365-now';
  }
  els.rawHeaders.value = 'Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=microsoft-alerts-support.com; dkim=none; dmarc=fail header.from=microsoft-alerts-support.com';
  runAnalysis();
  document.getElementById('analyzer').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

init();
