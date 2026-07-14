// ============================================================================
// Domain authentication + reputation health — SPF / DKIM / DMARC record checks
// and DNSBL (blacklist) lookups for every sending domain. Protects the domains
// you load into the warm-up pool: a domain with broken auth or on a blacklist
// will land in spam no matter how well you warm it.
//
// Pure DNS — Node's built-in `dns` module, no paid verifier, no external HTTP.
// Every lookup is wrapped in a short timeout and swallows errors, so a blocked
// resolver or a missing record degrades to "not found" instead of hanging.
// Each finding ships with an exact CURE (the record to add / setting to flip).
// ============================================================================
const dns = require('dns').promises;

function withTimeout(promise, ms) {
  return Promise.race([
    promise.catch(() => null),
    new Promise((resolve) => setTimeout(() => resolve(null), ms)),
  ]);
}
async function txt(name, ms = 4000) {
  const r = await withTimeout(dns.resolveTxt(name), ms);
  return r ? r.map((chunks) => chunks.join('')) : null; // join the 255-char chunks per record
}

// ── SPF ─────────────────────────────────────────────────────────────────────
async function checkSpf(domain) {
  const records = await txt(domain);
  if (records === null) return { ok: false, found: null, issues: ['Could not resolve DNS for the domain.'], cure: null };
  const spf = records.find((r) => /^v=spf1/i.test(r));
  if (!spf) return {
    ok: false, found: false, issues: ['No SPF record.'],
    cure: `Add a TXT record on "${domain}": v=spf1 include:spf.protection.outlook.com -all  (use include:_spf.google.com for Google Workspace; combine includes if you send from both).`,
  };
  const issues = [];
  const all = /-all/i.test(spf) ? '-all' : /~all/i.test(spf) ? '~all' : null;
  if (!all) issues.push('SPF has no -all / ~all — it never fails spoofed senders.');
  const lookups = (spf.match(/\b(include|a|mx|ptr|exists|redirect)[:=]/gi) || []).length;
  if (lookups > 10) issues.push(`SPF needs ${lookups} DNS lookups (limit is 10) — it can PermError. Flatten or consolidate includes.`);
  return { ok: issues.length === 0, found: true, record: spf, policy: all, lookups, issues, cure: issues.length ? `Update the SPF TXT on "${domain}" to end with -all and stay within 10 lookups.` : null };
}

// ── DMARC ─────────────────────────────────────────────────────────────────────
async function checkDmarc(domain) {
  const records = await txt(`_dmarc.${domain}`);
  if (records === null) return { ok: false, found: null, issues: ['Could not resolve DNS for _dmarc.'], cure: null };
  const dmarc = records.find((r) => /^v=DMARC1/i.test(r));
  if (!dmarc) return {
    ok: false, found: false, issues: ['No DMARC record.'],
    cure: `Add a TXT record on "_dmarc.${domain}": v=DMARC1; p=none; rua=mailto:dmarc@${domain}  — start at p=none to monitor, then move to quarantine, then reject.`,
  };
  const p = (dmarc.match(/;\s*p=(none|quarantine|reject)/i) || [])[1];
  const issues = [];
  if (!p) issues.push('DMARC record has no policy (p=).');
  else if (p.toLowerCase() === 'none') issues.push('DMARC is p=none (monitor only) — once SPF/DKIM align, move to p=quarantine then p=reject.');
  return { ok: issues.length === 0, found: true, record: dmarc, policy: (p || '').toLowerCase() || null, issues, cure: (p || '').toLowerCase() === 'none' ? `Once aligned, tighten "_dmarc.${domain}" to p=quarantine, then p=reject.` : null };
}

// ── DKIM (best-effort: probe the common provider selectors) ──────────────────
const DKIM_SELECTORS = ['selector1', 'selector2', 'google', 'k1', 's1', 's2', 'dkim', 'default', 'mail', 'smtp', 'mandrill', 'sendgrid'];
async function checkDkim(domain) {
  let resolvable = false;
  for (const sel of DKIM_SELECTORS) {
    const name = `${sel}._domainkey.${domain}`;
    const cname = await withTimeout(dns.resolveCname(name), 2500);
    if (cname && cname.length) return { ok: true, found: true, selector: sel, via: 'cname', issues: [] };
    const t = await txt(name, 2500);
    if (t !== null) resolvable = true;
    if (t && t.some((r) => /v=DKIM1|(^|;)\s*p=/i.test(r))) return { ok: true, found: true, selector: sel, via: 'txt', issues: [] };
  }
  return {
    ok: false, found: resolvable ? false : null,
    issues: ['No DKIM record at the common selectors.'],
    cure: `Enable DKIM in your mail provider and publish the record it gives you. Microsoft 365: Defender → Email authentication → DKIM (publishes selector1/selector2._domainkey CNAMEs). Google Workspace: Admin → Gmail → Authenticate email (publishes google._domainkey TXT).`,
  };
}

// ── Blacklists (DNSBL) ────────────────────────────────────────────────────────
const IP_DNSBLS = ['zen.spamhaus.org', 'b.barracudacentral.org', 'bl.spamcop.net'];
const DOMAIN_DNSBLS = ['dbl.spamhaus.org'];
async function checkBlacklists(domain) {
  const listed = [], checked = [];
  for (const bl of DOMAIN_DNSBLS) {
    checked.push(bl);
    const hit = await withTimeout(dns.resolve4(`${domain}.${bl}`), 2500);
    if (hit && hit.length) listed.push({ list: bl, type: 'domain' });
  }
  // resolve the domain's mail server IP for IP-based lists
  let ip = null, mailHost = domain;
  const mx = await withTimeout(dns.resolveMx(domain), 3000);
  if (mx && mx.length) mailHost = mx.slice().sort((a, b) => a.priority - b.priority)[0].exchange;
  const a = await withTimeout(dns.resolve4(mailHost), 3000);
  if (a && a.length) ip = a[0];
  if (ip) {
    const rev = ip.split('.').reverse().join('.');
    for (const bl of IP_DNSBLS) {
      checked.push(bl);
      const hit = await withTimeout(dns.resolve4(`${rev}.${bl}`), 2500);
      if (hit && hit.length) listed.push({ list: bl, type: 'ip', ip });
    }
  }
  return { ip, mail_host: mailHost, checked, listed };
}

// ── Full per-domain report ────────────────────────────────────────────────────
async function domainHealthReport(domain) {
  const [spf, dkim, dmarc, blacklist] = await Promise.all([
    checkSpf(domain), checkDkim(domain), checkDmarc(domain), checkBlacklists(domain),
  ]);
  let score = 100;
  const findings = [];
  const add = (area, severity, detail, cure) => findings.push({ area, severity, detail, cure });

  if (spf.found === false) { score -= 30; add('SPF', 'high', 'No SPF record — receivers can’t verify your senders.', spf.cure); }
  else if (spf.found && !spf.ok) { score -= 10; add('SPF', 'warn', (spf.issues || []).join(' '), spf.cure); }

  if (dkim.found === false) { score -= 25; add('DKIM', 'high', 'No DKIM signature — mail isn’t cryptographically signed.', dkim.cure); }
  else if (dkim.found === null) { add('DKIM', 'info', 'DKIM could not be verified from common selectors (may use a custom selector).', dkim.cure); }

  if (dmarc.found === false) { score -= 25; add('DMARC', 'high', 'No DMARC record — no policy protects your domain from spoofing.', dmarc.cure); }
  else if (dmarc.found && !dmarc.ok) { score -= 10; add('DMARC', 'warn', (dmarc.issues || []).join(' '), dmarc.cure); }

  for (const l of (blacklist.listed || [])) {
    score -= 20;
    add('Blacklist', 'high', `Listed on ${l.list}${l.ip ? ` (${l.ip})` : ''}.`, `Request delisting at the blacklist operator (e.g. spamhaus.org/lookup), fix the cause (compromised mailbox / open relay / spammy content), and pause cold sends from this domain until cleared.`);
  }

  // If SPF and DMARC both came back "unknown", our resolver couldn't reach DNS
  // — report that honestly instead of a misleading perfect score.
  if (spf.found === null && dmarc.found === null) {
    return { domain, checked_at: new Date().toISOString(), score: null, level: 'unknown',
      spf, dkim, dmarc, blacklist,
      findings: [{ area: 'DNS', severity: 'info', detail: 'Could not resolve DNS for this domain right now — try again shortly.', cure: null }] };
  }
  score = Math.max(0, Math.min(100, score));
  const level = score >= 85 ? 'good' : score >= 60 ? 'ok' : score >= 30 ? 'warn' : 'bad';
  return { domain, checked_at: new Date().toISOString(), score, level, spf, dkim, dmarc, blacklist, findings };
}

module.exports = { checkSpf, checkDmarc, checkDkim, checkBlacklists, domainHealthReport };
