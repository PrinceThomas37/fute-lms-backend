// ═══════════════════════════════════════════════════════════════
// Email deliverability validation (domain-level)
//
// At entry time we cannot know whether a specific mailbox exists, but we CAN
// cheaply reject dead domains and typos (e.g. "gamil.com") with a DNS MX
// lookup. Addresses whose domain has no mail exchanger get flagged
// email_status='invalid' so the send loop will skip them (a hard bounce to a
// dead domain is a primary driver of sender-reputation / "compromised account"
// damage). Mailbox-level existence is caught separately by the NDR/bounce
// feedback loop in index.js.
//
// Design notes:
//  - Domains are resolved once and cached (a sheet of 50 contacts at one
//    company costs a single DNS query, not 50).
//  - Transient DNS errors NEVER condemn an address — we only mark 'invalid'
//    when DNS authoritatively says the domain cannot receive mail.
// ═══════════════════════════════════════════════════════════════
const dns = require('dns').promises;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MX_TTL_MS = 6 * 60 * 60 * 1000; // 6h cache per domain
const mxCache = new Map(); // domain -> { ok, at }

function emailSyntaxValid(email) {
  return typeof email === 'string' && EMAIL_RE.test(email.trim());
}

function emailDomain(email) {
  if (!emailSyntaxValid(email)) return '';
  return email.trim().split('@').pop().toLowerCase();
}

// True if the domain can receive mail (has MX, or falls back to an A/AAAA
// record per RFC 5321). On transient errors returns true (unknown ≠ bad).
async function domainHasMx(domain) {
  if (!domain) return false;
  const cached = mxCache.get(domain);
  if (cached && Date.now() - cached.at < MX_TTL_MS) return cached.ok;

  let ok;
  try {
    const mx = await dns.resolveMx(domain);
    ok = Array.isArray(mx) && mx.some(r => r.exchange);
    if (!ok) ok = await hasAddressRecord(domain); // implicit MX fallback
  } catch (e) {
    if (e && (e.code === 'ENOTFOUND' || e.code === 'ENODATA')) {
      // Authoritative "no MX" — check A/AAAA fallback before condemning.
      ok = await hasAddressRecord(domain);
    } else {
      // Timeout / SERVFAIL / other transient — do not condemn the address.
      ok = true;
    }
  }
  mxCache.set(domain, { ok, at: Date.now() });
  return ok;
}

async function hasAddressRecord(domain) {
  try {
    const a = await dns.resolve4(domain);
    if (a && a.length) return true;
  } catch (_) {}
  try {
    const aaaa = await dns.resolve6(domain);
    if (aaaa && aaaa.length) return true;
  } catch (_) {}
  return false;
}

// Resolve a single address to 'valid' | 'invalid'. Empty email → 'valid'
// (nothing to validate; the row's default status stands).
async function classifyEmailDeliverability(email) {
  if (!email) return 'valid';
  if (!emailSyntaxValid(email)) return 'invalid';
  const ok = await domainHasMx(emailDomain(email));
  return ok ? 'valid' : 'invalid';
}

// Annotate contact rows in place: sets row.email_status='invalid' for bad
// syntax or dead domains, leaving deliverable/unknown rows untouched. Unique
// domains are warmed concurrently so bulk imports stay fast.
async function annotateContactEmailStatus(rows) {
  if (!Array.isArray(rows) || !rows.length) return rows;
  const domains = new Set();
  for (const r of rows) {
    if (r && r.email && emailSyntaxValid(r.email)) domains.add(emailDomain(r.email));
  }
  await Promise.all([...domains].map(d => domainHasMx(d).catch(() => true)));
  for (const r of rows) {
    if (!r || !r.email) continue;
    if (!emailSyntaxValid(r.email)) { r.email_status = 'invalid'; continue; }
    const ok = await domainHasMx(emailDomain(r.email));
    if (!ok) r.email_status = 'invalid';
  }
  return rows;
}

module.exports = {
  emailSyntaxValid,
  emailDomain,
  domainHasMx,
  classifyEmailDeliverability,
  annotateContactEmailStatus
};
