// ============================================================================
// Deliverability helpers — pure, dependency-free heuristics used across the
// send/verify/reply paths. Nothing here touches the database or network, so it
// is safe to call anywhere and easy to unit-test.
// ============================================================================

// ── Address classification ──────────────────────────────────────────────────

// Common disposable / throwaway domains. These are hard-bad (bounce or are
// abandoned), so callers may block them outright.
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org',
  'throwawaymail.com', 'yopmail.com', 'getnada.com', 'trashmail.com', 'sharklasers.com',
  'maildrop.cc', 'dispostable.com', 'fakeinbox.com', 'mailnesia.com', 'mintemail.com',
  'mohmal.com', 'emailondeck.com', 'spamgourmet.com', 'tempinbox.com', 'mailcatch.com',
  'guerrillamailblock.com', 'grr.la', 'pokemail.net', 'spam4.me', 'tempr.email'
]);

// Role / shared-inbox local-parts. In RECRUITING these are often the intended
// target (hr@, careers@, talent@), so callers should FLAG, not block, them.
const ROLE_LOCALPARTS = new Set([
  'info', 'admin', 'support', 'sales', 'contact', 'hello', 'help', 'office', 'team',
  'hr', 'careers', 'jobs', 'recruiting', 'recruitment', 'talent', 'hiring', 'staffing',
  'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'billing', 'accounts', 'marketing',
  'webmaster', 'postmaster', 'enquiries', 'inquiries', 'general', 'mail', 'hello'
]);

function emailParts(email) {
  if (typeof email !== 'string' || !email.includes('@')) return { local: '', domain: '' };
  const [local, domain] = email.trim().toLowerCase().split('@');
  return { local: local || '', domain: domain || '' };
}

function isDisposableDomain(domain) {
  return !!domain && DISPOSABLE_DOMAINS.has(String(domain).toLowerCase());
}

function isRoleAddress(email) {
  const { local } = emailParts(email);
  if (!local) return false;
  return ROLE_LOCALPARTS.has(local) || ROLE_LOCALPARTS.has(local.replace(/[._-]/g, ''));
}

// Soft flags for display/analytics — pure function of the address, no I/O.
function deliverabilityFlags(email) {
  const { domain } = emailParts(email);
  return { role: isRoleAddress(email), disposable: isDisposableDomain(domain) };
}

// ── Opt-out detection (for inbound replies) ─────────────────────────────────

const OPT_OUT_PATTERNS = [
  /\bunsubscribe\b/i,
  /\bopt[\s-]?out\b/i,
  /\bremove me\b/i,
  /\btake me off\b/i,
  /\bstop emailing\b/i,
  /\bdo not (?:contact|email)\b/i,
  /\bno longer (?:wish|want)\b/i
];

function isOptOutReply(text) {
  if (!text) return false;
  const t = String(text).slice(0, 2000);
  return OPT_OUT_PATTERNS.some(re => re.test(t));
}

// ── Spam-content scoring (pre-send heuristic) ───────────────────────────────

const SPAM_WORDS = [
  'free', 'risk-free', 'guarantee', 'guaranteed', 'act now', 'limited time', 'click here',
  'click below', 'buy now', 'order now', 'cash', 'earn money', 'make money', 'extra income',
  'no cost', 'no obligation', '100%', 'winner', 'congratulations', 'urgent', 'exclusive deal',
  'cheap', 'discount', 'lowest price', 'best price', 'credit card', 'investment', 'crypto',
  'viagra', 'loan', 'debt', 'income', 'work from home', 'this is not spam', 'dear friend'
];

function stripHtml(s) {
  return String(s || '').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
}

// Returns { score: 0-100 (higher = riskier), level: 'good'|'warn'|'risk', warnings: [] }.
function scoreEmailContent(subject, body) {
  const warnings = [];
  let score = 0;
  const subj = String(subject || '');
  const rawBody = String(body || '');
  const text = stripHtml(rawBody);
  const lower = (subj + ' ' + text).toLowerCase();

  const hits = SPAM_WORDS.filter(w => lower.includes(w));
  if (hits.length) { score += Math.min(30, hits.length * 6); warnings.push(`Spam-trigger words: ${hits.slice(0, 6).join(', ')}${hits.length > 6 ? '…' : ''}`); }

  // Links
  const linkCount = (rawBody.match(/https?:\/\//gi) || []).length + (rawBody.match(/<a\s/gi) || []).length;
  if (linkCount > 3) { score += 12; warnings.push(`${linkCount} links — keep cold emails to 0–2.`); }

  // Images
  const imgCount = (rawBody.match(/<img\s/gi) || []).length;
  if (imgCount > 1) { score += 10; warnings.push(`${imgCount} images — image-heavy mail filters poorly.`); }

  // ALL CAPS words
  const capsWords = (text.match(/\b[A-Z]{3,}\b/g) || []).filter(w => w !== 'USA' && w !== 'CEO' && w !== 'HR');
  if (capsWords.length >= 2) { score += 10; warnings.push(`ALL-CAPS words (${capsWords.slice(0, 4).join(', ')}).`); }

  // Exclamation marks
  const bangs = (subj + text).split('!').length - 1;
  if (bangs >= 2) { score += 8; warnings.push(`${bangs} exclamation marks — reads promotional.`); }

  // Subject
  if (subj.length > 70) { score += 6; warnings.push('Subject is long (>70 chars).'); }
  if (/[A-Z]{4,}/.test(subj)) { score += 6; warnings.push('Subject has shouting CAPS.'); }

  // Body length
  const words = text ? text.split(/\s+/).length : 0;
  if (words < 25) { score += 8; warnings.push('Body is very short — looks templated/thin.'); }
  if (words > 220) { score += 6; warnings.push('Body is long (>220 words) — cold emails convert better short.'); }

  // Missing opt-out (CAN-SPAM / complaint risk)
  if (!isOptOutReply(text) && !/unsubscrib/i.test(rawBody)) {
    warnings.push('No visible opt-out line — recommended for compliance & reputation.');
    score += 4;
  }

  score = Math.max(0, Math.min(100, score));
  const level = score >= 45 ? 'risk' : score >= 20 ? 'warn' : 'good';
  return { score, level, warnings };
}

module.exports = {
  DISPOSABLE_DOMAINS, ROLE_LOCALPARTS,
  isDisposableDomain, isRoleAddress, deliverabilityFlags,
  isOptOutReply, scoreEmailContent
};
