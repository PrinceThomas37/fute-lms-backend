require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { parseJobDescription, buildResearchFromLeadData, normalizeIndustry, normalizeJobTitle, titleSimilarity } = require('./jd-parser');
const { learnSkillsForIndustry } = require('./learned-skills');

function persistLearnedSkills(industry, research) {
  if (!research || !research.requirements) return;
  const key = normalizeIndustry(industry);
  if (!key) return;
  const req = research.requirements;
  const skills = [req.skill_1, req.skill_2, req.skill_3, ...(req.skills || []), ...(req.suggested_skills || [])].filter(Boolean);
  learnSkillsForIndustry(key, skills);
}
const {
  DEFAULT_TEMPLATES,
  buildEmailVars,
  fillTemplate,
  resolveTemplate,
  buildRotatingTemplateDeck,
  isRandomTemplateMode,
  getVariantById
} = require('./email-vars');
const {
  DEFAULT_SIGNATURE_HTML,
  mailboxSignatureKey,
  legacyUserSignatureKey,
  fillSignatureHtml,
  resolveSignatureHtml
} = require('./email-signature');

const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// ── MIDDLEWARE ─────────────────────────────────────────────────
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','PATCH','DELETE'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({ limit: '5mb' }));

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.replace('Bearer ', '');
  // Guest bypass — read-only portfolio access
  if (token === 'guest') {
    req.user = { id: 'guest', name: 'Guest User', email: 'guest@futeglobal.com', role: 'bd', roles: ['bd'], isGuest: true };
    return next();
  }
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// Role helper — works with both old single role and new roles array
function hasRole(req, ...roles) {
  const u = req.user;
  if (!u) return false;
  // New: roles array
  if (Array.isArray(u.roles) && u.roles.length) {
    return roles.some(r => u.roles.includes(r));
  }
  // Legacy: single role field
  return roles.includes(u.role);
}

// Guest guard — block write operations
function notGuest(req, res) {
  if (req.user && req.user.isGuest) {
    res.status(403).json({ error: 'Guest users cannot perform write operations.' });
    return true;
  }
  return false;
}

const today = () => new Date().toISOString().split('T')[0];

const US_TZ_MAP = {
  ny: 'EST', nj: 'EST', fl: 'EST', ma: 'EST', pa: 'EST', ga: 'EST', nc: 'EST', sc: 'EST', va: 'EST',
  ct: 'EST', me: 'EST', nh: 'EST', vt: 'EST', ri: 'EST', de: 'EST', md: 'EST', dc: 'EST', oh: 'EST',
  mi: 'EST', in: 'EST', ky: 'EST', wv: 'EST', tn: 'EST',
  tx: 'CST', il: 'CST', mn: 'CST', wi: 'CST', mo: 'CST', ia: 'CST', ks: 'CST', ne: 'CST', sd: 'CST',
  nd: 'CST', ok: 'CST', la: 'CST', ar: 'CST', ms: 'CST', al: 'CST',
  co: 'MST', az: 'MST', nm: 'MST', ut: 'MST', wy: 'MST', mt: 'MST', id: 'MST',
  ca: 'PST', wa: 'PST', or: 'PST', nv: 'PST', ak: 'PST', hi: 'PST'
};
const LEAD_TZ_IANA = {
  EST: 'America/New_York', EDT: 'America/New_York',
  CST: 'America/Chicago', CDT: 'America/Chicago',
  MST: 'America/Denver', MDT: 'America/Denver',
  PST: 'America/Los_Angeles', PDT: 'America/Los_Angeles',
  Unknown: 'America/New_York'
};
const PENDING_EMAIL_JOB_SELECT = 'id, to_email, subject, body, contact_id, job_id, from_email, followup_type, follow_up_id, job:jobs(timezone, sending_email_id, sending_email:user_emails!sending_email_id(id,email_address,display_name,platform,daily_send_limit))';

function getTimezoneFromLocation(location) {
  if (!location) return 'EST';
  const loc = String(location).toLowerCase();
  for (const [state, tz] of Object.entries(US_TZ_MAP)) {
    if (loc.includes(state)) return tz;
  }
  return 'EST';
}

let sendWindowCache = { start: 8, end: 16, loadedAt: 0 };
async function getSendWindowHours() {
  if (Date.now() - sendWindowCache.loadedAt < 60000) {
    return { start: sendWindowCache.start, end: sendWindowCache.end };
  }
  let start = 8;
  let end = 16;
  try {
    const { data } = await supabase.from('app_settings').select('key,value').in('key', ['send_window_start_hour', 'send_window_end_hour']);
    (data || []).forEach(r => {
      const n = parseInt(r.value, 10);
      if (r.key === 'send_window_start_hour' && !Number.isNaN(n) && n >= 0 && n <= 23) start = n;
      if (r.key === 'send_window_end_hour' && !Number.isNaN(n) && n >= 1 && n <= 24) end = n;
    });
  } catch (_) {}
  sendWindowCache = { start, end, loadedAt: Date.now() };
  return { start, end };
}

function getLocalMinutesInLeadZone(tz, date = new Date()) {
  const iana = LEAD_TZ_IANA[tz] || LEAD_TZ_IANA.EST;
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: iana, hour: 'numeric', minute: 'numeric', hour12: false }).formatToParts(date);
  const hour = parseInt(parts.find(p => p.type === 'hour').value, 10);
  const minute = parseInt(parts.find(p => p.type === 'minute').value, 10);
  return hour * 60 + minute;
}

function isInLeadSendWindow(tz, date = new Date(), window = { start: 8, end: 16 }) {
  const mins = getLocalMinutesInLeadZone(tz || 'EST', date);
  return mins >= window.start * 60 && mins < window.end * 60;
}

function getMinutesUntilWindowOpens(tz, date = new Date(), window = { start: 8, end: 16 }) {
  if (isInLeadSendWindow(tz, date, window)) return 0;
  const mins = getLocalMinutesInLeadZone(tz || 'EST', date);
  const startMins = window.start * 60;
  if (mins < startMins) return startMins - mins;
  return (24 * 60 - mins) + startMins;
}

function formatWindowOpensLabel(tz, window, date = new Date()) {
  const minsUntil = getMinutesUntilWindowOpens(tz, date, window);
  if (minsUntil <= 0) return 'Now';
  const iana = LEAD_TZ_IANA[tz] || LEAD_TZ_IANA.EST;
  const openAt = new Date(date.getTime() + minsUntil * 60000);
  const fmtDay = d => new Intl.DateTimeFormat('en-CA', { timeZone: iana, year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
  const dayWord = fmtDay(openAt) === fmtDay(date) ? 'Today' : 'Tomorrow';
  const timeStr = new Intl.DateTimeFormat('en-US', { timeZone: iana, hour: 'numeric', minute: '2-digit', hour12: true }).format(openAt);
  return `${dayWord} ${timeStr} ${tz || 'EST'}`;
}

function padHour(h) {
  const hr = h % 12 || 12;
  const ap = h < 12 ? 'AM' : 'PM';
  return `${hr}:00 ${ap}`;
}

function extractEmailDomain(addr) {
  if (!addr || typeof addr !== 'string' || !addr.includes('@')) return '';
  return addr.split('@').pop().toLowerCase().trim();
}

let bulkSendSettingsCache = { loadedAt: 0, delayMin: 30, delayMax: 60, domainMaxPerHour: 8, defaultDailyLimit: 300, maxPerRun: 0 };

async function getBulkSendSettings() {
  if (Date.now() - bulkSendSettingsCache.loadedAt < 60000) return bulkSendSettingsCache;
  let delayMin = 30, delayMax = 60, domainMaxPerHour = 8, defaultDailyLimit = 300, maxPerRun = 0;
  try {
    const { data } = await supabase.from('app_settings').select('key,value').in('key', [
      'send_delay_min_sec', 'send_delay_max_sec', 'domain_max_per_hour',
      'default_daily_send_limit', 'bulk_send_max_per_run'
    ]);
    (data || []).forEach(r => {
      const n = parseInt(r.value, 10);
      if (r.key === 'send_delay_min_sec' && !Number.isNaN(n) && n >= 1 && n <= 300) delayMin = n;
      if (r.key === 'send_delay_max_sec' && !Number.isNaN(n) && n >= 1 && n <= 600) delayMax = n;
      if (r.key === 'domain_max_per_hour' && !Number.isNaN(n) && n >= 1 && n <= 100) domainMaxPerHour = n;
      if (r.key === 'default_daily_send_limit' && !Number.isNaN(n) && n >= 1) defaultDailyLimit = n;
      if (r.key === 'bulk_send_max_per_run' && !Number.isNaN(n) && n >= 0) maxPerRun = n;
    });
  } catch (_) {}
  if (delayMax < delayMin) delayMax = delayMin;
  bulkSendSettingsCache = { loadedAt: Date.now(), delayMin, delayMax, domainMaxPerHour, defaultDailyLimit, maxPerRun };
  return bulkSendSettingsCache;
}

async function getMailboxDelayBounds(userEmailId, settings) {
  let min = settings.delayMin, max = settings.delayMax;
  try {
    const { data } = await supabase.from('app_settings').select('key,value').in('key', [
      `ue_${userEmailId}_send_delay_min`, `ue_${userEmailId}_send_delay_max`
    ]);
    (data || []).forEach(r => {
      const n = parseInt(r.value, 10);
      if (r.key.endsWith('_min') && !Number.isNaN(n) && n >= 1 && n <= 300) min = n;
      if (r.key.endsWith('_max') && !Number.isNaN(n) && n >= 1 && n <= 600) max = n;
    });
  } catch (_) {}
  if (max < min) max = min;
  return { min, max };
}

async function loadMailboxQuotaState(mailboxIds) {
  const settings = await getBulkSendSettings();
  const limits = {}, sentToday = {}, delays = {};
  const ids = [...new Set(mailboxIds.filter(Boolean))];
  if (ids.length) {
    const { data: accounts } = await supabase.from('user_emails').select('id,daily_send_limit').in('id', ids);
    (accounts || []).forEach(a => { limits[a.id] = a.daily_send_limit || settings.defaultDailyLimit; });
    const { data: logs } = await supabase.from('email_send_log').select('user_email_id,emails_sent').eq('send_date', today()).in('user_email_id', ids);
    (logs || []).forEach(l => { sentToday[l.user_email_id] = l.emails_sent || 0; });
    for (const id of ids) {
      delays[id] = await getMailboxDelayBounds(id, settings);
      if (!limits[id]) limits[id] = settings.defaultDailyLimit;
    }
  }
  return { limits, sentToday, delays, settings };
}

async function loadMailboxSignatures(mailboxIds, userId) {
  const ids = [...new Set(mailboxIds.filter(Boolean))];
  const map = {};
  if (!ids.length) return map;

  const keys = ids.map(mailboxSignatureKey);
  const { data: rows } = await supabase.from('app_settings').select('key,value').in('key', keys);
  (rows || []).forEach(r => {
    const id = r.key.replace(/^ue_/, '').replace(/_signature_html$/, '');
    map[id] = r.value;
  });

  let legacyUserSig = '';
  if (userId) {
    const { data: leg } = await supabase.from('app_settings').select('value').eq('key', legacyUserSignatureKey(userId)).maybeSingle();
    legacyUserSig = leg?.value || '';
  }

  const migrations = [];
  for (const id of ids) {
    if (!map[id] && legacyUserSig) {
      map[id] = legacyUserSig;
      migrations.push({ key: mailboxSignatureKey(id), value: legacyUserSig, updated_at: new Date() });
    }
    if (!map[id]) map[id] = DEFAULT_SIGNATURE_HTML;
  }
  if (migrations.length) {
    await supabase.from('app_settings').upsert(migrations, { onConflict: 'key' });
  }
  return map;
}

async function getMailboxSignature(userEmailId, userId) {
  const map = await loadMailboxSignatures([userEmailId], userId);
  return resolveSignatureHtml(map[userEmailId]);
}

function interleaveByMailbox(emails) {
  const buckets = new Map();
  emails.forEach(e => {
    const mb = e.job?.sending_email_id || '_none';
    if (!buckets.has(mb)) buckets.set(mb, []);
    buckets.get(mb).push(e);
  });
  const keys = [...buckets.keys()];
  const out = [];
  let progress = true;
  while (progress) {
    progress = false;
    for (const k of keys) {
      const q = buckets.get(k);
      if (q && q.length) { out.push(q.shift()); progress = true; }
    }
  }
  return out;
}

function domainSendsInLastHour(domainTimestamps, domain) {
  const cutoff = Date.now() - 3600000;
  return (domainTimestamps[domain] || []).filter(t => t > cutoff).length;
}

async function waitForMailboxSlot(mailboxId, lastSendAtByMailbox, delays) {
  if (!mailboxId || !lastSendAtByMailbox[mailboxId]) return;
  const bounds = delays[mailboxId] || { min: 30, max: 60 };
  const waitSec = Math.floor(Math.random() * (bounds.max - bounds.min + 1) + bounds.min);
  const elapsed = (Date.now() - lastSendAtByMailbox[mailboxId]) / 1000;
  const remaining = waitSec - elapsed;
  if (remaining > 0) await new Promise(r => setTimeout(r, remaining * 1000));
}

function buildDeferredNote({ skippedWindow, skippedQuota, skippedDomain, sendWindow }) {
  const parts = [];
  if (skippedWindow) parts.push(`${skippedWindow} waiting for send window (${sendWindow.start}:00–${sendWindow.end}:00 lead local)`);
  if (skippedQuota) parts.push(`${skippedQuota} waiting for mailbox daily limit (resumes tomorrow)`);
  if (skippedDomain) parts.push(`${skippedDomain} waiting for domain send spacing (retry soon)`);
  return parts.length ? parts.join(' · ') : undefined;
}

const activeSendByUser = new Set();

async function logActivity(job_id, contact_id, user_id, action_type, description, old_value, new_value) {
  try {
    await supabase.from('activity_log').insert({
      job_id: job_id || null, contact_id: contact_id || null, user_id: user_id || null,
      action_type, description: description || null,
      old_value: old_value || null, new_value: new_value || null
    });
  } catch (e) { console.error('activity_log insert failed:', e.message); }
}

// ── INDUSTRY NORMALIZATION (shared across routes) ──────────────
const INDUSTRIES = ["Accounting & Finance","Advertising & Public Relations","Agriculture","Airline, Aviation & Transportation","Architecture, Construction & Building Materials","Art, Photography & Journalism","Automotive & Motor Vehicles","Banking & Financial Services","Biotechnology & Pharmaceutical","Broadcasting, Media & Printing","Chemical & Industrial","Computer Hardware & Software","Consulting & Consulting Engineering","Consumer Products & Retail","Credit, Loan, Mortgage & Collections","Defense, Military & Aerospace","Education, Training & Library Science","Electronics & Semiconductor","Employment, Recruiting & Staffing","Energy, Utilities, Oil & Petroleum","Entertainment & Recreation","Environmental","Fashion, Apparel & Textile","Food & Restaurant","Funeral & Cemetery","Government & Civil Service","Healthcare & Health Services","Homebuilding & Real Estate","Hospitality, Hotel & Resort","HVAC","Import & Export","Insurance & Managed Care","Internet & ECommerce","Landscaping","Law Enforcement, Legal & Security","Manufacturing & Manufacturing Engineering","Medical Equipment","Not for Profit & Social Services","Office Supplies & Equipment","Packaging","Sales & Marketing","Securities","Social Media & Wireless Telecommunications","Travel"];
function normInd(raw) {
  if (!raw) return 'Unknown';
  if (INDUSTRIES.includes(raw)) return raw;
  const r = raw.toLowerCase();
  if (r.includes('account')||r.includes('cpa')||r.includes('bookkeep')) return 'Accounting & Finance';
  if (r.includes('advertis')||r.includes('public relation')) return 'Advertising & Public Relations';
  if (r.includes('agricultur')||r.includes('farm')) return 'Agriculture';
  if (r.includes('airline')||r.includes('aviation')||r.includes('transport')||r.includes('logistics')||r.includes('freight')) return 'Airline, Aviation & Transportation';
  if (r.includes('architect')||r.includes('construction')||r.includes('building material')) return 'Architecture, Construction & Building Materials';
  if (r.includes('photo')||r.includes('journalism')||r.includes('creative')) return 'Art, Photography & Journalism';
  if (r.includes('automotive')||r.includes('motor vehicle')||r.includes('automobile')) return 'Automotive & Motor Vehicles';
  if (r.includes('banking')||r.includes('bank ')||r.includes('financial service')) return 'Banking & Financial Services';
  if (r.includes('biotech')||r.includes('pharma')||r.includes('life science')) return 'Biotechnology & Pharmaceutical';
  if (r.includes('broadcast')||r.includes('media')||r.includes('print')||r.includes('publish')||r.includes('television')) return 'Broadcasting, Media & Printing';
  if (r.includes('chemical')||r.includes('industrial')||r.includes('petrochemical')) return 'Chemical & Industrial';
  if (r.includes('software')||r.includes('computer')||r.includes('hardware')||r.includes('technology')||r.includes(' tech')||r.includes(' it ')||r.includes('information tech')||r.includes('saas')||r.includes('cloud')) return 'Computer Hardware & Software';
  if (r.includes('consult')||r.includes('advisory')) return 'Consulting & Consulting Engineering';
  if (r.includes('consumer')||r.includes('retail')||r.includes('ecommerce')) return 'Consumer Products & Retail';
  if (r.includes('credit')||r.includes('loan')||r.includes('mortgage')||r.includes('collection')) return 'Credit, Loan, Mortgage & Collections';
  if (r.includes('defense')||r.includes('military')||r.includes('aerospace')) return 'Defense, Military & Aerospace';
  if (r.includes('educat')||r.includes('school')||r.includes('university')||r.includes('training')||r.includes('library')) return 'Education, Training & Library Science';
  if (r.includes('electron')||r.includes('semiconductor')) return 'Electronics & Semiconductor';
  if (r.includes('staffing')||r.includes('recruiting')||r.includes('employment')) return 'Employment, Recruiting & Staffing';
  if (r.includes('energy')||r.includes('utilit')||r.includes('oil')||r.includes('gas')||r.includes('petroleum')||r.includes('solar')||r.includes('renewable')) return 'Energy, Utilities, Oil & Petroleum';
  if (r.includes('entertain')||r.includes('recreation')||r.includes('gaming')||r.includes('casino')) return 'Entertainment & Recreation';
  if (r.includes('environ')) return 'Environmental';
  if (r.includes('fashion')||r.includes('apparel')||r.includes('textile')||r.includes('clothing')) return 'Fashion, Apparel & Textile';
  if (r.includes('food')||r.includes('restaurant')||r.includes('beverage')||r.includes('catering')) return 'Food & Restaurant';
  if (r.includes('funeral')||r.includes('cemetery')) return 'Funeral & Cemetery';
  if (r.includes('government')||r.includes('civil service')||r.includes('public sector')) return 'Government & Civil Service';
  if (r.includes('health')||r.includes('medical')||r.includes('hospital')||r.includes('dental')||r.includes('clinic')||r.includes('nurs')) return 'Healthcare & Health Services';
  if (r.includes('real estate')||r.includes('homebuilding')||r.includes('property')) return 'Homebuilding & Real Estate';
  if (r.includes('hotel')||r.includes('hospitality')||r.includes('resort')) return 'Hospitality, Hotel & Resort';
  if (r.includes('hvac')||r.includes('heating')||r.includes('ventilat')) return 'HVAC';
  if (r.includes('import')||r.includes('export')) return 'Import & Export';
  if (r.includes('insurance')||r.includes('managed care')) return 'Insurance & Managed Care';
  if (r.includes('internet')||r.includes('ecommerce')||r.includes('e-commerce')) return 'Internet & ECommerce';
  if (r.includes('landscap')) return 'Landscaping';
  if (r.includes('law')||r.includes('legal')||r.includes('security')||r.includes('enforce')) return 'Law Enforcement, Legal & Security';
  if (r.includes('manufactur')||r.includes('engineering')) return 'Manufacturing & Manufacturing Engineering';
  if (r.includes('medical equip')||r.includes('medical device')) return 'Medical Equipment';
  if (r.includes('non-profit')||r.includes('nonprofit')||r.includes('not for profit')||r.includes('social service')||r.includes('charity')) return 'Not for Profit & Social Services';
  if (r.includes('office suppli')||r.includes('office equip')) return 'Office Supplies & Equipment';
  if (r.includes('packag')) return 'Packaging';
  if (r.includes('sales')||r.includes('marketing')) return 'Sales & Marketing';
  if (r.includes('securit')||r.includes('investment')) return 'Securities';
  if (r.includes('telecom')||r.includes('wireless')||r.includes('social media')) return 'Social Media & Wireless Telecommunications';
  if (r.includes('travel')||r.includes('tourism')) return 'Travel';
  return raw || 'Unknown';
}

// ── HEALTH ─────────────────────────────────────────────────────
app.use(express.static('public', {
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));
// Block all write operations for guest users
app.use(function(req, res, next) {
  if (['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    const token = (req.headers.authorization||'').replace('Bearer ','');
    if (token === 'guest') return res.status(403).json({ error: 'Guest users have read-only access.' });
  }
  next();
});
app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('/health', (req, res) => res.json({ ok: true }));
app.get('/api/version', (req, res) => res.json({
  ok: true,
  version: '3.0.0',
  commit: process.env.RENDER_GIT_COMMIT || null,
  branch: process.env.RENDER_GIT_BRANCH || null,
  deployedAt: process.env.RENDER || 'local'
}));
app.get('/industries', auth, (req, res) => res.json(INDUSTRIES));

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const { data: user, error } = await supabase.from('users').select('*')
      .eq('email', email.toLowerCase().trim()).eq('is_active', true).is('deleted_at', null).single();
    if (error || !user) return res.status(401).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
    const roles = user.roles || (user.role ? [user.role] : []);
    const token = jwt.sign(
      { id: user.id, email: user.email, roles, role: roles[0] || 'ra', name: user.name },
      process.env.JWT_SECRET, { expiresIn: '8h' }
    );
    const { password_hash, ...safeUser } = user;
    res.json({ token, user: { ...safeUser, roles } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const { data: user } = await supabase.from('users').select('password_hash').eq('id', req.user.id).single();
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password incorrect' });
    const hash = await bcrypt.hash(newPassword, 10);
    await supabase.from('users').update({ password_hash: hash, updated_at: new Date() }).eq('id', req.user.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// USERS
// ══════════════════════════════════════════════════════════════
const USER_COLS = 'id,name,email,role,roles,employee_id,designation,platform,is_active,created_at';

app.get('/users', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select(USER_COLS).is('deleted_at', null).order('name');
    if (error) throw error;
    res.json(data.map(u => ({ ...u, roles: u.roles || (u.role ? [u.role] : []) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/users/me', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select(USER_COLS).eq('id', req.user.id).single();
    if (error) throw error;
    res.json({ ...data, roles: data.roles || (data.role ? [data.role] : []) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/users', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin')) return res.status(403).json({ error: 'Admin only' });
    const { name, email, password, roles, role, employee_id, designation, platform } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Name and email required' });
    const userRoles = roles || (role ? [role] : ['ra']);
    const hash = await bcrypt.hash(password || 'Fute@2024', 10);
    const { data, error } = await supabase.from('users').insert({
      name, email: email.toLowerCase().trim(), password_hash: hash,
      role: userRoles[0] || 'ra', roles: userRoles,
      employee_id, designation, platform: platform || 'Gmail'
    }).select(USER_COLS).single();
    if (error) throw error;
    res.status(201).json({ ...data, roles: data.roles || userRoles });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/users/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!hasRole(req, 'admin') && req.user.id !== id) return res.status(403).json({ error: 'Forbidden' });
    const { name, email, roles, role, employee_id, designation, platform } = req.body;
    const updates = { updated_at: new Date() };
    if (name) updates.name = name;
    if (email) updates.email = email.toLowerCase().trim();
    if (roles && hasRole(req, 'admin')) { updates.roles = roles; updates.role = roles[0] || 'ra'; }
    else if (role && hasRole(req, 'admin')) { updates.role = role; updates.roles = [role]; }
    if (employee_id) updates.employee_id = employee_id;
    if (designation !== undefined) updates.designation = designation;
    if (platform) updates.platform = platform;
    const { data, error } = await supabase.from('users').update(updates).eq('id', id).select(USER_COLS).single();
    if (error) throw error;
    res.json({ ...data, roles: data.roles || (data.role ? [data.role] : []) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update roles only
app.put('/users/:id/roles', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin')) return res.status(403).json({ error: 'Admin only' });
    const { roles } = req.body;
    if (!Array.isArray(roles) || !roles.length) return res.status(400).json({ error: 'roles array required' });
    const { data, error } = await supabase.from('users')
      .update({ roles, role: roles[0], updated_at: new Date() })
      .eq('id', req.params.id).select(USER_COLS).single();
    if (error) throw error;
    res.json({ ...data, roles });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/users/:id', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin')) return res.status(403).json({ error: 'Admin only' });
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    await supabase.from('users').update({ deleted_at: new Date(), is_active: false }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// USER EMAILS — email IDs per user
// ══════════════════════════════════════════════════════════════
app.get('/users/:id/emails', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('user_emails')
      .select('*').eq('user_id', req.params.id).order('created_at');
    if (error) throw error;
    // Attach ms_connected flag
    const ids = (data || []).map(e => e.id);
    const { data: tokens } = ids.length
      ? await supabase.from('microsoft_tokens').select('user_email_id').in('user_email_id', ids)
      : { data: [] };
    const connectedSet = new Set((tokens || []).map(t => t.user_email_id));
    res.json((data || []).map(e => ({ ...e, ms_connected: connectedSet.has(e.id) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/users/:id/emails', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd_lead') && req.user.id !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
    const { email_address, display_name, platform, daily_send_limit, is_primary } = req.body;
    if (!email_address) return res.status(400).json({ error: 'email_address required' });
    // If setting as primary, unset others first
    if (is_primary) {
      await supabase.from('user_emails').update({ is_primary: false }).eq('user_id', req.params.id);
    }
    const { data, error } = await supabase.from('user_emails').insert({
      user_id: req.params.id,
      email_address: email_address.toLowerCase().trim(),
      display_name: display_name || email_address,
      platform: platform || 'Microsoft',
      is_primary: is_primary || false,
      is_active: true,
      daily_send_limit: daily_send_limit || 150
    }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/users/:id/emails/:eid', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd_lead') && req.user.id !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
    const { is_active, is_primary, display_name, daily_send_limit, platform } = req.body;
    const updates = { updated_at: new Date() };

    // Enforce max 4 active per user
    if (is_active === true) {
      const { count } = await supabase.from('user_emails')
        .select('id', { count: 'exact', head: true })
        .eq('user_id', req.params.id).eq('is_active', true).neq('id', req.params.eid);
      if (count >= 4) return res.status(400).json({ error: 'Maximum 4 active email IDs allowed per user' });
    }

    if (is_active !== undefined) updates.is_active = is_active;
    if (display_name !== undefined) updates.display_name = display_name;
    if (daily_send_limit !== undefined) updates.daily_send_limit = daily_send_limit;
    if (platform !== undefined) updates.platform = platform;

    // If setting as primary, unset others first
    if (is_primary === true) {
      await supabase.from('user_emails').update({ is_primary: false }).eq('user_id', req.params.id);
      updates.is_primary = true;
    }

    const { data, error } = await supabase.from('user_emails').update(updates)
      .eq('id', req.params.eid).eq('user_id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/users/:id/emails/:eid', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd_lead') && req.user.id !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
    await supabase.from('user_emails').delete().eq('id', req.params.eid).eq('user_id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/users/:id/emails/:eid/signature', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd_lead') && req.user.id !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
    const { data: mailbox, error } = await supabase.from('user_emails').select('id,user_id,email_address,display_name').eq('id', req.params.eid).eq('user_id', req.params.id).single();
    if (error || !mailbox) return res.status(404).json({ error: 'Email ID not found' });
    const map = await loadMailboxSignatures([mailbox.id], mailbox.user_id);
    const raw = map[mailbox.id] || '';
    const signature_html = resolveSignatureHtml(raw);
    if (raw && signature_html !== raw) {
      const key = mailboxSignatureKey(mailbox.id);
      await supabase.from('app_settings').upsert(
        { key, value: signature_html, updated_at: new Date() },
        { onConflict: 'key' }
      );
    }
    res.json({ signature_html, display_name: mailbox.display_name, email_address: mailbox.email_address });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/users/:id/emails/:eid/signature', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd_lead', 'bd') && req.user.id !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
    const { signature_html } = req.body;
    if (signature_html === undefined) return res.status(400).json({ error: 'signature_html required' });
    const { data: mailbox, error } = await supabase.from('user_emails').select('id,user_id').eq('id', req.params.eid).eq('user_id', req.params.id).single();
    if (error || !mailbox) return res.status(404).json({ error: 'Email ID not found' });
    const key = mailboxSignatureKey(mailbox.id);
    const { error: upsertErr } = await supabase.from('app_settings').upsert(
      { key, value: String(signature_html), updated_at: new Date() },
      { onConflict: 'key' }
    );
    if (upsertErr) throw upsertErr;
    res.json({ success: true, signature_html: String(signature_html) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// TEAM ASSIGNMENTS
// ══════════════════════════════════════════════════════════════
app.get('/team-assignments', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('team_assignments')
      .select('*, member:users!member_id(id,name,email,roles,role), manager:users!manager_id(id,name,email,roles,role)')
      .order('created_at');
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/team-assignments', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin')) return res.status(403).json({ error: 'Admin only' });
    const { member_id, manager_id, assignment_type } = req.body;
    if (!member_id || !manager_id || !assignment_type) return res.status(400).json({ error: 'member_id, manager_id, assignment_type required' });
    const { data, error } = await supabase.from('team_assignments').insert({ member_id, manager_id, assignment_type }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/team-assignments/:id', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin')) return res.status(403).json({ error: 'Admin only' });
    await supabase.from('team_assignments').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// COMPANIES
// ══════════════════════════════════════════════════════════════
app.get('/companies', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('companies').select('*').is('deleted_at', null).order('name');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/lookup/zipcode', auth, async (req, res) => {
  try {
    const { zip } = req.query;
    if (!zip || zip.length < 3) return res.json([]);
    const resp = await fetch(`https://api.zippopotam.us/us/${zip.trim()}`);
    if (!resp.ok) return res.json([]);
    const data = await resp.json();
    const places = (data.places || []).map(p => ({
      zip: data['post code'], city: p['place name'], state: p['state'],
      state_abbr: p['state abbreviation'],
      display: `${p['place name']}, ${p['state abbreviation']} ${data['post code']}`
    }));
    res.json(places);
  } catch (err) { res.json([]); }
});

app.get('/companies/search', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) return res.json([]);
    const { data, error } = await supabase.from('companies')
      .select('id,name,industry,location,website').ilike('name', `%${q}%`).is('deleted_at', null).limit(8);
    if (error) throw error;
    const result = await Promise.all((data || []).map(async co => {
      const { count } = await supabase.from('jobs').select('id', { count: 'exact', head: true }).eq('company_id', co.id).is('deleted_at', null);
      return { ...co, job_count: count || 0 };
    }));
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/contacts/check-email', auth, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ duplicate: false });
    const twoMonthsAgo = new Date(); twoMonthsAgo.setMonth(twoMonthsAgo.getMonth() - 2);
    const { data, error } = await supabase.from('contacts')
      .select('id,first_name,last_name,email,created_at,job:jobs(id,position,company:companies(name))')
      .eq('email', email.toLowerCase().trim()).gte('created_at', twoMonthsAgo.toISOString()).limit(1);
    if (error) throw error;
    if (!data?.length) return res.json({ duplicate: false });
    const c = data[0];
    const daysSince = Math.floor((new Date() - new Date(c.created_at)) / 86400000);
    res.json({ duplicate: true, days_ago: daysSince, contact_name: `${c.first_name} ${c.last_name}`.trim(), company: c.job?.company?.name || '', position: c.job?.position || '' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/companies/bulk', auth, async (req, res) => {
  try {
    const { companies } = req.body;
    if (!Array.isArray(companies) || !companies.length) return res.status(400).json({ error: 'companies array required' });
    const rows = companies.map(c => ({ name: c.name, website: c.website || null, industry: c.industry || null, location: c.location || null, created_by: req.user.id }));
    const { data, error } = await supabase.from('companies').insert(rows).select('id,name');
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/companies', auth, async (req, res) => {
  try {
    const { name, website, industry, location, size, notes } = req.body;
    if (!name) return res.status(400).json({ error: 'Company name required' });
    const { data, error } = await supabase.from('companies').insert({ name, website, industry, location, size, notes, created_by: req.user.id }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/companies/:id', auth, async (req, res) => {
  try {
    const { name, website, industry, location, size, notes } = req.body;
    const updates = { updated_at: new Date() };
    if (name !== undefined) updates.name = name;
    if (website !== undefined) updates.website = website;
    if (industry !== undefined) updates.industry = industry;
    if (location !== undefined) updates.location = location;
    if (size !== undefined) updates.size = size;
    if (notes !== undefined) updates.notes = notes;
    const { data, error } = await supabase.from('companies').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/companies/:id', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin')) return res.status(403).json({ error: 'Admin only' });
    await supabase.from('companies').update({ deleted_at: new Date() }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// JOBS
// ══════════════════════════════════════════════════════════════
const JOB_SELECT = `*, research, company:companies(id,name,website,industry,location), contacts(id,job_id,first_name,last_name,designation,email,phone,linkedin,is_primary,email_status,ooo_until,email_sent_at,email_platform), creator:users!created_by(id,name,employee_id), assignee:users!assigned_to(id,name,employee_id), bd_assignee:users!assigned_to_bd(id,name,employee_id), sending_email:user_emails!sending_email_id(id,email_address,display_name)`;

app.get('/jobs', auth, async (req, res) => {
  try {
    let query = supabase.from('jobs').select(JOB_SELECT).is('deleted_at', null).order('created_at', { ascending: false });
    if (hasRole(req, 'admin', 'ra_lead')) {
      // see all
    } else if (hasRole(req, 'bd_lead')) {
      query = query.not('assigned_to_bd', 'is', null);
    } else if (hasRole(req, 'bd')) {
      query = query.eq('assigned_to_bd', req.user.id);
    } else {
      query = query.eq('created_by', req.user.id);
    }
    const { data, error } = await query;
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/jobs/today-summary', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'ra_lead')) return res.status(403).json({ error: 'Not allowed' });
    const todayStr = today();
    const { data: todayJobs, error } = await supabase
      .from('jobs')
      .select('id, position, industry, location, freshness, is_duplicate, timezone, company:companies(name, industry), contacts(id, designation)')
      .gte('created_at', todayStr + 'T00:00:00Z')
      .is('deleted_at', null);
    if (error) throw error;
    const total = todayJobs.length;
    const duplicates = todayJobs.filter(j => j.is_duplicate).length;
    const clean = total - duplicates;
    const byIndustry = {};
    todayJobs.forEach(j => { const ind = j.industry || j.company?.industry || 'Unknown'; byIndustry[ind] = (byIndustry[ind] || 0) + 1; });
    const byFreshness = {};
    todayJobs.forEach(j => { const f = j.freshness || 'Normal'; byFreshness[f] = (byFreshness[f] || 0) + 1; });
    const byTimezone = {};
    todayJobs.forEach(j => { const tz = j.timezone || 'EST'; byTimezone[tz] = (byTimezone[tz] || 0) + 1; });
    const byPosition = {};
    todayJobs.forEach(j => { byPosition[j.position] = (byPosition[j.position] || 0) + 1; });
    const topPositions = Object.entries(byPosition).sort((a,b) => b[1]-a[1]).slice(0,5).map(([k,v]) => `${k} (${v})`);
    const totalContacts = todayJobs.reduce((s, j) => s + (j.contacts?.length || 0), 0);
    const { count: poolSize } = await supabase.from('jobs').select('id', { count: 'exact', head: true }).eq('stage', 'Unassigned').is('deleted_at', null);
    res.json({ date: todayStr, total, clean, duplicates, totalContacts, byIndustry, byFreshness, byTimezone, topPositions, poolSize: poolSize || 0 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/jobs/:id', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('jobs').select(JOB_SELECT).eq('id', req.params.id).is('deleted_at', null).single();
    if (error) throw error;
    if (!hasRole(req, 'admin', 'ra_lead', 'bd_lead') && data.created_by !== req.user.id && data.assigned_to !== req.user.id && data.assigned_to_bd !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/**
 * Skill inference from the system's own job history.
 *
 * For title-only imports, look up past jobs with similar normalized titles
 * and reuse their verified skills. Past jobs whose skills were themselves
 * guessed (title_inference / history_match) are excluded so guesses never
 * compound. Human-assigned skill_1..3 are preferred over machine-suggested.
 *
 * Returns Map<originalTitle, skills[]>.
 */
async function inferSkillsFromJobHistory(positions) {
  const result = new Map();
  const wanted = [...new Set(positions.filter(Boolean))];
  if (!wanted.length) return result;

  const { data: history } = await supabase.from('jobs')
    .select('position, research')
    .not('research', 'is', null)
    .is('deleted_at', null)
    .order('created_at', { ascending: false })
    .limit(1500);
  if (!history || !history.length) return result;

  const entries = [];
  for (const row of history) {
    if (!row.position) continue;
    let research = row.research;
    if (typeof research === 'string') { try { research = JSON.parse(research); } catch { continue; } }
    const reqr = research && research.requirements;
    if (!reqr) continue;
    if (reqr.skills_source === 'title_inference' || reqr.skills_source === 'history_match') continue;
    let skills = [reqr.skill_1, reqr.skill_2, reqr.skill_3].filter(Boolean);
    if (skills.length < 2 && Array.isArray(reqr.suggested_skills)) skills = reqr.suggested_skills.filter(Boolean);
    if (!skills.length) continue;
    const norm = normalizeJobTitle(row.position);
    if (!norm.tokens.length) continue;
    entries.push({ norm, skills });
  }
  if (!entries.length) return result;

  for (const pos of wanted) {
    const norm = normalizeJobTitle(pos);
    if (!norm.tokens.length) continue;
    const freq = new Map();
    let matches = 0;
    for (const e of entries) {
      const sim = titleSimilarity(norm.canon, e.norm.canon);
      const headMatch = norm.head && e.norm.head === norm.head;
      // Either nearly identical titles, or same role noun with decent overlap
      if (!(sim >= 0.75 || (headMatch && sim >= 0.45))) continue;
      matches++;
      for (const s of e.skills) {
        const k = String(s).toLowerCase();
        const cur = freq.get(k) || { skill: s, score: 0 };
        cur.score += sim; // weight by similarity
        freq.set(k, cur);
      }
      if (matches >= 25) break; // enough evidence
    }
    if (!freq.size) continue;
    const top = [...freq.values()].sort((a, b) => b.score - a.score).slice(0, 5).map((x) => x.skill);
    result.set(pos, top);
  }
  return result;
}

app.post('/jobs/bulk', auth, async (req, res) => {
  try {
    const { jobs } = req.body;
    if (!Array.isArray(jobs) || !jobs.length) return res.status(400).json({ error: 'jobs array required' });
    // Filter out companies in 21-day cooldown for RA users
    const cooldownDate = new Date(Date.now() - 21 * 24 * 3600 * 1000).toISOString();
    const companyIds = [...new Set(jobs.map(j => j.company_id).filter(Boolean))];
    let cooledDown = new Set();
    if (companyIds.length) {
      const { data: recent } = await supabase.from('jobs').select('company_id').in('company_id', companyIds).gte('created_at', cooldownDate).is('deleted_at', null);
      cooledDown = new Set((recent || []).map(r => r.company_id));
    }
    const skipped = jobs.filter(j => cooledDown.has(j.company_id)).length;
    const filteredJobs = jobs.filter(j => !cooledDown.has(j.company_id));
    function getFreshness(openedDate, createdDate) {
      const ref = openedDate || createdDate;
      if (!ref) return 'Normal';
      const days = Math.floor((new Date() - new Date(ref)) / 86400000);
      if (days <= 3) return 'New'; if (days <= 10) return 'Normal'; return 'Old';
    }
    const jobRows = filteredJobs.map(j => {
      const research = buildResearchFromLeadData({
        notes: j.notes,
        jdText: j.jd_text,
        position: j.position,
        location: j.location,
        salaryRange: j.salary_range,
        industry: j.industry
      });
      const row = {
        company_id: j.company_id,
        position: j.position || '(unknown)',
        location: j.location || null,
        source: j.source || 'Import',
        job_url: j.job_url || null,
        stage: 'Unassigned',
        notes: j.notes || '',
        created_by: req.user.id,
        assigned_to: null,
        is_duplicate: j.is_duplicate || false,
        duplicate_of: j.duplicate_of || null,
        salary_range: j.salary_range || null,
        job_created_date: j.job_created_date || null,
        job_opened_date: j.job_opened_date || null,
        timezone: getTimezoneFromLocation(j.location),
        freshness: getFreshness(j.job_opened_date, j.job_created_date),
        bdm_assigned_name: j.bdm_assigned_name || null,
        industry: j.industry || null
      };
      if (research) row.research = research;
      return row;
    });
    if (!jobRows.length) return res.status(200).json({ imported: 0, contacts: 0, skipped, message: `All ${skipped} companies are in a 21-day cooldown period.` });

    // For title-only leads (skills guessed from the title, or none at all),
    // check the system's own history: similar past titles with verified
    // skills are a better source than archetype guesses.
    try {
      const needsHistory = jobRows.filter((row) => {
        const reqr = row.research && row.research.requirements;
        if (!reqr) return false;
        return reqr.skills_source === 'title_inference' || !(reqr.suggested_skills || []).length;
      });
      if (needsHistory.length) {
        const historySkills = await inferSkillsFromJobHistory(needsHistory.map((r) => r.position));
        for (const row of needsHistory) {
          const skills = historySkills.get(row.position);
          if (!skills || !skills.length) continue;
          const reqr = row.research.requirements;
          reqr.skills = skills;
          reqr.suggested_skills = skills;
          reqr.skill_1 = skills[0] || '';
          reqr.skill_2 = skills[1] || '';
          reqr.skill_3 = skills[2] || '';
          reqr.skills_source = 'history_match';
        }
      }
    } catch (e) { /* history lookup is best-effort — never block an import */ }
    const { data: insertedJobs, error: jobErr } = await supabase.from('jobs').insert(jobRows).select('id');
    if (jobErr) throw jobErr;
    const contactRows = [];
    insertedJobs.forEach((job, idx) => {
      const contacts = filteredJobs[idx].contacts || [];
      contacts.forEach((c, ci) => {
        if (!c.first_name && !c.email) return;
        contactRows.push({ job_id: job.id, first_name: c.first_name || '', last_name: c.last_name || '', designation: c.designation || null, email: c.email || null, phone: c.phone || null, linkedin: c.linkedin || null, is_primary: ci === 0 });
      });
    });
    if (contactRows.length) { await supabase.from('contacts').insert(contactRows); }
    res.status(201).json({ imported: insertedJobs.length, contacts: contactRows.length, skipped });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/jobs', auth, async (req, res) => {
  try {
    const { company_id, position, location, source, job_url, stage, notes, assigned_to, is_duplicate, duplicate_of, contacts, salary_range, job_created_date, job_opened_date, bdm_assigned_name, industry: jobIndustry, research } = req.body;
    if (!company_id || !position) return res.status(400).json({ error: 'company_id and position required' });
    // 21-day company cooldown — block RA from re-adding same company within 21 days
    if (hasRole(req, 'ra')) {
      const cooldownDate = new Date(Date.now() - 21 * 24 * 3600 * 1000).toISOString();
      const { data: recent } = await supabase.from('jobs').select('id,position,created_at').eq('company_id', company_id).gte('created_at', cooldownDate).is('deleted_at', null).limit(1);
      if (recent && recent.length > 0) {
        const daysAgo = Math.floor((Date.now() - new Date(recent[0].created_at).getTime()) / 86400000);
        const daysLeft = 21 - daysAgo;
        return res.status(409).json({ error: `This company is in a 21-day cooldown period. ${daysLeft} day${daysLeft !== 1 ? 's' : ''} remaining (last added: ${recent[0].position}).` });
      }
    }
    const timezone = getTimezoneFromLocation(location);
    let freshness = 'Normal';
    const refDate = job_opened_date || job_created_date;
    if (refDate) { const days = Math.floor((new Date() - new Date(refDate)) / 86400000); if (days <= 3) freshness = 'New'; else if (days <= 10) freshness = 'Normal'; else freshness = 'Old'; }
    const { data: job, error } = await supabase.from('jobs').insert({
      company_id, position, location, source, job_url, stage: stage || 'Unassigned', notes: notes || '',
      created_by: req.user.id,
      assigned_to: (hasRole(req, 'admin', 'ra_lead') ? (assigned_to || null) : null),
      is_duplicate: is_duplicate || false, duplicate_of: duplicate_of || null, salary_range: salary_range || null,
      job_created_date: job_created_date || null, job_opened_date: job_opened_date || null,
      timezone, freshness, bdm_assigned_name: bdm_assigned_name || null, industry: jobIndustry || null,
      research: research || null
    }).select().single();
    if (error) throw error;
    if (Array.isArray(contacts) && contacts.length) {
      const rows = contacts.map((c, i) => ({ job_id: job.id, first_name: c.first_name || '', last_name: c.last_name || '', designation: c.designation || null, email: c.email || null, phone: c.phone || null, linkedin: c.linkedin || null, is_primary: i === 0 }));
      await supabase.from('contacts').insert(rows);
    }
    await logActivity(job.id, null, req.user.id, 'job_created', `Job created: ${position}`, null, { position, stage: job.stage });
    if (research) persistLearnedSkills(jobIndustry, research);
    res.status(201).json(job);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/jobs/:id', auth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const isRA = hasRole(req, 'ra') && !hasRole(req, 'admin', 'ra_lead', 'bd', 'bd_lead');
    const hoursSinceCreation = (new Date() - new Date(existing.created_at)) / 3600000;
    const raCanEdit = isRA && existing.created_by === req.user.id && hoursSinceCreation <= 24;
    const canEdit = hasRole(req, 'admin', 'ra_lead', 'bd', 'bd_lead') || existing.created_by === req.user.id || existing.assigned_to_bd === req.user.id || raCanEdit;
    if (!canEdit) return res.status(403).json({ error: 'Forbidden' });
    if (isRA && !raCanEdit) return res.status(403).json({ error: 'Edit window has expired (24 hours)' });
    const { position, location, source, job_url, stage, notes, assigned_to, assigned_to_bd, sending_email_id, salary_range, job_created_date, industry: jobIndustry, research } = req.body;
    const updates = { updated_at: new Date() };
    if (position !== undefined) updates.position = position;
    if (location !== undefined) {
      updates.location = location;
      updates.timezone = getTimezoneFromLocation(location);
    }
    if (source !== undefined) updates.source = source;
    if (job_url !== undefined) updates.job_url = job_url;
    if (stage !== undefined) {
      const bdStages = ['Connected','Rejected','Future','In Discussion'];
      const systemStages = ['Unassigned','Assigned'];
      if (bdStages.includes(stage) && hasRole(req, 'admin', 'bd', 'bd_lead')) updates.stage = stage;
      else if (systemStages.includes(stage) && hasRole(req, 'admin', 'ra_lead')) updates.stage = stage;
      else if (hasRole(req, 'admin')) updates.stage = stage;
    }
    if (notes !== undefined) updates.notes = notes;
    if (assigned_to !== undefined && hasRole(req, 'admin', 'ra_lead')) updates.assigned_to = assigned_to || null;
    if (assigned_to_bd !== undefined && hasRole(req, 'admin', 'ra_lead')) {
      updates.assigned_to_bd = assigned_to_bd || null;
      updates.assigned_at = assigned_to_bd ? new Date() : null;
      if (assigned_to_bd && stage === undefined) updates.stage = 'Assigned';
    }
    if (sending_email_id !== undefined && hasRole(req, 'admin', 'ra_lead')) updates.sending_email_id = sending_email_id || null;
    if (salary_range !== undefined) updates.salary_range = salary_range || null;
    if (job_created_date !== undefined) updates.job_created_date = job_created_date || null;
    if (jobIndustry !== undefined) updates.industry = jobIndustry || null;
    if (research !== undefined) updates.research = research;
    const { data, error } = await supabase.from('jobs').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    if (stage !== undefined && stage !== existing.stage) {
      await logActivity(data.id, null, req.user.id, 'stage_change', `Stage: ${existing.stage} → ${stage}`, { stage: existing.stage }, { stage });
      if (existing.stage === 'Assigned' && stage !== 'Assigned') {
        await supabase.from('follow_ups').update({ status: 'skipped' }).eq('job_id', req.params.id).eq('status', 'active');
      }
    } else {
      await logActivity(data.id, null, req.user.id, 'job_updated', 'Job updated', null, null);
    }
    if (research !== undefined) persistLearnedSkills(jobIndustry || data.industry || existing.industry, research);
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/jobs/:id', auth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('jobs').select('created_by,position').eq('id', req.params.id).single();
    if (!existing) return res.status(404).json({ error: 'Not found' });
    if (!hasRole(req, 'admin') && existing.created_by !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    await supabase.from('jobs').update({ deleted_at: new Date() }).eq('id', req.params.id);
    await logActivity(req.params.id, null, req.user.id, 'job_deleted', `Job deleted: ${existing.position}`, null, null);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/jobs/export', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'ra_lead')) return res.status(403).json({ error: 'RA Lead only' });
    const { from, to, stage } = req.query;
    let query = supabase.from('jobs').select('id,position,stage,location,industry,timezone,freshness,salary_range,job_created_date,job_opened_date,bdm_assigned_name,source,created_at,company:companies(name,website,industry,location),contacts(first_name,last_name,designation,email,phone,linkedin),creator:users!created_by(name)').is('deleted_at', null).order('created_at', { ascending: false });
    if (from) query = query.gte('created_at', from);
    if (to) query = query.lte('created_at', to + 'T23:59:59Z');
    if (stage) query = query.eq('stage', stage);
    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/jobs/:id/research', auth, async (req, res) => {
  try {
    const { research } = req.body;
    if (!research) return res.status(400).json({ error: 'research object required' });
    const { data: job } = await supabase.from('jobs').select('created_by,industry').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (!hasRole(req, 'admin', 'ra_lead') && job.created_by !== req.user.id) return res.status(403).json({ error: 'Only the RA who created this lead can add research' });
    const { data, error } = await supabase.from('jobs').update({ research, updated_at: new Date() }).eq('id', req.params.id).select('id,research,industry').single();
    if (error) throw error;
    persistLearnedSkills(data.industry || job.industry, research);
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/parse-jd', auth, async (req, res) => {
  try {
    const { jd_text, industry } = req.body;
    if (!jd_text || !String(jd_text).trim()) return res.status(400).json({ error: 'jd_text required' });
    const parsed = parseJobDescription(jd_text, industry || '');
    res.json(parsed);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/jobs/:id/parse-jd', auth, async (req, res) => {
  try {
    const { jd_text, industry } = req.body;
    if (!jd_text || !String(jd_text).trim()) return res.status(400).json({ error: 'jd_text required' });
    const { data: job } = await supabase.from('jobs').select('created_by,industry,company:companies(industry)').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (!hasRole(req, 'admin', 'ra_lead') && job.created_by !== req.user.id) return res.status(403).json({ error: 'Only the RA who created this lead can parse JD' });
    const resolvedIndustry = industry || job.industry || job.company?.industry || '';
    const parsed = parseJobDescription(jd_text, resolvedIndustry);
    res.json(parsed);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// CONTACTS
// ══════════════════════════════════════════════════════════════
async function canTouchJob(req, job_id) {
  if (hasRole(req, 'admin')) return true;
  const { data } = await supabase.from('jobs').select('created_by,assigned_to,assigned_to_bd').eq('id', job_id).single();
  if (!data) return false;
  return data.created_by === req.user.id || data.assigned_to === req.user.id || data.assigned_to_bd === req.user.id;
}

app.get('/jobs/:job_id/contacts', auth, async (req, res) => {
  try {
    if (!(await canTouchJob(req, req.params.job_id))) return res.status(403).json({ error: 'Forbidden' });
    const { data, error } = await supabase.from('contacts').select('*').eq('job_id', req.params.job_id).order('is_primary', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/contacts', auth, async (req, res) => {
  try {
    const { job_id, first_name, last_name, designation, email, phone, linkedin, is_primary } = req.body;
    if (!job_id || !first_name) return res.status(400).json({ error: 'job_id and first_name required' });
    if (!(await canTouchJob(req, job_id))) return res.status(403).json({ error: 'Forbidden' });
    const { data, error } = await supabase.from('contacts').insert({ job_id, first_name, last_name: last_name || '', designation, email, phone, linkedin, is_primary: !!is_primary }).select().single();
    if (error) throw error;
    await logActivity(job_id, data.id, req.user.id, 'contact_added', `Contact added: ${first_name} ${last_name || ''}`.trim(), null, null);
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/contacts/:id', auth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('contacts').select('job_id').eq('id', req.params.id).single();
    if (!existing) return res.status(404).json({ error: 'Not found' });
    if (!(await canTouchJob(req, existing.job_id))) return res.status(403).json({ error: 'Forbidden' });
    const fields = ['first_name','last_name','designation','email','phone','linkedin','is_primary','email_status','ooo_until'];
    const updates = { updated_at: new Date() };
    fields.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });
    const { data, error } = await supabase.from('contacts').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    if (req.body.email_status !== undefined && isPermanentFollowupBlock(req.body.email_status)) {
      await skipActiveFollowUpsForContact(req.params.id);
    }
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/contacts/:id', auth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('contacts').select('job_id').eq('id', req.params.id).single();
    if (!existing) return res.status(404).json({ error: 'Not found' });
    if (!(await canTouchJob(req, existing.job_id))) return res.status(403).json({ error: 'Forbidden' });
    await supabase.from('contacts').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/contacts/:id/email-status', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd', 'bd_lead')) return res.status(403).json({ error: 'BD role required' });
    const { email_status, ooo_until } = req.body;
    const allowed = ['valid','invalid','deactivated','out_of_office'];
    if (!allowed.includes(email_status)) return res.status(400).json({ error: 'Invalid status' });
    const updates = { email_status, updated_at: new Date() };
    if (email_status === 'out_of_office' && ooo_until) updates.ooo_until = ooo_until;
    if (email_status !== 'out_of_office') updates.ooo_until = null;
    const { data: contact, error } = await supabase.from('contacts').update(updates).eq('id', req.params.id).select('*, job:jobs(id,position,company:companies(name))').single();
    if (error) throw error;
    if (email_status === 'out_of_office' && ooo_until) {
      const contactName = `${contact.first_name || ''} ${contact.last_name || ''}`.trim();
      await supabase.from('reminders').insert({ job_id: contact.job_id, user_id: req.user.id, contact_name: contactName, company_name: contact.job?.company?.name || '', email: contact.email, return_date: ooo_until, reminder_time: '09:00', note: `${contactName} is back from OOO.`, status: 'pending', reminder_type: 'ooo_return', contact_id: contact.id });
      await logActivity(contact.job_id, contact.id, req.user.id, 'ooo_set', `${contactName} marked OOO until ${ooo_until}`, null, { ooo_until });
    }
    if (isPermanentFollowupBlock(email_status)) {
      await skipActiveFollowUpsForContact(contact.id);
    }
    res.json(contact);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// EMAILS
// ══════════════════════════════════════════════════════════════
app.get('/emails', auth, async (req, res) => {
  try {
    const { status } = req.query;
    // Paginate to avoid Supabase 1000-row silent cap
    let allData = [], from = 0;
    while (true) {
      let query = supabase.from('emails').select(`*, contact:contacts(id,first_name,last_name,email,designation), job:jobs(id,position,timezone,company_id,company:companies(name,industry,location),sending_email:user_emails!sending_email_id(id,email_address,display_name)), sender:users!sent_by(id,name,email)`).order('created_at', { ascending: false });
      if (!hasRole(req, 'admin', 'ra_lead')) query = query.eq('sent_by', req.user.id);
      if (status) query = query.eq('status', status);
      query = query.range(from, from + 999);
      const { data, error } = await query;
      if (error) throw error;
      if (!data || !data.length) break;
      allData = allData.concat(data);
      if (data.length < 1000) break;
      from += 1000;
    }
    res.json(allData);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/emails/pending-count', auth, async (req, res) => {
  try {
    const { count, error } = await supabase.from('emails').select('id', { count: 'exact', head: true }).eq('sent_by', req.user.id).eq('status', 'pending');
    if (error) throw error;
    res.json({ count: count || 0 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/emails/pending-summary', auth, async (req, res) => {
  try {
    const sendWindow = await getSendWindowHours();
    if (!hasRole(req, 'admin', 'ra_lead', 'bd', 'bd_lead')) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    let query = supabase.from('emails').select('id, job:jobs(timezone)').eq('status', 'pending');
    if (hasRole(req, 'admin', 'ra_lead') && req.query.manager_id) {
      query = query.eq('sent_by', req.query.manager_id);
    } else if (!hasRole(req, 'admin', 'ra_lead')) {
      query = query.eq('sent_by', req.user.id);
    }

    let rows = [], from = 0;
    while (true) {
      const { data, error } = await query.range(from, from + 999);
      if (error) throw error;
      if (!data || !data.length) break;
      rows = rows.concat(data);
      if (data.length < 1000) break;
      from += 1000;
    }

    const byTz = {};
    let ready_now = 0;
    let waiting_window = 0;
    for (const row of rows) {
      const tz = row.job?.timezone || 'EST';
      if (!byTz[tz]) byTz[tz] = { timezone: tz, pending: 0, ready_now: 0, waiting_window: 0 };
      byTz[tz].pending++;
      if (isInLeadSendWindow(tz, new Date(), sendWindow)) {
        byTz[tz].ready_now++;
        ready_now++;
      } else {
        byTz[tz].waiting_window++;
        waiting_window++;
      }
    }

    const by_timezone = Object.values(byTz)
      .sort((a, b) => b.pending - a.pending)
      .map(t => ({
        ...t,
        minutes_until_opens: getMinutesUntilWindowOpens(t.timezone, new Date(), sendWindow),
        resumes_label: formatWindowOpensLabel(t.timezone, sendWindow)
      }));

    const winLbl = `${padHour(sendWindow.start)} – ${padHour(sendWindow.end)} lead local time`;
    res.json({
      total_pending: rows.length,
      ready_now,
      waiting_window,
      by_timezone,
      send_window: sendWindow,
      send_window_label: winLbl,
      auto_retry: {
        interval_minutes: 20,
        note: 'In-window emails auto-retry every 20 minutes while the server is awake, and again ~3 minutes after startup.'
      }
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/emails/retry-pending-window', auth, async (req, res) => {
  try {
    if (notGuest(req, res)) return;
    let managerId = req.user.id;
    if (hasRole(req, 'admin', 'ra_lead') && req.body?.manager_id) managerId = req.body.manager_id;
    if (activeSendByUser.has(managerId)) {
      return res.json({ started: false, message: 'Send already in progress for this manager' });
    }
    res.json({ started: true, message: 'Retrying in-window pending emails' });
    autoSendForManager(managerId).catch(e => console.error('[RetryPendingWindow]', e.message));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/emails', auth, async (req, res) => {
  try {
    const { contact_id, job_id, to_email, subject, body, platform } = req.body;
    if (!to_email) return res.status(400).json({ error: 'to_email required' });
    const { data, error } = await supabase.from('emails').insert({ contact_id: contact_id || null, job_id: job_id || null, to_email, subject, body, platform: platform || 'Gmail', sent_by: req.user.id, status: 'sent', sent_at: today() }).select().single();
    if (error) throw error;
    if (contact_id) await supabase.from('contacts').update({ email_sent_at: today(), email_platform: platform || 'Gmail', updated_at: new Date() }).eq('id', contact_id);
    if (job_id) await logActivity(job_id, contact_id || null, req.user.id, 'email_sent', `Email sent: ${subject || ''}`, null, null);
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

function buildPendingEmailsFromJobs(jobs, callerUserId, bdMap, bdPrimaryEmailMap, tmplSettings) {
  const tasksByBd = {};
  let contactsSkipped = 0;

  for (const job of jobs) {
    const bd = bdMap[job.assigned_to_bd] || { id: callerUserId, name: '', email: '' };
    const contacts = (job.contacts || []).filter(c => isValidEmail(c.email));
    if (!contacts.length) {
      contactsSkipped++;
      continue;
    }
    if (!tasksByBd[bd.id]) tasksByBd[bd.id] = [];
    for (const contact of contacts) {
      tasksByBd[bd.id].push({ job, contact, bd });
    }
  }

  const emailsToInsert = [];
  for (const bdId of Object.keys(tasksByBd)) {
    const tasks = tasksByBd[bdId];
    const useRandom = isRandomTemplateMode(tmplSettings[`u_${bdId}_random_template_mode`]);
    const deck = useRandom ? buildRotatingTemplateDeck(tasks.length) : null;
    if (useRandom) {
      console.log(`[GenerateEmails] Random template rotation for BD ${bdId}: ${tasks.length} emails across ${deck.length} slots`);
    }

    tasks.forEach((task, idx) => {
      const { job, contact, bd } = task;
      try {
        const variant = deck ? deck[idx] : null;
        const subjTmpl = variant
          ? variant.o1.subject
          : resolveTemplate(tmplSettings[`u_${bd.id}_tmpl_o1_subject`], 'o1_subject');
        const bodyTmpl = variant
          ? variant.o1.body
          : resolveTemplate(tmplSettings[`u_${bd.id}_tmpl_o1_body`], 'o1_body');
        const senderDisplayName = job.sending_email?.display_name || bdPrimaryEmailMap[bd.id]?.display_name || bd.name || '';
        const vars = buildEmailVars({ job, contact, senderDisplayName });
        const subject = fillTemplate(subjTmpl, vars);
        const body = fillTemplate(bodyTmpl, vars);
        const resolvedSendingEmail = job.sending_email || bdPrimaryEmailMap[bd.id];
        const sendingEmailAddress = resolvedSendingEmail?.email_address || '';
        const row = {
          contact_id: contact.id,
          job_id: job.id,
          to_email: contact.email,
          subject,
          body,
          platform: 'Outlook',
          sent_by: bd.id,
          from_email: sendingEmailAddress,
          status: 'pending'
        };
        if (variant?.id) row.template_variant = variant.id;
        emailsToInsert.push(row);
      } catch (e) {
        console.error(`[GenerateEmails] contact error (${contact.email}):`, e.message);
      }
    });
  }

  return { emailsToInsert, contactsSkipped };
}

// Standalone generation function — called directly by autoSendForManager (no HTTP)
async function generateEmailsForJobs(job_ids, callerUserId) {
  // Batch fetch jobs in chunks to avoid Supabase URL length limits on .in()
  const BATCH_SIZE = 50;
  let jobs = [];
  for (let i = 0; i < job_ids.length; i += BATCH_SIZE) {
    const chunk = job_ids.slice(i, i + BATCH_SIZE);
    const { data, error } = await supabase.from('jobs').select('id, position, location, salary_range, research, industry, assigned_to_bd, sending_email_id, sending_email:user_emails!sending_email_id(id,email_address,display_name), company:companies(name,industry,location), contacts(*)').in('id', chunk);
    if (error) {
      console.error(`[GenerateEmails] Failed to fetch jobs batch ${i}-${i + chunk.length}:`, error.message);
      throw error;
    }
    jobs = jobs.concat(data || []);
  }
  if (!jobs.length) {
    console.log(`[GenerateEmails] No jobs found for IDs: ${job_ids.slice(0, 5).join(',')}...`);
    return 0;
  }
  console.log(`[GenerateEmails] Fetched ${jobs.length} jobs (requested ${job_ids.length})`);
  const bdIds = [...new Set(jobs.map(j => j.assigned_to_bd).filter(Boolean))];
  const { data: bdUsers } = bdIds.length ? await supabase.from('users').select('id,name,email').in('id', bdIds) : { data: [] };
  const bdMap = {};
  (bdUsers || []).forEach(u => { bdMap[u.id] = u; });
  const allBdIds = [...new Set([callerUserId, ...bdIds])];
  const { data: bdEmailRows } = allBdIds.length
    ? await supabase.from('user_emails').select('id,user_id,email_address,display_name,is_primary').in('user_id', allBdIds).order('is_primary', { ascending: false })
    : { data: [] };
  const bdPrimaryEmailMap = {};
  (bdEmailRows || []).forEach(e => { if (!bdPrimaryEmailMap[e.user_id]) bdPrimaryEmailMap[e.user_id] = e; });
  const tmplKeys = allBdIds.flatMap(id => [
    `u_${id}_tmpl_o1_subject`, `u_${id}_tmpl_o1_body`, `u_${id}_random_template_mode`
  ]);
  const { data: tmplRows } = await supabase.from('app_settings').select('key,value').in('key', tmplKeys);
  const tmplSettings = {};
  (tmplRows || []).forEach(r => { tmplSettings[r.key] = r.value; });

  const { emailsToInsert, contactsSkipped } = buildPendingEmailsFromJobs(
    jobs, callerUserId, bdMap, bdPrimaryEmailMap, tmplSettings
  );
  if (contactsSkipped) console.log(`[GenerateEmails] ${contactsSkipped} jobs had no valid contacts — skipped`);
  // Insert emails in batches of 500 to avoid Supabase payload limits
  const INSERT_BATCH = 500;
  let totalInserted = 0;
  for (let i = 0; i < emailsToInsert.length; i += INSERT_BATCH) {
    const batch = emailsToInsert.slice(i, i + INSERT_BATCH);
    const { error: insErr } = await supabase.from('emails').insert(batch);
    if (insErr) {
      console.error(`[GenerateEmails] Insert batch ${i}-${i + batch.length} failed:`, insErr.message);
      throw insErr;
    }
    totalInserted += batch.length;
  }
  console.log(`[GenerateEmails] Inserted ${totalInserted} emails for ${jobs.length} jobs (${job_ids.length} requested)`);
  return totalInserted;
}

app.post('/emails/generate', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'ra_lead', 'bd', 'bd_lead')) return res.status(403).json({ error: 'Not allowed' });
    const { job_ids } = req.body;
    if (!Array.isArray(job_ids) || !job_ids.length) return res.status(400).json({ error: 'job_ids required' });
    const { data: jobs, error: jErr } = await supabase.from('jobs').select('id, position, location, salary_range, research, industry, assigned_to_bd, sending_email_id, sending_email:user_emails!sending_email_id(id,email_address,display_name), company:companies(name,industry,location), contacts(*)').in('id', job_ids);
    if (jErr) throw jErr;
    const bdIds = [...new Set(jobs.map(j => j.assigned_to_bd).filter(Boolean))];
    const { data: bdUsers } = bdIds.length ? await supabase.from('users').select('id,name,email').in('id', bdIds) : { data: [] };
    const bdMap = {};
    (bdUsers || []).forEach(u => { bdMap[u.id] = u; });

    // Pre-fetch primary sending email for each BD (used as fallback if job.sending_email_id is null)
    const allBdIds = [...new Set([req.user.id, ...bdIds])];
    const { data: bdEmailRows } = allBdIds.length
      ? await supabase.from('user_emails').select('id,user_id,email_address,display_name,is_primary').in('user_id', allBdIds).order('is_primary', { ascending: false })
      : { data: [] };
    const bdPrimaryEmailMap = {};
    (bdEmailRows || []).forEach(e => {
      if (!bdPrimaryEmailMap[e.user_id]) bdPrimaryEmailMap[e.user_id] = e; // first = primary (ordered desc)
    });

    const tmplKeys = allBdIds.flatMap(id => [
      `u_${id}_tmpl_o1_subject`, `u_${id}_tmpl_o1_body`, `u_${id}_random_template_mode`
    ]);
    const { data: tmplRows } = await supabase.from('app_settings').select('key,value').in('key', tmplKeys);
    const tmplSettings = {};
    (tmplRows || []).forEach(r => { tmplSettings[r.key] = r.value; });

    const { emailsToInsert } = buildPendingEmailsFromJobs(
      jobs, req.user.id, bdMap, bdPrimaryEmailMap, tmplSettings
    );
    if (emailsToInsert.length) {
      const { error: insErr } = await supabase.from('emails').insert(emailsToInsert);
      if (insErr) throw insErr;
    }
    res.json({
      generated: emailsToInsert.length,
      failed: 0,
      failDetails: []
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/emails/send-selected', auth, async (req, res) => {
  try {
    const { email_ids } = req.body;
    if (!Array.isArray(email_ids) || !email_ids.length) return res.status(400).json({ error: 'email_ids required' });

    const { data: pendingEmails, error: fetchErr } = await supabase
      .from('emails')
      .select('id, to_email, subject, body, contact_id, job_id, from_email, followup_type, follow_up_id, job:jobs(timezone, sending_email_id, sending_email:user_emails!sending_email_id(id,email_address,display_name,platform,daily_send_limit))')
      .eq('sent_by', req.user.id)
      .eq('status', 'pending')
      .in('id', email_ids);
    if (fetchErr) throw fetchErr;
    if (!pendingEmails || !pendingEmails.length) return res.json({ success: true, sent: 0, failed: 0 });

    const totalCount = pendingEmails.length;
    const userId = req.user.id;
    res.json({ success: true, queued: totalCount });
    await setSendProgress(userId, { active: true, total: totalCount, sent: 0, failed: 0, current: '', failDetails: [], startedAt: new Date().toISOString() });

    console.log(`[SendSelected] Starting ${totalCount} emails, userId=${userId}`);
    const { sent, failed, skippedWindow, skippedQuota, skippedDomain, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(userId, pendingEmails, { autoSend: false });
    const uniqueContactIds = [...new Set(sentContactIds.filter(Boolean))];
    if (uniqueContactIds.length) await supabase.from('contacts').update({ email_sent_at: today() }).in('id', uniqueContactIds);
    const uniqueJobIds = [...new Set(sentJobIds.filter(Boolean))];
    for (const jid of uniqueJobIds) await logActivity(jid, null, userId, 'emails_sent', `${sent} email(s) sent via Microsoft`, null, null);
    const deferredTotal = skippedWindow + skippedQuota + skippedDomain;
    await setSendProgress(userId, {
      active: false, done: true, total: totalCount, sent, failed, deferred: deferredTotal,
      deferredWindow: skippedWindow, deferredQuota: skippedQuota, deferredDomain: skippedDomain,
      failDetails,
      deferredNote: buildDeferredNote({ skippedWindow, skippedQuota, skippedDomain, sendWindow }),
      completedAt: new Date().toISOString()
    });
    setTimeout(() => clearSendProgress(userId), 60000);
    console.log(`[SendSelected] Completed: ${sent} sent, ${failed} failed, deferred window=${skippedWindow} quota=${skippedQuota} domain=${skippedDomain}`);
  } catch (err) { console.error('[SendSelected] Error:', err.message); }
});

app.get('/emails/send-progress', auth, async (req, res) => {
  try {
    const key = `send_progress_${req.user.id}`;
    const { data } = await supabase.from('app_settings').select('value').eq('key', key).single();
    if (!data) return res.json({ active: false });
    const progress = JSON.parse(data.value);
    res.json(progress);
  } catch { res.json({ active: false }); }
});

app.post('/emails/queue-all', auth, async (req, res) => {
  try {
    // Fetch all pending emails for this user, joining job -> sending_email_id + platform
    const pendingEmails = await fetchPendingEmailsForUser(req.user.id);
    if (!pendingEmails.length) return res.json({ success: true, sent: 0, failed: 0, queued: 0 });

    // Respond immediately so browser doesn't time out — send loop runs in background
    const totalCount = pendingEmails.length;
    const userId = req.user.id;
    res.json({ success: true, queued: totalCount });
    await setSendProgress(userId, { active: true, total: totalCount, sent: 0, failed: 0, current: '', failDetails: [], startedAt: new Date().toISOString() });

    console.log(`[SendAll] Starting loop for ${totalCount} emails, userId=${userId}`);
    const { sent, failed, skippedWindow, skippedQuota, skippedDomain, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(userId, pendingEmails, { autoSend: false });
    const uniqueContactIds = [...new Set(sentContactIds.filter(Boolean))];
    if (uniqueContactIds.length) await supabase.from('contacts').update({ email_sent_at: today() }).in('id', uniqueContactIds);
    const uniqueJobIds = [...new Set(sentJobIds.filter(Boolean))];
    for (const jid of uniqueJobIds) await logActivity(jid, null, userId, 'emails_sent', `${sent} email(s) sent via Microsoft`, null, null);
    const deferredTotal = skippedWindow + skippedQuota + skippedDomain;
    await setSendProgress(userId, {
      active: false, done: true, total: totalCount, sent, failed, deferred: deferredTotal,
      deferredWindow: skippedWindow, deferredQuota: skippedQuota, deferredDomain: skippedDomain,
      failDetails,
      deferredNote: buildDeferredNote({ skippedWindow, skippedQuota, skippedDomain, sendWindow }),
      completedAt: new Date().toISOString()
    });
    setTimeout(() => clearSendProgress(userId), 300000);
    console.log(`[SendAll] Completed: ${sent} sent, ${failed} failed, deferred window=${skippedWindow} quota=${skippedQuota} domain=${skippedDomain}`); console.log(`[SendAll] FailDetails:`, JSON.stringify(failDetails.slice(0,3)));
  } catch (err) { console.error('[SendAll] Error:', err.message); }
});

app.delete('/emails/:id', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('emails').select('id,status,sent_by').eq('id', req.params.id).single();
    if (error || !data) return res.status(404).json({ error: 'Email not found' });
    if (data.sent_by !== req.user.id && !hasRole(req, 'admin')) return res.status(403).json({ error: 'Forbidden' });
    if (data.status !== 'pending' && data.status !== 'failed') return res.status(400).json({ error: 'Can only delete pending or failed emails' });
    const { error: delErr } = await supabase.from('emails').delete().eq('id', req.params.id);
    if (delErr) throw delErr;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/emails/:id', auth, async (req, res) => {
  try {
    const { subject, body } = req.body;
    const updates = {};
    if (subject !== undefined) updates.subject = subject;
    if (body !== undefined) updates.body = body;
    const { data, error } = await supabase.from('emails').update(updates).eq('id', req.params.id).eq('sent_by', req.user.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// REMINDERS
// ══════════════════════════════════════════════════════════════
app.get('/reminders', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('reminders').select(`*, job:jobs(id,position,stage,company_id,company:companies(name)), contact:contacts(id,first_name,last_name,email)`).eq('user_id', req.user.id).order('return_date');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/reminders', auth, async (req, res) => {
  try {
    const { job_id, contact_name, company_name, email, return_date, reminder_time, note, contact_id, reminder_type } = req.body;
    if (!return_date) return res.status(400).json({ error: 'Return date required' });
    const { data, error } = await supabase.from('reminders').insert({ job_id: job_id || null, user_id: req.user.id, contact_name, company_name, email, return_date, reminder_time: reminder_time || '09:00', note, status: 'pending', contact_id: contact_id || null, reminder_type: reminder_type || null }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/reminders/:id', auth, async (req, res) => {
  try {
    const { status, return_date, reminder_time, note } = req.body;
    const updates = { updated_at: new Date() };
    if (status) updates.status = status;
    if (return_date) updates.return_date = return_date;
    if (reminder_time) updates.reminder_time = reminder_time;
    if (note !== undefined) updates.note = note;
    const { data, error } = await supabase.from('reminders').update(updates).eq('id', req.params.id).eq('user_id', req.user.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/reminders/:id', auth, async (req, res) => {
  try {
    await supabase.from('reminders').delete().eq('id', req.params.id).eq('user_id', req.user.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// INSIGHTS
// ══════════════════════════════════════════════════════════════
app.get('/insights/ra/:userId', auth, async (req, res) => {
  try {
    const targetId = req.params.userId;
    if (hasRole(req, 'ra') && !hasRole(req, 'admin', 'ra_lead') && req.user.id !== targetId) return res.status(403).json({ error: 'Forbidden' });
    const now = new Date();
    const todayStr = now.toISOString().split('T')[0];
    const weekAgo = new Date(now); weekAgo.setDate(weekAgo.getDate() - 7);
    const monthAgo = new Date(now); monthAgo.setDate(monthAgo.getDate() - 30);
    const { data: jobs, error } = await supabase.from('jobs').select('id,stage,freshness,industry,timezone,is_duplicate,created_at,created_date').eq('created_by', targetId).is('deleted_at', null).gte('created_at', monthAgo.toISOString());
    if (error) throw error;
    const all = jobs || [];
    const todayJobs = all.filter(j => j.created_date === todayStr);
    const weekJobs = all.filter(j => new Date(j.created_at) >= weekAgo);
    const last7 = {};
    for (let i = 6; i >= 0; i--) { const d = new Date(now); d.setDate(d.getDate() - i); const key = d.toISOString().split('T')[0]; last7[key] = all.filter(j => j.created_date === key).length; }
    const INDUSTRIES = ["Accounting & Finance","Advertising & Public Relations","Agriculture","Airline, Aviation & Transportation","Architecture, Construction & Building Materials","Art, Photography & Journalism","Automotive & Motor Vehicles","Banking & Financial Services","Biotechnology & Pharmaceutical","Broadcasting, Media & Printing","Chemical & Industrial","Computer Hardware & Software","Consulting & Consulting Engineering","Consumer Products & Retail","Credit, Loan, Mortgage & Collections","Defense, Military & Aerospace","Education, Training & Library Science","Electronics & Semiconductor","Employment, Recruiting & Staffing","Energy, Utilities, Oil & Petroleum","Entertainment & Recreation","Environmental","Fashion, Apparel & Textile","Food & Restaurant","Funeral & Cemetery","Government & Civil Service","Healthcare & Health Services","Homebuilding & Real Estate","Hospitality, Hotel & Resort","HVAC","Import & Export","Insurance & Managed Care","Internet & ECommerce","Landscaping","Law Enforcement, Legal & Security","Manufacturing & Manufacturing Engineering","Medical Equipment","Not for Profit & Social Services","Office Supplies & Equipment","Packaging","Sales & Marketing","Securities","Social Media & Wireless Telecommunications","Travel"];
    function normInd(raw) {
      if (!raw) return 'Unknown';
      if (INDUSTRIES.includes(raw)) return raw; // already a known value
      const r = raw.toLowerCase();
      if (r.includes('account')||r.includes('cpa')||r.includes('bookkeep')) return 'Accounting & Finance';
      if (r.includes('advertis')||r.includes('public relation')) return 'Advertising & Public Relations';
      if (r.includes('agricultur')||r.includes('farm')) return 'Agriculture';
      if (r.includes('airline')||r.includes('aviation')||r.includes('transport')||r.includes('logistics')||r.includes('freight')) return 'Airline, Aviation & Transportation';
      if (r.includes('architect')||r.includes('construction')||r.includes('building material')) return 'Architecture, Construction & Building Materials';
      if (r.includes('photo')||r.includes('journalism')||r.includes('creative')) return 'Art, Photography & Journalism';
      if (r.includes('automotive')||r.includes('motor vehicle')||r.includes('automobile')) return 'Automotive & Motor Vehicles';
      if (r.includes('banking')||r.includes('bank ')||r.includes('financial service')) return 'Banking & Financial Services';
      if (r.includes('biotech')||r.includes('pharma')||r.includes('life science')) return 'Biotechnology & Pharmaceutical';
      if (r.includes('broadcast')||r.includes('media')||r.includes('print')||r.includes('publish')||r.includes('television')) return 'Broadcasting, Media & Printing';
      if (r.includes('chemical')||r.includes('industrial')||r.includes('petrochemical')) return 'Chemical & Industrial';
      if (r.includes('software')||r.includes('computer')||r.includes('hardware')||r.includes('technology')||r.includes(' tech')||r.includes(' it ')||r.includes('information tech')||r.includes('saas')||r.includes('cloud')) return 'Computer Hardware & Software';
      if (r.includes('consult')||r.includes('advisory')) return 'Consulting & Consulting Engineering';
      if (r.includes('consumer')||r.includes('retail')||r.includes('ecommerce')) return 'Consumer Products & Retail';
      if (r.includes('credit')||r.includes('loan')||r.includes('mortgage')||r.includes('collection')) return 'Credit, Loan, Mortgage & Collections';
      if (r.includes('defense')||r.includes('military')||r.includes('aerospace')) return 'Defense, Military & Aerospace';
      if (r.includes('education')||r.includes('training')||r.includes('school')||r.includes('university')||r.includes('college')||r.includes('library')) return 'Education, Training & Library Science';
      if (r.includes('electronic')||r.includes('semiconductor')||r.includes('chip')) return 'Electronics & Semiconductor';
      if (r.includes('employ')||r.includes('recruit')||r.includes('staffing')||r.includes('human resource')) return 'Employment, Recruiting & Staffing';
      if (r.includes('energy')||r.includes('utilities')||r.includes('oil ')||r.includes('gas ')||r.includes('petroleum')||r.includes('solar')||r.includes('renewable')) return 'Energy, Utilities, Oil & Petroleum';
      if (r.includes('entertainment')||r.includes('recreation')||r.includes('gaming')||r.includes('sport')) return 'Entertainment & Recreation';
      if (r.includes('environment')||r.includes('sustainability')||r.includes('waste')||r.includes('recycl')) return 'Environmental';
      if (r.includes('fashion')||r.includes('apparel')||r.includes('textile')||r.includes('clothing')) return 'Fashion, Apparel & Textile';
      if (r.includes('food')||r.includes('restaurant')||r.includes('beverage')||r.includes('catering')) return 'Food & Restaurant';
      if (r.includes('funeral')||r.includes('cemetery')||r.includes('mortuary')) return 'Funeral & Cemetery';
      if (r.includes('government')||r.includes('civil service')||r.includes('public sector')||r.includes('municipal')) return 'Government & Civil Service';
      if (r.includes('health')||r.includes('medical')||r.includes('hospital')||r.includes('clinic')||r.includes('wellness')||r.includes('dental')) return 'Healthcare & Health Services';
      if (r.includes('real estate')||r.includes('homebuilding')||r.includes('property')||r.includes('realty')) return 'Homebuilding & Real Estate';
      if (r.includes('hotel')||r.includes('resort')||r.includes('hospitality')||r.includes('lodging')) return 'Hospitality, Hotel & Resort';
      if (r.includes('hvac')||r.includes('heating')||r.includes('cooling')||r.includes('air condition')) return 'HVAC';
      if (r.includes('import')||r.includes('export')) return 'Import & Export';
      if (r.includes('insurance')||r.includes('managed care')) return 'Insurance & Managed Care';
      if (r.includes('internet')||r.includes('online')||r.includes('digital')||r.includes('web ')) return 'Internet & ECommerce';
      if (r.includes('landscap')||r.includes('lawn')||r.includes('garden')) return 'Landscaping';
      if (r.includes('legal')||r.includes('law')||r.includes('attorney')||r.includes('compliance')||r.includes('litigation')||r.includes('law enforce')) return 'Law Enforcement, Legal & Security';
      if (r.includes('manufactur')||r.includes('engineering')||r.includes('mechanical')||r.includes('production')) return 'Manufacturing & Manufacturing Engineering';
      if (r.includes('medical equip')||r.includes('medical device')||r.includes('surgical')) return 'Medical Equipment';
      if (r.includes('nonprofit')||r.includes('not for profit')||r.includes('social service')||r.includes('charity')||r.includes('ngo')) return 'Not for Profit & Social Services';
      if (r.includes('office suppl')||r.includes('stationery')) return 'Office Supplies & Equipment';
      if (r.includes('packag')||r.includes('container')) return 'Packaging';
      if (r.includes('sales')||r.includes('marketing')) return 'Sales & Marketing';
      if (r.includes('securit')||r.includes('investment')||r.includes('hedge fund')||r.includes('private equity')) return 'Securities';
      if (r.includes('social media')||r.includes('wireless')||r.includes('telecom')||r.includes('mobile')) return 'Social Media & Wireless Telecommunications';
      if (r.includes('travel')||r.includes('tourism')) return 'Travel';
      return raw; // keep original if no match
    }
    function breakdown(arr, field) { const map = {}; arr.forEach(j => { const raw = j[field] || ''; const v = field === 'industry' ? normInd(raw) : (raw || 'Unknown'); map[v] = (map[v] || 0) + 1; }); return map; }
    res.json({ total_month: all.length, total_week: weekJobs.length, total_today: todayJobs.length, duplicates: all.filter(j => j.is_duplicate).length, last_7_days: last7, by_industry: breakdown(all,'industry'), by_timezone: breakdown(all,'timezone'), by_freshness: breakdown(all,'freshness'), by_stage: breakdown(all,'stage') });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── BD Manager Insights ────────────────────────────────────────
app.get('/insights/bd/:userId', auth, async (req, res) => {
  try {
    const targetId = req.params.userId;
    // BD can only see their own; BD Lead and admin can see any
    if (hasRole(req, 'bd') && !hasRole(req, 'admin', 'bd_lead') && req.user.id !== targetId) return res.status(403).json({ error: 'Forbidden' });

    const now = new Date();
    const todayStr = now.toISOString().split('T')[0];
    const weekAgo = new Date(now); weekAgo.setDate(weekAgo.getDate() - 7);
    const monthAgo = new Date(now); monthAgo.setDate(monthAgo.getDate() - 30);

    // Jobs assigned to this BD Manager
    const { data: jobs } = await supabase.from('jobs')
      .select('id,stage,industry,position,assigned_at,company:companies(name,industry)')
      .eq('assigned_to_bd', targetId)
      .is('deleted_at', null);

    const allJobs = jobs || [];
    function jAt(j) { return j.assigned_at ? j.assigned_at.slice(0, 10) : ''; }

    const todayJobs  = allJobs.filter(j => jAt(j) === todayStr);
    const weekJobs   = allJobs.filter(j => jAt(j) >= weekAgo.toISOString().split('T')[0]);
    const monthJobs  = allJobs.filter(j => jAt(j) >= monthAgo.toISOString().split('T')[0]);

    // Funnel stages
    const convStages    = ['Connected', 'In Discussion'];
    const positiveStage = ['Positive'];
    const negStages     = ['Negative', 'No Response'];
    const oooStage      = ['Out of Office'];
    const converted  = allJobs.filter(j => convStages.includes(j.stage));
    const positive   = allJobs.filter(j => positiveStage.includes(j.stage));
    const negative   = allJobs.filter(j => negStages.includes(j.stage));
    const ooo        = allJobs.filter(j => oooStage.includes(j.stage));
    const future     = allJobs.filter(j => j.stage === 'Future');
    const assigned   = allJobs.filter(j => j.stage === 'Assigned');

    // Emails
    const { data: emails } = await supabase.from('emails')
      .select('id,status,created_at,sent_at')
      .eq('assigned_to', targetId)
      .gte('created_at', monthAgo.toISOString());

    const allEmails   = emails || [];
    const sentEmails  = allEmails.filter(e => e.status === 'sent');
    const pendEmails  = allEmails.filter(e => e.status === 'pending');
    const failEmails  = allEmails.filter(e => e.status === 'failed');

    // Last 7 days — emails sent per day
    const last7emails = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now); d.setDate(d.getDate() - i);
      const key = d.toISOString().split('T')[0];
      last7emails[key] = sentEmails.filter(e => (e.sent_at || e.created_at || '').slice(0, 10) === key).length;
    }

    // Last 7 days — leads assigned per day
    const last7leads = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now); d.setDate(d.getDate() - i);
      const key = d.toISOString().split('T')[0];
      last7leads[key] = allJobs.filter(j => jAt(j) === key).length;
    }

    // Stage breakdown
    const stageBreakdown = {};
    allJobs.forEach(j => { stageBreakdown[j.stage || 'Unknown'] = (stageBreakdown[j.stage || 'Unknown'] || 0) + 1; });

    // Industry breakdown from company data
    const industryBreakdown = {};
    allJobs.forEach(j => {
      const ind = (j.company && j.company.industry) || j.industry || 'Unknown';
      industryBreakdown[ind] = (industryBreakdown[ind] || 0) + 1;
    });

    const convRate     = allJobs.length ? Math.round(converted.length / allJobs.length * 100) : 0;
    const responseRate = allJobs.length ? Math.round((converted.length + positive.length) / allJobs.length * 100) : 0;

    res.json({
      // Volume
      total_all: allJobs.length,
      total_today: todayJobs.length,
      total_week: weekJobs.length,
      total_month: monthJobs.length,
      // Funnel
      assigned: assigned.length,
      positive: positive.length,
      converted: converted.length,
      negative: negative.length,
      ooo: ooo.length,
      future: future.length,
      conv_rate: convRate,
      response_rate: responseRate,
      // Emails
      emails_sent: sentEmails.length,
      emails_sent_today: sentEmails.filter(e => (e.sent_at || e.created_at || '').slice(0, 10) === todayStr).length,
      emails_pending: pendEmails.length,
      emails_failed: failEmails.length,
      // Charts
      last_7_emails: last7emails,
      last_7_leads: last7leads,
      // Breakdowns
      by_stage: stageBreakdown,
      by_industry: industryBreakdown,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// STATS
// ══════════════════════════════════════════════════════════════
app.get('/stats', auth, async (req, res) => {
  try {
    const { period } = req.query;
    const now = new Date();
    let dateFrom;
    if (period === 'daily') dateFrom = today();
    else if (period === 'weekly') { const w = new Date(now); w.setDate(w.getDate()-7); dateFrom = w.toISOString().split('T')[0]; }
    else if (period === 'quarterly') { const q = new Date(now); q.setMonth(q.getMonth()-3); dateFrom = q.toISOString().split('T')[0]; }
    else { const m = new Date(now.getFullYear(), now.getMonth(), 1); dateFrom = m.toISOString().split('T')[0]; }
    let query = supabase.from('jobs').select('id,stage,created_by,assigned_to,contacts(id,email_sent_at)').is('deleted_at', null).gte('created_at', dateFrom + 'T00:00:00Z');
    if (!hasRole(req, 'admin')) query = query.or(`created_by.eq.${req.user.id},assigned_to.eq.${req.user.id}`);
    const { data, error } = await query;
    if (error) throw error;
    const total = data.length;
    const emailed = data.filter(j => (j.contacts || []).some(c => c.email_sent_at)).length;
    const byStage = {};
    data.forEach(j => { byStage[j.stage] = (byStage[j.stage] || 0) + 1; });
    res.json({ total, emailed, responseRate: total ? Math.round(emailed/total*100) : 0, byStage, period: period || 'monthly', dateFrom });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// ACTIVITY LOG
// ══════════════════════════════════════════════════════════════
app.get('/jobs/:job_id/activity', auth, async (req, res) => {
  try {
    if (!(await canTouchJob(req, req.params.job_id))) return res.status(403).json({ error: 'Forbidden' });
    const { data, error } = await supabase.from('activity_log').select(`*, user:users(id,name,employee_id)`).eq('job_id', req.params.job_id).order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// DISTRIBUTION
// ══════════════════════════════════════════════════════════════
function buildAutoRatio(pool_stats, capacity) {
  const total = Math.min(pool_stats?.total || 0, capacity);
  function evenSplit(obj) { const keys = Object.keys(obj).filter(k => obj[k] > 0); if (!keys.length) return {}; const base = Math.floor(100 / keys.length); const result = {}; let rem = 100; keys.forEach((k, i) => { result[k] = i === keys.length - 1 ? rem : base; rem -= base; }); return result; }
  return { total_to_send: total, by_freshness: evenSplit(pool_stats?.by_freshness || {}), by_industry: evenSplit(pool_stats?.by_industry || {}), by_timezone: evenSplit(pool_stats?.by_timezone || {}), exclude_duplicates: false, summary: `Auto-balanced distribution of ${total} leads.` };
}

app.post('/distribute/generate-ratio', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'ra_lead')) return res.status(403).json({ error: 'RA Lead only' });
    const { priority_text, pool_stats, manager_id } = req.body;
    const { data: manager } = await supabase.from('users').select('id,name').eq('id', manager_id).single();
    const capacity = pool_stats.capacity || 150;
    if (!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY === 'your_anthropic_api_key_here') return res.json(buildAutoRatio(pool_stats, capacity));
    // Build dynamic industry keys from what's actually in the pool
    const poolIndustries = Object.keys(pool_stats.by_industry || {}).filter(Boolean);
    const industryKeys = poolIndustries.length ? poolIndustries.reduce((o,k) => { o[k]='<pct>'; return o; }, {}) : {'Other':'<pct>'};
    const prompt = `You are a lead distribution engine for Fute Global LLC.\nPool: ${JSON.stringify(pool_stats)}\nManager: ${manager?.name}\nCapacity: ${capacity}\nInstructions: "${priority_text}"\nRespond ONLY with valid JSON:\n{"total_to_send":<number>,"by_freshness":{"New":<pct>,"Normal":<pct>,"Old":<pct>},"by_industry":${JSON.stringify(industryKeys)},"by_timezone":{"EST":<pct>,"CST":<pct>,"MST":<pct>,"PST":<pct>},"exclude_duplicates":<bool>,"summary":"<text>"}`;
    const aiResp = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 400, messages: [{ role: 'user', content: prompt }] }) });
    const aiData = await aiResp.json();
    const ratio = JSON.parse((aiData.content?.[0]?.text || '{}').replace(/```json|```/g, '').trim());
    res.json(ratio);
  } catch (err) { res.json(buildAutoRatio(req.body.pool_stats, req.body.pool_stats?.capacity || 150)); }
});

// ── Microsoft Graph threaded send (follow-ups quote prior emails like Gmail/Outlook) ──
async function graphMailRequest(accessToken, path, options = {}) {
  const res = await fetch(`https://graph.microsoft.com/v1.0${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', ...(options.headers || {}) }
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error?.message || `Graph API ${res.status}`);
  return data;
}

async function sendMicrosoftNewMessage(userEmailId, { to, subject, htmlBody }) {
  const accessToken = await getMicrosoftToken(userEmailId);
  const msg = await graphMailRequest(accessToken, '/me/messages', {
    method: 'POST',
    body: JSON.stringify({
      subject,
      body: { contentType: 'HTML', content: htmlBody },
      toRecipients: [{ emailAddress: { address: to } }]
    })
  });
  await graphMailRequest(accessToken, `/me/messages/${msg.id}/send`, { method: 'POST' });
  return { graphMessageId: msg.id, conversationId: msg.conversationId || null, inReplyTo: null };
}

async function sendMicrosoftThreadReply(userEmailId, parentGraphMessageId, { htmlBody, subject }) {
  const accessToken = await getMicrosoftToken(userEmailId);
  const draft = await graphMailRequest(accessToken, `/me/messages/${parentGraphMessageId}/createReply`, {
    method: 'POST',
    body: JSON.stringify({})
  });
  const full = await graphMailRequest(accessToken, `/me/messages/${draft.id}?$select=body,subject,conversationId`);
  const quotedPart = full.body?.content || '';
  const combinedHtml = quotedPart ? `${htmlBody}<br><br>${quotedPart}` : htmlBody;
  const patch = { body: { contentType: 'HTML', content: combinedHtml } };
  if (subject) patch.subject = subject;
  await graphMailRequest(accessToken, `/me/messages/${draft.id}`, { method: 'PATCH', body: JSON.stringify(patch) });
  await graphMailRequest(accessToken, `/me/messages/${draft.id}/send`, { method: 'POST' });
  return { graphMessageId: draft.id, conversationId: full.conversationId || draft.conversationId || null, inReplyTo: parentGraphMessageId };
}

async function findSentMessageInMailbox(accessToken, { toEmail, subjectHint, minDate, conversationId }) {
  const params = new URLSearchParams({ '$select': 'id,subject,toRecipients,sentDateTime,conversationId', '$orderby': 'sentDateTime desc', '$top': '75' });
  if (minDate) params.set('$filter', `sentDateTime ge ${minDate}T00:00:00Z`);
  const data = await graphMailRequest(accessToken, `/me/mailFolders/sentitems/messages?${params}`);
  const to = toEmail.toLowerCase().trim();
  const hint = (subjectHint || '').toLowerCase().replace(/^re:\s*/i, '').trim();
  for (const m of (data.value || [])) {
    const recipients = (m.toRecipients || []).map(r => (r.emailAddress?.address || '').toLowerCase());
    if (!recipients.includes(to)) continue;
    if (conversationId && m.conversationId && m.conversationId !== conversationId) continue;
    if (hint && m.subject) {
      const sub = m.subject.toLowerCase().replace(/^re:\s*/i, '').trim();
      if (!sub.includes(hint) && !hint.includes(sub.slice(0, 20))) continue;
    }
    return m.id;
  }
  return null;
}

async function loadSentEmailRecord({ jobId, contactId, followupType }) {
  if (followupType === 'fu2') {
    const { data: fu1 } = await supabase.from('emails').select('id,graph_message_id,conversation_id,subject,body,sent_at,from_email')
      .eq('job_id', jobId).eq('contact_id', contactId).eq('status', 'sent').eq('followup_type', 'fu1')
      .order('sent_at', { ascending: false }).limit(1);
    if (fu1?.[0]) return fu1[0];
  }
  const { data } = await supabase.from('emails').select('id,graph_message_id,conversation_id,subject,body,sent_at,from_email,followup_type')
    .eq('job_id', jobId).eq('contact_id', contactId).eq('status', 'sent').order('sent_at', { ascending: true });
  const rows = data || [];
  return rows.find(r => !r.followup_type || r.followup_type === 'initial') || rows[0] || null;
}

async function resolveThreadParentMessageId({ jobId, contactId, followupType, userEmailId, toEmail, subjectHint }) {
  const prior = await loadSentEmailRecord({ jobId, contactId, followupType });
  if (prior?.graph_message_id) return { parentId: prior.graph_message_id, priorSubject: prior.subject, conversationId: prior.conversation_id };
  const accessToken = await getMicrosoftToken(userEmailId);
  const parentId = await findSentMessageInMailbox(accessToken, {
    toEmail, subjectHint: subjectHint || prior?.subject, minDate: prior?.sent_at, conversationId: prior?.conversation_id
  });
  if (!parentId) return null;
  return { parentId, priorSubject: prior?.subject || subjectHint, conversationId: prior?.conversation_id };
}

function formatQuoteDate(sentAt) {
  if (!sentAt) return '';
  try {
    return new Intl.DateTimeFormat('en-US', { weekday: 'short', month: 'numeric', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }).format(new Date(sentAt));
  } catch (_) { return String(sentAt); }
}

function buildOutlookQuoteBlock({ fromName, fromEmail, sentAt, subject, body }) {
  const bodyHtml = (body || '').includes('<')
    ? body
    : buildHtmlEmailBody(body, '');
  const dateStr = formatQuoteDate(sentAt);
  return `<div style="border:none;border-top:solid #B5C4DF 1.0pt;padding:3.0pt 0in 0in 0in;margin-top:12pt">` +
    `<p style="font-size:11pt;font-family:Calibri,sans-serif;margin:0 0 8pt 0">` +
    `<b>From:</b> ${fromName || 'Sender'}${fromEmail ? ` &lt;${fromEmail}&gt;` : ''}<br>` +
    (dateStr ? `<b>Sent:</b> ${dateStr}<br>` : '') +
    `<b>Subject:</b> ${subject || ''}</p></div>${bodyHtml}`;
}

async function buildQuotedChainFromDb({ jobId, contactId, followupType }) {
  const quoteFrom = async (filterFn) => {
    const { data } = await supabase.from('emails').select('subject,body,sent_at,from_email,followup_type')
      .eq('job_id', jobId).eq('contact_id', contactId).eq('status', 'sent')
      .order('sent_at', { ascending: false }).limit(5);
    const row = (data || []).find(filterFn);
    if (!row) return '';
    return buildOutlookQuoteBlock({
      fromName: row.from_email?.split('@')[0] || 'Sender',
      fromEmail: row.from_email,
      sentAt: row.sent_at,
      subject: row.subject,
      body: row.body
    });
  };
  if (followupType === 'fu2') {
    const fu1Quote = await quoteFrom(r => r.followup_type === 'fu1');
    if (fu1Quote) return fu1Quote;
  }
  return quoteFrom(r => !r.followup_type || r.followup_type === 'initial');
}

async function persistGraphIds(emailId, graph) {
  if (!emailId || !graph?.graphMessageId) return;
  const { error } = await supabase.from('emails').update({
    graph_message_id: graph.graphMessageId,
    conversation_id: graph.conversationId || null,
    in_reply_to_graph_message_id: graph.inReplyTo || null
  }).eq('id', emailId);
  if (error?.message?.includes('column') || error?.code === '42703') {
    console.warn('[GraphMail] Run migrations/001_email_threading.sql to store message ids for threading');
  }
}

async function deliverOutboundEmail(email, userEmailId, signatureHtml, sendingEmail) {
  const filledSig = fillSignatureHtml(signatureHtml, {
    displayName: sendingEmail?.display_name || '',
    emailAddress: sendingEmail?.email_address || email.from_email || ''
  });
  const htmlBody = buildHtmlEmailBody(email.body, filledSig);
  const isFollowup = email.followup_type === 'fu1' || email.followup_type === 'fu2';
  if (!isFollowup) {
    return sendMicrosoftNewMessage(userEmailId, { to: email.to_email, subject: email.subject, htmlBody });
  }
  const thread = await resolveThreadParentMessageId({
    jobId: email.job_id, contactId: email.contact_id, followupType: email.followup_type,
    userEmailId, toEmail: email.to_email, subjectHint: email.subject
  });
  if (thread?.parentId) {
    return sendMicrosoftThreadReply(userEmailId, thread.parentId, { htmlBody, subject: email.subject });
  }
  const quotedHtml = await buildQuotedChainFromDb({ jobId: email.job_id, contactId: email.contact_id, followupType: email.followup_type });
  if (!quotedHtml) throw new Error('Could not find the original outreach email — follow-up must include quoted context.');
  return sendMicrosoftNewMessage(userEmailId, { to: email.to_email, subject: email.subject, htmlBody: `${htmlBody}<br><br>${quotedHtml}` });
}

// Auto-send all pending emails for a specific BD manager (called after assignment)
async function fetchPendingEmailsForUser(userId) {
  let pendingEmails = [], from = 0;
  while (true) {
    const { data, error } = await supabase
      .from('emails')
      .select(PENDING_EMAIL_JOB_SELECT)
      .eq('sent_by', userId)
      .eq('status', 'pending')
      .range(from, from + 999);
    if (error) throw error;
    if (!data || !data.length) break;
    pendingEmails = pendingEmails.concat(data);
    if (data.length < 1000) break;
    from += 1000;
  }
  return pendingEmails;
}

async function processPendingEmailSends(userId, pendingEmails, opts = {}) {
  const { autoSend = false } = opts;
  const sendWindow = await getSendWindowHours();
  const totalCount = pendingEmails.length;
  let sent = 0, failed = 0, skippedWindow = 0, skippedQuota = 0, skippedDomain = 0, skippedContactStatus = 0;
  const failDetails = [], sentContactIds = [], sentJobIds = [];
  const startedAt = new Date().toISOString();

  const followupContactIds = [...new Set(
    pendingEmails
      .filter(e => e.followup_type === 'fu1' || e.followup_type === 'fu2')
      .map(e => e.contact_id)
      .filter(Boolean)
  )];
  const contactStatusById = {};
  if (followupContactIds.length) {
    const { data: followupContacts } = await supabase.from('contacts').select('id,email,email_status').in('id', followupContactIds);
    (followupContacts || []).forEach(c => { contactStatusById[c.id] = c; });
  }

  const mailboxIds = [...new Set(pendingEmails.map(e => e.job?.sending_email_id).filter(Boolean))];
  const [mailboxSignatures, quotaState] = await Promise.all([
    loadMailboxSignatures(mailboxIds, userId),
    loadMailboxQuotaState(mailboxIds)
  ]);
  const { limits, sentToday, delays, settings } = quotaState;
  const lastSendAtByMailbox = {};
  const domainTimestamps = {};
  let sendAttempts = 0;
  const maxPerRun = settings.maxPerRun || 0;

  const inWindow = [], outWindow = [];
  for (const email of pendingEmails) {
    const leadTz = email.job?.timezone || 'EST';
    if (isInLeadSendWindow(leadTz, new Date(), sendWindow)) inWindow.push(email);
    else outWindow.push(email);
  }
  const ordered = interleaveByMailbox(inWindow).concat(outWindow);

  for (const email of ordered) {
    const leadTz = email.job?.timezone || 'EST';
    const userEmailId = email.job?.sending_email_id;
    const sendingEmail = email.job?.sending_email;
    const platform = (sendingEmail?.platform || 'Microsoft').toLowerCase();

    const progressBase = {
      active: true, total: totalCount, sent, failed,
      deferred: skippedWindow + skippedQuota + skippedDomain + skippedContactStatus,
      deferredWindow: skippedWindow, deferredQuota: skippedQuota, deferredDomain: skippedDomain,
      skippedContactStatus,
      failDetails, startedAt, autoSend
    };

    if (!isInLeadSendWindow(leadTz, new Date(), sendWindow)) {
      skippedWindow++;
      await setSendProgress(userId, { ...progressBase, current: `${email.to_email} (waiting ${leadTz} send window)` });
      continue;
    }

    if (maxPerRun > 0 && sendAttempts >= maxPerRun) break;

    if (!userEmailId) {
      sendAttempts++;
      failed++;
      failDetails.push({ id: email.id, to: email.to_email, from: email.from_email || '—', error: 'No sending email configured for this job' });
      try { await supabase.from('emails').update({ status: 'failed' }).eq('id', email.id); } catch (_) {}
      await setSendProgress(userId, { ...progressBase, current: email.to_email });
      continue;
    }

    const limit = limits[userEmailId] || sendingEmail?.daily_send_limit || settings.defaultDailyLimit;
    if ((sentToday[userEmailId] || 0) >= limit) {
      skippedQuota++;
      await setSendProgress(userId, { ...progressBase, current: `${email.to_email} (mailbox daily limit ${limit} reached)` });
      continue;
    }

    const domain = extractEmailDomain(email.to_email);
    if (domain && domainSendsInLastHour(domainTimestamps, domain) >= settings.domainMaxPerHour) {
      skippedDomain++;
      await setSendProgress(userId, { ...progressBase, current: `${email.to_email} (domain ${domain} throttled)` });
      continue;
    }

    if (platform === 'gmail' || platform === 'google') {
      sendAttempts++;
      failed++;
      failDetails.push({ id: email.id, to: email.to_email, from: sendingEmail?.email_address || '—', error: 'Gmail sending not connected yet' });
      try { await supabase.from('emails').update({ status: 'failed' }).eq('id', email.id); } catch (_) {}
      await setSendProgress(userId, { ...progressBase, current: email.to_email });
      continue;
    }
    if (!isValidEmail(email.to_email)) {
      sendAttempts++;
      failed++;
      failDetails.push({ id: email.id, to: email.to_email || '(empty)', from: sendingEmail?.email_address || email.from_email || '—', error: `Invalid recipient address: "${email.to_email}" — not an email` });
      try { await supabase.from('emails').update({ status: 'failed' }).eq('id', email.id); } catch (_) {}
      await setSendProgress(userId, { ...progressBase, current: email.to_email });
      continue;
    }

    const isFollowup = email.followup_type === 'fu1' || email.followup_type === 'fu2';
    if (isFollowup && email.contact_id) {
      const contact = contactStatusById[email.contact_id];
      if (contact && !isFollowupEligibleContact(contact)) {
        skippedContactStatus++;
        await cancelBlockedFollowupSend(email, contact.email_status);
        await setSendProgress(userId, { ...progressBase, current: `${email.to_email} (follow-up skipped: ${contactEmailStatus(contact)})` });
        continue;
      }
    }

    await waitForMailboxSlot(userEmailId, lastSendAtByMailbox, delays);
    await setSendProgress(userId, { ...progressBase, current: email.to_email });

    try {
      sendAttempts++;
      const sigTemplate = resolveSignatureHtml(email._sigHtml || mailboxSignatures[userEmailId]);
      const graph = await deliverOutboundEmail(email, userEmailId, sigTemplate, sendingEmail);
      await supabase.from('emails').update({ status: 'sent', sent_at: today() }).eq('id', email.id);
      await persistGraphIds(email.id, graph);
      const todayDate = today();
      sentToday[userEmailId] = (sentToday[userEmailId] || 0) + 1;
      await supabase.from('email_send_log').upsert(
        { user_email_id: userEmailId, send_date: todayDate, emails_sent: sentToday[userEmailId] },
        { onConflict: 'user_email_id,send_date' }
      );
      lastSendAtByMailbox[userEmailId] = Date.now();
      if (domain) {
        if (!domainTimestamps[domain]) domainTimestamps[domain] = [];
        domainTimestamps[domain].push(Date.now());
      }
      if (email.contact_id) sentContactIds.push(email.contact_id);
      if (email.job_id) sentJobIds.push(email.job_id);
      sent++;
      await setSendProgress(userId, { ...progressBase, sent, current: email.to_email });
    } catch (e) {
      failed++;
      failDetails.push({ id: email.id, to: email.to_email, from: sendingEmail?.email_address || email.from_email || '—', error: e.message });
      try { await supabase.from('emails').update({ status: 'failed' }).eq('id', email.id); } catch (_) {}
      lastSendAtByMailbox[userEmailId] = Date.now();
      await setSendProgress(userId, { ...progressBase, failed, current: email.to_email });
    }
  }

  return { sent, failed, skippedWindow, skippedQuota, skippedDomain, skippedContactStatus, failDetails, sentContactIds, sentJobIds, totalCount, sendWindow };
}

async function retryDeferredPendingSends() {
  try {
    const { data, error } = await supabase.from('emails').select('sent_by').eq('status', 'pending');
    if (error) throw error;
    const userIds = [...new Set((data || []).map(r => r.sent_by).filter(Boolean))];
    for (const uid of userIds) await autoSendForManager(uid);
  } catch (e) {
    console.error('[SendWindowRetry] Error:', e.message);
  }
}

async function autoSendForManager(managerId) {
  if (activeSendByUser.has(managerId)) {
    console.log(`[AutoSend] Already running for manager ${managerId}, skipping`);
    return;
  }
  activeSendByUser.add(managerId);
  try {
    let pendingEmails = await fetchPendingEmailsForUser(managerId);
    if (!pendingEmails.length) {
      console.log(`[AutoSend] No pending emails yet for manager ${managerId}, retrying in 5s...`);
      await new Promise(r => setTimeout(r, 5000));
      pendingEmails = await fetchPendingEmailsForUser(managerId);
      if (!pendingEmails.length) {
        console.log(`[AutoSend] Still no pending emails for manager ${managerId} after retry — aborting`);
        return;
      }
    }
    const totalCount = pendingEmails.length;
    console.log(`[AutoSend] Starting auto-send of ${totalCount} emails for manager ${managerId}`);
    await setSendProgress(managerId, { active: true, total: totalCount, sent: 0, failed: 0, deferred: 0, current: '', failDetails: [], startedAt: new Date().toISOString(), autoSend: true });

    const { sent, failed, skippedWindow, skippedQuota, skippedDomain, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(managerId, pendingEmails, { autoSend: true });

    const uniqueContactIds = [...new Set(sentContactIds.filter(Boolean))];
    if (uniqueContactIds.length) await supabase.from('contacts').update({ email_sent_at: today() }).in('id', uniqueContactIds);
    const uniqueJobIds = [...new Set(sentJobIds.filter(Boolean))];
    for (const jid of uniqueJobIds) await logActivity(jid, null, managerId, 'emails_sent', `${sent} email(s) auto-sent via Microsoft`, null, null);

    const deferredTotal = skippedWindow + skippedQuota + skippedDomain;
    await setSendProgress(managerId, {
      active: false, done: true, total: totalCount, sent, failed, deferred: deferredTotal,
      deferredWindow: skippedWindow, deferredQuota: skippedQuota, deferredDomain: skippedDomain,
      failDetails,
      deferredNote: buildDeferredNote({ skippedWindow, skippedQuota, skippedDomain, sendWindow }),
      completedAt: new Date().toISOString(), autoSend: true
    });
    setTimeout(() => clearSendProgress(managerId), 300000);
    console.log(`[AutoSend] Completed for manager ${managerId}: ${sent} sent, ${failed} failed, ${skippedWindow} quota=${skippedQuota} domain=${skippedDomain}`);
  } catch (err) {
    console.error(`[AutoSend] Error for manager ${managerId}:`, err.message);
  } finally {
    activeSendByUser.delete(managerId);
  }
}


app.post('/distribute/execute', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'ra_lead')) return res.status(403).json({ error: 'RA Lead only' });
    const { manager_id, ratio } = req.body;
    if (!manager_id || !ratio) return res.status(400).json({ error: 'manager_id and ratio required' });

    // Get manager's email accounts that have a connected Microsoft token (ready to send)
    const { data: allUserEmails } = await supabase.from('user_emails')
      .select('id,email_address,display_name,daily_send_limit').eq('user_id', manager_id);
    if (!allUserEmails?.length) return res.status(400).json({ error: 'Manager has no email IDs configured' });
    // Only use accounts with a valid OAuth token
    const { data: connectedTokens } = await supabase.from('microsoft_tokens')
      .select('user_email_id').in('user_email_id', allUserEmails.map(e => e.id));
    const connectedIds = new Set((connectedTokens || []).map(t => t.user_email_id));
    const userEmails = allUserEmails.filter(e => connectedIds.has(e.id));
    if (!userEmails?.length) return res.status(400).json({ error: 'Manager has no connected Microsoft email accounts — please connect via Manage Users' });

    const todayDate = today();
    const { data: sendLogs } = await supabase.from('email_send_log').select('user_email_id,emails_sent').eq('send_date', todayDate);
    const sentToday = {};
    (sendLogs || []).forEach(l => { sentToday[l.user_email_id] = l.emails_sent; });

    const accounts = userEmails.map(a => ({ ...a, remaining: (a.daily_send_limit || 150) - (sentToday[a.id] || 0) })).filter(a => a.remaining > 0);
    if (!accounts.length) return res.status(400).json({ error: 'All email IDs have reached daily limit' });

    const totalCapacity = accounts.reduce((s, a) => s + a.remaining, 0);
    const totalToSend = Math.min(ratio.total_to_send || 50, totalCapacity);

    // Fetch all unassigned leads — use range to bypass Supabase 1000 row default limit
    let pool = [], from = 0;
    while (true) {
      let q = supabase.from('jobs').select('id,position,freshness,industry,timezone,is_duplicate').is('deleted_at', null).eq('stage', 'Unassigned').is('assigned_to_bd', null).range(from, from + 999);
      if (ratio.exclude_duplicates) q = q.eq('is_duplicate', false);
      const { data } = await q;
      if (!data || !data.length) break;
      pool = pool.concat(data);
      if (data.length < 1000) break;
      from += 1000;
    }
    if (!pool?.length) return res.status(400).json({ error: 'No unassigned leads in pool' });

    const freshnessOrder = { 'Old': 0, 'Normal': 1, 'New': 2, '': 3 };
    const sorted = [...pool].sort((a, b) => (freshnessOrder[a.freshness] ?? 3) - (freshnessOrder[b.freshness] ?? 3));
    const selected = [];
    const used = { freshness: {}, industry: {}, timezone: {} };
    for (const job of sorted) {
      if (selected.length >= totalToSend) break;
      selected.push(job);
      used.freshness[job.freshness] = (used.freshness[job.freshness] || 0) + 1;
      used.industry[job.industry] = (used.industry[job.industry] || 0) + 1;
      used.timezone[job.timezone] = (used.timezone[job.timezone] || 0) + 1;
    }
    if (!selected.length) return res.status(400).json({ error: 'No leads matched distribution criteria' });

    const assignedLeads = [];
    const now = new Date();

    // Build a flat assignment queue — fill each account's slot count proportionally,
    // then shuffle the whole queue so jobs are interleaved randomly
    const totalToAssign = selected.length;
    const totalCap = accounts.reduce((s, a) => s + a.remaining, 0);
    const assignmentQueue = [];
    for (const account of accounts) {
      // How many of the totalToAssign does this account get, proportional to its remaining capacity
      const share = Math.round((account.remaining / totalCap) * totalToAssign);
      for (let i = 0; i < share; i++) assignmentQueue.push(account.id);
    }
    // If rounding left us short or over, pad/trim to exactly totalToAssign
    while (assignmentQueue.length < totalToAssign) assignmentQueue.push(accounts[assignmentQueue.length % accounts.length].id);
    while (assignmentQueue.length > totalToAssign) assignmentQueue.pop();
    // Fisher-Yates shuffle so assignment order is random, not blocks
    for (let i = assignmentQueue.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [assignmentQueue[i], assignmentQueue[j]] = [assignmentQueue[j], assignmentQueue[i]];
    }

    console.log(`[Distribute] Accounts in pool: ${accounts.map(a => a.email_address).join(', ')}`);
    console.log(`[Distribute] Assignment queue breakdown:`, assignmentQueue.reduce((m, id) => { m[id] = (m[id]||0)+1; return m; }, {}));

    for (let i = 0; i < selected.length; i++) {
      const job = selected[i];
      const emailId = assignmentQueue[i];
      await supabase.from('jobs').update({ assigned_to_bd: manager_id, sending_email_id: emailId, stage: 'Assigned', assigned_at: now, updated_at: now }).eq('id', job.id);
      assignedLeads.push({ job_id: job.id, user_email_id: emailId });
    }

    const countPerAccount = {};
    assignedLeads.forEach(l => { countPerAccount[l.user_email_id] = (countPerAccount[l.user_email_id] || 0) + 1; });
    for (const [eid, cnt] of Object.entries(countPerAccount)) {
      await supabase.from('email_send_log').upsert({ user_email_id: eid, send_date: todayDate, emails_sent: (sentToday[eid] || 0) + cnt }, { onConflict: 'user_email_id,send_date' });
    }

    // Create follow-up rows
    const jobIds = selected.map(j => j.id);
    const outreachDateStr = now.toISOString().split('T')[0];
    const { data: bdSettings } = await supabase.from('app_settings').select('key,value').in('key', [`u_${manager_id}_fu1_day`, `u_${manager_id}_fu2_day`]);
    const bdSettingsMap = {};
    (bdSettings || []).forEach(r => { bdSettingsMap[r.key] = r.value; });
    const fu1Day = parseInt(bdSettingsMap[`u_${manager_id}_fu1_day`] || '3', 10);
    const fu2Day = parseInt(bdSettingsMap[`u_${manager_id}_fu2_day`] || '7', 10);
    const fu1Date = new Date(now); fu1Date.setDate(fu1Date.getDate() + fu1Day);
    const fu2Date = new Date(now); fu2Date.setDate(fu2Date.getDate() + fu2Day);
    const fu1Str = fu1Date.toISOString().split('T')[0];
    const fu2Str = fu2Date.toISOString().split('T')[0];
    const { data: assignedJobs } = await supabase.from('jobs').select('id,sending_email_id,contacts(id,email,email_status)').in('id', jobIds);
    const followUpRows = [];
    for (const aj of (assignedJobs || [])) {
      const contacts = (aj.contacts || []).filter(c => isValidEmail(c.email) && isFollowupEligibleContact(c));
      for (const c of contacts) {
        followUpRows.push({ job_id: aj.id, contact_id: c.id, user_email_id: aj.sending_email_id, outreach_sent_at: outreachDateStr, followup1_due_date: fu1Str, followup2_due_date: fu2Str, status: 'active' });
      }
    }
    if (followUpRows.length) await supabase.from('follow_ups').insert(followUpRows);

    // Generate emails then auto-send — run fully in background, no HTTP self-call
    setImmediate(async () => {
      try {
        console.log(`[AutoSend] Starting background generate+send for manager ${manager_id}, ${jobIds.length} jobs`);
        await setSendProgress(manager_id, { active: true, total: 0, sent: 0, failed: 0, current: 'Generating emails...', failDetails: [], startedAt: new Date().toISOString(), autoSend: true });
        const generated = await generateEmailsForJobs(jobIds, manager_id);
        console.log(`[AutoSend] Generated ${generated} emails, now sending...`);
        if (generated === 0) {
          console.log(`[AutoSend] No emails generated for manager ${manager_id} — check contacts/templates`);
          await setSendProgress(manager_id, { active: false, done: true, total: 0, sent: 0, failed: 0, failDetails: [{ error: 'No emails generated — jobs may have no valid contact emails' }], completedAt: new Date().toISOString(), autoSend: true });
          setTimeout(() => clearSendProgress(manager_id), 300000);
          return;
        }
        await autoSendForManager(manager_id);
      } catch(e) {
        console.error('[AutoSend] Background error:', e.message, e.stack);
        await setSendProgress(manager_id, { active: false, done: true, total: 0, sent: 0, failed: 1, failDetails: [{ error: `Pipeline error: ${e.message}` }], completedAt: new Date().toISOString(), autoSend: true });
        setTimeout(() => clearSendProgress(manager_id), 300000);
      }
    });

    res.json({ success: true, total_assigned: selected.length, manager_id, by_freshness: used.freshness, by_industry: used.industry, by_timezone: used.timezone, email_accounts_used: Object.keys(countPerAccount).length, ratio_summary: ratio.summary || '', assigned_at: now.toISOString(), auto_send: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/distribute/pool-stats', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'ra_lead')) return res.status(403).json({ error: 'RA Lead only' });
    // Supabase default limit is 1000 — use range to fetch all rows in batches
    let pool = [], from = 0, batchSize = 1000;
    while (true) {
      const { data, error } = await supabase.from('jobs')
        .select('id,freshness,industry,timezone,is_duplicate,company:companies(industry)')
        .is('deleted_at', null).eq('stage', 'Unassigned').is('assigned_to_bd', null)
        .range(from, from + batchSize - 1);
      if (error) throw error;
      if (!data || !data.length) break;
      pool = pool.concat(data);
      if (data.length < batchSize) break;
      from += batchSize;
    }
    const stats = { total: pool.length, by_industry: {}, by_timezone: {}, duplicates: 0 };
    pool.forEach(j => {
      const rawInd = j.industry || j.company?.industry || '';
      const ind = normInd(rawInd) || 'Unknown';
      stats.by_industry[ind] = (stats.by_industry[ind] || 0) + 1;
      stats.by_timezone[j.timezone || 'Unknown'] = (stats.by_timezone[j.timezone || 'Unknown'] || 0) + 1;
      if (j.is_duplicate) stats.duplicates++;
    });
    res.json(stats);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/distribute/today-summary', auth, async (req, res) => {
  try {
    const targetId = req.query.manager_id || req.user.id;
    const { data: jobs } = await supabase.from('jobs').select('id,industry,timezone,assigned_at,company:companies(industry)').eq('assigned_to_bd', targetId).gte('assigned_at', today() + 'T00:00:00Z');
    const summary = { total: jobs?.length || 0, by_industry: {}, by_timezone: {} };
    (jobs || []).forEach(j => {
      const rawInd = j.industry || j.company?.industry || '';
      const ind = normInd(rawInd) || 'Unknown';
      summary.by_industry[ind] = (summary.by_industry[ind] || 0) + 1;
      summary.by_timezone[j.timezone || 'Unknown'] = (summary.by_timezone[j.timezone || 'Unknown'] || 0) + 1;
    });
    res.json(summary);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/jobs/bulk-stage', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd', 'bd_lead', 'ra_lead')) return res.status(403).json({ error: 'Not allowed' });
    const { job_ids, stage } = req.body;
    if (!Array.isArray(job_ids) || !job_ids.length) return res.status(400).json({ error: 'job_ids required' });
    const validStages = ['Unassigned', 'Assigned', 'Connected', 'Rejected', 'Future', 'In Discussion'];
    if (!validStages.includes(stage)) return res.status(400).json({ error: 'Invalid stage' });
    // BD users can only move leads to post-assignment stages — not back to Unassigned or Assigned
    const bdOnlyStages = ['Connected', 'Rejected', 'Future', 'In Discussion'];
    if (hasRole(req, 'bd', 'bd_lead') && !hasRole(req, 'admin', 'ra_lead') && !bdOnlyStages.includes(stage)) {
      return res.status(403).json({ error: 'BD users cannot set stage to ' + stage });
    }

    const updates = { stage, updated_at: new Date() };
    // If resetting to Unassigned, clear assignment fields so it re-enters the pool
    if (stage === 'Unassigned') {
      updates.assigned_to_bd = null;
      updates.sending_email_id = null;
      updates.assigned_at = null;
    }

    const { error } = await supabase.from('jobs').update(updates).in('id', job_ids);
    if (error) throw error;

    for (const jid of job_ids) await logActivity(jid, null, req.user.id, 'stage_changed', `Stage changed to ${stage}`, null, { stage });

    // If resetting to Unassigned, also delete any pending emails for these jobs
    if (stage === 'Unassigned') {
      await supabase.from('emails').delete().in('job_id', job_ids).eq('status', 'pending');
    }

    res.json({ success: true, updated: job_ids.length, stage });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/jobs/bulk-assign', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'ra_lead')) return res.status(403).json({ error: 'ra_lead or admin only' });
    const { job_ids, assigned_to_bd } = req.body;
    if (!Array.isArray(job_ids) || !job_ids.length) return res.status(400).json({ error: 'job_ids array required' });
    if (!assigned_to_bd) return res.status(400).json({ error: 'assigned_to_bd required' });
    const { data: bd } = await supabase.from('users').select('id,name').eq('id', assigned_to_bd).single();
    if (!bd) return res.status(400).json({ error: 'BD user not found' });

    // Get BD's primary active email ID for sending
    const { data: bdEmails } = await supabase.from('user_emails')
      .select('id,email_address,is_primary')
      .eq('user_id', assigned_to_bd)
      .eq('is_active', true)
      .order('is_primary', { ascending: false });
    const sendingEmailId = (bdEmails && bdEmails.length) ? bdEmails[0].id : null;

    const now = new Date();
    const updatePayload = { assigned_to_bd, assigned_at: now, stage: 'Assigned', updated_at: now };
    if (sendingEmailId) updatePayload.sending_email_id = sendingEmailId;
    const { error } = await supabase.from('jobs').update(updatePayload).in('id', job_ids);
    if (error) throw error;
    for (const jid of job_ids) await logActivity(jid, null, req.user.id, 'bulk_assigned', `Bulk assigned to BD: ${bd.name}`, null, { assigned_to_bd, bd_name: bd.name });
    res.json({ success: true, assigned: job_ids.length, bd_name: bd.name, sending_email_id: sendingEmailId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/jobs/check-duplicates', auth, async (req, res) => {
  try {
    const { emails } = req.body;
    if (!Array.isArray(emails) || !emails.length) return res.json({ duplicates: [] });
    const { data, error } = await supabase.from('contacts').select('email, job_id, job:jobs(id,position,company_id,company:companies(name))').in('email', emails.map(e => e.toLowerCase().trim())).not('email', 'is', null);
    if (error) throw error;
    res.json({ duplicates: data || [] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// AI EMAIL GENERATION
// ══════════════════════════════════════════════════════════════
app.post('/ai/generate-email', auth, async (req, res) => {
  try {
    const { lead, contact, company, template } = req.body;
    const c = contact || lead || {};
    const vars = { fn: c.first_name, ln: c.last_name, company: company?.name, ind: company?.industry, pos: c.position || req.body.position, desig: c.designation, loc: company?.location, sender: req.user.name };
    const fill = (s) => (s || '').replace(/{{(\w+)}}/g, (m, k) => vars[k] || m);
    if (!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY === 'your_anthropic_api_key_here') {
      return res.json({ subject: fill(template?.subject || 'Opportunity at {{company}}'), body: fill(template?.body || 'Hi {{fn}},') });
    }
    const prompt = `Write a hyper-personalized cold outreach email for a business development executive at Fute Global LLC.\nContact: ${vars.fn} ${vars.ln || ''}, ${vars.desig || ''} at ${vars.company} (${vars.ind || ''}, ${vars.loc || ''})\nPosition: ${vars.pos || ''}\nFormat:\nSubject: [subject line]\n\n[email body]`;
    const response = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 600, messages: [{ role: 'user', content: prompt }] }) });
    const aiData = await response.json();
    const text = aiData.content?.[0]?.text || '';
    const subjectMatch = text.match(/Subject:\s*(.+)/i);
    res.json({ subject: subjectMatch ? subjectMatch[1].trim() : `Opportunity at ${vars.company}`, body: text.replace(/^Subject:.+\n*/im, '').trim() });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// APP SETTINGS
// ══════════════════════════════════════════════════════════════
app.post('/ai/generate-summary', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'ra_lead')) return res.status(403).json({ error: 'Not allowed' });
    const { data } = req.body;
    if (!data) return res.status(400).json({ error: 'data required' });

    if (!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY === 'your_anthropic_api_key_here') {
      return res.json({ summary: 'AI summary unavailable — no API key configured.' });
    }

    // Build top industries string
    const indEntries = Object.entries(data.byIndustry || {}).sort((a,b) => b[1]-a[1]);
    const topInds = indEntries.slice(0,4).map(([k,v]) => `${k} (${v})`).join(', ');
    const freshEntries = Object.entries(data.byFreshness || {});
    const freshStr = freshEntries.map(([k,v]) => `${v} ${k}`).join(', ');
    const tzEntries = Object.entries(data.byTimezone || {}).sort((a,b) => b[1]-a[1]);
    const topTz = tzEntries.slice(0,3).map(([k,v]) => `${k} (${v})`).join(', ');

    const prompt = `You are writing a daily lead import briefing for the BD (Business Development) team at Fute Global LLC, a staffing/recruitment firm. Write a warm, professional 3-4 sentence summary in plain prose — no bullet points, no headers, no lists. Make it feel like a helpful manager giving context to the team before they start their day.

Cover these points naturally:
- Total leads imported today (${data.total}) with ${data.clean} clean and ${data.duplicates > 0 ? data.duplicates + ' flagged as duplicates' : 'no duplicates'}
- Top industries: ${topInds || 'mixed industries'}
- Freshness mix: ${freshStr || 'normal'}
- Timezone spread: ${topTz || 'EST'}
- Top positions being hired: ${(data.topPositions || []).slice(0,3).join(', ')}
- Total unassigned pool now has ${data.poolSize} leads ready to work

Keep it concise, informative and actionable. End with one sentence about what the team should focus on today based on the data.`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 400, messages: [{ role: 'user', content: prompt }] })
    });
    const aiData = await response.json();
    const summary = aiData.content?.[0]?.text?.trim() || 'Summary unavailable.';
    res.json({ summary });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/app-settings', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('app_settings').select('key,value');
    if (error) throw error;
    const settings = {};
    (data || []).forEach(r => { settings[r.key] = r.value; });
    res.json(settings);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/app-settings', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'ra_lead')) return res.status(403).json({ error: 'Admin or RA Lead only' });
    const { key, value } = req.body;
    if (!key || value === undefined) return res.status(400).json({ error: 'key and value required' });
    const { error } = await supabase.from('app_settings').upsert({ key, value, updated_at: new Date() }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true, key, value });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// OUTREACH PLAN (per-user)
// ══════════════════════════════════════════════════════════════
app.get('/outreach-plan', auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const keys = [`u_${uid}_fu1_day`,`u_${uid}_fu2_day`,`u_${uid}_tmpl_o1_subject`,`u_${uid}_tmpl_o1_body`,`u_${uid}_tmpl_fu1_subject`,`u_${uid}_tmpl_fu1_body`,`u_${uid}_tmpl_fu2_subject`,`u_${uid}_tmpl_fu2_body`,`u_${uid}_signature_html`,`u_${uid}_random_template_mode`,`u_${uid}_compose_style_preset`];
    const { data } = await supabase.from('app_settings').select('key,value').in('key', keys);
    const plan = {};
    (data || []).forEach(r => { plan[r.key.replace(`u_${uid}_`, '')] = r.value; });

    const tmplFields = ['tmpl_o1_subject', 'tmpl_o1_body', 'tmpl_fu1_subject', 'tmpl_fu1_body', 'tmpl_fu2_subject', 'tmpl_fu2_body'];
    const migrations = [];
    tmplFields.forEach(field => {
      const shortKey = field.replace('tmpl_', '');
      const resolved = resolveTemplate(plan[field], shortKey);
      if (plan[field] && resolved !== plan[field]) {
        plan[field] = resolved;
        migrations.push({ key: `u_${uid}_${field}`, value: resolved });
      }
    });
    if (migrations.length) {
      await supabase.from('app_settings').upsert(
        migrations.map(m => ({ key: m.key, value: m.value, updated_at: new Date() })),
        { onConflict: 'key' }
      );
    }

    res.json(plan);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/outreach-plan', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'bd', 'bd_lead', 'admin')) return res.status(403).json({ error: 'BD role required' });
    const uid = req.user.id;
    const allowed = ['fu1_day','fu2_day','tmpl_o1_subject','tmpl_o1_body','tmpl_fu1_subject','tmpl_fu1_body','tmpl_fu2_subject','tmpl_fu2_body','signature_html','random_template_mode','compose_style_preset'];
    const { key, value } = req.body;
    if (!allowed.includes(key)) return res.status(400).json({ error: 'Invalid key' });
    const fullKey = `u_${uid}_${key}`;
    const { error } = await supabase.from('app_settings').upsert({ key: fullKey, value: String(value), updated_at: new Date() }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true, key: fullKey, value });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// FOLLOW-UPS
// ══════════════════════════════════════════════════════════════
app.get('/follow-ups', auth, async (req, res) => {
  try {
    let query = supabase.from('follow_ups').select(`*, contact:contacts(id,first_name,last_name,email,designation), job:jobs(id,position,stage,company:companies(name))`).order('followup1_due_date', { ascending: true });
    if (hasRole(req, 'bd') && !hasRole(req, 'admin', 'ra_lead', 'bd_lead')) {
      const { data: myJobs } = await supabase.from('jobs').select('id').eq('assigned_to_bd', req.user.id).is('deleted_at', null);
      const myJobIds = (myJobs || []).map(j => j.id);
      if (!myJobIds.length) return res.json([]);
      query = query.in('job_id', myJobIds);
    }
    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/follow-ups/run', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd_lead')) return res.status(403).json({ error: 'Admin only' });
    const result = await runFollowupEngine();
    res.json({ success: true, ...result });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

async function runFollowupEngine() {
  const todayDate = today();
  const log = { checked: 0, fu1_queued: 0, fu2_queued: 0, skipped_quota: 0, skipped_stage: 0, skipped_contact_status: 0 };
  try {
    const { data: dueFu, error: fuErr } = await supabase.from('follow_ups')
      .select(`*, contact:contacts(id,first_name,last_name,email,designation,email_status,ooo_until), job:jobs(id,position,location,salary_range,research,industry,stage,timezone,assigned_to_bd,company:companies(name,industry,location),sending_email:user_emails!sending_email_id(id,email_address,display_name))`)
      .eq('status', 'active');
    if (fuErr) throw fuErr;
    log.checked = (dueFu || []).length;

    const { data: settingsRows } = await supabase.from('app_settings').select('key,value');
    const settings = {};
    (settingsRows || []).forEach(r => { settings[r.key] = r.value; });

    function getBDTemplate(bdId, key, globalKey, fallback) {
      const shortKey = key.replace('tmpl_', '');
      const saved = settings[`u_${bdId}_${key}`] || settings[globalKey] || '';
      return resolveTemplate(saved, shortKey) || fallback;
    }
    const { data: sendLogs } = await supabase.from('email_send_log').select('user_email_id,emails_sent').eq('send_date', todayDate);
    const sentToday = {};
    (sendLogs || []).forEach(l => { sentToday[l.user_email_id] = l.emails_sent || 0; });

    const { data: allEmails } = await supabase.from('user_emails').select('id,daily_send_limit').eq('is_active', true);
    const limitMap = {};
    (allEmails || []).forEach(a => { limitMap[a.id] = a.daily_send_limit || 150; });

    const bdIdSet = [...new Set((dueFu || []).map(f => f.job?.assigned_to_bd).filter(Boolean))];
    let bdMap = {};
    if (bdIdSet.length) {
      const { data: bdUsers } = await supabase.from('users').select('id,name').in('id', bdIdSet);
      (bdUsers || []).forEach(u => { bdMap[u.id] = u.name; });
    }

    const emailsToInsert = [];
    const fu1Updates = [];
    const fu2Updates = [];
    const acCountDelta = {};

    const fu1Due = (dueFu || []).filter(f => !f.followup1_sent_at && f.followup1_due_date <= todayDate);
    const fu2Due = (dueFu || []).filter(f => f.followup1_sent_at && !f.followup2_sent_at && f.followup2_due_date <= todayDate);

    const fuJobIds = [...new Set((dueFu || []).map(f => f.job_id).filter(Boolean))];
    const variantByPair = {};
    if (fuJobIds.length) {
      const { data: o1Sent } = await supabase.from('emails')
        .select('job_id, contact_id, template_variant, sent_at')
        .in('job_id', fuJobIds)
        .eq('status', 'sent')
        .is('followup_type', null)
        .order('sent_at', { ascending: false });
      (o1Sent || []).forEach(row => {
        const key = `${row.job_id}:${row.contact_id}`;
        if (!variantByPair[key] && row.template_variant) variantByPair[key] = row.template_variant;
      });
    }

    for (const fuList of [fu1Due, fu2Due]) {
      const isFu2 = fuList === fu2Due;
      for (const fu of fuList) {
        const job = fu.job;
        if (!job || job.stage !== 'Assigned') {
          await supabase.from('follow_ups').update({ status: 'skipped' }).eq('id', fu.id);
          log.skipped_stage++; continue;
        }
        const acId = job.sending_email?.id;
        if (!acId) continue;
        const rem = (limitMap[acId] || 150) - (sentToday[acId] || 0) - (acCountDelta[acId] || 0);
        if (rem <= 0) { log.skipped_quota++; continue; }
        const contact = fu.contact;
        if (!contact?.email) continue;
        if (!isFollowupEligibleContact(contact)) {
          log.skipped_contact_status++;
          if (isPermanentFollowupBlock(contactEmailStatus(contact))) {
            await supabase.from('follow_ups').update({ status: 'skipped' }).eq('id', fu.id);
          }
          continue;
        }
        const bdId = job.assigned_to_bd;
        // Use sending email display_name so signature matches the From address
        const senderName = job.sending_email?.display_name || bdMap[bdId] || 'Fute Global';
        const vars = buildEmailVars({ job, contact, senderDisplayName: senderName });
        const useRandomFu = isRandomTemplateMode(settings[`u_${bdId}_random_template_mode`]);
        let subjTmpl, bodyTmpl, variantId;
        if (useRandomFu) {
          const pairKey = `${fu.job_id}:${fu.contact_id}`;
          variantId = variantByPair[pairKey] || settings[`u_${bdId}_compose_style_preset`] || 'v1';
          const variant = getVariantById(variantId);
          const fuTmpl = isFu2 ? variant.fu2 : variant.fu1;
          subjTmpl = fuTmpl.subject;
          bodyTmpl = fuTmpl.body;
        } else {
          subjTmpl = isFu2
            ? getBDTemplate(bdId, 'tmpl_fu2_subject', 'template_fu2_subject', DEFAULT_TEMPLATES.fu2_subject)
            : getBDTemplate(bdId, 'tmpl_fu1_subject', 'template_fu1_subject', DEFAULT_TEMPLATES.fu1_subject);
          bodyTmpl = isFu2
            ? getBDTemplate(bdId, 'tmpl_fu2_body', 'template_fu2_body', DEFAULT_TEMPLATES.fu2_body)
            : getBDTemplate(bdId, 'tmpl_fu1_body', 'template_fu1_body', DEFAULT_TEMPLATES.fu1_body);
        }
        const fuRow = {
          contact_id: fu.contact_id,
          job_id: fu.job_id,
          to_email: contact.email,
          from_email: job.sending_email?.email_address || null,
          subject: fillTemplate(subjTmpl, vars),
          body: fillTemplate(bodyTmpl, vars),
          platform: 'Outlook',
          sent_by: bdId,
          status: 'pending',
          followup_type: isFu2 ? 'fu2' : 'fu1',
          follow_up_id: fu.id
        };
        if (variantId) fuRow.template_variant = variantId;
        emailsToInsert.push(fuRow);
        if (isFu2) { fu2Updates.push(fu.id); log.fu2_queued++; } else { fu1Updates.push(fu.id); log.fu1_queued++; }
        acCountDelta[acId] = (acCountDelta[acId] || 0) + 1;
      }
    }

    if (emailsToInsert.length) {
      await supabase.from('emails').insert(emailsToInsert);
      const fuBdIds = [...new Set(emailsToInsert.map(e => e.sent_by).filter(Boolean))];
      setImmediate(() => {
        fuBdIds.forEach(bdId => autoSendForManager(bdId).catch(e => console.error('[FollowupEngine] autoSend error:', e.message)));
      });
    }
    const nowTs = new Date().toISOString();
    if (fu1Updates.length) await supabase.from('follow_ups').update({ followup1_sent_at: nowTs }).in('id', fu1Updates);
    if (fu2Updates.length) { await supabase.from('follow_ups').update({ followup2_sent_at: nowTs, status: 'completed' }).in('id', fu2Updates); }
    for (const [acId, cnt] of Object.entries(acCountDelta)) {
      await supabase.from('email_send_log').upsert({ user_email_id: acId, send_date: todayDate, emails_sent: (sentToday[acId] || 0) + cnt }, { onConflict: 'user_email_id,send_date' });
    }
    console.log(`[FollowupEngine] FU1: ${log.fu1_queued}, FU2: ${log.fu2_queued}, skipped_quota: ${log.skipped_quota}, skipped_stage: ${log.skipped_stage}, skipped_contact_status: ${log.skipped_contact_status}`);
    return log;
  } catch (err) { console.error('[FollowupEngine] Error:', err.message); return { ...log, error: err.message }; }
}

function toIST(date) { const utc = date.getTime() + date.getTimezoneOffset() * 60000; return new Date(utc + 5.5 * 3600000); }

async function getLastFollowupRun() {
  try {
    const { data } = await supabase.from('app_settings').select('value').eq('key', 'last_followup_run').single();
    return data?.value || null;
  } catch { return null; }
}
async function setLastFollowupRun(dateStr) {
  try {
    await supabase.from('app_settings').upsert({ key: 'last_followup_run', value: dateStr }, { onConflict: 'key' });
  } catch (e) { console.error('[Cron] Failed to persist last_followup_run:', e.message); }
}

// Run follow-ups on startup if not already run today
(async () => {
  try {
    const now = toIST(new Date());
    const todayStr = now.toISOString().split('T')[0];
    const lastRun = await getLastFollowupRun();
    if (lastRun !== todayStr) {
      console.log(`[Startup] Follow-ups not yet run today (last: ${lastRun || 'never'}). Running now...`);
      await setLastFollowupRun(todayStr);
      const result = await runFollowupEngine();
      console.log(`[Startup] Follow-up engine result: FU1=${result.fu1_queued}, FU2=${result.fu2_queued}`);
    } else {
      console.log(`[Startup] Follow-ups already ran today (${lastRun}). Skipping.`);
    }
  } catch (e) { console.error('[Startup] Follow-up check error:', e.message); }
})();

// Interval cron as backup — persisted to DB instead of in-memory
setInterval(async () => {
  try {
    const now = toIST(new Date());
    const hhmm = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
    const dateStr = now.toISOString().split('T')[0];
    const { data: settingsRows } = await supabase.from('app_settings').select('key,value');
    const settings = {};
    (settingsRows || []).forEach(r => { settings[r.key] = r.value; });
    const lastRun = settings['last_followup_run'];
    if (hhmm === (settings['followup_send_time'] || '08:30') && lastRun !== dateStr) {
      await setLastFollowupRun(dateStr);
      console.log(`[Cron] Follow-up engine triggered at ${hhmm} IST`);
      await runFollowupEngine();
    }
  } catch (e) { console.error('[Cron] Error:', e.message); }
}, 60000);

// Retry pending emails when leads enter their local send window (every 20 minutes)
setInterval(() => { retryDeferredPendingSends(); }, 20 * 60 * 1000);
setTimeout(() => { retryDeferredPendingSends(); }, 3 * 60 * 1000);

// ══════════════════════════════════════════════════════════════
// MICROSOFT OAUTH
// ══════════════════════════════════════════════════════════════
const MS_TENANT   = process.env.MICROSOFT_TENANT_ID;
const MS_CLIENT   = process.env.MICROSOFT_CLIENT_ID;
const MS_SECRET   = process.env.MICROSOFT_CLIENT_SECRET;
const MS_REDIRECT = 'https://fute-lms-backend.onrender.com/auth/microsoft/callback';
const MS_SCOPES   = 'Mail.Send Mail.ReadWrite offline_access User.Read';

app.get('/auth/microsoft/connect', async (req, res) => {
  try {
    const token = req.query.token || (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return res.status(401).send('Unauthorized');
    let reqUser;
    try { reqUser = jwt.verify(token, process.env.JWT_SECRET); } catch { return res.status(401).send('Invalid token'); }
    if (!reqUser.roles?.includes('admin') && reqUser.role !== 'admin') return res.status(403).send('Admin only');
    const { userEmailId } = req.query;
    if (!userEmailId) return res.status(400).send('userEmailId required');
    const state = Buffer.from(JSON.stringify({ userEmailId, userId: reqUser.id })).toString('base64');
    const url = `https://login.microsoftonline.com/${MS_TENANT}/oauth2/v2.0/authorize?client_id=${MS_CLIENT}&response_type=code&redirect_uri=${encodeURIComponent(MS_REDIRECT)}&scope=${encodeURIComponent(MS_SCOPES)}&state=${encodeURIComponent(state)}&prompt=select_account`;
    res.redirect(url);
  } catch (err) { res.status(500).send(err.message); }
});

app.get('/auth/microsoft/callback', async (req, res) => {
  try {
    const { code, state, error: msError } = req.query;
    if (msError) return res.send(`<script>window.opener&&window.opener.postMessage({type:'ms_oauth_error',error:'${msError}'},'*');window.close();</script>`);
    if (!code || !state) return res.status(400).send('Missing code or state');
    const { userEmailId, userId } = JSON.parse(Buffer.from(decodeURIComponent(state), 'base64').toString());
    const tokenRes = await fetch(`https://login.microsoftonline.com/${MS_TENANT}/oauth2/v2.0/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: MS_CLIENT, client_secret: MS_SECRET, code, redirect_uri: MS_REDIRECT, grant_type: 'authorization_code', scope: MS_SCOPES }) });
    const tokens = await tokenRes.json();
    if (tokens.error) return res.send(`<scr`+`ipt>window.opener&&window.opener.postMessage({type:'ms_oauth_error',userEmailId:'${userEmailId}',error:'${tokens.error_description}'},'*');window.close();</scr`+`ipt>`);
    const expiresAt = new Date(Date.now() + tokens.expires_in * 1000).toISOString();
    const profileRes = await fetch('https://graph.microsoft.com/v1.0/me', { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    const profile = await profileRes.json();
    const emailAddress = profile.mail || profile.userPrincipalName || '';

    // ── VALIDATE FIRST before touching the DB ──────────────────
    const { data: userEmailRow } = await supabase.from('user_emails').select('email_address').eq('id', userEmailId).single();
    const expectedEmail = (userEmailRow?.email_address || '').toLowerCase().trim();
    const actualEmail = emailAddress.toLowerCase().trim();
    if (expectedEmail && actualEmail && expectedEmail !== actualEmail) {
      const errMsg = `Wrong account: you logged in as ${emailAddress} but this slot is for ${userEmailRow.email_address}. Please sign out of Microsoft and try again with the correct account.`;
      return res.send(`<scr`+`ipt>window.opener&&window.opener.postMessage({type:'ms_oauth_error',userEmailId:'${userEmailId}',error:${JSON.stringify(errMsg)}},'*');window.close();</scr`+`ipt>`);
    }

    // Validation passed — now safe to delete old token and save new one
    await supabase.from('microsoft_tokens').delete().eq('user_email_id', userEmailId);
    const { error: insertErr } = await supabase.from('microsoft_tokens').insert(
      { user_email_id: userEmailId, user_id: userId, email_address: emailAddress, access_token: tokens.access_token, refresh_token: tokens.refresh_token, expires_at: expiresAt, updated_at: new Date() }
    );
    if (insertErr) {
      console.error('microsoft_tokens insert error:', insertErr);
      return res.send(`<scr`+`ipt>window.opener&&window.opener.postMessage({type:'ms_oauth_error',userEmailId:'${userEmailId}',error:'DB save failed: ${insertErr.message}'},'*');window.close();</scr`+`ipt>`);
    }
    await supabase.from('user_emails').update({ platform: 'Microsoft', is_active: true }).eq('id', userEmailId);
    res.send(`<scr`+`ipt>window.opener&&window.opener.postMessage({type:'ms_oauth_success',userEmailId:'${userEmailId}',email:'${emailAddress}'},'*');window.close();</scr`+`ipt>`);
  } catch (err) {
    console.error('Microsoft OAuth callback error:', err);
    res.send(`<scr`+`ipt>window.opener&&window.opener.postMessage({type:'ms_oauth_error',userEmailId:'${userEmailId||''}',error:'${err.message}'},'*');window.close();</scr`+`ipt>`);
  }
});

// Random delay between emails to avoid domain flagging (1–120 seconds)
// Validate recipient email before sending — prevents Microsoft Graph 'not resolved' errors
function isValidEmail(addr) {
  return typeof addr === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(addr.trim());
}

const BLOCKED_FOLLOWUP_STATUSES = new Set(['invalid', 'deactivated', 'out_of_office']);

function contactEmailStatus(contact) {
  return String(contact?.email_status || 'valid').toLowerCase();
}

function isFollowupEligibleContact(contact) {
  if (!contact || !isValidEmail(contact.email)) return false;
  return !BLOCKED_FOLLOWUP_STATUSES.has(contactEmailStatus(contact));
}

function isPermanentFollowupBlock(status) {
  const s = String(status || '').toLowerCase();
  return s === 'invalid' || s === 'deactivated';
}

async function skipActiveFollowUpsForContact(contactId) {
  if (!contactId) return;
  await supabase.from('follow_ups').update({ status: 'skipped' }).eq('contact_id', contactId).eq('status', 'active');
}

async function cancelBlockedFollowupSend(email, contactStatus) {
  if (!email?.id) return;
  try { await supabase.from('emails').delete().eq('id', email.id); } catch (_) {}
  if (!email.follow_up_id) return;
  const status = String(contactStatus || '').toLowerCase();
  if (email.followup_type === 'fu1') {
    await supabase.from('follow_ups').update({ followup1_sent_at: null }).eq('id', email.follow_up_id);
  } else if (email.followup_type === 'fu2') {
    await supabase.from('follow_ups').update({ followup2_sent_at: null, status: 'active' }).eq('id', email.follow_up_id);
  }
  if (isPermanentFollowupBlock(status)) {
    await supabase.from('follow_ups').update({ status: 'skipped' }).eq('id', email.follow_up_id);
  }
}

function randomDelay(minSec = 1, maxSec = 120) {
  const ms = Math.floor(Math.random() * (maxSec - minSec + 1) + minSec) * 1000;
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Send progress tracking — stored in app_settings keyed per user
async function setSendProgress(userId, data) {
  const key = `send_progress_${userId}`;
  try { await supabase.from('app_settings').upsert({ key, value: JSON.stringify(data) }, { onConflict: 'key' }); } catch(_) {}
}
async function clearSendProgress(userId) {
  const key = `send_progress_${userId}`;
  try { await supabase.from('app_settings').delete().eq('key', key); } catch(_) {}
}

async function getMicrosoftToken(userEmailId) {
  const { data: tokenRow, error } = await supabase.from('microsoft_tokens').select('*').eq('user_email_id', userEmailId).single();
  if (error || !tokenRow) throw new Error('No Microsoft token found. Please reconnect.');
  const now = new Date();
  if (new Date(tokenRow.expires_at).getTime() - now.getTime() > 5 * 60 * 1000) return tokenRow.access_token;
  const refreshRes = await fetch(`https://login.microsoftonline.com/${MS_TENANT}/oauth2/v2.0/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: MS_CLIENT, client_secret: MS_SECRET, refresh_token: tokenRow.refresh_token, grant_type: 'refresh_token', scope: MS_SCOPES }) });
  const refreshed = await refreshRes.json();
  if (refreshed.error) throw new Error('Token refresh failed: ' + refreshed.error_description);
  await supabase.from('microsoft_tokens').update({ access_token: refreshed.access_token, refresh_token: refreshed.refresh_token || tokenRow.refresh_token, expires_at: new Date(Date.now() + refreshed.expires_in * 1000).toISOString(), updated_at: new Date() }).eq('user_email_id', userEmailId);
  return refreshed.access_token;
}

// Build an HTML email body from plain text + optional HTML signature.
// Plain text is escaped and wrapped in <p> tags with <br> for line breaks.
// The signature (already HTML) is appended after a ruled separator.
function buildHtmlEmailBody(plainText, signatureHtml) {
  const escaped = (plainText || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const htmlBody = '<p>' + escaped.replace(/\n\n/g, '</p><p>').replace(/\n/g, '<br>') + '</p>';
  const sig = signatureHtml && signatureHtml.trim()
    ? '<hr style="border:none;border-top:1px solid #e2e8f0;margin:18px 0">' + signatureHtml
    : '';
  return '<div style="font-family:Arial,sans-serif;font-size:14px;line-height:1.6;color:#0F172A">' + htmlBody + sig + '</div>';
}

app.post('/emails/send-microsoft', auth, async (req, res) => {
  try {
    const { user_email_id, to_email, subject, body, email_id, signature_html } = req.body;
    if (!user_email_id || !to_email || !subject || !body) return res.status(400).json({ error: 'user_email_id, to_email, subject, body required' });
    const { data: mailbox } = await supabase.from('user_emails').select('id,user_id,email_address,display_name').eq('id', user_email_id).single();
    const sigTemplate = resolveSignatureHtml(signature_html || await getMailboxSignature(user_email_id, mailbox?.user_id || req.user.id));
    const filledSig = fillSignatureHtml(sigTemplate, {
      displayName: mailbox?.display_name || '',
      emailAddress: mailbox?.email_address || ''
    });
    const accessToken = await getMicrosoftToken(user_email_id);
    const htmlContent = buildHtmlEmailBody(body, filledSig);
    const sendRes = await fetch('https://graph.microsoft.com/v1.0/me/sendMail', { method: 'POST', headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ message: { subject, body: { contentType: 'HTML', content: htmlContent }, toRecipients: [{ emailAddress: { address: to_email } }] }, saveToSentItems: true }) });
    if (!sendRes.ok) { const errData = await sendRes.json().catch(() => ({})); throw new Error(errData?.error?.message || `Send failed: ${sendRes.status}`); }
    if (email_id) await supabase.from('emails').update({ status: 'sent', sent_at: today() }).eq('id', email_id);
    const todayDate = today();
    const { data: logRow } = await supabase.from('email_send_log').select('emails_sent').eq('user_email_id', user_email_id).eq('send_date', todayDate).single();
    await supabase.from('email_send_log').upsert({ user_email_id, send_date: todayDate, emails_sent: (logRow?.emails_sent || 0) + 1 }, { onConflict: 'user_email_id,send_date' });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/auth/microsoft/status/:userEmailId', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('microsoft_tokens').select('email_address,expires_at').eq('user_email_id', req.params.userEmailId).single();
    if (!data) return res.json({ connected: false });
    res.json({ connected: true, email_address: data.email_address, expired: new Date(data.expires_at) < new Date() });
  } catch { res.json({ connected: false }); }
});

app.get('/auth/microsoft/schema-check', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin')) return res.status(403).json({ error: 'Admin only' });
    // Check what columns microsoft_tokens actually has by trying a select
    const { data, error } = await supabase.from('microsoft_tokens').select('*').eq('user_id', req.user.id);
    if (error) return res.json({ error: error.message, hint: error.hint, details: error.details });
    res.json({ rows: data, count: (data||[]).length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/auth/microsoft/debug', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin')) return res.status(403).json({ error: 'Admin only' });
    // All user_emails for this user
    const { data: userEmails } = await supabase.from('user_emails').select('id,email_address,display_name,platform,is_active').eq('user_id', req.user.id);
    // All microsoft_tokens for this user
    const { data: tokens } = await supabase.from('microsoft_tokens').select('user_email_id,email_address,expires_at').eq('user_id', req.user.id);
    // Jobs assigned to this user with their sending_email_id
    const { data: jobs } = await supabase.from('jobs').select('id,position,sending_email_id,sending_email:user_emails!sending_email_id(id,email_address,platform)').eq('assigned_to_bd', req.user.id).is('deleted_at', null);
    // Cross-reference: which job sending_email_ids have tokens
    const tokenIds = new Set((tokens||[]).map(t => t.user_email_id));
    const jobSummary = (jobs||[]).map(j => ({
      job_id: j.id, position: j.position,
      sending_email_id: j.sending_email_id,
      sending_email: j.sending_email?.email_address,
      platform: j.sending_email?.platform,
      has_token: j.sending_email_id ? tokenIds.has(j.sending_email_id) : false
    }));
    res.json({ user_emails: userEmails, tokens: (tokens||[]).map(t => ({ ...t, expired: new Date(t.expires_at) < new Date() })), jobs: jobSummary });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/auth/microsoft/:userEmailId', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd_lead')) return res.status(403).json({ error: 'Admin only' });
    await supabase.from('microsoft_tokens').delete().eq('user_email_id', req.params.userEmailId);
    await supabase.from('user_emails').update({ is_active: false }).eq('id', req.params.userEmailId);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── BD MANAGER / RECRUITER WORKFLOW (branch: bd-manager-recruiter-workflow) ──
// Additive module — registers new routes only; nothing above is modified.
require('./bd_recruiter_routes')(app, { supabase, auth, hasRole, notGuest, today });

// ── START ──────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Fute Global LMS API v3.0.0 running on port ${PORT}`));
module.exports = app;
