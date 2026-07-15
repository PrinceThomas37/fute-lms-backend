// ============================================================================
// EXTERNAL INTEGRATIONS — API keys managed from the admin UI.
//
// A registry of third-party providers (AI, email verification, contact
// databases, …) and a small store on top of app_settings, so an admin can paste
// a key in the UI and the backend hook picks it up — no redeploy, no env var.
//
// Security posture:
//   - Keys live in app_settings under "int_<id>_<field>" (same store the app
//     already uses for config). Admin-only read/write at the route layer.
//   - Reads for the UI are ALWAYS masked (never return a stored secret to the
//     browser) — the UI shows "configured" + a masked hint, not the value.
//   - getSecret() returns the real value for SERVER-SIDE use only.
//   - Anthropic falls back to the ANTHROPIC_API_KEY env var if no UI key is set,
//     so nothing that works today breaks.
// (Hardening note: values are stored as-is, like the rest of app_settings. A
//  future pass could encrypt-at-rest behind a KMS; out of scope here.)
// ============================================================================

const PREFIX = 'int_';
const ACTIVE_VERIFIER_KEY = 'int_email_verify_active';

// Registry. `test` names a provider-specific connection test (routes/integrations
// implements them); `env_fallback` lets a value come from an env var if unset.
const INTEGRATIONS = [
  {
    id: 'anthropic', category: 'AI', label: 'Anthropic (Claude)',
    description: 'Powers AI email drafting and summaries.',
    docs: 'https://console.anthropic.com/settings/keys',
    fields: [{ key: 'api_key', label: 'API key', placeholder: 'sk-ant-…' }],
    env_fallback: { api_key: 'ANTHROPIC_API_KEY' }, test: 'anthropic',
  },
  {
    id: 'zerobounce', category: 'Email verification', label: 'ZeroBounce',
    description: 'Verify an address before the first send, so dead inboxes never get mailed.',
    docs: 'https://www.zerobounce.net/members/api/', verifier: true,
    fields: [{ key: 'api_key', label: 'API key' }], test: 'zerobounce',
  },
  {
    id: 'neverbounce', category: 'Email verification', label: 'NeverBounce',
    description: 'Alternative pre-send email verifier.',
    docs: 'https://developers.neverbounce.com/', verifier: true,
    fields: [{ key: 'api_key', label: 'API key' }], test: 'neverbounce',
  },
  {
    id: 'hunter', category: 'Contact database', label: 'Hunter.io',
    description: 'Find and verify work emails by domain. Can also act as an email verifier.',
    docs: 'https://hunter.io/api-keys', verifier: true,
    fields: [{ key: 'api_key', label: 'API key' }], test: 'hunter',
  },
  {
    id: 'apollo', category: 'Contact database', label: 'Apollo.io',
    description: 'Find POC contacts + emails and enrich companies (used by the future auto-sourcing engine).',
    docs: 'https://apolloio.github.io/apollo-api-docs/',
    fields: [{ key: 'api_key', label: 'API key' }], test: 'apollo',
  },
];

const BY_ID = new Map(INTEGRATIONS.map((i) => [i.id, i]));
const keyName = (id, field) => `${PREFIX}${id}_${field}`;
const mask = (v) => (v ? '••••••' + String(v).slice(-4) : null);

// Real secret for server-side use: stored value first, then env fallback.
async function getSecret(supabase, id, field = 'api_key') {
  const def = BY_ID.get(id);
  if (!def) return null;
  try {
    const { data } = await supabase.from('app_settings').select('value').eq('key', keyName(id, field)).maybeSingle();
    if (data && data.value) return data.value;
  } catch (_) {}
  const envVar = def.env_fallback && def.env_fallback[field];
  return envVar ? (process.env[envVar] || null) : null;
}

async function isConfigured(supabase, id) {
  const def = BY_ID.get(id);
  if (!def) return false;
  for (const f of def.fields) {
    const v = await getSecret(supabase, id, f.key);
    if (!v) return false;
  }
  return true;
}

// Registry + masked status for the admin UI. Never returns raw secrets.
async function getAll(supabase) {
  let rows = [];
  try {
    const { data } = await supabase.from('app_settings').select('key,value').ilike('key', `${PREFIX}%`);
    rows = data || [];
  } catch (_) {}
  const stored = {}; rows.forEach((r) => { stored[r.key] = r.value; });
  const activeVerifier = stored[ACTIVE_VERIFIER_KEY] || null;

  const items = INTEGRATIONS.map((def) => {
    const fields = def.fields.map((f) => {
      const raw = stored[keyName(def.id, f.key)];
      const envVar = def.env_fallback && def.env_fallback[f.key];
      const fromEnv = !raw && envVar && !!process.env[envVar];
      return { ...f, configured: !!raw || fromEnv, hint: raw ? mask(raw) : (fromEnv ? 'set via environment' : null), from_env: fromEnv };
    });
    return {
      id: def.id, category: def.category, label: def.label, description: def.description,
      docs: def.docs, verifier: !!def.verifier, has_test: !!def.test,
      fields, configured: fields.every((f) => f.configured),
      active_verifier: def.verifier ? (activeVerifier === def.id) : undefined,
    };
  });

  // group by category, preserving registry order
  const order = []; const groups = {};
  items.forEach((it) => { if (!groups[it.category]) { groups[it.category] = []; order.push(it.category); } groups[it.category].push(it); });
  return { categories: order.map((c) => ({ category: c, items: groups[c] })), active_verifier: activeVerifier };
}

// Save fields for one integration. Empty string clears (disconnects) that field.
async function setIntegration(supabase, id, values) {
  const def = BY_ID.get(id);
  if (!def) return { error: `Unknown integration "${id}"` };
  const valid = new Set(def.fields.map((f) => f.key));
  const upserts = []; const deletes = [];
  for (const [k, v] of Object.entries(values || {})) {
    if (!valid.has(k)) continue;
    if (v === '' || v === null) deletes.push(keyName(id, k));
    else upserts.push({ key: keyName(id, k), value: String(v), updated_at: new Date() });
  }
  if (upserts.length) { const { error } = await supabase.from('app_settings').upsert(upserts, { onConflict: 'key' }); if (error) return { error: error.message }; }
  for (const k of deletes) { try { await supabase.from('app_settings').delete().eq('key', k); } catch (_) {} }
  return { success: true };
}

async function clearIntegration(supabase, id) {
  const def = BY_ID.get(id);
  if (!def) return { error: `Unknown integration "${id}"` };
  for (const f of def.fields) { try { await supabase.from('app_settings').delete().eq('key', keyName(id, f.key)); } catch (_) {} }
  return { success: true };
}

async function setActiveVerifier(supabase, id) {
  const def = id ? BY_ID.get(id) : null;
  if (id && (!def || !def.verifier)) return { error: 'Not an email-verification provider' };
  if (!id) { try { await supabase.from('app_settings').delete().eq('key', ACTIVE_VERIFIER_KEY); } catch (_) {} return { success: true }; }
  const { error } = await supabase.from('app_settings').upsert({ key: ACTIVE_VERIFIER_KEY, value: id, updated_at: new Date() }, { onConflict: 'key' });
  return error ? { error: error.message } : { success: true };
}

// The verifier the send-time hook should use: the explicitly-active one if its
// key is set, else the first configured verifier. Returns { id, key } or null.
async function getActiveVerifier(supabase) {
  let activeId = null;
  try {
    const { data } = await supabase.from('app_settings').select('value').eq('key', ACTIVE_VERIFIER_KEY).maybeSingle();
    activeId = data?.value || null;
  } catch (_) {}
  const order = activeId ? [activeId, ...INTEGRATIONS.filter((i) => i.verifier && i.id !== activeId).map((i) => i.id)]
                         : INTEGRATIONS.filter((i) => i.verifier).map((i) => i.id);
  for (const id of order) {
    const def = BY_ID.get(id);
    if (!def || !def.verifier) continue;
    const key = await getSecret(supabase, id, 'api_key');
    if (key) return { id, key };
  }
  return null;
}

module.exports = {
  INTEGRATIONS, BY_ID, keyName,
  getSecret, isConfigured, getAll, setIntegration, clearIntegration,
  setActiveVerifier, getActiveVerifier,
};
