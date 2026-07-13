// Unit test for config/env.js — verifies fail-fast validation of required
// secrets and the behaviour-preserving Microsoft redirect-URI fallback.
// Usage: node test/config-env.mjs   (no external dependencies)

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { loadConfig, DEFAULT_MICROSOFT_REDIRECT_URI } = require('../config/env.js');

const results = [];
const ok = (name, cond, detail = '') => results.push({ name, ok: !!cond, detail });

// Silence the informational [config] warnings during the test.
const origWarn = console.warn;
console.warn = () => {};

function withEnv(overrides, fn) {
  const snapshot = { ...process.env };
  for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'JWT_SECRET',
    'MICROSOFT_REDIRECT_URI', 'MICROSOFT_TENANT_ID', 'PORT']) delete process.env[k];
  Object.assign(process.env, overrides);
  try { return fn(); } finally {
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, snapshot);
  }
}

const BASE = { SUPABASE_URL: 'http://db', SUPABASE_SERVICE_KEY: 'k', JWT_SECRET: 's' };

// 1. Happy path: all required present, optional redirect unset → fallback used.
withEnv(BASE, () => {
  const c = loadConfig();
  ok('loads with required vars present', c.supabaseUrl === 'http://db' && c.jwtSecret === 's');
  ok('port defaults to 3000', c.port === 3000, `got ${c.port}`);
  ok('redirect falls back to previous hardcoded value',
    c.microsoft.redirectUri === DEFAULT_MICROSOFT_REDIRECT_URI, c.microsoft.redirectUri);
});

// 2. Redirect read from env when set.
withEnv({ ...BASE, MICROSOFT_REDIRECT_URI: 'https://example.com/cb' }, () => {
  const c = loadConfig();
  ok('redirect read from MICROSOFT_REDIRECT_URI when set',
    c.microsoft.redirectUri === 'https://example.com/cb', c.microsoft.redirectUri);
});

// 3/4. Fail-fast on each missing required secret.
for (const missing of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'JWT_SECRET']) {
  const env = { ...BASE };
  delete env[missing];
  let threw = false, msg = '';
  withEnv(env, () => { try { loadConfig(); } catch (e) { threw = true; msg = e.message; } });
  ok(`fails fast when ${missing} missing`, threw && msg.includes(missing), msg);
}

console.warn = origWarn;

console.log('\n=== CONFIG ENV TEST ===');
let failed = 0;
for (const r of results) {
  if (!r.ok) failed++;
  console.log(`[${r.ok ? 'PASS' : 'FAIL'}] ${r.name}${r.ok ? '' : '  — ' + r.detail}`);
}
console.log(`\nSUMMARY: ${results.length - failed}/${results.length} passed`);
console.log(failed ? 'RESULT: FAIL' : 'RESULT: PASS');
process.exit(failed ? 1 : 0);
