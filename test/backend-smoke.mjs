// Backend boot smoke test — starts index.js with throwaway env on a random port
// (no real Supabase needed) and asserts the HTTP layer is intact after the route
// extraction:
//   - the server boots and /health responds,
//   - the EXTRACTED routes are mounted and auth-gated (401 without a token, which
//     proves the route exists — a missing route would 404),
//   - routes left inline in index.js still respond,
//   - an unknown path still 404s (so the 401s above are meaningful).
//
// Usage: node test/backend-smoke.mjs      (no external dependencies)

import { spawn } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const PORT = 20000 + Math.floor(Math.random() * 20000);

const child = spawn('node', ['index.js'], {
  cwd: ROOT,
  env: {
    ...process.env,
    PORT: String(PORT),
    SUPABASE_URL: 'http://127.0.0.1:59999',
    SUPABASE_SERVICE_KEY: 'dummy-service-key',
    JWT_SECRET: 'test-secret',
    NODE_ENV: 'test',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let stderr = '';
child.stdout.on('data', () => {});
child.stderr.on('data', (d) => { stderr += d.toString(); });
let exitedEarly = false;
child.on('exit', (code) => { if (!done) exitedEarly = true; });

function req(method, p) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method, timeout: 4000 },
      (res) => { res.resume(); resolve(res.statusCode); });
    r.on('timeout', () => { r.destroy(new Error('timeout')); });
    r.on('error', reject);
    r.end();
  });
}

async function waitForBoot(timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (exitedEarly) throw new Error('server exited before boot:\n' + stderr);
    try { await req('GET', '/health'); return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('server did not boot within ' + timeoutMs + 'ms\n' + stderr);
}

const results = [];
const check = (name, actual, expected) =>
  results.push({ name, ok: actual === expected, detail: `got ${actual}, expected ${expected}` });

let done = false;
try {
  await waitForBoot(12000);

  check('GET /health → 200 (server boots)', await req('GET', '/health'), 200);
  check('GET /api/version → 200', await req('GET', '/api/version'), 200);

  // Extracted routers: mounted + auth-gated → 401 (not 404).
  check('GET /companies → 401 (extracted, gated)', await req('GET', '/companies'), 401);
  check('GET /companies/search → 401 (extracted)', await req('GET', '/companies/search'), 401);
  check('POST /companies → 401 (extracted)', await req('POST', '/companies'), 401);
  check('GET /reminders → 401 (extracted)', await req('GET', '/reminders'), 401);
  check('POST /contacts → 401 (extracted)', await req('POST', '/contacts'), 401);
  check('PATCH /contacts/x/email-status → 401 (extracted)', await req('PATCH', '/contacts/x/email-status'), 401);
  check('GET /app-settings → 401 (extracted)', await req('GET', '/app-settings'), 401);
  check('GET /outreach-plan → 401 (extracted)', await req('GET', '/outreach-plan'), 401);
  check('GET /suppression → 401 (extracted)', await req('GET', '/suppression'), 401);
  check('GET /analytics/templates → 401 (extracted)', await req('GET', '/analytics/templates'), 401);
  check('GET /admin/deliverability → 401 (extracted)', await req('GET', '/admin/deliverability'), 401);
  check('POST /ai/generate-email → 401 (extracted)', await req('POST', '/ai/generate-email'), 401);
  check('GET /events/recent → 401 (extracted)', await req('GET', '/events/recent'), 401);

  // Still-inline routes unaffected.
  check('GET /jobs → 401 (still inline)', await req('GET', '/jobs'), 401);
  check('GET /industries → 401 (still inline)', await req('GET', '/industries'), 401);
  check('GET /jobs/x/contacts → 401 (still inline)', await req('GET', '/jobs/x/contacts'), 401);

  // Unknown path still 404s → proves the 401s above mean "route exists + gated".
  check('GET /definitely-not-a-route → 404', await req('GET', '/definitely-not-a-route'), 404);
} catch (e) {
  results.push({ name: 'FATAL', ok: false, detail: String(e.message || e) });
} finally {
  done = true;
  child.kill('SIGKILL');
}

console.log('\n=== BACKEND SMOKE TEST ===');
let failed = 0;
for (const r of results) {
  if (!r.ok) failed++;
  console.log(`[${r.ok ? 'PASS' : 'FAIL'}] ${r.name}${r.ok ? '' : '  — ' + r.detail}`);
}
console.log(`\nSUMMARY: ${results.length - failed}/${results.length} passed`);
console.log(failed ? 'RESULT: FAIL' : 'RESULT: PASS');
process.exit(failed ? 1 : 0);
