// Unit test for middleware/authorize.js — verifies the extracted authorization
// helpers behave exactly as the previous inline implementations.
// Usage: node test/authorize.mjs   (no external dependencies)

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const createAuthorize = require('../middleware/authorize.js');

const results = [];
const ok = (name, cond, detail = '') => results.push({ name, ok: !!cond, detail });

// Minimal Supabase stub: from(...).select(...).eq(...).single() → { data }.
const mockSupabase = (jobRow) => ({
  from: () => ({ select: () => ({ eq: () => ({ single: async () => ({ data: jobRow }) }) }) }),
});

const req = (user) => ({ user });

// hasRole
{
  const { hasRole } = createAuthorize({ supabase: mockSupabase(null) });
  ok('hasRole: no user → false', hasRole(req(null), 'admin') === false);
  ok('hasRole: roles array match', hasRole(req({ roles: ['bd', 'ra'] }), 'ra') === true);
  ok('hasRole: roles array no match', hasRole(req({ roles: ['ra'] }), 'admin') === false);
  ok('hasRole: legacy single role match', hasRole(req({ role: 'admin' }), 'admin', 'bd') === true);
  ok('hasRole: legacy single role no match', hasRole(req({ role: 'ra' }), 'admin') === false);
}

// notGuest
{
  const { notGuest } = createAuthorize({ supabase: mockSupabase(null) });
  let sent = null;
  const res = { status: (c) => ({ json: (b) => { sent = { c, b }; } }) };
  ok('notGuest: guest → true and 403', notGuest(req({ isGuest: true }), res) === true && sent.c === 403);
  ok('notGuest: normal user → false', notGuest(req({ id: 'u1' }), { status: () => ({ json: () => {} }) }) === false);
}

// requireRole middleware
{
  const { requireRole } = createAuthorize({ supabase: mockSupabase(null) });
  let nextCalled = false, sent = null;
  const res = { status: (c) => ({ json: (b) => { sent = { c, b }; } }) };
  requireRole('admin')(req({ roles: ['admin'] }), res, () => { nextCalled = true; });
  ok('requireRole: allowed → next()', nextCalled === true && sent === null);
  nextCalled = false; sent = null;
  requireRole('admin')(req({ roles: ['ra'] }), res, () => { nextCalled = true; });
  ok('requireRole: denied → 403, no next', nextCalled === false && sent && sent.c === 403);
}

// canTouchJob
{
  const admin = req({ id: 'a', roles: ['admin'] });
  const { canTouchJob: ctjAdmin } = createAuthorize({ supabase: mockSupabase(null) });
  ok('canTouchJob: admin → true (no lookup)', (await ctjAdmin(admin, 'j1')) === true);

  const owner = req({ id: 'u1', roles: ['bd'] });
  const mk = (row) => createAuthorize({ supabase: mockSupabase(row) }).canTouchJob;
  ok('canTouchJob: created_by owner → true', (await mk({ created_by: 'u1', assigned_to: 'x', assigned_to_bd: 'y' })(owner, 'j')) === true);
  ok('canTouchJob: assigned_to → true', (await mk({ created_by: 'x', assigned_to: 'u1', assigned_to_bd: 'y' })(owner, 'j')) === true);
  ok('canTouchJob: assigned_to_bd → true', (await mk({ created_by: 'x', assigned_to: 'y', assigned_to_bd: 'u1' })(owner, 'j')) === true);
  ok('canTouchJob: unrelated → false', (await mk({ created_by: 'x', assigned_to: 'y', assigned_to_bd: 'z' })(owner, 'j')) === false);
  ok('canTouchJob: no job row → false', (await mk(null)(owner, 'j')) === false);
}

console.log('\n=== AUTHORIZE TEST ===');
let failed = 0;
for (const r of results) {
  if (!r.ok) failed++;
  console.log(`[${r.ok ? 'PASS' : 'FAIL'}] ${r.name}${r.ok ? '' : '  — ' + r.detail}`);
}
console.log(`\nSUMMARY: ${results.length - failed}/${results.length} passed`);
console.log(failed ? 'RESULT: FAIL' : 'RESULT: PASS');
process.exit(failed ? 1 : 0);
