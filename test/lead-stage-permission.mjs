// Unit test for the lead-stage permission matrix in routes/jobs.js
// (resolveLeadStageUpdate), extracted so this can run without a server or a
// live Supabase connection.
//
// Regression covered: BD/BD Lead moving a "Connected" lead back to "Assigned"
// used to silently no-op — PUT /jobs/:id returned 200 with nothing written,
// because no branch in the old inline logic matched (stage) for their role.
// The frontend still showed "Stage updated" since the request didn't error.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const { hasRole } = require('../middleware/authorize')({ supabase: null });
const { resolveLeadStageUpdate } = require('../routes/jobs.js');

const results = [];
const step = (name, ok, detail = '') => { results.push({ name, ok }); console.log((ok ? '[PASS] ' : '[FAIL] ') + name + (detail ? ' — ' + detail : '')); };

function reqAs(role) { return { user: { id: 'u1', roles: [role] } }; }

// ── the reported bug: BD reverting Connected -> Assigned ───────────────────
let r = resolveLeadStageUpdate(hasRole, reqAs('bd'), 'Assigned');
step('BD can revert a lead to Assigned', r.stage === 'Assigned', JSON.stringify(r));

r = resolveLeadStageUpdate(hasRole, reqAs('bd_lead'), 'Assigned');
step('BD Lead can revert a lead to Assigned', r.stage === 'Assigned', JSON.stringify(r));

r = resolveLeadStageUpdate(hasRole, reqAs('admin'), 'Assigned');
step('Admin can set Assigned', r.stage === 'Assigned', JSON.stringify(r));

// ── forward stages unaffected ──────────────────────────────────────────────
for (const stage of ['Connected', 'Rejected', 'Future', 'In Discussion']) {
  r = resolveLeadStageUpdate(hasRole, reqAs('bd'), stage);
  step(`BD can still set ${stage}`, r.stage === stage, JSON.stringify(r));
}

// ── RA Lead's existing permissions unchanged ───────────────────────────────
r = resolveLeadStageUpdate(hasRole, reqAs('ra_lead'), 'Assigned');
step('RA Lead can still set Assigned', r.stage === 'Assigned', JSON.stringify(r));

r = resolveLeadStageUpdate(hasRole, reqAs('ra_lead'), 'Unassigned');
step('RA Lead can still set Unassigned', r.stage === 'Unassigned', JSON.stringify(r));

// ── correctly still restricted ─────────────────────────────────────────────
r = resolveLeadStageUpdate(hasRole, reqAs('bd'), 'Unassigned');
step('BD is still blocked from Unassigned (pool-return stays RA Lead/Admin)', !!r.error, JSON.stringify(r));

r = resolveLeadStageUpdate(hasRole, reqAs('ra_lead'), 'Connected');
step('RA Lead is still blocked from BD-owned stages like Connected', !!r.error, JSON.stringify(r));

r = resolveLeadStageUpdate(hasRole, reqAs('ra'), 'Assigned');
step('Plain RA is blocked from changing stage at all', !!r.error, JSON.stringify(r));

r = resolveLeadStageUpdate(hasRole, reqAs('recruiter'), 'Connected');
step('Recruiter role (unrelated to leads) is blocked', !!r.error, JSON.stringify(r));

const fails = results.filter(x => !x.ok).length;
console.log(`\nSUMMARY: ${results.length - fails}/${results.length} passed`);
process.exit(fails ? 1 : 0);
