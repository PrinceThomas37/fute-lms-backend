// ============================================================================
// REPORTING HIERARCHY — shared scoping primitive
// ----------------------------------------------------------------------------
// The single source of truth for "team" across the app: a user's direct +
// transitive reports under users.manager_id (migration 026 — a flexible tree,
// any user may report to any other user regardless of role). Used to scope
// reports and dashboards (a manager sees their own numbers plus everyone under
// them) and to trim cross-team fields out of GET /users.
//
// Exposed as a factory so both bd_recruiter_routes.js and routes/auth.js share
// one implementation instead of drifting copies.
// ============================================================================
module.exports = function (supabase) {
  // Everyone a user is responsible for on the flexible reporting hierarchy —
  // themselves plus every direct and transitive report. A user nobody reports
  // to just gets [self]. BFS over manager_id, scoped to one org.
  async function reportingChainIds(userId, orgId) {
    let q = supabase.from('users').select('id,manager_id').is('deleted_at', null);
    if (orgId) q = q.eq('org_id', orgId);
    const { data } = await q;
    const childrenOf = {};
    (data || []).forEach(u => { if (u.manager_id) (childrenOf[u.manager_id] = childrenOf[u.manager_id] || []).push(u.id); });
    const chain = new Set([userId]);
    const queue = [userId];
    while (queue.length) {
      const next = childrenOf[queue.shift()] || [];
      next.forEach(id => { if (!chain.has(id)) { chain.add(id); queue.push(id); } });
    }
    return [...chain];
  }
  return { reportingChainIds };
};
