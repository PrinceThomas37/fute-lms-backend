// ============================================================================
// DOMAIN EVENTS — recent event-log viewer (admins / leads).
// ----------------------------------------------------------------------------
// Extracted from index.js. Mounted via: app.use(require('./routes/events')(ctx));
// Route paths, handler logic and behaviour are unchanged from the original.
// ============================================================================
const express = require('express');

module.exports = (ctx) => {
  const router = express.Router();
  const { supabase, auth, hasRole } = ctx;

router.get('/events/recent', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd_lead', 'ra_lead')) return res.status(403).json({ error: 'Forbidden' });
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    let q = supabase.from('domain_events')
      .select('id,event,payload,actor_user_id,created_at')
      .order('created_at', { ascending: false })
      .limit(limit);
    if (req.query.event) q = q.eq('event', req.query.event);
    const { data, error } = await q;
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

  return router;
};
