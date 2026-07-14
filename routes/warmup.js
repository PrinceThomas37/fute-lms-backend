// ============================================================================
// Warm-up pool API — /warmup/*
// Mounted from index.js: app.use(require('./routes/warmup')(ctx));
// ctx = { supabase, auth, hasRole, engine, emit, EVENTS }
//
// Enrol a mailbox into warm-up, monitor it, and graduate it to outreach. All
// mutations are admin-only; reads are admin / team-lead. Off by default — a
// mailbox only warms once started here.
// ============================================================================
const express = require('express');
const { getSetting } = require('../config/settings');

module.exports = (ctx) => {
  const router = express.Router();
  const { supabase, auth, hasRole, engine, emit, EVENTS } = ctx;

  const canView = (req) => hasRole(req, 'admin', 'bd_lead', 'ra_lead');
  const canManage = (req) => hasRole(req, 'admin');
  const todayStr = () => new Date().toISOString().split('T')[0];
  const daysSince = (d) => {
    if (!d) return 0;
    const t = new Date(d).getTime();
    return isNaN(t) ? 0 : Math.max(0, Math.floor((Date.now() - t) / 86400000));
  };

  // A plain-English readiness read on the pool, shown in the admin UI so the
  // system tells you whether you have enough mailboxes/domains for smooth
  // warm-up (rather than you having to guess). Rule of thumb: reputation is
  // domain-scoped and built by CROSS-domain traffic, and each warming mailbox
  // needs healthy partners to email — aim for ~1.5x as many pool mailboxes as
  // you warm at once, spread over 3+ domains.
  function poolReadiness(poolCount, domainCount, warmingCount) {
    if (poolCount < 2)
      return { level: 'none', note: 'Add at least 2 connected mailboxes — a mailbox needs partners to warm up with. Nothing sends until then.' };
    if (domainCount < 2)
      return { level: 'minimal', note: `All ${poolCount} pool mailboxes are on one domain. Add mailboxes on other domains — cross-domain email is the reputation signal that matters.` };
    if (warmingCount > 0 && poolCount < Math.ceil(warmingCount * 1.5))
      return { level: 'minimal', note: `Thin pool for ${warmingCount} warming mailbox(es): add more receiver mailboxes (aim for ~1.5x the number you warm at once) so no single inbox is flooded.` };
    if (domainCount < 3)
      return { level: 'ok', note: `${poolCount} mailboxes across ${domainCount} domains — workable. 3+ domains warms more naturally.` };
    return { level: 'good', note: `${poolCount} mailboxes across ${domainCount} domains — healthy pool.` };
  }

  async function connectedSet(ids) {
    if (!ids.length) return new Set();
    const { data } = await supabase.from('microsoft_tokens').select('user_email_id').in('user_email_id', ids);
    return new Set((data || []).map(t => t.user_email_id));
  }

  // ── Pool overview: every active mailbox with its warm-up state + health ─────
  router.get('/warmup/mailboxes', auth, async (req, res) => {
    try {
      if (!canView(req)) return res.status(403).json({ error: 'Forbidden' });
      const { data: mbs, error } = await supabase.from('user_emails')
        .select('id,user_id,email_address,display_name,platform,is_active,warmup_status,warmup_start_date,warmup_days,warmup_pool_opt_in,warmup_graduated_at,owner:users!user_id(name)')
        .eq('is_active', true).order('warmup_status', { ascending: true });
      if (error) throw error;
      const ids = (mbs || []).map(m => m.id);
      const connected = await connectedSet(ids);
      const [start, step, hardCap, defDays] = await Promise.all([
        getSetting(supabase, 'warmup_pool_start'), getSetting(supabase, 'warmup_pool_step'),
        getSetting(supabase, 'warmup_daily_hard_cap'), getSetting(supabase, 'warmup_pool_days'),
      ]);
      // today's warm-up send counts
      const { data: logs } = ids.length
        ? await supabase.from('warmup_send_log').select('user_email_id,emails_sent').eq('send_date', todayStr()).in('user_email_id', ids)
        : { data: [] };
      const sentToday = {}; (logs || []).forEach(l => { sentToday[l.user_email_id] = l.emails_sent; });

      const out = [];
      for (const m of (mbs || [])) {
        const day = daysSince(m.warmup_start_date);
        const days = m.warmup_days || defDays;
        const target = m.warmup_status === 'warming' ? Math.min(hardCap, start + step * day) : null;
        let health = null;
        try { health = await engine.healthScore(m.id); } catch (_) {}
        out.push({
          id: m.id, email: m.email_address, display_name: m.display_name || m.email_address,
          platform: m.platform, owner: (m.owner && m.owner.name) || null,
          connected: m.platform === 'Microsoft' ? connected.has(m.id) : false,
          warmup_status: m.warmup_status || null,
          opt_in: !!m.warmup_pool_opt_in,
          start_date: m.warmup_start_date || null,
          day, days, day_label: m.warmup_status === 'warming' ? `${Math.min(day + 1, days)}/${days}` : null,
          target_today: target, sent_today: sentToday[m.id] || 0,
          graduated_at: m.warmup_graduated_at || null,
          health
        });
      }
      // pool = participants that can actually exchange mail
      const poolMembers = out.filter(m => (m.warmup_status === 'warming' || m.opt_in) && m.connected);
      const domains = new Set(poolMembers.map(m => (m.email.split('@')[1] || '').toLowerCase()).filter(Boolean));
      const warmingCount = out.filter(m => m.warmup_status === 'warming').length;
      res.json({
        mailboxes: out,
        pool_count: poolMembers.length,
        pool_domains: domains.size,
        warming_count: warmingCount,
        readiness: poolReadiness(poolMembers.length, domains.size, warmingCount),
        defaults: { start, step, days: defDays }
      });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  async function loadMailbox(id) {
    const { data } = await supabase.from('user_emails').select('id,email_address,platform,is_active').eq('id', id).maybeSingle();
    return data || null;
  }
  async function isConnected(id) {
    const { data } = await supabase.from('microsoft_tokens').select('user_email_id').eq('user_email_id', id).maybeSingle();
    return !!data;
  }

  // ── Start warm-up on a mailbox ─────────────────────────────────────────────
  router.post('/warmup/:id/start', auth, async (req, res) => {
    try {
      if (!canManage(req)) return res.status(403).json({ error: 'Admin only' });
      const mb = await loadMailbox(req.params.id);
      if (!mb || !mb.is_active) return res.status(404).json({ error: 'Mailbox not found or inactive' });
      if (mb.platform === 'Microsoft' && !(await isConnected(mb.id)))
        return res.status(400).json({ error: 'Mailbox must be connected before warm-up can send. Connect it under the user\'s Email IDs first.' });
      const defDays = await getSetting(supabase, 'warmup_pool_days');
      let days = parseInt(req.body?.days, 10);
      if (!Number.isInteger(days) || days < 1 || days > 120) days = defDays;
      const optIn = req.body?.opt_in_receive !== false; // default: also receive
      const { error } = await supabase.from('user_emails').update({
        warmup_status: 'warming', warmup_start_date: todayStr(), warmup_days: days,
        warmup_pool_opt_in: optIn, warmup_graduated_at: null
      }).eq('id', mb.id);
      if (error) throw error;
      emit(EVENTS.WARMUP_STARTED, { userEmailId: mb.id, email: mb.email_address, days });
      res.json({ success: true, id: mb.id, warmup_status: 'warming', warmup_days: days });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  async function setStatus(req, res, patch, okStatuses, guardMsg) {
    if (!canManage(req)) return res.status(403).json({ error: 'Admin only' });
    const mb = await loadMailbox(req.params.id);
    if (!mb) return res.status(404).json({ error: 'Mailbox not found' });
    if (okStatuses) {
      const { data: cur } = await supabase.from('user_emails').select('warmup_status').eq('id', mb.id).maybeSingle();
      if (!okStatuses.includes(cur?.warmup_status)) return res.status(409).json({ error: guardMsg });
    }
    const { error } = await supabase.from('user_emails').update(patch).eq('id', mb.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, id: mb.id, ...patch });
  }

  router.post('/warmup/:id/pause',  auth, (req, res) => setStatus(req, res, { warmup_status: 'paused' },  ['warming'], 'Mailbox is not warming'));
  router.post('/warmup/:id/resume', auth, (req, res) => setStatus(req, res, { warmup_status: 'warming' }, ['paused'],  'Mailbox is not paused'));
  // Finish early → graduated ('warmed'), ready for outreach, and leave the pool.
  router.post('/warmup/:id/stop', auth, (req, res) =>
    setStatus(req, res, { warmup_status: 'warmed', warmup_graduated_at: new Date().toISOString(), warmup_pool_opt_in: false }, null));
  // Join / leave the pool as a receiver only (a healthy mailbox that helps others).
  router.post('/warmup/:id/opt-in',  auth, (req, res) => setStatus(req, res, { warmup_pool_opt_in: true },  null));
  router.post('/warmup/:id/opt-out', auth, (req, res) => setStatus(req, res, { warmup_pool_opt_in: false }, null));

  // Recent conversations for inspection.
  router.get('/warmup/:id/threads', auth, async (req, res) => {
    try {
      if (!canView(req)) return res.status(403).json({ error: 'Forbidden' });
      const { data, error } = await supabase.from('warmup_threads')
        .select('id,to_mailbox_id,subject,exchanges,target_exchanges,landed_in,rescued,status,created_at,to:user_emails!to_mailbox_id(email_address)')
        .eq('from_mailbox_id', req.params.id).order('created_at', { ascending: false }).limit(50);
      if (error) throw error;
      res.json(data || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Manual "run warm-up now" (mirrors /wf/tick).
  router.post('/warmup/tick', auth, async (req, res) => {
    try {
      if (!canManage(req)) return res.status(403).json({ error: 'Admin only' });
      res.json(await engine.tick());
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  return router;
};
