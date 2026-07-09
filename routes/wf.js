// ============================================================================
// Workflow engine API — /wf/*
// Mounted from index.js: app.use(require('./routes/wf')(ctx));
// ctx = { supabase, auth, hasRole, engine, logActivity }
// Definitions are org data; enrollments are the running state machines.
// ============================================================================
const express = require('express');

module.exports = (ctx) => {
  const router = express.Router();
  const { supabase, auth, hasRole, engine, logActivity } = ctx;

  const canDesign = (req) => hasRole(req, 'admin', 'ra_lead', 'bd_lead');

  const DEF_SELECT = '*, steps:workflow_steps(*), creator:users!created_by(id,name)';

  function normalizeSteps(steps) {
    if (!Array.isArray(steps) || !steps.length) throw new Error('At least one step is required');
    const known = new Set(engine.listChannels());
    return steps.map((s, i) => {
      if (!s.channel || !known.has(s.channel)) throw new Error(`Unknown channel "${s.channel}" — available: ${[...known].join(', ')}`);
      const delay = Number(s.delay_days || 0);
      if (!Number.isInteger(delay) || delay < 0 || delay > 90) throw new Error('delay_days must be an integer between 0 and 90');
      return { step_order: i + 1, name: s.name || `Step ${i + 1}`, channel: s.channel, delay_days: delay, config: s.config || {} };
    });
  }

  router.get('/wf/channels', auth, (req, res) => res.json({ channels: engine.listChannels() }));

  router.get('/wf/definitions', auth, async (req, res) => {
    try {
      let q = supabase.from('workflow_definitions').select(DEF_SELECT).order('created_at', { ascending: false });
      if (req.query.domain) q = q.eq('domain', req.query.domain);
      if (req.query.status) q = q.eq('status', req.query.status);
      const { data, error } = await q;
      if (error) throw error;
      (data || []).forEach(d => (d.steps || []).sort((a, b) => a.step_order - b.step_order));
      res.json(data || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.post('/wf/definitions', auth, async (req, res) => {
    try {
      if (!canDesign(req)) return res.status(403).json({ error: 'Forbidden' });
      const b = req.body || {};
      if (!b.name) return res.status(400).json({ error: 'name required' });
      const steps = normalizeSteps(b.steps);
      const { data: org } = await supabase.from('organizations').select('id').eq('slug', 'fute').maybeSingle();
      const { data: wf, error } = await supabase.from('workflow_definitions').insert({
        org_id: b.org_id || org?.id || null,
        domain: b.domain || 'sales', name: b.name, description: b.description || null,
        entity_type: b.entity_type || 'contact', trigger_event: b.trigger_event || null,
        status: 'draft', created_by: req.user.id
      }).select().single();
      if (error) throw error;
      const { error: stErr } = await supabase.from('workflow_steps').insert(steps.map(s => ({ ...s, workflow_id: wf.id })));
      if (stErr) throw stErr;
      const { data: full } = await supabase.from('workflow_definitions').select(DEF_SELECT).eq('id', wf.id).single();
      res.json(full);
    } catch (err) { res.status(err.message.includes('required') || err.message.includes('channel') ? 400 : 500).json({ error: err.message }); }
  });

  router.put('/wf/definitions/:id', auth, async (req, res) => {
    try {
      if (!canDesign(req)) return res.status(403).json({ error: 'Forbidden' });
      const b = req.body || {};
      const meta = {};
      ['name', 'description', 'domain', 'trigger_event'].forEach(k => { if (b[k] !== undefined) meta[k] = b[k]; });
      if (Array.isArray(b.steps)) {
        // Replacing steps under running enrollments would corrupt their state.
        const { count } = await supabase.from('workflow_enrollments')
          .select('id', { count: 'exact', head: true }).eq('workflow_id', req.params.id).eq('status', 'active');
        if (count > 0) return res.status(409).json({ error: `Workflow has ${count} active enrollment(s) — exit or complete them before editing steps.` });
        const steps = normalizeSteps(b.steps);
        await supabase.from('workflow_steps').delete().eq('workflow_id', req.params.id);
        const { error: stErr } = await supabase.from('workflow_steps').insert(steps.map(s => ({ ...s, workflow_id: req.params.id })));
        if (stErr) throw stErr;
        const { data: cur } = await supabase.from('workflow_definitions').select('version').eq('id', req.params.id).single();
        meta.version = (cur?.version || 1) + 1;
      }
      if (Object.keys(meta).length) {
        meta.updated_at = new Date().toISOString();
        const { error } = await supabase.from('workflow_definitions').update(meta).eq('id', req.params.id);
        if (error) throw error;
      }
      const { data } = await supabase.from('workflow_definitions').select(DEF_SELECT).eq('id', req.params.id).single();
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.post('/wf/definitions/:id/status', auth, async (req, res) => {
    try {
      if (!canDesign(req)) return res.status(403).json({ error: 'Forbidden' });
      const status = req.body?.status;
      if (!['draft', 'active', 'archived'].includes(status)) return res.status(400).json({ error: 'status must be draft | active | archived' });
      const { data, error } = await supabase.from('workflow_definitions')
        .update({ status, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
      if (error) throw error;
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ── Enroll a contact (or any entity) into a workflow ───────────────────────
  router.post('/wf/enroll', auth, async (req, res) => {
    try {
      const b = req.body || {};
      if (!b.workflow_id) return res.status(400).json({ error: 'workflow_id required' });
      const entityId = b.entity_id || b.contact_id;
      if (!entityId) return res.status(400).json({ error: 'entity_id (or contact_id) required' });
      const enrollment = await engine.enroll({
        workflow_id: b.workflow_id,
        entity_type: b.entity_type || 'contact',
        entity_id: entityId,
        job_id: b.job_id || null,
        contact_id: b.contact_id || ((b.entity_type || 'contact') === 'contact' ? entityId : null),
        enrolled_by: req.user.id,
        metadata: b.metadata || {}
      });
      if (b.job_id) await logActivity(b.job_id, b.contact_id || null, req.user.id, 'workflow_enrolled', `Enrolled in workflow`, null, null);
      res.json(enrollment);
    } catch (err) {
      const msg = err.message || 'enroll failed';
      res.status(/not found|not active|already|expects|no steps/i.test(msg) ? 400 : 500).json({ error: msg });
    }
  });

  router.get('/wf/enrollments', auth, async (req, res) => {
    try {
      let q = supabase.from('workflow_enrollments')
        .select('*, workflow:workflow_definitions(id,name,domain), contact:contacts(id,first_name,last_name,email), job:jobs(id,position,company:companies(name))')
        .order('created_at', { ascending: false }).limit(500);
      if (req.query.status) q = q.eq('status', req.query.status);
      if (req.query.workflow_id) q = q.eq('workflow_id', req.query.workflow_id);
      if (req.query.job_id) q = q.eq('job_id', req.query.job_id);
      const { data, error } = await q;
      if (error) throw error;
      res.json(data || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.get('/wf/enrollments/:id/runs', auth, async (req, res) => {
    try {
      const { data, error } = await supabase.from('workflow_step_runs')
        .select('*').eq('enrollment_id', req.params.id).order('run_at');
      if (error) throw error;
      res.json(data || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.post('/wf/enrollments/:id/pause', auth, async (req, res) => setEnrollmentStatus(req, res, 'paused', { fromStatuses: ['active'] }));
  router.post('/wf/enrollments/:id/resume', auth, async (req, res) => setEnrollmentStatus(req, res, 'active', { fromStatuses: ['paused'] }));
  router.post('/wf/enrollments/:id/exit', auth, async (req, res) => setEnrollmentStatus(req, res, 'exited', { fromStatuses: ['active', 'paused'], exitReason: req.body?.reason || 'manual', close: true }));

  async function setEnrollmentStatus(req, res, status, { fromStatuses, exitReason, close }) {
    try {
      const patch = { status, updated_at: new Date().toISOString() };
      if (exitReason) patch.exit_reason = exitReason;
      if (close) patch.completed_at = new Date().toISOString();
      const { data, error } = await supabase.from('workflow_enrollments')
        .update(patch).eq('id', req.params.id).in('status', fromStatuses).select().maybeSingle();
      if (error) throw error;
      if (!data) return res.status(409).json({ error: `Enrollment is not in a state that allows "${status}"` });
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  }

  router.post('/wf/tick', auth, async (req, res) => {
    try {
      if (!hasRole(req, 'admin', 'bd_lead')) return res.status(403).json({ error: 'Admin only' });
      res.json(await engine.tick());
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.get('/wf/stats', auth, async (req, res) => {
    try {
      const { data, error } = await supabase.from('workflow_enrollments').select('workflow_id,status');
      if (error) throw error;
      const byWorkflow = {};
      (data || []).forEach(r => {
        byWorkflow[r.workflow_id] = byWorkflow[r.workflow_id] || { active: 0, paused: 0, completed: 0, exited: 0, failed: 0 };
        byWorkflow[r.workflow_id][r.status] = (byWorkflow[r.workflow_id][r.status] || 0) + 1;
      });
      res.json({ by_workflow: byWorkflow, total: (data || []).length });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  return router;
};
