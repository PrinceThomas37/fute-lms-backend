// ============================================================================
// BD MANAGER / RECRUITER WORKFLOW — BACKEND ROUTES
// Branch: bd-manager-recruiter-workflow
// ----------------------------------------------------------------------------
// Isolated module. Mounted from index.js with a single line:
//
//     require('./bd_recruiter_routes')(app, { supabase, auth, hasRole, notGuest, today });
//
// Nothing in the existing index.js is modified except that one require line.
// All routes here are NEW paths; none collide with existing routes.
// ============================================================================

module.exports = function (app, deps) {
  const { supabase, auth, hasRole, notGuest, today } = deps;

  // ── pipeline stage definitions ───────────────────────────────────────────
  const STAGES = [
    'Sourced',
    'Screening',
    'Submitted to BDM',
    'Submitted to Client',
    'Interview Scheduled',
    'Offer',
    'Placed',
    'Rejected',
    'On Hold'
  ];
  // Stage a recruiter may NOT move INTO without BD Manager approval.
  const BDM_GATED_STAGE = 'Submitted to Client';

  function isBDM(req) { return hasRole(req, 'admin', 'bd', 'bd_lead'); }
  function isRecruiter(req) { return hasRole(req, 'recruiter'); }

  // human-readable id helper (LD- / JOB- / CN-) via the SQL function next_id()
  async function nextId(prefix) {
    const { data, error } = await supabase.rpc('next_id', { p_prefix: prefix });
    if (error) throw new Error(`next_id(${prefix}) failed: ${error.message}`);
    return data;
  }

  async function logSubmissionActivity(submissionId, jobOrderId, recruiterId, action, oldStage, newStage, note) {
    try {
      await supabase.from('submission_activity').insert({
        submission_id: submissionId, job_order_id: jobOrderId, recruiter_id: recruiterId,
        action, old_stage: oldStage || null, new_stage: newStage || null, note: note || null
      });
    } catch (_) { /* non-fatal */ }
  }

  // recruiter scoping: which job_order ids is this recruiter assigned to?
  async function assignedJobOrderIds(userId) {
    const { data } = await supabase.from('recruiter_assignments')
      .select('job_order_id').eq('recruiter_id', userId);
    return [...new Set((data || []).map(r => r.job_order_id))];
  }

  const JOB_ORDER_SELECT =
    '*, company:companies(id,name,industry,location), ' +
    'source_lead:jobs!source_lead_id(id,position,stage,lead_code), ' +
    'bd_manager:users!bd_manager_id(id,name,employee_id), ' +
    'creator:users!created_by(id,name,employee_id)';

  // ==========================================================================
  // CONVERSION — lead -> job order
  // ==========================================================================

  // Convert an existing CONNECTED lead (a jobs row) into a job order.
  app.post('/job-orders/from-lead/:jobId', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req)) return res.status(403).json({ error: 'Only BD Managers can convert leads to job orders.' });

      const { data: lead, error: leadErr } = await supabase
        .from('jobs').select('*').eq('id', req.params.jobId).is('deleted_at', null).single();
      if (leadErr || !lead) return res.status(404).json({ error: 'Lead not found' });
      if (lead.stage !== 'Connected') {
        return res.status(409).json({ error: `Lead must be at stage "Connected" to convert (currently "${lead.stage}").` });
      }

      // guard against double-conversion of the same lead
      const { data: existing } = await supabase
        .from('job_orders').select('id,job_code').eq('source_lead_id', lead.id).is('deleted_at', null).limit(1);
      if (existing && existing.length) {
        return res.status(409).json({ error: `This lead was already converted (${existing[0].job_code}).`, job_order_id: existing[0].id });
      }

      // ensure the lead has an LD- code (older rows backfilled by migration, but be safe)
      let leadCode = lead.lead_code;
      if (!leadCode) {
        leadCode = await nextId('LD');
        await supabase.from('jobs').update({ lead_code: leadCode }).eq('id', lead.id);
      }

      const b = req.body || {};
      const jobCode = await nextId('JOB');
      const { data: jobOrder, error } = await supabase.from('job_orders').insert({
        job_code: jobCode,
        source_lead_id: lead.id,
        lead_code: leadCode,
        company_id: lead.company_id,
        position_title: lead.position,              // title carries over from the lead
        client_name: b.client_name || null,
        job_description: b.job_description || null,
        location: b.location || lead.location || null,
        pay_rate: b.pay_rate || null,
        bill_rate: b.bill_rate || null,
        positions_count: b.positions_count || 1,
        employment_type: b.employment_type || null,
        priority: b.priority || 'Normal',
        status: 'Open',
        bd_manager_id: b.bd_manager_id || req.user.id,
        created_by: req.user.id
      }).select(JOB_ORDER_SELECT).single();
      if (error) throw error;

      res.status(201).json(jobOrder);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // BD creates a job order directly. Lead-first: a jobs (lead) row is created,
  // gets an LD- code, THEN the job order is created from it and gets a JOB- code.
  app.post('/job-orders', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req)) return res.status(403).json({ error: 'Only BD Managers can create job orders.' });

      const b = req.body || {};
      const lead = b.lead || {};
      const job = b.job || {};

      if (!lead.company_id || !lead.position) {
        return res.status(400).json({ error: 'lead.company_id and lead.position are required (lead info must be filled first).' });
      }

      // 1) create the underlying lead (jobs row), pre-stamped Connected since it
      //    is a real, client-confirmed opening originating from the BD directly.
      const leadCode = await nextId('LD');
      const { data: leadRow, error: leadErr } = await supabase.from('jobs').insert({
        company_id: lead.company_id,
        position: lead.position,
        location: lead.location || null,
        source: lead.source || 'BD Direct',
        stage: 'Connected',
        notes: lead.notes || '',
        created_by: req.user.id,
        assigned_to_bd: req.user.id,
        lead_code: leadCode
      }).select().single();
      if (leadErr) throw leadErr;

      // optional contacts on the lead, reusing the existing contacts table shape
      if (Array.isArray(lead.contacts) && lead.contacts.length) {
        const rows = lead.contacts.map((c, i) => ({
          job_id: leadRow.id, first_name: c.first_name || '', last_name: c.last_name || '',
          designation: c.designation || null, email: c.email || null, phone: c.phone || null,
          linkedin: c.linkedin || null, is_primary: i === 0
        }));
        await supabase.from('contacts').insert(rows);
      }

      // 2) create the job order from that lead
      const jobCode = await nextId('JOB');
      const { data: jobOrder, error } = await supabase.from('job_orders').insert({
        job_code: jobCode,
        source_lead_id: leadRow.id,
        lead_code: leadCode,
        company_id: leadRow.company_id,
        position_title: leadRow.position,
        client_name: job.client_name || null,
        job_description: job.job_description || null,
        location: job.location || leadRow.location || null,
        pay_rate: job.pay_rate || null,
        bill_rate: job.bill_rate || null,
        positions_count: job.positions_count || 1,
        employment_type: job.employment_type || null,
        priority: job.priority || 'Normal',
        status: 'Open',
        bd_manager_id: job.bd_manager_id || req.user.id,
        created_by: req.user.id
      }).select(JOB_ORDER_SELECT).single();
      if (error) throw error;

      res.status(201).json(jobOrder);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ==========================================================================
  // JOB ORDERS — list / read / update / soft-delete
  // ==========================================================================

  app.get('/job-orders', auth, async (req, res) => {
    try {
      let query = supabase.from('job_orders').select(JOB_ORDER_SELECT).is('deleted_at', null);

      // recruiters only see job orders they are assigned to
      if (isRecruiter(req) && !isBDM(req)) {
        const ids = await assignedJobOrderIds(req.user.id);
        if (!ids.length) return res.json([]);
        query = query.in('id', ids);
      }
      if (req.query.status) query = query.eq('status', req.query.status);

      const { data, error } = await query.order('created_at', { ascending: false });
      if (error) throw error;
      res.json(data || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.get('/job-orders/:id', auth, async (req, res) => {
    try {
      const { data, error } = await supabase.from('job_orders')
        .select(JOB_ORDER_SELECT).eq('id', req.params.id).is('deleted_at', null).single();
      if (error || !data) return res.status(404).json({ error: 'Job order not found' });

      if (isRecruiter(req) && !isBDM(req)) {
        const ids = await assignedJobOrderIds(req.user.id);
        if (!ids.includes(data.id)) return res.status(403).json({ error: 'Not assigned to this job order.' });
      }

      // attach assigned recruiters
      const { data: assigns } = await supabase.from('recruiter_assignments')
        .select('id, assigned_at, recruiter:users!recruiter_id(id,name,employee_id)')
        .eq('job_order_id', data.id);
      data.recruiters = assigns || [];
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.put('/job-orders/:id', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req)) return res.status(403).json({ error: 'Only BD Managers can edit job orders.' });
      const b = req.body || {};
      const allowed = ['client_name','job_description','location','pay_rate','bill_rate',
                       'positions_count','employment_type','priority','status','bd_manager_id','position_title'];
      const updates = { updated_at: new Date() };
      for (const k of allowed) if (b[k] !== undefined) updates[k] = b[k];
      const { data, error } = await supabase.from('job_orders')
        .update(updates).eq('id', req.params.id).select(JOB_ORDER_SELECT).single();
      if (error) throw error;
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.delete('/job-orders/:id', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req)) return res.status(403).json({ error: 'Only BD Managers can delete job orders.' });
      await supabase.from('job_orders').update({ deleted_at: new Date() }).eq('id', req.params.id);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ==========================================================================
  // RECRUITER ASSIGNMENT
  // ==========================================================================

  app.post('/job-orders/:id/recruiters', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req)) return res.status(403).json({ error: 'Only BD Managers can assign recruiters.' });
      const recruiterIds = req.body.recruiter_ids || (req.body.recruiter_id ? [req.body.recruiter_id] : []);
      if (!recruiterIds.length) return res.status(400).json({ error: 'recruiter_ids required' });

      const rows = recruiterIds.map(rid => ({
        job_order_id: req.params.id, recruiter_id: rid, assigned_by: req.user.id
      }));
      // upsert avoids duplicate-assignment errors thanks to the unique index
      const { error } = await supabase.from('recruiter_assignments')
        .upsert(rows, { onConflict: 'job_order_id,recruiter_id', ignoreDuplicates: true });
      if (error) throw error;

      const { data: assigns } = await supabase.from('recruiter_assignments')
        .select('id, assigned_at, recruiter:users!recruiter_id(id,name,employee_id)')
        .eq('job_order_id', req.params.id);
      res.json(assigns || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.delete('/job-orders/:id/recruiters/:rid', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req)) return res.status(403).json({ error: 'Only BD Managers can unassign recruiters.' });
      await supabase.from('recruiter_assignments')
        .delete().eq('job_order_id', req.params.id).eq('recruiter_id', req.params.rid);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ==========================================================================
  // CANDIDATES — shared pool
  // ==========================================================================

  app.get('/candidates', auth, async (req, res) => {
    try {
      let query = supabase.from('candidates').select('*').is('deleted_at', null);
      const q = (req.query.q || '').trim();
      if (q) query = query.or(`full_name.ilike.%${q}%,email.ilike.%${q}%,candidate_code.ilike.%${q}%`);
      const { data, error } = await query.order('created_at', { ascending: false }).limit(100);
      if (error) throw error;
      res.json(data || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/candidates', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const b = req.body || {};
      if (!b.full_name) return res.status(400).json({ error: 'full_name required' });
      const code = await nextId('CN');
      const { data, error } = await supabase.from('candidates').insert({
        candidate_code: code,
        full_name: b.full_name, email: b.email || null, phone: b.phone || null,
        current_location: b.current_location || null, current_title: b.current_title || null,
        skills: b.skills || null, experience_years: b.experience_years || null,
        resume_url: b.resume_url || null, source: b.source || null,
        created_by: req.user.id
      }).select().single();
      if (error) throw error;
      res.status(201).json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.put('/candidates/:id', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const b = req.body || {};
      const allowed = ['full_name','email','phone','current_location','current_title',
                       'skills','experience_years','resume_url','source'];
      const updates = { updated_at: new Date() };
      for (const k of allowed) if (b[k] !== undefined) updates[k] = b[k];
      const { data, error } = await supabase.from('candidates')
        .update(updates).eq('id', req.params.id).select().single();
      if (error) throw error;
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ==========================================================================
  // SUBMISSIONS — pipeline (per-candidate stage, with BDM approval gate)
  // ==========================================================================

  const SUBMISSION_SELECT =
    '*, candidate:candidates(id,candidate_code,full_name,email,phone,current_title), ' +
    'recruiter:users!recruiter_id(id,name,employee_id)';

  // list submissions for a job order (the kanban data)
  app.get('/job-orders/:id/submissions', auth, async (req, res) => {
    try {
      if (isRecruiter(req) && !isBDM(req)) {
        const ids = await assignedJobOrderIds(req.user.id);
        if (!ids.includes(req.params.id)) return res.status(403).json({ error: 'Not assigned to this job order.' });
      }
      const { data, error } = await supabase.from('submissions')
        .select(SUBMISSION_SELECT).eq('job_order_id', req.params.id).is('deleted_at', null)
        .order('created_at', { ascending: false });
      if (error) throw error;
      res.json(data || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // add a candidate (from the shared pool) to a job order
  app.post('/submissions', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const b = req.body || {};
      if (!b.candidate_id || !b.job_order_id) {
        return res.status(400).json({ error: 'candidate_id and job_order_id required' });
      }
      // recruiters can only submit into job orders they are assigned to
      if (isRecruiter(req) && !isBDM(req)) {
        const ids = await assignedJobOrderIds(req.user.id);
        if (!ids.includes(b.job_order_id)) return res.status(403).json({ error: 'Not assigned to this job order.' });
      }
      const { data, error } = await supabase.from('submissions').insert({
        candidate_id: b.candidate_id, job_order_id: b.job_order_id,
        recruiter_id: b.recruiter_id || req.user.id,
        stage: 'Sourced', submitted_rate: b.submitted_rate || null, notes: b.notes || null
      }).select(SUBMISSION_SELECT).single();
      if (error) {
        if (error.code === '23505') return res.status(409).json({ error: 'This candidate is already in this job order.' });
        throw error;
      }
      await logSubmissionActivity(data.id, b.job_order_id, data.recruiter_id, 'created', null, 'Sourced', null);
      res.status(201).json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // move a submission to a new stage — enforces the BDM approval gate
  app.patch('/submissions/:id/stage', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      const newStage = req.body.stage;
      if (!STAGES.includes(newStage)) return res.status(400).json({ error: `Invalid stage. Allowed: ${STAGES.join(', ')}` });

      const { data: sub, error: subErr } = await supabase.from('submissions')
        .select('*').eq('id', req.params.id).is('deleted_at', null).single();
      if (subErr || !sub) return res.status(404).json({ error: 'Submission not found' });

      const recruiterScoped = isRecruiter(req) && !isBDM(req);
      if (recruiterScoped) {
        const ids = await assignedJobOrderIds(req.user.id);
        if (!ids.includes(sub.job_order_id)) return res.status(403).json({ error: 'Not assigned to this job order.' });
      }

      // ── THE GATE ──────────────────────────────────────────────────────────
      // Moving INTO "Submitted to Client" requires BD Manager. A recruiter can
      // take a candidate up to "Submitted to BDM" but no further on their own.
      if (newStage === BDM_GATED_STAGE && !isBDM(req)) {
        return res.status(403).json({ error: 'Only a BD Manager can approve "Submitted to BDM" candidates through to the client.' });
      }

      const updates = { stage: newStage, stage_updated_at: new Date() };
      let action = 'stage_change';
      if (newStage === BDM_GATED_STAGE && isBDM(req)) {
        updates.bdm_approved_at = new Date();
        updates.bdm_approved_by = req.user.id;
        action = 'bdm_approved';
      }

      const { data, error } = await supabase.from('submissions')
        .update(updates).eq('id', req.params.id).select(SUBMISSION_SELECT).single();
      if (error) throw error;

      await logSubmissionActivity(data.id, sub.job_order_id, sub.recruiter_id, action, sub.stage, newStage, req.body.note || null);
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.delete('/submissions/:id', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      await supabase.from('submissions').update({ deleted_at: new Date() }).eq('id', req.params.id);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ==========================================================================
  // BD MANAGER ANALYTICS
  // ==========================================================================

  // per-recruiter performance
  app.get('/bd-analytics/recruiters', auth, async (req, res) => {
    try {
      if (!isBDM(req)) return res.status(403).json({ error: 'BD Manager only.' });

      const { data: subs } = await supabase.from('submissions')
        .select('recruiter_id, stage').is('deleted_at', null);
      const { data: recruiters } = await supabase.from('users')
        .select('id,name,employee_id,roles,role');

      const isRec = u => (Array.isArray(u.roles) && u.roles.includes('recruiter')) || u.role === 'recruiter';
      const recMap = {};
      (recruiters || []).filter(isRec).forEach(u => {
        recMap[u.id] = { recruiter_id: u.id, name: u.name, employee_id: u.employee_id,
                         total: 0, submitted_to_bdm: 0, submitted_to_client: 0, interview: 0, offer: 0, placed: 0, rejected: 0 };
      });
      (subs || []).forEach(s => {
        const r = recMap[s.recruiter_id];
        if (!r) return;
        r.total++;
        if (s.stage === 'Submitted to BDM') r.submitted_to_bdm++;
        else if (s.stage === 'Submitted to Client') r.submitted_to_client++;
        else if (s.stage === 'Interview Scheduled') r.interview++;
        else if (s.stage === 'Offer') r.offer++;
        else if (s.stage === 'Placed') r.placed++;
        else if (s.stage === 'Rejected') r.rejected++;
      });
      const rows = Object.values(recMap).map(r => ({
        ...r, fill_rate: r.total ? Math.round((r.placed / r.total) * 100) : 0
      })).sort((a, b) => b.placed - a.placed || b.total - a.total);
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // pipeline funnel (counts by stage, optionally for one job order)
  app.get('/bd-analytics/funnel', auth, async (req, res) => {
    try {
      if (!isBDM(req)) return res.status(403).json({ error: 'BD Manager only.' });
      let query = supabase.from('submissions').select('stage').is('deleted_at', null);
      if (req.query.job_order_id) query = query.eq('job_order_id', req.query.job_order_id);
      const { data } = await query;
      const counts = {};
      STAGES.forEach(s => { counts[s] = 0; });
      (data || []).forEach(s => { if (counts[s.stage] !== undefined) counts[s.stage]++; });
      res.json({ stages: STAGES, counts });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  console.log('[BD-Recruiter] Routes mounted (job-orders, candidates, submissions, recruiter assignment, analytics)');
};
