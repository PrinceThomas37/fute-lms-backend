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

const { EVENTS, emit } = require('./events');

module.exports = function (app, deps) {
  const { supabase, auth, hasRole, notGuest, today } = deps;

  // ── pipeline stage definitions ───────────────────────────────────────────
  // Canonical submission lifecycle = the Ceipal application status. `stage` holds
  // it; the grid labels it "Application Status". The BDM gate is on Submitted to Client.
  const STAGES = [
    'Sourced',
    'Screening',
    'Submitted to BDM',
    'Submitted to Client',
    'Interview Scheduled',
    'Interview Completed',
    'Offer',
    'Confirmation',
    'Placement',
    'Rejected',
    'Not Joined',
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

  // All editable job fields (matches the frontend form + migration #2 columns).
  // Used by both create routes and the PUT so every field round-trips.
  const JOB_FIELDS = [
    'job_title','client','client_job_id','client_manager','end_client',
    'status','job_type','emp_level','work_auth','priority','remote','clearance',
    'country','state','city','zip','pay_cur','pay_min','pay_max',
    'start_date','end_date','duration','placement_fee','req_docs',
    'primary_skills','secondary_skills','exp_min','exp_max',
    'industry','domain','degree','languages','job_category',
    'positions','job_description','comments'
  ];
  // Date columns need null (not '') when empty, or Postgres rejects them.
  const JOB_DATE_FIELDS = ['start_date','end_date'];
  function pickJobFields(src) {
    const out = {};
    src = src || {};
    JOB_FIELDS.forEach(function (k) {
      if (src[k] === undefined) return;
      let v = src[k];
      if (JOB_DATE_FIELDS.indexOf(k) > -1 && (v === '' || v === null)) { out[k] = null; return; }
      out[k] = v;
    });
    return out;
  }

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
      const jobRow = Object.assign({
        job_code: jobCode,
        source_lead_id: lead.id,
        lead_code: leadCode,
        company_id: lead.company_id,
        job_title: lead.position,                   // title carries over from the lead
        priority: 'Normal',
        status: 'Active',
        bd_manager_id: b.bd_manager_id || req.user.id,
        created_by: req.user.id
      }, pickJobFields(b));
      // never let the client blank out the inherited title
      if (!jobRow.job_title) jobRow.job_title = lead.position;
      const { data: jobOrder, error } = await supabase.from('job_orders')
        .insert(jobRow).select(JOB_ORDER_SELECT).single();
      if (error) throw error;

      const openedDate = new Date().toISOString().slice(0, 10);
      await supabase.from('jobs').update({
        job_opened_date: openedDate,
        updated_at: new Date()
      }).eq('id', lead.id);

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
      const jobRow = Object.assign({
        job_code: jobCode,
        source_lead_id: leadRow.id,
        lead_code: leadCode,
        company_id: leadRow.company_id,
        job_title: leadRow.position,
        priority: 'Normal',
        status: 'Active',
        bd_manager_id: job.bd_manager_id || req.user.id,
        created_by: req.user.id
      }, pickJobFields(job));
      if (!jobRow.job_title) jobRow.job_title = leadRow.position;
      const { data: jobOrder, error } = await supabase.from('job_orders')
        .insert(jobRow).select(JOB_ORDER_SELECT).single();
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
      const list = data || [];
      // Attach assigned recruiters to every job order (the single-get already
      // does this; the list did not — which made the recruiter "My Jobs" filter
      // return nothing and showed everyone as "Unassigned" on the BDM list).
      if (list.length) {
        const { data: assigns } = await supabase.from('recruiter_assignments')
          .select('job_order_id, id, assigned_at, recruiter:users!recruiter_id(id,name,employee_id)')
          .in('job_order_id', list.map(j => j.id));
        const byJob = {};
        (assigns || []).forEach(a => { (byJob[a.job_order_id] = byJob[a.job_order_id] || []).push(a); });
        list.forEach(j => { j.recruiters = byJob[j.id] || []; });
      }
      res.json(list);
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
      const updates = Object.assign({ updated_at: new Date() }, pickJobFields(b));
      if (b.bd_manager_id !== undefined) updates.bd_manager_id = b.bd_manager_id || null;
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

  // Job orders a specific user is assigned to — lets an admin/BDM see a
  // recruiter's assignments from that recruiter's profile (the recruiter's own
  // /job-orders is scoped to themselves; this is the "view someone else" version).
  app.get('/users/:id/job-orders', auth, async (req, res) => {
    try {
      if (!isBDM(req)) return res.status(403).json({ error: 'Admin or BD Manager only' });
      const ids = await assignedJobOrderIds(req.params.id);
      if (!ids.length) return res.json([]);
      const { data, error } = await supabase.from('job_orders')
        .select(JOB_ORDER_SELECT).in('id', ids).is('deleted_at', null)
        .order('created_at', { ascending: false });
      if (error) throw error;
      res.json(data || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ==========================================================================
  // CANDIDATES — shared pool (Ceipal-style Applicants database)
  // ==========================================================================

  // Writable candidate fields (matches migration 012 + the Applicants form).
  const CANDIDATE_FIELDS = [
    'full_name','first_name','last_name','email','phone','alt_phone','linkedin_url',
    'current_location','city','state','country','zip',
    'current_title','headline','skills','experience_years',
    'work_authorization','clearance','current_employer',
    'availability','notice_period','current_ctc','expected_ctc',
    'bill_rate','pay_rate','pay_type','pay_currency',
    'applicant_status','source','resume_url','resume_filename'
  ];
  const CANDIDATE_SELECT =
    'id,candidate_code,full_name,first_name,last_name,email,phone,alt_phone,linkedin_url,' +
    'current_location,city,state,country,zip,current_title,headline,skills,experience_years,' +
    'work_authorization,clearance,current_employer,availability,notice_period,current_ctc,expected_ctc,' +
    'bill_rate,pay_rate,pay_type,pay_currency,applicant_status,source,resume_url,resume_filename,' +
    'tags,owner_id,created_by,created_at,updated_at,' +
    'owner:users!owner_id(id,name,employee_id),creator:users!created_by(id,name,employee_id)';

  function pickCandidateFields(src) {
    const out = {};
    src = src || {};
    CANDIDATE_FIELDS.forEach(function (k) {
      if (src[k] === undefined) return;
      const v = src[k];
      if (k === 'experience_years') { out[k] = (v === '' || v === null) ? null : v; return; }
      out[k] = (v === '') ? null : v;
    });
    return out;
  }

  // Normalizers — mirror the generated columns created in migration 012.
  function normName(s) { return String(s || '').toLowerCase().trim().replace(/\s+/g, ' '); }
  function normEmail(s) { return String(s || '').toLowerCase().trim(); }
  function normPhone(s) { return (String(s || '').match(/\d/g) || []).join('').slice(-10); }

  // Duplicate rule (owner's spec): same normalized full name AND (email OR phone
  // matches). Returns the matching non-deleted candidates ([] = no duplicate).
  async function findCandidateDuplicates({ full_name, email, phone, excludeId }) {
    const n = normName(full_name), e = normEmail(email), p = normPhone(phone);
    if (!n) return [];
    if (!e && !p) return [];                 // need at least one of email / phone to match on
    let q = supabase.from('candidates')
      .select('id,candidate_code,full_name,email,phone,current_title,applicant_status,owner_id')
      .is('deleted_at', null).eq('name_norm', n).limit(25);
    if (excludeId) q = q.neq('id', excludeId);
    const { data, error } = await q;
    if (error) throw error;
    return (data || []).filter(function (c) {
      const ce = normEmail(c.email), cp = normPhone(c.phone);
      return (e && ce && ce === e) || (p && cp && cp === p);
    });
  }

  // GET /candidates
  //  - legacy (no ?page): returns a plain array (used by the job-page add modal)
  //  - paged  (?page=N):  returns { data, total, page, limit } for the Applicants grid
  app.get('/candidates', auth, async (req, res) => {
    try {
      const paged = req.query.page !== undefined;
      const q = (req.query.q || '').trim().replace(/[,()]/g, ' ').trim();  // strip or()-structural chars
      let query = supabase.from('candidates')
        .select(CANDIDATE_SELECT, paged ? { count: 'exact' } : undefined)
        .is('deleted_at', null);
      if (q) query = query.or(
        `full_name.ilike.%${q}%,email.ilike.%${q}%,candidate_code.ilike.%${q}%,phone.ilike.%${q}%,current_title.ilike.%${q}%`
      );
      if (req.query.applicant_status) query = query.eq('applicant_status', req.query.applicant_status);
      if (req.query.source) query = query.eq('source', req.query.source);
      if (req.query.state) query = query.eq('state', req.query.state);
      if (req.query.work_authorization) query = query.eq('work_authorization', req.query.work_authorization);
      if (req.query.owner_id) query = query.eq('owner_id', req.query.owner_id);
      query = query.order('created_at', { ascending: false });

      if (paged) {
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 25));
        const from = (page - 1) * limit;
        const { data, error, count } = await query.range(from, from + limit - 1);
        if (error) throw error;
        return res.json({ data: data || [], total: count || 0, page, limit });
      }
      const { data, error } = await query.limit(100);
      if (error) throw error;
      res.json(data || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // GET /candidates/check-duplicate?full_name=&email=&phone=
  // Registered before /candidates/:id so the literal path wins the match.
  app.get('/candidates/check-duplicate', auth, async (req, res) => {
    try {
      const dups = await findCandidateDuplicates({
        full_name: req.query.full_name, email: req.query.email,
        phone: req.query.phone, excludeId: req.query.exclude_id
      });
      res.json({ duplicate: dups.length > 0, duplicates: dups });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.get('/candidates/:id', auth, async (req, res) => {
    try {
      const { data, error } = await supabase.from('candidates')
        .select(CANDIDATE_SELECT).eq('id', req.params.id).is('deleted_at', null).single();
      if (error || !data) return res.status(404).json({ error: 'Candidate not found' });
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // A candidate's recruiting history across every job — pipelines, submissions,
  // and the stage-change activity that drives the profile lifecycle bar.
  app.get('/candidates/:id/history', auth, async (req, res) => {
    try {
      const cid = req.params.id;
      const JOB = 'job:job_orders(id,job_code,job_title,client)';
      const { data: pipeline } = await supabase.from('candidate_pipeline')
        .select('id,pipeline_code,pipeline_status,job_order_id,tagged_at,submission_id,' + JOB)
        .eq('candidate_id', cid).is('deleted_at', null).order('tagged_at', { ascending: false });
      const { data: submissions } = await supabase.from('submissions')
        .select('id,submission_code,stage,job_order_id,submitted_at,created_at,bdm_approved_at,pipeline_id,revision_status,' + JOB)
        .eq('candidate_id', cid).is('deleted_at', null).order('created_at', { ascending: false });
      let activity = [];
      const subIds = (submissions || []).map(s => s.id);
      if (subIds.length) {
        const { data: act } = await supabase.from('submission_activity')
          .select('id,submission_id,job_order_id,action,old_stage,new_stage,note,created_at')
          .in('submission_id', subIds).order('created_at', { ascending: true });
        activity = act || [];
      }
      res.json({ pipeline: pipeline || [], submissions: submissions || [], activity });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/candidates', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const b = req.body || {};
      if (!b.full_name || !String(b.full_name).trim()) return res.status(400).json({ error: 'full_name required' });

      // Duplicate catch — name + (email or phone). Warn-and-offer: unless `force`,
      // return the matches (409) so the UI can offer "open existing" over a copy.
      if (!b.force) {
        const dups = await findCandidateDuplicates({ full_name: b.full_name, email: b.email, phone: b.phone });
        if (dups.length) return res.status(409).json({ error: 'possible_duplicate', duplicates: dups });
      }

      const code = await nextId('CN');
      const row = Object.assign(pickCandidateFields(b), {
        candidate_code: code,
        applicant_status: b.applicant_status || 'New lead',
        owner_id: b.owner_id || req.user.id,
        created_by: req.user.id
      });
      if (Array.isArray(b.tags)) row.tags = b.tags;
      const { data, error } = await supabase.from('candidates').insert(row).select(CANDIDATE_SELECT).single();
      if (error) throw error;
      res.status(201).json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.put('/candidates/:id', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const b = req.body || {};
      const updates = Object.assign(pickCandidateFields(b), { updated_at: new Date(), updated_by: req.user.id });
      if (b.owner_id !== undefined) updates.owner_id = b.owner_id || null;
      if (Array.isArray(b.tags)) updates.tags = b.tags;
      const { data, error } = await supabase.from('candidates')
        .update(updates).eq('id', req.params.id).select(CANDIDATE_SELECT).single();
      if (error) throw error;
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.delete('/candidates/:id', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      await supabase.from('candidates').update({ deleted_at: new Date() }).eq('id', req.params.id);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ==========================================================================
  // CANDIDATE NOTES & DOCUMENTS (Slice 5)
  // ==========================================================================

  const NOTE_TYPES = ['job_posting', 'applicant_reference'];
  const DOC_BUCKET = 'candidate-docs';
  const MAX_DOC_BYTES = 4.5 * 1024 * 1024;   // fits the 5mb express json limit after base64
  let _bucketEnsured = false;
  async function ensureDocBucket() {
    if (_bucketEnsured) return;
    try { await supabase.storage.createBucket(DOC_BUCKET, { public: false }); } catch (_) { /* exists */ }
    _bucketEnsured = true;
  }

  // ── notes ────────────────────────────────────────────────────────────────
  app.get('/candidates/:id/notes', auth, async (req, res) => {
    try {
      const { data, error } = await supabase.from('candidate_notes')
        .select('*, author:users!created_by(id,name,employee_id)')
        .eq('candidate_id', req.params.id).is('deleted_at', null)
        .order('created_at', { ascending: false });
      if (error) throw error;
      res.json(data || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/candidates/:id/notes', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const b = req.body || {};
      if (!b.body || !String(b.body).trim()) return res.status(400).json({ error: 'body required' });
      const noteType = NOTE_TYPES.includes(b.note_type) ? b.note_type : 'applicant_reference';
      const { data, error } = await supabase.from('candidate_notes').insert({
        candidate_id: req.params.id, job_order_id: b.job_order_id || null,
        note_type: noteType, body: String(b.body), created_by: req.user.id
      }).select('*, author:users!created_by(id,name,employee_id)').single();
      if (error) throw error;
      res.status(201).json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.delete('/candidates/:id/notes/:noteId', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      await supabase.from('candidate_notes').update({ deleted_at: new Date() })
        .eq('id', req.params.noteId).eq('candidate_id', req.params.id);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ── documents (stored in the private candidate-docs bucket) ────────────────
  app.get('/candidates/:id/documents', auth, async (req, res) => {
    try {
      const { data, error } = await supabase.from('candidate_documents')
        .select('*, uploader:users!uploaded_by(id,name,employee_id)')
        .eq('candidate_id', req.params.id).is('deleted_at', null)
        .order('uploaded_at', { ascending: false });
      if (error) throw error;
      // attach a short-lived signed URL for each (private bucket)
      const rows = await Promise.all((data || []).map(async (d) => {
        let url = null;
        try {
          const { data: s } = await supabase.storage.from(DOC_BUCKET).createSignedUrl(d.storage_path, 3600);
          url = s ? s.signedUrl : null;
        } catch (_) { /* leave null */ }
        return Object.assign({}, d, { url });
      }));
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/candidates/:id/documents', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const b = req.body || {};
      if (!b.filename || !b.data_base64) return res.status(400).json({ error: 'filename and data_base64 required' });
      const raw = String(b.data_base64).replace(/^data:.*;base64,/, '');
      const buffer = Buffer.from(raw, 'base64');
      if (!buffer.length) return res.status(400).json({ error: 'empty file' });
      if (buffer.length > MAX_DOC_BYTES) return res.status(413).json({ error: 'File too large (max ~4.5 MB).' });

      await ensureDocBucket();
      const safe = String(b.filename).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
      const path = req.params.id + '/' + Date.now() + '-' + safe;
      const { error: upErr } = await supabase.storage.from(DOC_BUCKET)
        .upload(path, buffer, { contentType: b.content_type || 'application/octet-stream', upsert: false });
      if (upErr) throw upErr;

      const docType = ['resume', 'cover_letter', 'other'].includes(b.doc_type) ? b.doc_type : 'resume';
      const { data, error } = await supabase.from('candidate_documents').insert({
        candidate_id: req.params.id, doc_type: docType, filename: String(b.filename),
        storage_path: path, content_type: b.content_type || null, size_bytes: buffer.length,
        uploaded_by: req.user.id
      }).select('*, uploader:users!uploaded_by(id,name,employee_id)').single();
      if (error) throw error;

      // convenience: if this is the first résumé, backfill candidate.resume_url metadata
      if (docType === 'resume') {
        try { await supabase.from('candidates').update({ resume_filename: String(b.filename) }).eq('id', req.params.id); } catch (_) {}
      }
      res.status(201).json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.delete('/candidates/:id/documents/:docId', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const { data: doc } = await supabase.from('candidate_documents')
        .select('storage_path').eq('id', req.params.docId).eq('candidate_id', req.params.id).single();
      await supabase.from('candidate_documents').update({ deleted_at: new Date() })
        .eq('id', req.params.docId).eq('candidate_id', req.params.id);
      if (doc && doc.storage_path) { try { await supabase.storage.from(DOC_BUCKET).remove([doc.storage_path]); } catch (_) {} }
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ==========================================================================
  // SUBMISSIONS — pipeline (per-candidate stage, with BDM approval gate)
  // ==========================================================================

  const SUBMISSION_SELECT =
    '*, candidate:candidates(id,candidate_code,full_name,email,phone,work_authorization,' +
    'city,state,country,current_location,experience_years,source,resume_url,current_title), ' +
    'recruiter:users!recruiter_id(id,name,employee_id), ' +
    'submitter:users!submitted_by(id,name,employee_id)';

  // editable submission display fields (the Submissions grid)
  const SUBMISSION_FIELDS = ['revision_status','bill_rate','pay_rate','employer_name','availability','notice_period','submitted_rate','notes'];

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
      // snapshot rate/availability/employer from the candidate (overridable via body)
      const { data: cand } = await supabase.from('candidates')
        .select('bill_rate,pay_rate,current_employer,availability,notice_period')
        .eq('id', b.candidate_id).single();
      const c = cand || {};
      const pick = (k, fb) => (b[k] !== undefined ? b[k] : (fb || null));
      const { data, error } = await supabase.from('submissions').insert({
        submission_code: await nextId('SB'),
        candidate_id: b.candidate_id, job_order_id: b.job_order_id,
        recruiter_id: b.recruiter_id || req.user.id,
        stage: 'Sourced', submitted_rate: b.submitted_rate || null, notes: b.notes || null,
        revision_status: b.revision_status || 'N/A',
        bill_rate: pick('bill_rate', c.bill_rate),
        pay_rate: pick('pay_rate', c.pay_rate),
        employer_name: pick('employer_name', c.current_employer),
        availability: pick('availability', c.availability),
        notice_period: pick('notice_period', c.notice_period),
        submitted_by: req.user.id, submitted_at: new Date()
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
      emit(EVENTS.SUBMISSION_ADVANCED, { submissionId: data.id, jobOrderId: sub.job_order_id, fromStage: sub.stage, toStage: newStage, actorUserId: req.user.id });
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // edit a submission's display fields (revision status / rate / employer …)
  app.patch('/submissions/:id', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const { data: sub, error: e0 } = await supabase.from('submissions')
        .select('job_order_id').eq('id', req.params.id).is('deleted_at', null).single();
      if (e0 || !sub) return res.status(404).json({ error: 'Submission not found' });
      if (isRecruiter(req) && !isBDM(req)) {
        const ids = await assignedJobOrderIds(req.user.id);
        if (!ids.includes(sub.job_order_id)) return res.status(403).json({ error: 'Not assigned to this job order.' });
      }
      const b = req.body || {};
      const updates = {};
      SUBMISSION_FIELDS.forEach(k => { if (b[k] !== undefined) updates[k] = (b[k] === '' ? null : b[k]); });
      const { data, error } = await supabase.from('submissions')
        .update(updates).eq('id', req.params.id).select(SUBMISSION_SELECT).single();
      if (error) throw error;
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
  // PIPELINE — candidate tagging layer (Ceipal "Pipeline" tab)
  // A candidate is TAGGED into a job order, then PROMOTED to a submission.
  // ==========================================================================

  const PIPELINE_STATUSES = ['Tagged','Contacted','Interested','Screening','Shortlisted','Moved to Submission','Not Interested','Rejected'];
  const PIPELINE_SELECT =
    '*, candidate:candidates(id,candidate_code,full_name,email,phone,work_authorization,' +
    'city,state,country,current_location,experience_years,source,resume_url), ' +
    'tagger:users!tagged_by(id,name,employee_id)';

  // recruiter may only touch a job order they are assigned to
  async function recruiterCanTouchJob(req, jobOrderId) {
    if (!(isRecruiter(req) && !isBDM(req))) return true;
    const ids = await assignedJobOrderIds(req.user.id);
    return ids.includes(jobOrderId);
  }

  // list the pipeline (tagged candidates) for a job order — the Pipeline-tab grid
  app.get('/job-orders/:id/pipeline', auth, async (req, res) => {
    try {
      if (!(await recruiterCanTouchJob(req, req.params.id))) return res.status(403).json({ error: 'Not assigned to this job order.' });
      const { data, error } = await supabase.from('candidate_pipeline')
        .select(PIPELINE_SELECT).eq('job_order_id', req.params.id).is('deleted_at', null)
        .order('tagged_at', { ascending: false });
      if (error) throw error;
      res.json(data || []);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // tag a candidate (from the pool) into a job order's pipeline
  app.post('/pipeline', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const b = req.body || {};
      if (!b.candidate_id || !b.job_order_id) return res.status(400).json({ error: 'candidate_id and job_order_id required' });
      if (!(await recruiterCanTouchJob(req, b.job_order_id))) return res.status(403).json({ error: 'Not assigned to this job order.' });

      // snapshot rate/availability/employer from the candidate (overridable via body)
      const { data: cand } = await supabase.from('candidates')
        .select('work_authorization,bill_rate,pay_rate,current_employer,availability,notice_period,current_ctc,source')
        .eq('id', b.candidate_id).single();
      const c = cand || {};
      const pick = (k, fallback) => (b[k] !== undefined ? b[k] : (fallback || null));
      const row = {
        pipeline_code: await nextId('PL'),
        candidate_id: b.candidate_id, job_order_id: b.job_order_id,
        pipeline_status: b.pipeline_status || 'Tagged',
        work_auth_snap: pick('work_auth_snap', c.work_authorization),
        bill_rate: pick('bill_rate', c.bill_rate),
        pay_rate: pick('pay_rate', c.pay_rate),
        employer_name: pick('employer_name', c.current_employer),
        availability: pick('availability', c.availability),
        notice_period: pick('notice_period', c.notice_period),
        current_ctc: pick('current_ctc', c.current_ctc),
        source: pick('source', c.source),
        notes: b.notes || null,
        tagged_by: req.user.id
      };
      const { data, error } = await supabase.from('candidate_pipeline').insert(row).select(PIPELINE_SELECT).single();
      if (error) {
        if (error.code === '23505') return res.status(409).json({ error: 'This candidate is already tagged to this job.' });
        throw error;
      }
      await logSubmissionActivity(null, b.job_order_id, req.user.id, 'tagged', null, 'Tagged', null);
      res.status(201).json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // change a pipeline entry's status
  app.patch('/pipeline/:id/status', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const st = req.body.status;
      if (!PIPELINE_STATUSES.includes(st)) return res.status(400).json({ error: `Invalid pipeline status. Allowed: ${PIPELINE_STATUSES.join(', ')}` });
      const { data: row, error: e0 } = await supabase.from('candidate_pipeline')
        .select('job_order_id').eq('id', req.params.id).is('deleted_at', null).single();
      if (e0 || !row) return res.status(404).json({ error: 'Pipeline entry not found' });
      if (!(await recruiterCanTouchJob(req, row.job_order_id))) return res.status(403).json({ error: 'Not assigned to this job order.' });
      const { data, error } = await supabase.from('candidate_pipeline')
        .update({ pipeline_status: st, updated_at: new Date() }).eq('id', req.params.id).select(PIPELINE_SELECT).single();
      if (error) throw error;
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // edit a pipeline entry's snapshot fields (rate / availability / employer …)
  app.patch('/pipeline/:id', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const { data: row, error: e0 } = await supabase.from('candidate_pipeline')
        .select('job_order_id').eq('id', req.params.id).is('deleted_at', null).single();
      if (e0 || !row) return res.status(404).json({ error: 'Pipeline entry not found' });
      if (!(await recruiterCanTouchJob(req, row.job_order_id))) return res.status(403).json({ error: 'Not assigned to this job order.' });
      const allowed = ['work_auth_snap','bill_rate','pay_rate','employer_name','availability','notice_period','current_ctc','source','notes','pipeline_status'];
      const b = req.body || {};
      const updates = { updated_at: new Date() };
      allowed.forEach(k => { if (b[k] !== undefined) updates[k] = (b[k] === '' ? null : b[k]); });
      const { data, error } = await supabase.from('candidate_pipeline')
        .update(updates).eq('id', req.params.id).select(PIPELINE_SELECT).single();
      if (error) throw error;
      res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // promote a pipeline entry into a formal submission
  app.post('/pipeline/:id/promote', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      const { data: pl, error: e0 } = await supabase.from('candidate_pipeline')
        .select('*').eq('id', req.params.id).is('deleted_at', null).single();
      if (e0 || !pl) return res.status(404).json({ error: 'Pipeline entry not found' });
      if (!(await recruiterCanTouchJob(req, pl.job_order_id))) return res.status(403).json({ error: 'Not assigned to this job order.' });

      // already promoted → return the linked submission
      if (pl.submission_id) {
        const { data: existing } = await supabase.from('submissions').select(SUBMISSION_SELECT).eq('id', pl.submission_id).single();
        return res.json({ pipeline_id: pl.id, submission: existing, already: true });
      }

      const targetStage = req.body.stage || 'Submitted to BDM';
      let submission;
      const { data: sub, error } = await supabase.from('submissions').insert({
        submission_code: await nextId('SB'),
        candidate_id: pl.candidate_id, job_order_id: pl.job_order_id,
        recruiter_id: req.user.id, stage: targetStage,
        pipeline_id: pl.id, revision_status: 'N/A',
        bill_rate: pl.bill_rate || null, pay_rate: pl.pay_rate || null,
        employer_name: pl.employer_name || null, availability: pl.availability || null,
        notice_period: pl.notice_period || null,
        submitted_rate: pl.pay_rate || null, notes: pl.notes || null,
        submitted_by: req.user.id, submitted_at: new Date()
      }).select(SUBMISSION_SELECT).single();
      if (error) {
        if (error.code === '23505') {
          // a submission already exists for this candidate+job — link to it
          const { data: existing } = await supabase.from('submissions').select(SUBMISSION_SELECT)
            .eq('candidate_id', pl.candidate_id).eq('job_order_id', pl.job_order_id).is('deleted_at', null).single();
          submission = existing;
        } else throw error;
      } else submission = sub;
      if (!submission) return res.status(500).json({ error: 'Could not create or find the submission.' });

      await supabase.from('candidate_pipeline')
        .update({ submission_id: submission.id, pipeline_status: 'Moved to Submission', updated_at: new Date() })
        .eq('id', pl.id);
      await logSubmissionActivity(submission.id, pl.job_order_id, req.user.id, 'promoted', 'Tagged', targetStage, null);
      emit(EVENTS.SUBMISSION_ADVANCED, { submissionId: submission.id, jobOrderId: pl.job_order_id, fromStage: null, toStage: targetStage, actorUserId: req.user.id });
      res.status(201).json({ pipeline_id: pl.id, submission });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.delete('/pipeline/:id', auth, async (req, res) => {
    try {
      if (notGuest(req, res)) return;
      if (!isBDM(req) && !isRecruiter(req)) return res.status(403).json({ error: 'Not permitted.' });
      await supabase.from('candidate_pipeline').update({ deleted_at: new Date() }).eq('id', req.params.id);
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
        else if (s.stage === 'Placement') r.placed++;
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

  console.log('[BD-Recruiter] Routes mounted (job-orders, candidates, pipeline, submissions, recruiter assignment, analytics)');
};
