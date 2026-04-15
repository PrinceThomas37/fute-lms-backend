require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// ── MIDDLEWARE ─────────────────────────────────────────────────
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','PATCH','DELETE'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({ limit: '5mb' }));

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), process.env.JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

const today = () => new Date().toISOString().split('T')[0];

async function logActivity(job_id, contact_id, user_id, action_type, description, old_value, new_value) {
  try {
    await supabase.from('activity_log').insert({
      job_id: job_id || null, contact_id: contact_id || null, user_id: user_id || null,
      action_type, description: description || null,
      old_value: old_value || null, new_value: new_value || null
    });
  } catch (e) { console.error('activity_log insert failed:', e.message); }
}

// ── HEALTH ─────────────────────────────────────────────────────
app.use(express.static('public'));
app.get('/api/health', (req, res) => res.json({ status: 'ok', app: 'Fute Global LMS API', version: '2.7.0-insights' }));

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const { data: user, error } = await supabase.from('users').select('*')
      .eq('email', email.toLowerCase().trim()).eq('is_active', true).is('deleted_at', null).single();
    if (error || !user) return res.status(401).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name },
      process.env.JWT_SECRET, { expiresIn: '8h' });
    const { password_hash, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const { data: user } = await supabase.from('users').select('password_hash').eq('id', req.user.id).single();
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password incorrect' });
    const hash = await bcrypt.hash(newPassword, 10);
    await supabase.from('users').update({ password_hash: hash, updated_at: new Date() }).eq('id', req.user.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// USERS  (assigned_bdm_id removed)
// ══════════════════════════════════════════════════════════════
const USER_COLS = 'id,name,email,role,employee_id,designation,platform,is_active,created_at';

app.get('/users', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select(USER_COLS).is('deleted_at', null).order('employee_id');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/users/me', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select(USER_COLS).eq('id', req.user.id).single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/users', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const { name, email, password, role, employee_id, designation, platform } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Name and email required' });
    const hash = await bcrypt.hash(password || 'Fute@2024', 10);
    const { data, error } = await supabase.from('users').insert({
      name, email: email.toLowerCase().trim(), password_hash: hash,
      role: role || 'ra', employee_id, designation, platform: platform || 'Gmail'
    }).select(USER_COLS).single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/users/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    if (req.user.role !== 'admin' && req.user.id !== id) return res.status(403).json({ error: 'Forbidden' });
    const { name, email, role, employee_id, designation, platform } = req.body;
    const updates = { updated_at: new Date() };
    if (name) updates.name = name;
    if (email) updates.email = email.toLowerCase().trim();
    if (role && req.user.role === 'admin') updates.role = role;
    if (employee_id) updates.employee_id = employee_id;
    if (designation !== undefined) updates.designation = designation;
    if (platform) updates.platform = platform;
    const { data, error } = await supabase.from('users').update(updates).eq('id', id).select(USER_COLS).single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/users/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    await supabase.from('users').update({ deleted_at: new Date(), is_active: false }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// COMPANIES
// ══════════════════════════════════════════════════════════════
app.get('/companies', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('companies').select('*').is('deleted_at', null).order('name');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ── Zip code lookup (US) ────────────────────────────────────
app.get('/lookup/zipcode', auth, async (req, res) => {
  try {
    const { zip } = req.query;
    if (!zip || zip.length < 3) return res.json([]);
    // Use zippopotam.us free API
    const resp = await fetch(`https://api.zippopotam.us/us/${zip.trim()}`);
    if (!resp.ok) return res.json([]);
    const data = await resp.json();
    const places = (data.places || []).map(p => ({
      zip: data['post code'],
      city: p['place name'],
      state: p['state'],
      state_abbr: p['state abbreviation'],
      display: `${p['place name']}, ${p['state abbreviation']} ${data['post code']}`
    }));
    res.json(places);
  } catch (err) { res.json([]); }
});

// ── Company search (typeahead for RA form) ──────────────────
app.get('/companies/search', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) return res.json([]);
    const { data, error } = await supabase.from('companies')
      .select('id,name,industry,location,website')
      .ilike('name', `%${q}%`)
      .is('deleted_at', null)
      .limit(8);
    if (error) throw error;
    // For each company, get job count and assigned BD
    const result = await Promise.all((data || []).map(async co => {
      const { count } = await supabase.from('jobs')
        .select('id', { count: 'exact', head: true })
        .eq('company_id', co.id).is('deleted_at', null);
      // Find most recent BD assigned to a job in this company
      const { data: jobs } = await supabase.from('jobs')
        .select('assigned_to_bd, bd:users!assigned_to_bd(name)')
        .eq('company_id', co.id).is('deleted_at', null)
        .not('assigned_to_bd', 'is', null).limit(1);
      const bdName = jobs?.[0]?.bd?.name || null;
      return { ...co, job_count: count || 0, bd_name: bdName };
    }));
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Email duplicate check (real-time, 2-month window) ──────
app.post('/contacts/check-email', auth, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ duplicate: false });
    const twoMonthsAgo = new Date();
    twoMonthsAgo.setMonth(twoMonthsAgo.getMonth() - 2);
    const { data, error } = await supabase.from('contacts')
      .select('id,first_name,last_name,email,created_at,job:jobs(id,position,company:companies(name)),creator:jobs!inner(created_by,creator:users!created_by(name))')
      .eq('email', email.toLowerCase().trim())
      .gte('created_at', twoMonthsAgo.toISOString())
      .limit(1);
    if (error) throw error;
    if (!data?.length) return res.json({ duplicate: false });
    const c = data[0];
    const daysSince = Math.floor((new Date() - new Date(c.created_at)) / 86400000);
    res.json({
      duplicate: true,
      days_ago: daysSince,
      contact_name: `${c.first_name} ${c.last_name}`.trim(),
      company: c.job?.company?.name || '',
      position: c.job?.position || '',
      added_by: c.creator?.creator?.name || 'Unknown RA'
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ── Bulk create companies ──────────────────────────────────────
app.post('/companies/bulk', auth, async (req, res) => {
  try {
    const { companies } = req.body;
    if (!Array.isArray(companies) || !companies.length) return res.status(400).json({ error: 'companies array required' });
    const rows = companies.map(c => ({
      name: c.name, website: c.website || null,
      industry: c.industry || null, location: c.location || null,
      created_by: req.user.id
    }));
    const { data, error } = await supabase.from('companies').insert(rows).select('id,name');
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});


app.post('/companies', auth, async (req, res) => {
  try {
    const { name, website, industry, location, size, notes } = req.body;
    if (!name) return res.status(400).json({ error: 'Company name required' });
    const { data, error } = await supabase.from('companies').insert({
      name, website, industry, location, size, notes, created_by: req.user.id
    }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/companies/:id', auth, async (req, res) => {
  try {
    const { name, website, industry, location, size, notes } = req.body;
    const updates = { updated_at: new Date() };
    if (name !== undefined) updates.name = name;
    if (website !== undefined) updates.website = website;
    if (industry !== undefined) updates.industry = industry;
    if (location !== undefined) updates.location = location;
    if (size !== undefined) updates.size = size;
    if (notes !== undefined) updates.notes = notes;
    const { data, error } = await supabase.from('companies').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/companies/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    await supabase.from('companies').update({ deleted_at: new Date() }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// JOBS  (the new "lead" = a job opening)
// Scoping: admin sees all; bd/ra sees created_by=self OR assigned_to=self
// ══════════════════════════════════════════════════════════════
const JOB_SELECT = `*, research, company:companies(id,name,website,industry,location), contacts(id,job_id,first_name,last_name,designation,email,phone,linkedin,is_primary,email_status,ooo_until,email_sent_at,email_platform), creator:users!created_by(id,name,employee_id), assignee:users!assigned_to(id,name,employee_id), bd_assignee:users!assigned_to_bd(id,name,employee_id), sending_account:email_accounts!sending_email_id(id,email_address,display_name)`;

app.get('/jobs', auth, async (req, res) => {
  try {
    let query = supabase.from('jobs').select(JOB_SELECT).is('deleted_at', null).order('created_at', { ascending: false });
    if (req.user.role === 'admin' || req.user.role === 'ra_lead') {
      // admin and ra_lead see all jobs
    } else if (req.user.role === 'bd_lead') {
      // bd_lead sees all jobs assigned to any BD
      query = query.not('assigned_to_bd', 'is', null);
    } else if (req.user.role === 'bd') {
      // BD sees only jobs assigned to them
      query = query.eq('assigned_to_bd', req.user.id);
    } else {
      // RA sees only jobs they created
      query = query.eq('created_by', req.user.id);
    }
    const { data, error } = await query;
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/jobs/:id', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('jobs').select(JOB_SELECT).eq('id', req.params.id).is('deleted_at', null).single();
    if (error) throw error;
    if (req.user.role !== 'admin' && data.created_by !== req.user.id && data.assigned_to !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Bulk import jobs (fast batch insert) ──────────────────────
app.post('/jobs/bulk', auth, async (req, res) => {
  try {
    const { jobs } = req.body; // array of job objects each with optional contacts[]
    if (!Array.isArray(jobs) || !jobs.length) return res.status(400).json({ error: 'jobs array required' });

    const tzMap = {
      'ny':'EST','nj':'EST','fl':'EST','ma':'EST','pa':'EST','ga':'EST','nc':'EST','sc':'EST','va':'EST','ct':'EST','me':'EST','nh':'EST','vt':'EST','ri':'EST','de':'EST','md':'EST','dc':'EST','oh':'EST','mi':'EST','in':'EST','ky':'EST','wv':'EST','tn':'EST',
      'tx':'CST','il':'CST','mn':'CST','wi':'CST','mo':'CST','ia':'CST','ks':'CST','ne':'CST','sd':'CST','nd':'CST','ok':'CST','la':'CST','ar':'CST','ms':'CST','al':'CST',
      'co':'MST','az':'MST','nm':'MST','ut':'MST','wy':'MST','mt':'MST','id':'MST',
      'ca':'PST','wa':'PST','or':'PST','nv':'PST','ak':'PST','hi':'PST'
    };

    function getTimezone(location) {
      if (!location) return 'EST';
      const loc = location.toLowerCase();
      for (const [state, tz] of Object.entries(tzMap)) {
        if (loc.includes(state)) return tz;
      }
      return 'EST';
    }

    function getFreshness(openedDate, createdDate) {
      const ref = openedDate || createdDate;
      if (!ref) return 'Normal';
      const days = Math.floor((new Date() - new Date(ref)) / 86400000);
      if (days <= 3) return 'New';
      if (days <= 10) return 'Normal';
      return 'Old';
    }

    // Build job rows for batch insert
    const jobRows = jobs.map(j => ({
      company_id: j.company_id,
      position: j.position || '(unknown)',
      location: j.location || null,
      source: j.source || 'Import',
      job_url: j.job_url || null,
      stage: 'Unassigned',
      notes: '',
      created_by: req.user.id,
      assigned_to: null,
      is_duplicate: j.is_duplicate || false,
      duplicate_of: j.duplicate_of || null,
      salary_range: j.salary_range || null,
      job_created_date: j.job_created_date || null,
      job_opened_date: j.job_opened_date || null,
      timezone: getTimezone(j.location),
      freshness: getFreshness(j.job_opened_date, j.job_created_date),
      bdm_assigned_name: j.bdm_assigned_name || null,
      industry: j.industry || null
    }));

    // Batch insert all jobs at once
    const { data: insertedJobs, error: jobErr } = await supabase
      .from('jobs').insert(jobRows).select('id');
    if (jobErr) throw jobErr;

    // Build contacts rows for all jobs
    const contactRows = [];
    insertedJobs.forEach((job, idx) => {
      const contacts = jobs[idx].contacts || [];
      contacts.forEach((c, ci) => {
        if (!c.first_name && !c.email) return; // skip empty
        contactRows.push({
          job_id: job.id,
          first_name: c.first_name || '',
          last_name: c.last_name || '',
          designation: c.designation || null,
          email: c.email || null,
          phone: c.phone || null,
          linkedin: c.linkedin || null,
          is_primary: ci === 0
        });
      });
    });

    // Batch insert all contacts at once
    if (contactRows.length) {
      const { error: cErr } = await supabase.from('contacts').insert(contactRows);
      if (cErr) console.error('Contact batch insert error:', cErr.message);
    }

    res.status(201).json({
      imported: insertedJobs.length,
      contacts: contactRows.length
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


app.post('/jobs', auth, async (req, res) => {
  try {
    const { company_id, position, location, source, job_url, stage, notes, assigned_to, is_duplicate, duplicate_of, contacts, salary_range, job_created_date, job_opened_date, bdm_assigned_name, industry: jobIndustry } = req.body;
    if (!company_id || !position) return res.status(400).json({ error: 'company_id and position required' });
    // Auto-calculate timezone from location
    const tzMap = {
      'ny':'EST','nj':'EST','fl':'EST','ma':'EST','pa':'EST','ga':'EST','nc':'EST','sc':'EST','va':'EST','ct':'EST','me':'EST','nh':'EST','vt':'EST','ri':'EST','de':'EST','md':'EST','dc':'EST','oh':'EST','mi':'EST','in':'EST','ky':'EST','wv':'EST','tn':'EST',
      'tx':'CST','il':'CST','mn':'CST','wi':'CST','mo':'CST','ia':'CST','ks':'CST','ne':'CST','sd':'CST','nd':'CST','ok':'CST','la':'CST','ar':'CST','ms':'CST','al':'CST',
      'co':'MST','az':'MST','nm':'MST','ut':'MST','wy':'MST','mt':'MST','id':'MST',
      'ca':'PST','wa':'PST','or':'PST','nv':'PST','ak':'PST','hi':'PST'
    };
    let timezone = 'EST';
    if (location) {
      const loc = location.toLowerCase();
      for (const [state, tz] of Object.entries(tzMap)) {
        if (loc.includes(state)) { timezone = tz; break; }
      }
    }
    // Auto-calculate freshness
    let freshness = 'Normal';
    const refDate = job_opened_date || job_created_date;
    if (refDate) {
      const days = Math.floor((new Date() - new Date(refDate)) / 86400000);
      if (days <= 3) freshness = 'New';
      else if (days <= 10) freshness = 'Normal';
      else freshness = 'Old';
    }
    const { data: job, error } = await supabase.from('jobs').insert({
      company_id, position, location, source, job_url,
      stage: stage || 'Unassigned', notes: notes || '',
      created_by: req.user.id,
      assigned_to: (['admin','ra_lead'].includes(req.user.role) ? (assigned_to || null) : null),
      is_duplicate: is_duplicate || false,
      duplicate_of: duplicate_of || null,
      salary_range: salary_range || null,
      job_created_date: job_created_date || null,
      job_opened_date: job_opened_date || null,
      timezone, freshness,
      bdm_assigned_name: bdm_assigned_name || null,
      industry: jobIndustry || null
    }).select().single();
    if (error) throw error;

    if (Array.isArray(contacts) && contacts.length) {
      const rows = contacts.map((c, i) => ({
        job_id: job.id, first_name: c.first_name || '', last_name: c.last_name || '',
        designation: c.designation || null, email: c.email || null, phone: c.phone || null,
        linkedin: c.linkedin || null, is_primary: i === 0
      }));
      await supabase.from('contacts').insert(rows);
    }
    await logActivity(job.id, null, req.user.id, 'job_created', `Job created: ${position}`, null, { position, stage: job.stage });
    res.status(201).json(job);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/jobs/:id', auth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const isRA = req.user.role === 'ra';
    const hoursSinceCreation = (new Date() - new Date(existing.created_at)) / 3600000;
    const raCanEdit = isRA && existing.created_by === req.user.id && hoursSinceCreation <= 24;
    const canEdit = ['admin','ra_lead','bd','bd_lead'].includes(req.user.role) || existing.created_by === req.user.id || existing.assigned_to === req.user.id || existing.assigned_to_bd === req.user.id || raCanEdit;
    if (!canEdit) return res.status(403).json({ error: 'Forbidden' });
    // RA can only edit within 24 hours and only certain fields
    if (isRA && !raCanEdit) return res.status(403).json({ error: 'Edit window has expired (24 hours)' });
    const { position, location, source, job_url, stage, notes, assigned_to, assigned_to_bd, sending_email_id } = req.body;
    const updates = { updated_at: new Date() };
    if (position !== undefined) updates.position = position;
    if (location !== undefined) updates.location = location;
    if (source !== undefined) updates.source = source;
    if (job_url !== undefined) updates.job_url = job_url;
    if (stage !== undefined) {
      const bdStages = ['Connected','Rejected','Future','In Discussion'];
      const systemStages = ['Unassigned','Assigned'];
      const canSetBDStage = ['admin','bd','bd_lead'].includes(req.user.role);
      const canSetSystemStage = ['admin','ra_lead'].includes(req.user.role);
      if (bdStages.includes(stage) && canSetBDStage) updates.stage = stage;
      else if (systemStages.includes(stage) && canSetSystemStage) updates.stage = stage;
      else if (req.user.role === 'admin') updates.stage = stage;
    }
    if (notes !== undefined) updates.notes = notes;
    if (assigned_to !== undefined && ['admin','ra_lead'].includes(req.user.role)) updates.assigned_to = assigned_to || null;
    if (assigned_to_bd !== undefined && ['admin','ra_lead'].includes(req.user.role)) {
      updates.assigned_to_bd = assigned_to_bd || null;
      updates.assigned_at = assigned_to_bd ? new Date() : null;
      if (assigned_to_bd && stage === undefined) updates.stage = 'Assigned';
    }
    if (sending_email_id !== undefined && ['admin','ra_lead'].includes(req.user.role)) {
      updates.sending_email_id = sending_email_id || null;
    }

    const { data, error } = await supabase.from('jobs').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;

    if (stage !== undefined && stage !== existing.stage) {
      await logActivity(data.id, null, req.user.id, 'stage_change', `Stage: ${existing.stage} → ${stage}`, { stage: existing.stage }, { stage });
      // If stage moved away from Assigned, skip any active follow-ups for this job
      if (existing.stage === 'Assigned' && stage !== 'Assigned') {
        await supabase.from('follow_ups').update({ status: 'skipped' })
          .eq('job_id', req.params.id).eq('status', 'active');
      }
    } else {
      await logActivity(data.id, null, req.user.id, 'job_updated', 'Job updated', null, null);
    }
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/jobs/:id', auth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('jobs').select('created_by,assigned_to,position').eq('id', req.params.id).single();
    if (!existing) return res.status(404).json({ error: 'Not found' });
    if (req.user.role !== 'admin' && existing.created_by !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    await supabase.from('jobs').update({ deleted_at: new Date() }).eq('id', req.params.id);
    await logActivity(req.params.id, null, req.user.id, 'job_deleted', `Job deleted: ${existing.position}`, null, null);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});



// ══════════════════════════════════════════════════════════════
// EMAIL ACCOUNTS (sending identities)
// ══════════════════════════════════════════════════════════════
app.get('/email-accounts', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('email_accounts')
      .select('*, assigned_user:users!assigned_to(id,name,email,role), assigner:users!assigned_by(id,name)')
      .order('created_at');
    if (error) throw error;
    const filtered = ['admin','ra_lead','bd_lead'].includes(req.user.role)
      ? data
      : data.filter(a => a.assigned_to === req.user.id);
    // Attach ms_connected flag
    const accountIds = filtered.map(a => a.id);
    const { data: tokens } = accountIds.length
      ? await supabase.from('microsoft_tokens').select('email_account_id').in('email_account_id', accountIds)
      : { data: [] };
    const connectedSet = new Set((tokens || []).map(t => t.email_account_id));
    const result = filtered.map(a => ({ ...a, ms_connected: connectedSet.has(a.id) }));
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/email-accounts', auth, async (req, res) => {
  try {
    if (!['admin','bd_lead'].includes(req.user.role)) return res.status(403).json({ error: 'Admin only' });
    const { email_address, display_name, assigned_to, daily_send_limit } = req.body;
    if (!email_address || !display_name) return res.status(400).json({ error: 'email_address and display_name required' });
    const { data, error } = await supabase.from('email_accounts').insert({
      email_address: email_address.toLowerCase().trim(),
      display_name, assigned_to: assigned_to || null,
      assigned_by: req.user.id,
      daily_send_limit: daily_send_limit || 150
    }).select('*, assigned_user:users!assigned_to(id,name,email,role)').single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/email-accounts/:id', auth, async (req, res) => {
  try {
    if (!['admin','bd_lead'].includes(req.user.role)) return res.status(403).json({ error: 'Admin only' });
    const { email_address, display_name, assigned_to, daily_send_limit, is_active } = req.body;
    const updates = { updated_at: new Date() };
    if (email_address) updates.email_address = email_address.toLowerCase().trim();
    if (display_name) updates.display_name = display_name;
    if (assigned_to !== undefined) { updates.assigned_to = assigned_to || null; updates.assigned_by = req.user.id; }
    if (daily_send_limit !== undefined) updates.daily_send_limit = daily_send_limit;
    if (is_active !== undefined) updates.is_active = is_active;
    const { data, error } = await supabase.from('email_accounts').update(updates)
      .eq('id', req.params.id).select('*, assigned_user:users!assigned_to(id,name,email,role)').single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/email-accounts/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    await supabase.from('email_accounts').update({ is_active: false, updated_at: new Date() }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get send count for today per email account
app.get('/email-accounts/:id/send-count', auth, async (req, res) => {
  try {
    const todayDate = today();
    const { data, error } = await supabase.from('email_send_log')
      .select('emails_sent').eq('email_account_id', req.params.id).eq('send_date', todayDate).single();
    if (error && error.code !== 'PGRST116') throw error;
    res.json({ emails_sent: data?.emails_sent || 0, date: todayDate });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ══════════════════════════════════════════════════════════════

// ── Export leads as JSON (frontend builds XLSX) ─────────────
app.get('/jobs/export', auth, async (req, res) => {
  try {
    if (!['admin','ra_lead'].includes(req.user.role)) return res.status(403).json({ error: 'RA Lead only' });
    const { from, to, stage } = req.query;
    let query = supabase.from('jobs')
      .select('id,position,stage,location,industry,timezone,freshness,salary_range,job_created_date,job_opened_date,bdm_assigned_name,source,created_at,company:companies(name,website,industry,location),contacts(first_name,last_name,designation,email,phone,linkedin),creator:users!created_by(name)')
      .is('deleted_at', null).order('created_at', { ascending: false });
    if (from) query = query.gte('created_at', from);
    if (to) query = query.lte('created_at', to + 'T23:59:59Z');
    if (stage) query = query.eq('stage', stage);
    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// RESEARCH — save research data for a job
// ══════════════════════════════════════════════════════════════
app.patch('/jobs/:id/research', auth, async (req, res) => {
  try {
    const { research } = req.body;
    if (!research) return res.status(400).json({ error: 'research object required' });
    const { data: job } = await supabase.from('jobs').select('created_by').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (!['admin','ra_lead'].includes(req.user.role) && job.created_by !== req.user.id) {
      return res.status(403).json({ error: 'Only the RA who created this lead can add research' });
    }
    const { data, error } = await supabase.from('jobs')
      .update({ research, updated_at: new Date() }).eq('id', req.params.id).select('id,research').single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// INSIGHTS — RA activity stats
// ══════════════════════════════════════════════════════════════
app.get('/insights/ra/:userId', auth, async (req, res) => {
  try {
    const targetId = req.params.userId;
    if (req.user.role === 'ra' && req.user.id !== targetId) return res.status(403).json({ error: 'Forbidden' });
    const now = new Date();
    const todayStr = now.toISOString().split('T')[0];
    const weekAgo = new Date(now); weekAgo.setDate(weekAgo.getDate() - 7);
    const monthAgo = new Date(now); monthAgo.setDate(monthAgo.getDate() - 30);
    const { data: jobs, error } = await supabase.from('jobs')
      .select('id,stage,freshness,industry,timezone,is_duplicate,created_at,created_date')
      .eq('created_by', targetId).is('deleted_at', null).gte('created_at', monthAgo.toISOString());
    if (error) throw error;
    const all = jobs || [];
    const todayJobs = all.filter(j => j.created_date === todayStr);
    const weekJobs = all.filter(j => new Date(j.created_at) >= weekAgo);
    const last7 = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now); d.setDate(d.getDate() - i);
      const key = d.toISOString().split('T')[0];
      last7[key] = all.filter(j => j.created_date === key).length;
    }
    function normalizeIndustry(raw) {
      if (!raw) return 'Other';
      const r = raw.toLowerCase();
      if (r.includes('engineer') || r.includes('manufactur') || r.includes('machinery') ||
          r.includes('automation') || r.includes('aerospace') || r.includes('defense') ||
          r.includes('construction') || r.includes('civil') || r.includes('mechanical') ||
          r.includes('architecture') || r.includes('industrial') || r.includes('oil') ||
          r.includes('gas') || r.includes('aviation') || r.includes('transportation') ||
          r.includes('logistics') || r.includes('real estate') || r.includes('planning')) return 'Engineering';
      if (r.includes('health') || r.includes('medical') || r.includes('pharma') ||
          r.includes('hospital') || r.includes('wellness') || r.includes('fitness') ||
          r.includes('biotech') || r.includes('dental') || r.includes('clinical')) return 'Healthcare';
      if (r.includes('legal') || r.includes('law') || r.includes('attorney') ||
          r.includes('compliance') || r.includes('litigation')) return 'Legal';
      if (r.includes('account') || r.includes('financ') || r.includes('audit') ||
          r.includes('tax') || r.includes('bookkeep') || r.includes('cpa')) return 'Accounting';
      if (r.includes('manag') || r.includes('consult') || r.includes('staffing') ||
          r.includes('recruit') || r.includes('hr') || r.includes('human resource') ||
          r.includes('executive') || r.includes('leadership') || r.includes('strategy')) return 'Management';
      return 'Other';
    }
    function breakdown(arr, field) {
      const map = {};
      arr.forEach(j => {
        const raw = j[field] || '';
        const v = field === 'industry' ? normalizeIndustry(raw) : (raw || 'Unknown');
        map[v] = (map[v] || 0) + 1;
      });
      return map;
    }
    res.json({
      total_month: all.length, total_week: weekJobs.length, total_today: todayJobs.length,
      duplicates: all.filter(j => j.is_duplicate).length,
      last_7_days: last7, by_industry: breakdown(all,'industry'),
      by_timezone: breakdown(all,'timezone'), by_freshness: breakdown(all,'freshness'),
      by_stage: breakdown(all,'stage')
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// SMART LEAD DISTRIBUTION — RA Team Lead assigns pool to a Manager
// ══════════════════════════════════════════════════════════════

// AI generates ratio from priority text + pool composition
app.post('/distribute/generate-ratio', auth, async (req, res) => {
  try {
    if (!['admin','ra_lead'].includes(req.user.role)) return res.status(403).json({ error: 'RA Lead only' });
    const { priority_text, pool_stats, manager_id } = req.body;

    const { data: manager } = await supabase.from('users').select('id,name').eq('id', manager_id).single();
    const capacity = pool_stats.capacity || 150;

    const prompt = `You are a lead distribution engine for Fute Global LLC, a staffing/recruitment firm.

Pool of unassigned leads available:
- Total: ${pool_stats.total} leads
- Freshness: ${JSON.stringify(pool_stats.by_freshness)}
- Industry: ${JSON.stringify(pool_stats.by_industry)}
- Timezone: ${JSON.stringify(pool_stats.by_timezone)}
- Duplicates in pool: ${pool_stats.duplicates || 0}

Manager: ${manager?.name}
Email sending capacity today: ${capacity} emails

RA Team Lead priority instructions: "${priority_text}"

Based on the instructions and pool composition, generate a distribution plan.
Respond ONLY with valid JSON, no explanation, no markdown:
{
  "total_to_send": <number, max ${Math.min(pool_stats.total, capacity)}>,
  "by_freshness": {"New": <percent 0-100>, "Normal": <percent>, "Old": <percent>},
  "by_industry": {"Engineering": <percent>, "Healthcare": <percent>, "Legal": <percent>, "Accounting": <percent>, "Management": <percent>, "Other": <percent>},
  "by_timezone": {"EST": <percent>, "CST": <percent>, "MST": <percent>, "PST": <percent>},
  "exclude_duplicates": <true/false>,
  "summary": "<2-sentence human-readable summary of what will be sent and why>"
}
Percentages in each group must sum to 100. Prioritise Old leads always unless instructed otherwise.`;

    if (!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY === 'your_anthropic_api_key_here') {
      // Fallback: balanced auto ratio
      return res.json(buildAutoRatio(pool_stats, capacity));
    }

    const aiResp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 400, messages: [{ role: 'user', content: prompt }] })
    });
    const aiData = await aiResp.json();
    const text = aiData.content?.[0]?.text || '';
    const clean = text.replace(/```json|```/g, '').trim();
    const ratio = JSON.parse(clean);
    res.json(ratio);
  } catch (err) {
    // fallback to auto on any error
    const { pool_stats } = req.body;
    res.json(buildAutoRatio(pool_stats, pool_stats?.capacity || 150));
  }
});

function buildAutoRatio(pool_stats, capacity) {
  const total = Math.min(pool_stats?.total || 0, capacity);
  const bf = pool_stats?.by_freshness || {};
  const bi = pool_stats?.by_industry || {};
  const btz = pool_stats?.by_timezone || {};
  // helper: even split of existing keys
  function evenSplit(obj) {
    const keys = Object.keys(obj).filter(k => obj[k] > 0);
    if (!keys.length) return {};
    const base = Math.floor(100 / keys.length);
    const result = {};
    let rem = 100;
    keys.forEach((k, i) => { result[k] = i === keys.length - 1 ? rem : base; rem -= base; });
    return result;
  }
  return {
    total_to_send: total,
    by_freshness: evenSplit(bf),
    by_industry: evenSplit(bi),
    by_timezone: evenSplit(btz),
    exclude_duplicates: false,
    summary: `Auto-balanced distribution of ${total} leads across available categories.`
  };
}

// Execute the distribution — assign leads to manager + email IDs
app.post('/distribute/execute', auth, async (req, res) => {
  try {
    if (!['admin','ra_lead'].includes(req.user.role)) return res.status(403).json({ error: 'RA Lead only' });
    const { manager_id, ratio } = req.body;
    if (!manager_id || !ratio) return res.status(400).json({ error: 'manager_id and ratio required' });

    // Get manager's active email accounts
    const { data: emailAccounts } = await supabase.from('email_accounts')
      .select('id,email_address,display_name,daily_send_limit').eq('assigned_to', manager_id).eq('is_active', true);
    if (!emailAccounts?.length) return res.status(400).json({ error: 'Manager has no active email IDs' });

    // Get today's send counts per email account
    const todayDate = today();
    const { data: sendLogs } = await supabase.from('email_send_log')
      .select('email_account_id,emails_sent').eq('send_date', todayDate);
    const sentToday = {};
    (sendLogs || []).forEach(l => { sentToday[l.email_account_id] = l.emails_sent; });

    // Calculate remaining capacity per email ID
    const accounts = emailAccounts.map(a => ({
      ...a,
      remaining: (a.daily_send_limit || 150) - (sentToday[a.id] || 0)
    })).filter(a => a.remaining > 0);
    if (!accounts.length) return res.status(400).json({ error: 'All email IDs have reached daily limit' });

    const totalCapacity = accounts.reduce((s, a) => s + a.remaining, 0);
    const totalToSend = Math.min(ratio.total_to_send || 50, totalCapacity);

    // Fetch unassigned leads from pool applying ratio filters
    let query = supabase.from('jobs').select('id,position,freshness,industry,timezone,is_duplicate')
      .is('deleted_at', null).eq('stage', 'Unassigned').is('assigned_to_bd', null);

    if (ratio.exclude_duplicates) query = query.eq('is_duplicate', false);

    const { data: pool } = await query;
    if (!pool?.length) return res.status(400).json({ error: 'No unassigned leads in pool' });

    // Score and select leads based on ratio
    // Freshness priority: Old first always
    const freshnessOrder = { 'Old': 0, 'Normal': 1, 'New': 2, '': 3 };
    const sorted = [...pool].sort((a, b) => (freshnessOrder[a.freshness] ?? 3) - (freshnessOrder[b.freshness] ?? 3));

    // Select leads respecting ratio targets (best-effort)
    const byF = ratio.by_freshness || {};
    const byI = ratio.by_industry || {};
    const byTz = ratio.by_timezone || {};

    // Build target counts
    const targets = { freshness: {}, industry: {}, timezone: {} };
    Object.keys(byF).forEach(k => { targets.freshness[k] = Math.round((byF[k] / 100) * totalToSend); });
    Object.keys(byI).forEach(k => { targets.industry[k] = Math.round((byI[k] / 100) * totalToSend); });
    Object.keys(byTz).forEach(k => { targets.timezone[k] = Math.round((byTz[k] / 100) * totalToSend); });

    // Greedy selection: pick up to totalToSend leads, preferring those matching targets
    const selected = [];
    const used = { freshness: {}, industry: {}, timezone: {} };
    for (const job of sorted) {
      if (selected.length >= totalToSend) break;
      selected.push(job);
      used.freshness[job.freshness] = (used.freshness[job.freshness] || 0) + 1;
      used.industry[job.industry] = (used.industry[job.industry] || 0) + 1;
      used.timezone[job.timezone] = (used.timezone[job.timezone] || 0) + 1;
    }

    if (!selected.length) return res.status(400).json({ error: 'No leads matched distribution criteria' });

    // Round-robin distribute selected leads across email IDs
    const assignedLeads = [];
    let acIdx = 0;
    const now = new Date();

    for (const job of selected) {
      // Find next account with remaining capacity
      let tries = 0;
      while (accounts[acIdx % accounts.length].remaining <= 0 && tries < accounts.length) {
        acIdx++; tries++;
      }
      const account = accounts[acIdx % accounts.length];
      account.remaining--;
      acIdx++;

      // Update job: assign to manager + email account
      await supabase.from('jobs').update({
        assigned_to_bd: manager_id,
        sending_email_id: account.id,
        stage: 'Assigned',
        assigned_at: now,
        updated_at: now
      }).eq('id', job.id);

      assignedLeads.push({ job_id: job.id, email_account_id: account.id });
    }

    // Update send log counts
    const countPerAccount = {};
    assignedLeads.forEach(l => { countPerAccount[l.email_account_id] = (countPerAccount[l.email_account_id] || 0) + 1; });
    for (const [acId, cnt] of Object.entries(countPerAccount)) {
      await supabase.from('email_send_log').upsert({
        email_account_id: acId, send_date: todayDate,
        emails_sent: (sentToday[acId] || 0) + cnt
      }, { onConflict: 'email_account_id,send_date' });
    }

    // Create follow-up rows for all assigned jobs
    const jobIds = selected.map(j => j.id);
    const outreachDateStr = now.toISOString().split('T')[0];

    // Look up this manager's personal FU day settings (fallback: 3 and 7)
    const { data: bdSettings } = await supabase.from('app_settings')
      .select('key,value')
      .in('key', [`u_${manager_id}_fu1_day`, `u_${manager_id}_fu2_day`]);
    const bdSettingsMap = {};
    (bdSettings || []).forEach(r => { bdSettingsMap[r.key] = r.value; });
    const fu1Day = parseInt(bdSettingsMap[`u_${manager_id}_fu1_day`] || '3', 10);
    const fu2Day = parseInt(bdSettingsMap[`u_${manager_id}_fu2_day`] || '7', 10);

    const fu1Date = new Date(now); fu1Date.setDate(fu1Date.getDate() + fu1Day);
    const fu2Date = new Date(now); fu2Date.setDate(fu2Date.getDate() + fu2Day);
    const fu1Str = fu1Date.toISOString().split('T')[0];
    const fu2Str = fu2Date.toISOString().split('T')[0];

    // For each assigned job, find its primary contact and create follow-up rows
    const { data: assignedJobs } = await supabase.from('jobs')
      .select('id,sending_email_id,contacts(id,email)')
      .in('id', jobIds);
    const followUpRows = [];
    for (const aj of (assignedJobs || [])) {
      const contacts = (aj.contacts || []).filter(c => c.email);
      for (const c of contacts) {
        followUpRows.push({
          job_id: aj.id,
          contact_id: c.id,
          email_account_id: aj.sending_email_id,
          outreach_sent_at: outreachDateStr,
          followup1_due_date: fu1Str,
          followup2_due_date: fu2Str,
          status: 'active'
        });
      }
    }
    if (followUpRows.length) {
      await supabase.from('follow_ups').insert(followUpRows);
    }

    // Generate AI emails for all assigned jobs
    // Fire and forget — don't wait for email generation to respond
    fetch(`${req.protocol}://${req.get('host')}/emails/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': req.headers.authorization },
      body: JSON.stringify({ job_ids: jobIds })
    }).catch(e => console.error('Email generation error:', e.message));

    // Build distribution summary for dashboard
    const summary = {
      total_assigned: selected.length,
      manager_id,
      by_freshness: used.freshness,
      by_industry: used.industry,
      by_timezone: used.timezone,
      email_accounts_used: Object.keys(countPerAccount).length,
      ratio_summary: ratio.summary || '',
      assigned_at: now.toISOString()
    };

    // Store summary for BD dashboard
    await supabase.from('jobs').update({
      updated_at: now
    }).in('id', jobIds); // already updated above, just ensure consistency

    res.json({ success: true, ...summary });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get pool stats for a distribution session
app.get('/distribute/pool-stats', auth, async (req, res) => {
  try {
    if (!['admin','ra_lead'].includes(req.user.role)) return res.status(403).json({ error: 'RA Lead only' });
    const { data: pool } = await supabase.from('jobs').select('id,freshness,industry,timezone,is_duplicate')
      .is('deleted_at', null).eq('stage', 'Unassigned').is('assigned_to_bd', null);

    const stats = { total: pool?.length || 0, by_freshness: {}, by_industry: {}, by_timezone: {}, duplicates: 0 };
    (pool || []).forEach(j => {
      stats.by_freshness[j.freshness || 'Unknown'] = (stats.by_freshness[j.freshness || 'Unknown'] || 0) + 1;
      stats.by_industry[j.industry || 'Unknown'] = (stats.by_industry[j.industry || 'Unknown'] || 0) + 1;
      stats.by_timezone[j.timezone || 'Unknown'] = (stats.by_timezone[j.timezone || 'Unknown'] || 0) + 1;
      if (j.is_duplicate) stats.duplicates++;
    });
    res.json(stats);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get today's assignment summary for a manager (BD dashboard)
app.get('/distribute/today-summary', auth, async (req, res) => {
  try {
    const targetId = req.query.manager_id || req.user.id;
    const todayDate = today();
    const { data: jobs } = await supabase.from('jobs').select('id,freshness,industry,timezone,assigned_at')
      .eq('assigned_to_bd', targetId).gte('assigned_at', todayDate + 'T00:00:00Z');
    function normInd(raw) {
      if (!raw) return 'Other';
      const r = raw.toLowerCase();
      if (r.includes('engineer')||r.includes('manufactur')||r.includes('construction')||r.includes('civil')||r.includes('mechanical')||r.includes('oil')||r.includes('gas')||r.includes('aerospace')||r.includes('aviation')||r.includes('transportation')||r.includes('logistics')||r.includes('real estate')||r.includes('architecture')||r.includes('industrial')||r.includes('defense')||r.includes('machinery')||r.includes('automation')) return 'Engineering';
      if (r.includes('health')||r.includes('medical')||r.includes('pharma')||r.includes('hospital')||r.includes('wellness')||r.includes('fitness')||r.includes('biotech')||r.includes('dental')||r.includes('clinical')) return 'Healthcare';
      if (r.includes('legal')||r.includes('law')||r.includes('attorney')||r.includes('compliance')||r.includes('litigation')) return 'Legal';
      if (r.includes('account')||r.includes('financ')||r.includes('audit')||r.includes('tax')||r.includes('bookkeep')||r.includes('cpa')) return 'Accounting';
      if (r.includes('manag')||r.includes('consult')||r.includes('staffing')||r.includes('recruit')||r.includes('hr')||r.includes('human resource')||r.includes('executive')||r.includes('strategy')) return 'Management';
      return 'Other';
    }
    const summary = { total: jobs?.length || 0, by_freshness: {}, by_industry: {}, by_timezone: {} };
    (jobs || []).forEach(j => {
      summary.by_freshness[j.freshness || 'Unknown'] = (summary.by_freshness[j.freshness || 'Unknown'] || 0) + 1;
      const ind = normInd(j.industry || '');
      summary.by_industry[ind] = (summary.by_industry[ind] || 0) + 1;
      summary.by_timezone[j.timezone || 'Unknown'] = (summary.by_timezone[j.timezone || 'Unknown'] || 0) + 1;
    });
    res.json(summary);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// BULK ASSIGN — RA Team Lead assigns multiple jobs to a BD
// ══════════════════════════════════════════════════════════════
app.post('/jobs/bulk-assign', auth, async (req, res) => {
  try {
    if (!['admin','ra_lead'].includes(req.user.role)) return res.status(403).json({ error: 'ra_lead or admin only' });
    const { job_ids, assigned_to_bd } = req.body;
    if (!Array.isArray(job_ids) || !job_ids.length) return res.status(400).json({ error: 'job_ids array required' });
    if (!assigned_to_bd) return res.status(400).json({ error: 'assigned_to_bd required' });
    const { data: bd, error: bdErr } = await supabase.from('users').select('id,name,role').eq('id', assigned_to_bd).single();
    if (bdErr || !bd) return res.status(400).json({ error: 'BD user not found' });
    const now = new Date();
    const { error } = await supabase.from('jobs')
      .update({ assigned_to_bd, assigned_at: now, stage: 'Assigned', updated_at: now })
      .in('id', job_ids);
    if (error) throw error;
    for (const jid of job_ids) {
      await logActivity(jid, null, req.user.id, 'bulk_assigned', `Bulk assigned to BD: ${bd.name}`, null, { assigned_to_bd, bd_name: bd.name });
    }
    res.json({ success: true, assigned: job_ids.length, bd_name: bd.name });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Duplicate check endpoint ────────────────────────────────
app.post('/jobs/check-duplicates', auth, async (req, res) => {
  try {
    const { emails } = req.body;
    if (!Array.isArray(emails) || !emails.length) return res.json({ duplicates: [] });
    const { data, error } = await supabase
      .from('contacts')
      .select('email, job_id, job:jobs(id,position,company_id,company:companies(name))')
      .in('email', emails.map(e => e.toLowerCase().trim()))
      .not('email', 'is', null);
    if (error) throw error;
    res.json({ duplicates: data || [] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// CONTACTS  (children of jobs)
// ══════════════════════════════════════════════════════════════
async function canTouchJob(req, job_id) {
  if (req.user.role === 'admin') return true;
  const { data } = await supabase.from('jobs').select('created_by,assigned_to').eq('id', job_id).single();
  if (!data) return false;
  return data.created_by === req.user.id || data.assigned_to === req.user.id;
}

app.get('/jobs/:job_id/contacts', auth, async (req, res) => {
  try {
    if (!(await canTouchJob(req, req.params.job_id))) return res.status(403).json({ error: 'Forbidden' });
    const { data, error } = await supabase.from('contacts').select('*').eq('job_id', req.params.job_id).order('is_primary', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/contacts', auth, async (req, res) => {
  try {
    const { job_id, first_name, last_name, designation, email, phone, linkedin, is_primary } = req.body;
    if (!job_id || !first_name) return res.status(400).json({ error: 'job_id and first_name required' });
    if (!(await canTouchJob(req, job_id))) return res.status(403).json({ error: 'Forbidden' });
    const { data, error } = await supabase.from('contacts').insert({
      job_id, first_name, last_name: last_name || '', designation, email, phone, linkedin,
      is_primary: !!is_primary
    }).select().single();
    if (error) throw error;
    await logActivity(job_id, data.id, req.user.id, 'contact_added', `Contact added: ${first_name} ${last_name || ''}`.trim(), null, null);
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/contacts/:id', auth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('contacts').select('job_id').eq('id', req.params.id).single();
    if (!existing) return res.status(404).json({ error: 'Not found' });
    if (!(await canTouchJob(req, existing.job_id))) return res.status(403).json({ error: 'Forbidden' });
    const fields = ['first_name','last_name','designation','email','phone','linkedin','is_primary','email_status','ooo_until'];
    const updates = { updated_at: new Date() };
    fields.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });
    const { data, error } = await supabase.from('contacts').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/contacts/:id', auth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('contacts').select('job_id').eq('id', req.params.id).single();
    if (!existing) return res.status(404).json({ error: 'Not found' });
    if (!(await canTouchJob(req, existing.job_id))) return res.status(403).json({ error: 'Forbidden' });
    await supabase.from('contacts').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ── Update contact email status (BD action) ──────────────
app.patch('/contacts/:id/email-status', auth, async (req, res) => {
  try {
    const canChange = ['admin','bd','bd_lead'].includes(req.user.role);
    if (!canChange) return res.status(403).json({ error: 'BD role required' });
    const { email_status, ooo_until } = req.body;
    const allowed = ['valid','invalid','deactivated','out_of_office'];
    if (!allowed.includes(email_status)) return res.status(400).json({ error: 'Invalid status' });

    const updates = { email_status, updated_at: new Date() };
    if (email_status === 'out_of_office' && ooo_until) updates.ooo_until = ooo_until;
    if (email_status !== 'out_of_office') updates.ooo_until = null;

    const { data: contact, error } = await supabase.from('contacts')
      .update(updates).eq('id', req.params.id).select('*, job:jobs(id,position,company:companies(name))').single();
    if (error) throw error;

    // Create OOO reminder automatically
    if (email_status === 'out_of_office' && ooo_until) {
      const contactName = `${contact.first_name || ''} ${contact.last_name || ''}`.trim();
      const companyName = contact.job?.company?.name || '';
      const position = contact.job?.position || '';
      await supabase.from('reminders').insert({
        job_id: contact.job_id,
        user_id: req.user.id,
        contact_name: contactName,
        company_name: companyName,
        email: contact.email,
        return_date: ooo_until,
        reminder_time: '09:00',
        note: `${contactName} (${companyName} — ${position}) is back from Out of Office. Compose and send a follow-up email.`,
        status: 'pending',
        reminder_type: 'ooo_return',
        contact_id: contact.id
      });
      await logActivity(contact.job_id, contact.id, req.user.id, 'ooo_set',
        `${contactName} marked OOO until ${ooo_until}`, null, { ooo_until });
    }

    res.json(contact);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// EMAILS
// ══════════════════════════════════════════════════════════════
app.get('/emails', auth, async (req, res) => {
  try {
    const { status } = req.query;
    let query = supabase.from('emails')
      .select(`*, contact:contacts(id,first_name,last_name,email,designation), job:jobs(id,position,company_id,company:companies(name,industry,location)), sender:users!sent_by(id,name,email)`)
      .order('created_at', { ascending: false });
    // scoping: bd sees only their own; ra_lead/admin see all
    if (!['admin','ra_lead'].includes(req.user.role)) query = query.eq('sent_by', req.user.id);
    if (status) query = query.eq('status', status);
    const { data, error } = await query;
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Pending email count for BD dashboard badge
app.get('/emails/pending-count', auth, async (req, res) => {
  try {
    const { count, error } = await supabase.from('emails')
      .select('id', { count: 'exact', head: true })
      .eq('sent_by', req.user.id).eq('status', 'pending');
    if (error) throw error;
    res.json({ count: count || 0 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/emails', auth, async (req, res) => {
  try {
    const { contact_id, job_id, to_email, subject, body, platform } = req.body;
    if (!to_email) return res.status(400).json({ error: 'to_email required' });
    const { data, error } = await supabase.from('emails').insert({
      contact_id: contact_id || null, job_id: job_id || null, to_email, subject, body,
      platform: platform || 'Gmail', sent_by: req.user.id, status: 'sent', sent_at: today()
    }).select().single();
    if (error) throw error;
    if (contact_id) {
      await supabase.from('contacts').update({ email_sent_at: today(), email_platform: platform || 'Gmail', updated_at: new Date() }).eq('id', contact_id);
    }
    if (job_id) {
      await logActivity(job_id, contact_id || null, req.user.id, 'email_sent', `Email sent via ${platform || 'Gmail'}: ${subject || ''}`, null, null);
    }
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ── Generate emails for a list of jobs (called after bulk assign or BD import) ──
app.post('/emails/generate', auth, async (req, res) => {
  try {
    if (!['admin','ra_lead','bd','bd_lead'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Not allowed' });
    }
    const { job_ids } = req.body;
    if (!Array.isArray(job_ids) || !job_ids.length) return res.status(400).json({ error: 'job_ids required' });

    // Fetch jobs with contacts and company info
    const { data: jobs, error: jErr } = await supabase.from('jobs')
      .select('id, position, assigned_to_bd, company:companies(name,industry,location), contacts(*)')
      .in('id', job_ids);
    if (jErr) throw jErr;

    // Determine the BD sender for each job
    const bdIds = [...new Set(jobs.map(j => j.assigned_to_bd).filter(Boolean))];
    const bdIds2 = bdIds.length ? bdIds : [req.user.id];
    const { data: bdUsers } = await supabase.from('users').select('id,name,email').in('id', bdIds2);
    const bdMap = {};
    (bdUsers || []).forEach(u => { bdMap[u.id] = u; });

    const emailsToInsert = [];
    const generated = [];
    const failed = [];

    for (const job of jobs) {
      const bd = bdMap[job.assigned_to_bd] || bdMap[req.user.id] || { id: req.user.id, name: req.user.name, email: req.user.email };
      const contacts = (job.contacts || []).filter(c => c.email);
      for (const contact of contacts) {
        try {
          let subject, body;
          if (process.env.ANTHROPIC_API_KEY && process.env.ANTHROPIC_API_KEY !== 'your_anthropic_api_key_here') {
            const prompt = `Write a hyper-personalized cold outreach email from ${bd.name} at Fute Global LLC (a staffing/recruitment firm) to ${contact.first_name} ${contact.last_name || ''}, ${contact.designation || 'Hiring Manager'} at ${job.company?.name || ''} (${job.company?.industry || ''}, ${job.company?.location || ''}).\n\nThey are hiring for: ${job.position}\n\nEmail purpose: Introduce Fute Global as a staffing partner who can help fill this role with top candidates.\n\nInstructions: 3 short paragraphs, warm but professional tone, no fluff, end with a clear and specific call to action. Make it feel personal and relevant to their role.\n\nFormat strictly as:\nSubject: [subject line]\n\n[email body]`;
            const aiResp = await fetch('https://api.anthropic.com/v1/messages', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
              body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 500, messages: [{ role: 'user', content: prompt }] })
            });
            const aiData = await aiResp.json();
            const text = aiData.content?.[0]?.text || '';
            const subjectMatch = text.match(/Subject:\s*(.+)/i);
            subject = subjectMatch ? subjectMatch[1].trim() : `Staffing Partnership — ${job.company?.name}`;
            body = text.replace(/^Subject:.+\n*/im, '').trim();
          } else {
            subject = `Staffing Partnership — ${job.company?.name || job.position}`;
            body = `Hi ${contact.first_name},\n\nI came across ${job.company?.name || 'your company'} and noticed you're hiring for ${job.position}. At Fute Global, we specialize in placing top-tier talent for roles exactly like this.\n\nWe've helped similar companies reduce time-to-hire significantly. I'd love to share how we can support your hiring goals.\n\nWould you be open to a quick 15-minute call this week?\n\nBest regards,\n${bd.name}\nFute Global LLC`;
          }
          emailsToInsert.push({
            contact_id: contact.id, job_id: job.id, to_email: contact.email,
            subject, body, platform: 'Outlook',
            sent_by: bd.id, from_email: bd.email,
            status: 'pending'
          });
          generated.push({ contact_id: contact.id, email: contact.email });
        } catch(e) {
          failed.push({ contact_id: contact.id, email: contact.email, error: e.message });
        }
      }
    }

    if (emailsToInsert.length) {
      const { error: insErr } = await supabase.from('emails').insert(emailsToInsert);
      if (insErr) throw insErr;
    }

    res.json({ generated: generated.length, failed: failed.length, failDetails: failed });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Queue all pending emails for BD (mark as queued = ready to send) ──
app.post('/emails/queue-all', auth, async (req, res) => {
  try {
    const { error } = await supabase.from('emails')
      .update({ status: 'queued', updated_at: new Date() })
      .eq('sent_by', req.user.id).eq('status', 'pending');
    if (error) throw error;
    // update email_sent_at on contacts that have pending emails
    const { data: queued } = await supabase.from('emails')
      .select('contact_id, job_id').eq('sent_by', req.user.id).eq('status', 'queued');
    const contactIds = [...new Set((queued || []).map(e => e.contact_id).filter(Boolean))];
    if (contactIds.length) {
      await supabase.from('contacts').update({ email_sent_at: today(), updated_at: new Date() }).in('id', contactIds);
    }
    const jobIds = [...new Set((queued || []).map(e => e.job_id).filter(Boolean))];
    for (const jid of jobIds) {
      await logActivity(jid, null, req.user.id, 'emails_queued', 'Emails queued for sending', null, null);
    }
    res.json({ success: true, queued: contactIds.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Update single email body (BD preview edit) ──
app.patch('/emails/:id', auth, async (req, res) => {
  try {
    const { subject, body } = req.body;
    const updates = { updated_at: new Date() };
    if (subject !== undefined) updates.subject = subject;
    if (body !== undefined) updates.body = body;
    const { data, error } = await supabase.from('emails').update(updates)
      .eq('id', req.params.id).eq('sent_by', req.user.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// REMINDERS
// ══════════════════════════════════════════════════════════════
app.get('/reminders', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('reminders')
      .select(`*, job:jobs(id,position,stage,company_id,company:companies(name)), contact:contacts(id,first_name,last_name,email)`)
      .eq('user_id', req.user.id).order('return_date');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/reminders', auth, async (req, res) => {
  try {
    const { job_id, contact_name, company_name, email, return_date, reminder_time, note, contact_id, reminder_type } = req.body;
    if (!return_date) return res.status(400).json({ error: 'Return date required' });
    const { data, error } = await supabase.from('reminders').insert({
      job_id: job_id || null, user_id: req.user.id, contact_name, company_name, email,
      return_date, reminder_time: reminder_time || '09:00', note, status: 'pending',
      contact_id: contact_id || null, reminder_type: reminder_type || null
    }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/reminders/:id', auth, async (req, res) => {
  try {
    const { status, return_date, reminder_time, note } = req.body;
    const updates = { updated_at: new Date() };
    if (status) updates.status = status;
    if (return_date) updates.return_date = return_date;
    if (reminder_time) updates.reminder_time = reminder_time;
    if (note !== undefined) updates.note = note;
    const { data, error } = await supabase.from('reminders').update(updates).eq('id', req.params.id).eq('user_id', req.user.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/reminders/:id', auth, async (req, res) => {
  try {
    await supabase.from('reminders').delete().eq('id', req.params.id).eq('user_id', req.user.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// STATS  (job-based; admin = team-wide, bd/ra = self-scoped)
// ══════════════════════════════════════════════════════════════
app.get('/stats', auth, async (req, res) => {
  try {
    const { period } = req.query;
    const now = new Date();
    let dateFrom;
    if (period === 'daily') dateFrom = today();
    else if (period === 'weekly') { const w = new Date(now); w.setDate(w.getDate()-7); dateFrom = w.toISOString().split('T')[0]; }
    else if (period === 'quarterly') { const q = new Date(now); q.setMonth(q.getMonth()-3); dateFrom = q.toISOString().split('T')[0]; }
    else { const m = new Date(now.getFullYear(), now.getMonth(), 1); dateFrom = m.toISOString().split('T')[0]; }

    let query = supabase.from('jobs').select('id,stage,created_by,assigned_to,created_date,contacts(id,email_sent_at)')
      .is('deleted_at', null).gte('created_date', dateFrom);
    if (req.user.role !== 'admin') {
      query = query.or(`created_by.eq.${req.user.id},assigned_to.eq.${req.user.id}`);
    }
    const { data, error } = await query;
    if (error) throw error;

    const total = data.length;
    const emailed = data.filter(j => (j.contacts || []).some(c => c.email_sent_at)).length;
    const positive = data.filter(j => j.stage === 'Positive' || j.stage === 'Connected').length;
    const negative = data.filter(j => j.stage === 'Negative').length;
    const pending = data.filter(j => j.stage === 'Active').length;
    const responseRate = total ? Math.round(emailed/total*100) : 0;
    const byStage = {};
    data.forEach(j => { byStage[j.stage] = (byStage[j.stage] || 0) + 1; });

    res.json({ total, emailed, positive, negative, pending, responseRate, byStage, period: period || 'monthly', dateFrom });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// ACTIVITY LOG (per job)
// ══════════════════════════════════════════════════════════════
app.get('/jobs/:job_id/activity', auth, async (req, res) => {
  try {
    if (!(await canTouchJob(req, req.params.job_id))) return res.status(403).json({ error: 'Forbidden' });
    const { data, error } = await supabase.from('activity_log')
      .select(`*, user:users(id,name,employee_id)`)
      .eq('job_id', req.params.job_id).order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// AI EMAIL GENERATION  (unchanged behaviour; updated field names)
// ══════════════════════════════════════════════════════════════
app.post('/ai/generate-email', auth, async (req, res) => {
  try {
    const { lead, contact, company, template } = req.body;
    const c = contact || lead || {};
    const vars = {
      fn: c.first_name, ln: c.last_name, company: company?.name, ind: company?.industry,
      pos: c.position || req.body.position, desig: c.designation, loc: company?.location, sender: req.user.name
    };
    const fill = (s) => (s || '').replace(/{{(\w+)}}/g, (m, k) => vars[k] || m);

    if (!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY === 'your_anthropic_api_key_here') {
      return res.json({
        subject: fill(template?.subject || 'Opportunity at {{company}}'),
        body: fill(template?.body || 'Hi {{fn}},')
      });
    }

    const prompt = `Write a hyper-personalized cold outreach email for a business development executive at Fute Global LLC (a staffing/recruitment firm).\n\nContact: ${vars.fn} ${vars.ln || ''}, ${vars.desig || ''} at ${vars.company} (${vars.ind || ''}, ${vars.loc || ''})\nPosition they are hiring for: ${vars.pos || ''}\n\nWrite a subject line and email body (3 short paragraphs). Tone: professional but warm, direct, no fluff.\nFormat:\nSubject: [subject line]\n\n[email body]`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 600, messages: [{ role: 'user', content: prompt }] })
    });
    const aiData = await response.json();
    const text = aiData.content?.[0]?.text || '';
    const subjectMatch = text.match(/Subject:\s*(.+)/i);
    const subject = subjectMatch ? subjectMatch[1].trim() : `Opportunity at ${vars.company}`;
    const body = text.replace(/^Subject:.+\n*/im, '').trim();
    res.json({ subject, body });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// APP SETTINGS  (admin-controlled key/value store)
// ══════════════════════════════════════════════════════════════
app.get('/app-settings', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('app_settings').select('key,value');
    if (error) throw error;
    const settings = {};
    (data || []).forEach(r => { settings[r.key] = r.value; });
    res.json(settings);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/app-settings', auth, async (req, res) => {
  try {
    if (!['admin','ra_lead'].includes(req.user.role)) return res.status(403).json({ error: 'Admin or RA Lead only' });
    const { key, value } = req.body;
    if (!key || value === undefined) return res.status(400).json({ error: 'key and value required' });
    const { error } = await supabase.from('app_settings')
      .upsert({ key, value, updated_at: new Date() }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true, key, value });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// FOLLOW-UPS
// ══════════════════════════════════════════════════════════════
app.get('/follow-ups', auth, async (req, res) => {
  try {
    let query = supabase.from('follow_ups')
      .select(`*, contact:contacts(id,first_name,last_name,email,designation), job:jobs(id,position,stage,company:companies(name))`)
      .order('followup1_due_date', { ascending: true });
    // BD sees only their own jobs; admin/ra_lead/bd_lead see all
    if (req.user.role === 'bd') {
      // filter via job assigned_to_bd
      const { data: myJobs } = await supabase.from('jobs').select('id').eq('assigned_to_bd', req.user.id).is('deleted_at', null);
      const myJobIds = (myJobs || []).map(j => j.id);
      if (!myJobIds.length) return res.json([]);
      query = query.in('job_id', myJobIds);
    }
    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// MICROSOFT OAUTH — Email sending
// ══════════════════════════════════════════════════════════════

const MS_TENANT   = process.env.MICROSOFT_TENANT_ID;
const MS_CLIENT   = process.env.MICROSOFT_CLIENT_ID;
const MS_SECRET   = process.env.MICROSOFT_CLIENT_SECRET;
const MS_REDIRECT = 'https://fute-lms-backend.onrender.com/auth/microsoft/callback';
const MS_SCOPES   = 'Mail.Send offline_access User.Read';

// Step 1 — redirect admin to Microsoft consent page
// Browser redirect can't send Authorization header — accept token via query param
app.get('/auth/microsoft/connect', async (req, res) => {
  try {
    const token = req.query.token || (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return res.status(401).send('Unauthorized');
    let reqUser;
    try { reqUser = jwt.verify(token, process.env.JWT_SECRET); } catch { return res.status(401).send('Invalid token'); }
    if (!['admin','bd_lead'].includes(reqUser.role)) return res.status(403).send('Admin only');
    const { accountId } = req.query;
    if (!accountId) return res.status(400).send('accountId required');
    const state = Buffer.from(JSON.stringify({ accountId, userId: reqUser.id })).toString('base64');
    const url = `https://login.microsoftonline.com/${MS_TENANT}/oauth2/v2.0/authorize`
      + `?client_id=${MS_CLIENT}`
      + `&response_type=code`
      + `&redirect_uri=${encodeURIComponent(MS_REDIRECT)}`
      + `&scope=${encodeURIComponent(MS_SCOPES)}`
      + `&state=${encodeURIComponent(state)}`
      + `&prompt=select_account`;
    res.redirect(url);
  } catch (err) { res.status(500).send(err.message); }
});

// Step 2 — Microsoft redirects back with code
app.get('/auth/microsoft/callback', async (req, res) => {
  try {
    const { code, state, error: msError } = req.query;
    if (msError) return res.send(`<script>window.opener&&window.opener.postMessage({type:'ms_oauth_error',error:'${msError}'},'*');window.close();</script>`);
    if (!code || !state) return res.status(400).send('Missing code or state');

    const { accountId } = JSON.parse(Buffer.from(decodeURIComponent(state), 'base64').toString());

    // Exchange code for tokens
    const tokenRes = await fetch(`https://login.microsoftonline.com/${MS_TENANT}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: MS_CLIENT,
        client_secret: MS_SECRET,
        code,
        redirect_uri: MS_REDIRECT,
        grant_type: 'authorization_code',
        scope: MS_SCOPES
      })
    });
    const tokens = await tokenRes.json();
    if (tokens.error) return res.send(`<script>window.opener&&window.opener.postMessage({type:'ms_oauth_error',error:'${tokens.error_description}'},'*');window.close();</script>`);

    const expiresAt = new Date(Date.now() + tokens.expires_in * 1000).toISOString();

    // Get the email address from Microsoft
    const profileRes = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const profile = await profileRes.json();
    const emailAddress = profile.mail || profile.userPrincipalName || '';

    // Store tokens
    await supabase.from('microsoft_tokens').upsert({
      email_account_id: accountId,
      email_address: emailAddress,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_at: expiresAt,
      updated_at: new Date()
    }, { onConflict: 'email_account_id' });

    // Mark email account as microsoft platform
    await supabase.from('email_accounts').update({ platform: 'Microsoft', updated_at: new Date() }).eq('id', accountId);

    res.send(`<script>window.opener&&window.opener.postMessage({type:'ms_oauth_success',accountId:'${accountId}',email:'${emailAddress}'},'*');window.close();</script>`);
  } catch (err) {
    console.error('MS OAuth callback error:', err.message);
    res.send(`<script>window.opener&&window.opener.postMessage({type:'ms_oauth_error',error:'${err.message}'},'*');window.close();</script>`);
  }
});

// Helper — get a valid access token (refresh if expired)
async function getMicrosoftToken(emailAccountId) {
  const { data: tokenRow, error } = await supabase.from('microsoft_tokens')
    .select('*').eq('email_account_id', emailAccountId).single();
  if (error || !tokenRow) throw new Error('No Microsoft token found for this account. Please reconnect.');

  const now = new Date();
  const expiresAt = new Date(tokenRow.expires_at);
  const bufferMs = 5 * 60 * 1000; // refresh 5 min before expiry

  if (expiresAt.getTime() - now.getTime() > bufferMs) {
    return tokenRow.access_token; // still valid
  }

  // Refresh the token
  const refreshRes = await fetch(`https://login.microsoftonline.com/${MS_TENANT}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: MS_CLIENT,
      client_secret: MS_SECRET,
      refresh_token: tokenRow.refresh_token,
      grant_type: 'refresh_token',
      scope: MS_SCOPES
    })
  });
  const refreshed = await refreshRes.json();
  if (refreshed.error) throw new Error('Token refresh failed: ' + refreshed.error_description);

  const newExpiresAt = new Date(Date.now() + refreshed.expires_in * 1000).toISOString();
  await supabase.from('microsoft_tokens').update({
    access_token: refreshed.access_token,
    refresh_token: refreshed.refresh_token || tokenRow.refresh_token,
    expires_at: newExpiresAt,
    updated_at: new Date()
  }).eq('email_account_id', emailAccountId);

  return refreshed.access_token;
}

// Send email via Microsoft Graph
app.post('/emails/send-microsoft', auth, async (req, res) => {
  try {
    const { email_account_id, to_email, subject, body, email_id } = req.body;
    if (!email_account_id || !to_email || !subject || !body) {
      return res.status(400).json({ error: 'email_account_id, to_email, subject, body required' });
    }

    const accessToken = await getMicrosoftToken(email_account_id);

    const message = {
      message: {
        subject,
        body: { contentType: 'Text', content: body },
        toRecipients: [{ emailAddress: { address: to_email } }]
      },
      saveToSentItems: true
    };

    const sendRes = await fetch('https://graph.microsoft.com/v1.0/me/sendMail', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(message)
    });

    if (!sendRes.ok) {
      const errData = await sendRes.json().catch(() => ({}));
      throw new Error(errData?.error?.message || `Send failed: ${sendRes.status}`);
    }

    // Mark email as sent if email_id provided
    if (email_id) {
      await supabase.from('emails').update({
        status: 'sent', sent_at: today(), updated_at: new Date()
      }).eq('id', email_id);
    }

    // Update send log
    const todayDate = today();
    const { data: acData } = await supabase.from('email_accounts').select('id').eq('id', email_account_id).single();
    if (acData) {
      const { data: logRow } = await supabase.from('email_send_log')
        .select('emails_sent').eq('email_account_id', email_account_id).eq('send_date', todayDate).single();
      await supabase.from('email_send_log').upsert({
        email_account_id,
        send_date: todayDate,
        emails_sent: (logRow?.emails_sent || 0) + 1
      }, { onConflict: 'email_account_id,send_date' });
    }

    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Check connection status for an email account
app.get('/auth/microsoft/status/:accountId', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('microsoft_tokens')
      .select('email_address,expires_at').eq('email_account_id', req.params.accountId).single();
    if (!data) return res.json({ connected: false });
    const expired = new Date(data.expires_at) < new Date();
    res.json({ connected: true, email_address: data.email_address, expired });
  } catch { res.json({ connected: false }); }
});

// Disconnect Microsoft account
app.delete('/auth/microsoft/:accountId', auth, async (req, res) => {
  try {
    if (!['admin','bd_lead'].includes(req.user.role)) return res.status(403).json({ error: 'Admin only' });
    await supabase.from('microsoft_tokens').delete().eq('email_account_id', req.params.accountId);
    await supabase.from('email_accounts').update({ platform: 'Gmail', updated_at: new Date() }).eq('id', req.params.accountId);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Per-user outreach plan settings ──────────────────────────
app.get('/outreach-plan', auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const keys = [
      `u_${uid}_fu1_day`, `u_${uid}_fu2_day`,
      `u_${uid}_tmpl_o1_subject`, `u_${uid}_tmpl_o1_body`,
      `u_${uid}_tmpl_fu1_subject`, `u_${uid}_tmpl_fu1_body`,
      `u_${uid}_tmpl_fu2_subject`, `u_${uid}_tmpl_fu2_body`
    ];
    const { data } = await supabase.from('app_settings').select('key,value').in('key', keys);
    const plan = {};
    (data || []).forEach(r => { plan[r.key.replace(`u_${uid}_`, '')] = r.value; });
    res.json(plan);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/outreach-plan', auth, async (req, res) => {
  try {
    if (!['bd','bd_lead','admin'].includes(req.user.role)) return res.status(403).json({ error: 'BD role required' });
    const uid = req.user.id;
    const allowed = ['fu1_day','fu2_day','tmpl_o1_subject','tmpl_o1_body','tmpl_fu1_subject','tmpl_fu1_body','tmpl_fu2_subject','tmpl_fu2_body'];
    const { key, value } = req.body;
    if (!allowed.includes(key)) return res.status(400).json({ error: 'Invalid key' });
    const fullKey = `u_${uid}_${key}`;
    const { error } = await supabase.from('app_settings')
      .upsert({ key: fullKey, value: String(value), updated_at: new Date() }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true, key: fullKey, value });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Manual trigger — admin/bd_lead only
app.post('/follow-ups/run', auth, async (req, res) => {
  try {
    if (!['admin','bd_lead'].includes(req.user.role)) return res.status(403).json({ error: 'Admin only' });
    const result = await runFollowupEngine();
    res.json({ success: true, ...result });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Follow-up engine core ──────────────────────────────────────
async function runFollowupEngine() {
  const todayDate = today();
  const log = { checked: 0, fu1_queued: 0, fu2_queued: 0, skipped_quota: 0, skipped_stage: 0 };

  try {
    // Get all active follow-ups due today or earlier
    const { data: dueFu, error: fuErr } = await supabase.from('follow_ups')
      .select(`*, contact:contacts(id,first_name,last_name,email,designation), job:jobs(id,position,stage,assigned_to_bd,company:companies(name,industry,location),sending_account:email_accounts!sending_email_id(id,email_address,display_name))`)
      .eq('status', 'active');
    if (fuErr) throw fuErr;
    log.checked = (dueFu || []).length;

    // Get all app_settings (global + per-user)
    const { data: settingsRows } = await supabase.from('app_settings').select('key,value');
    const settings = {};
    (settingsRows || []).forEach(r => { settings[r.key] = r.value; });

    // Helper: get per-BD template, fallback to global, fallback to hardcoded default
    function getBDTemplate(bdId, key, globalKey, fallback) {
      return settings[`u_${bdId}_${key}`] || settings[globalKey] || fallback;
    }

    function fillTemplate(tmpl, vars) {
      return (tmpl || '').replace(/{{(\w+)}}/g, (m, k) => vars[k] || m);
    }

    // Get today's send counts per email account
    const { data: sendLogs } = await supabase.from('email_send_log')
      .select('email_account_id,emails_sent').eq('send_date', todayDate);
    const sentToday = {};
    (sendLogs || []).forEach(l => { sentToday[l.email_account_id] = l.emails_sent || 0; });

    // Get daily limits per email account
    const { data: allAccounts } = await supabase.from('email_accounts').select('id,daily_send_limit').eq('is_active', true);
    const limitMap = {};
    (allAccounts || []).forEach(a => { limitMap[a.id] = a.daily_send_limit || 150; });

    // Helper: remaining quota for an account
    function remaining(acId) {
      return (limitMap[acId] || 150) - (sentToday[acId] || 0);
    }

    // Get BD user names for sender var
    const bdIdSet = [...new Set((dueFu || []).map(f => f.job?.assigned_to_bd).filter(Boolean))];
    let bdMap = {};
    if (bdIdSet.length) {
      const { data: bdUsers } = await supabase.from('users').select('id,name').in('id', bdIdSet);
      (bdUsers || []).forEach(u => { bdMap[u.id] = u.name; });
    }

    const emailsToInsert = [];
    const fu1Updates = []; // follow_up ids to mark fu1 sent
    const fu2Updates = []; // follow_up ids to mark fu2 sent
    const acCountDelta = {}; // email_account_id → count added this run

    // Separate FU1 and FU2 due items — priority: FU1 first, FU2 second
    const fu1Due = (dueFu || []).filter(f => !f.followup1_sent_at && f.followup1_due_date <= todayDate);
    const fu2Due = (dueFu || []).filter(f => f.followup1_sent_at && !f.followup2_sent_at && f.followup2_due_date <= todayDate);

    for (const fuList of [fu1Due, fu2Due]) {
      const isFu2 = fuList === fu2Due;
      for (const fu of fuList) {
        const job = fu.job;
        if (!job || job.stage !== 'Assigned') {
          // Stage changed — skip and mark
          await supabase.from('follow_ups').update({ status: 'skipped' }).eq('id', fu.id);
          log.skipped_stage++;
          continue;
        }
        const acId = job.sending_account?.id;
        if (!acId) continue;
        const rem = (limitMap[acId] || 150) - (sentToday[acId] || 0) - (acCountDelta[acId] || 0);
        if (rem <= 0) { log.skipped_quota++; continue; }

        const contact = fu.contact;
        if (!contact?.email) continue;
        const senderName = bdMap[job.assigned_to_bd] || 'Fute Global';
        const vars = {
          fn: contact.first_name || '',
          ln: contact.last_name || '',
          company: job.company?.name || '',
          pos: job.position || '',
          desig: contact.designation || '',
          ind: job.company?.industry || '',
          loc: job.company?.location || '',
          sender: senderName
        };

        const bdId = job.assigned_to_bd;
        const subjTmpl = isFu2
          ? getBDTemplate(bdId, 'tmpl_fu2_subject', 'template_fu2_subject', 'Re: Staffing Partnership — {{company}}')
          : getBDTemplate(bdId, 'tmpl_fu1_subject', 'template_fu1_subject', 'Re: Staffing Partnership — {{company}}');
        const bodyTmpl = isFu2
          ? getBDTemplate(bdId, 'tmpl_fu2_body', 'template_fu2_body', 'Hi {{fn}},\n\nI wanted to reach out one last time regarding {{pos}} at {{company}}. If the timing isn\'t right, no worries at all — happy to reconnect whenever it makes sense.\n\nBest,\n{{sender}}')
          : getBDTemplate(bdId, 'tmpl_fu1_body', 'template_fu1_body', 'Hi {{fn}},\n\nJust following up on my previous email regarding {{pos}} at {{company}}. I wanted to make sure it didn\'t get buried.\n\nWe\'ve helped similar companies fill roles like this quickly. Would love to connect briefly.\n\nBest,\n{{sender}}');
        const subject = fillTemplate(subjTmpl, vars);
        const body = fillTemplate(bodyTmpl, vars);
        const followupType = isFu2 ? 'fu2' : 'fu1';

        emailsToInsert.push({
          contact_id: fu.contact_id,
          job_id: fu.job_id,
          to_email: contact.email,
          from_email: job.sending_account?.email_address || null,
          subject, body,
          platform: 'Outlook',
          sent_by: job.assigned_to_bd,
          status: 'pending',
          followup_type: followupType,
          follow_up_id: fu.id
        });

        if (isFu2) { fu2Updates.push(fu.id); } else { fu1Updates.push(fu.id); }
        acCountDelta[acId] = (acCountDelta[acId] || 0) + 1;
        if (isFu2) { log.fu2_queued++; } else { log.fu1_queued++; }
      }
    }

    // Insert emails
    if (emailsToInsert.length) {
      await supabase.from('emails').insert(emailsToInsert);
    }

    // Mark follow-ups as sent
    const nowTs = new Date().toISOString();
    if (fu1Updates.length) {
      await supabase.from('follow_ups').update({ followup1_sent_at: nowTs }).in('id', fu1Updates);
    }
    if (fu2Updates.length) {
      await supabase.from('follow_ups').update({ followup2_sent_at: nowTs }).in('id', fu2Updates);
      // Mark completed if both sent
      const completedIds = fu2Updates; // fu2 = last follow-up
      await supabase.from('follow_ups').update({ status: 'completed' }).in('id', completedIds);
    }

    // Update send log counts
    for (const [acId, cnt] of Object.entries(acCountDelta)) {
      await supabase.from('email_send_log').upsert({
        email_account_id: acId,
        send_date: todayDate,
        emails_sent: (sentToday[acId] || 0) + cnt
      }, { onConflict: 'email_account_id,send_date' });
    }

    console.log(`[FollowupEngine] ${new Date().toISOString()} — FU1: ${log.fu1_queued}, FU2: ${log.fu2_queued}, skipped_quota: ${log.skipped_quota}, skipped_stage: ${log.skipped_stage}`);
    return log;
  } catch (err) {
    console.error('[FollowupEngine] Error:', err.message);
    return { ...log, error: err.message };
  }
}

// ── Cron: check every minute if it's time to run either engine ──
function toIST(date) {
  // IST = UTC+5:30
  const utc = date.getTime() + date.getTimezoneOffset() * 60000;
  return new Date(utc + 5.5 * 3600000);
}

const cronState = { lastOutreachRun: null, lastFollowupRun: null };

setInterval(async () => {
  try {
    const now = toIST(new Date());
    const hhmm = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
    const dateStr = now.toISOString().split('T')[0];

    const { data: settingsRows } = await supabase.from('app_settings').select('key,value');
    const settings = {};
    (settingsRows || []).forEach(r => { settings[r.key] = r.value; });

    const outreachTime = settings['outreach_send_time'] || '08:00';
    const followupTime = settings['followup_send_time'] || '08:30';

    if (hhmm === outreachTime && cronState.lastOutreachRun !== dateStr) {
      cronState.lastOutreachRun = dateStr;
      console.log(`[Cron] Outreach engine triggered at ${hhmm} IST`);
      // Outreach engine: currently emails are generated at assign time and sit as pending.
      // Future: auto-send pending outreach emails here.
    }

    if (hhmm === followupTime && cronState.lastFollowupRun !== dateStr) {
      cronState.lastFollowupRun = dateStr;
      console.log(`[Cron] Follow-up engine triggered at ${hhmm} IST`);
      await runFollowupEngine();
    }
  } catch (e) {
    console.error('[Cron] Error:', e.message);
  }
}, 60000);

// ── START ──────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Fute Global LMS API v2.0.0-jobs running on port ${PORT}`));
module.exports = app;
