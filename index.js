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
app.get('/api/health', (req, res) => res.json({ status: 'ok', app: 'Fute Global LMS API', version: '2.0.0-jobs' }));

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
const JOB_SELECT = `*, company:companies(id,name,website,industry,location), contacts(*), creator:users!created_by(id,name,employee_id), assignee:users!assigned_to(id,name,employee_id)`;

app.get('/jobs', auth, async (req, res) => {
  try {
    let query = supabase.from('jobs').select(JOB_SELECT).is('deleted_at', null).order('created_at', { ascending: false });
    if (req.user.role !== 'admin') {
      query = query.or(`created_by.eq.${req.user.id},assigned_to.eq.${req.user.id}`);
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

app.post('/jobs', auth, async (req, res) => {
  try {
    const { company_id, position, location, source, job_url, stage, notes, assigned_to, contacts } = req.body;
    if (!company_id || !position) return res.status(400).json({ error: 'company_id and position required' });
    const { data: job, error } = await supabase.from('jobs').insert({
      company_id, position, location, source, job_url,
      stage: stage || 'Active', notes: notes || '',
      created_by: req.user.id,
      assigned_to: (req.user.role === 'admin' ? (assigned_to || null) : null)
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
    if (req.user.role !== 'admin' && existing.created_by !== req.user.id && existing.assigned_to !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const { position, location, source, job_url, stage, notes, assigned_to } = req.body;
    const updates = { updated_at: new Date() };
    if (position !== undefined) updates.position = position;
    if (location !== undefined) updates.location = location;
    if (source !== undefined) updates.source = source;
    if (job_url !== undefined) updates.job_url = job_url;
    if (stage !== undefined) updates.stage = stage;
    if (notes !== undefined) updates.notes = notes;
    if (assigned_to !== undefined && req.user.role === 'admin') updates.assigned_to = assigned_to || null;

    const { data, error } = await supabase.from('jobs').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;

    if (stage !== undefined && stage !== existing.stage) {
      await logActivity(data.id, null, req.user.id, 'stage_change', `Stage: ${existing.stage} → ${stage}`, { stage: existing.stage }, { stage });
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
    const fields = ['first_name','last_name','designation','email','phone','linkedin','is_primary'];
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

// ══════════════════════════════════════════════════════════════
// EMAILS
// ══════════════════════════════════════════════════════════════
app.get('/emails', auth, async (req, res) => {
  try {
    let query = supabase.from('emails')
      .select(`*, contact:contacts(id,first_name,last_name,email), job:jobs(id,position,company_id), sender:users!sent_by(id,name)`)
      .order('created_at', { ascending: false });
    if (req.user.role !== 'admin') query = query.eq('sent_by', req.user.id);
    const { data, error } = await query;
    if (error) throw error;
    res.json(data);
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

// ══════════════════════════════════════════════════════════════
// REMINDERS
// ══════════════════════════════════════════════════════════════
app.get('/reminders', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('reminders')
      .select(`*, job:jobs(id,position,stage,company_id)`)
      .eq('user_id', req.user.id).order('return_date');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/reminders', auth, async (req, res) => {
  try {
    const { job_id, contact_name, company_name, email, return_date, reminder_time, note } = req.body;
    if (!return_date) return res.status(400).json({ error: 'Return date required' });
    const { data, error } = await supabase.from('reminders').insert({
      job_id: job_id || null, user_id: req.user.id, contact_name, company_name, email,
      return_date, reminder_time: reminder_time || '09:00', note, status: 'pending'
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

// ── START ──────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Fute Global LMS API v2.0.0-jobs running on port ${PORT}`));
module.exports = app;
