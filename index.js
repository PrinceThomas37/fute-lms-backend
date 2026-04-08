require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase client using service role key (full access)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── MIDDLEWARE ─────────────────────────────────────────────────
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','PATCH','DELETE'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({ limit: '2mb' }));

// Auth middleware
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), process.env.JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function adminOrBd(req, res, next) {
  if (!['admin','bd'].includes(req.user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
  next();
}

// ── HEALTH ─────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', app: 'Fute Global LMS API', version: '1.0.0' }));

// ══════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════

// POST /auth/login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase().trim())
      .eq('is_active', true)
      .is('deleted_at', null)
      .single();

    if (error || !user) return res.status(401).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    // Return user without password
    const { password_hash, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /auth/change-password
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════
// USERS ROUTES
// ══════════════════════════════════════════════════════════════

// GET /users — get all active users
app.get('/users', auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('id,name,email,role,employee_id,designation,assigned_bdm_id,platform,is_active,created_at')
      .is('deleted_at', null)
      .order('employee_id');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /users/me
app.get('/users/me', auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('id,name,email,role,employee_id,designation,assigned_bdm_id,platform,is_active')
      .eq('id', req.user.id)
      .single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /users — admin only
app.post('/users', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const { name, email, password, role, employee_id, designation, assigned_bdm_id, platform } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required' });

    const hash = await bcrypt.hash(password || 'Fute@2024', 10);
    const { data, error } = await supabase.from('users').insert({
      name, email: email.toLowerCase().trim(), password_hash: hash,
      role: role || 'ra', employee_id, designation, assigned_bdm_id: assigned_bdm_id || null, platform: platform || 'Gmail'
    }).select('id,name,email,role,employee_id,designation,assigned_bdm_id,platform').single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /users/:id
app.put('/users/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    if (req.user.role !== 'admin' && req.user.id !== id) return res.status(403).json({ error: 'Forbidden' });
    const { name, email, role, employee_id, designation, assigned_bdm_id, platform } = req.body;
    const updates = { updated_at: new Date() };
    if (name) updates.name = name;
    if (email) updates.email = email.toLowerCase().trim();
    if (role && req.user.role === 'admin') updates.role = role;
    if (employee_id) updates.employee_id = employee_id;
    if (designation !== undefined) updates.designation = designation;
    if (assigned_bdm_id !== undefined) updates.assigned_bdm_id = assigned_bdm_id || null;
    if (platform) updates.platform = platform;
    const { data, error } = await supabase.from('users').update(updates).eq('id', id)
      .select('id,name,email,role,employee_id,designation,assigned_bdm_id,platform').single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /users/:id — soft delete
app.delete('/users/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    await supabase.from('users').update({ deleted_at: new Date(), is_active: false }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// COMPANIES ROUTES
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
    const { name, website, industry, location } = req.body;
    if (!name) return res.status(400).json({ error: 'Company name required' });
    const { data, error } = await supabase.from('companies').insert({ name, website, industry, location }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/companies/:id', auth, async (req, res) => {
  try {
    const { name, website, industry, location } = req.body;
    const { data, error } = await supabase.from('companies').update({ name, website, industry, location, updated_at: new Date() })
      .eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// LEADS ROUTES
// ══════════════════════════════════════════════════════════════

// GET /leads — with filters
app.get('/leads', auth, async (req, res) => {
  try {
    const { date_from, date_to, stage, industry, search, analyst_id, bdm_id } = req.query;
    let query = supabase
      .from('leads')
      .select(`*, company:companies(id,name,website,industry,location), analyst:users!analyst_id(id,name,employee_id), bdm:users!bdm_id(id,name)`)
      .is('deleted_at', null)
      .order('lead_date', { ascending: false });

    // Role-based scoping
    if (req.user.role === 'ra') query = query.eq('analyst_id', req.user.id);
    else if (req.user.role === 'bd') query = query.eq('bdm_id', req.user.id);

    if (date_from) query = query.gte('lead_date', date_from);
    if (date_to) query = query.lte('lead_date', date_to);
    if (stage && stage !== 'all') query = query.eq('stage', stage);
    if (analyst_id) query = query.eq('analyst_id', analyst_id);
    if (bdm_id) query = query.eq('bdm_id', bdm_id);

    const { data, error } = await query;
    if (error) throw error;

    let results = data;
    // Search filter (post-query for flexibility)
    if (search) {
      const q = search.toLowerCase();
      results = data.filter(l =>
        [l.email, l.first_name, l.last_name, l.position, l.designation,
          l.company?.name, l.analyst?.name, l.bdm?.name]
          .some(v => (v || '').toLowerCase().includes(q))
      );
    }
    // Industry filter
    if (industry && industry !== 'all') {
      results = results.filter(l => l.company?.industry === industry);
    }

    res.json(results);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /leads/:id
app.get('/leads/:id', auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('leads')
      .select(`*, company:companies(*), analyst:users!analyst_id(id,name), bdm:users!bdm_id(id,name)`)
      .eq('id', req.params.id)
      .is('deleted_at', null)
      .single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /leads
app.post('/leads', auth, async (req, res) => {
  try {
    const { company_id, position, first_name, last_name, designation, email, phone, linkedin, source, analyst_id, bdm_id, lead_date, notes } = req.body;
    if (!position || !first_name) return res.status(400).json({ error: 'Position and first name required' });

    const finalAnalystId = req.user.role === 'ra' ? req.user.id : (analyst_id || req.user.id);
    const { data, error } = await supabase.from('leads').insert({
      company_id, position, first_name, last_name, designation, email, phone, linkedin, source,
      analyst_id: finalAnalystId, bdm_id, lead_date: lead_date || new Date().toISOString().split('T')[0], notes: notes || '', stage: 'Active'
    }).select(`*, company:companies(id,name,website,industry,location)`).single();
    if (error) throw error;

    // Log activity
    await supabase.from('activity_log').insert({ lead_id: data.id, user_id: req.user.id, action_type: 'created', description: 'Lead created' });
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PATCH /leads/:id
app.patch('/leads/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    const allowed = ['position','first_name','last_name','designation','email','phone','linkedin','source','stage','notes','analyst_id','bdm_id','email_sent_at','email_platform'];
    const updates = { updated_at: new Date() };
    const oldStage = req.body._oldStage;
    allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

    const { data, error } = await supabase.from('leads').update(updates).eq('id', id)
      .select(`*, company:companies(id,name,website,industry,location)`).single();
    if (error) throw error;

    // Log stage change
    if (req.body.stage && oldStage && oldStage !== req.body.stage) {
      await supabase.from('activity_log').insert({
        lead_id: id, user_id: req.user.id, action_type: 'stage_changed',
        description: `Stage changed from "${oldStage}" to "${req.body.stage}"`,
        old_value: { stage: oldStage }, new_value: { stage: req.body.stage }
      });
    }
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /leads/:id — soft delete
app.delete('/leads/:id', auth, async (req, res) => {
  try {
    await supabase.from('leads').update({ deleted_at: new Date() }).eq('id', req.params.id);
    await supabase.from('activity_log').insert({ lead_id: req.params.id, user_id: req.user.id, action_type: 'deleted', description: 'Lead soft-deleted (60 day retention)' });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PATCH /leads/bulk/stage — bulk stage update
app.patch('/leads/bulk/stage', auth, async (req, res) => {
  try {
    const { ids, stage } = req.body;
    if (!ids?.length || !stage) return res.status(400).json({ error: 'ids and stage required' });
    await supabase.from('leads').update({ stage, updated_at: new Date() }).in('id', ids);
    const logs = ids.map(id => ({ lead_id: id, user_id: req.user.id, action_type: 'stage_changed', description: `Bulk stage update to "${stage}"` }));
    await supabase.from('activity_log').insert(logs);
    res.json({ success: true, count: ids.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// ACTIVITY LOG
// ══════════════════════════════════════════════════════════════

app.get('/leads/:id/activity', auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('activity_log')
      .select(`*, user:users(id,name)`)
      .eq('lead_id', req.params.id)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// EMAILS ROUTES
// ══════════════════════════════════════════════════════════════

app.get('/emails', auth, async (req, res) => {
  try {
    let query = supabase.from('emails').select(`*, lead:leads(id,first_name,last_name,position,company_id), sender:users!sent_by(id,name)`).order('created_at', { ascending: false });
    if (req.user.role === 'ra') query = query.eq('sent_by', req.user.id);
    const { data, error } = await query;
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/emails', auth, async (req, res) => {
  try {
    const { lead_id, to_email, subject, body, platform } = req.body;
    const { data, error } = await supabase.from('emails').insert({
      lead_id, to_email, subject, body, platform: platform || req.user.platform || 'Gmail',
      sent_by: req.user.id, status: 'sent', sent_at: new Date().toISOString().split('T')[0]
    }).select().single();
    if (error) throw error;

    // Update lead email_sent_at
    if (lead_id) {
      await supabase.from('leads').update({ email_sent_at: new Date().toISOString().split('T')[0], email_platform: platform, updated_at: new Date() }).eq('id', lead_id);
      await supabase.from('activity_log').insert({ lead_id, user_id: req.user.id, action_type: 'email_sent', description: `Email sent via ${platform || 'Gmail'}: ${subject}` });
    }
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// REMINDERS ROUTES
// ══════════════════════════════════════════════════════════════

app.get('/reminders', auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('reminders')
      .select(`*, lead:leads(id,first_name,last_name,position,stage,company_id)`)
      .eq('user_id', req.user.id)
      .order('return_date');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/reminders', auth, async (req, res) => {
  try {
    const { lead_id, contact_name, company_name, email, return_date, reminder_time, note } = req.body;
    if (!return_date) return res.status(400).json({ error: 'Return date required' });
    const { data, error } = await supabase.from('reminders').insert({
      lead_id, user_id: req.user.id, contact_name, company_name, email,
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
// EMAIL TEMPLATES
// ══════════════════════════════════════════════════════════════

app.get('/templates', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('email_templates').select('*').eq('is_global', true).order('created_at');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/templates/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const { name, subject, body } = req.body;
    const { data, error } = await supabase.from('email_templates').update({ name, subject, body, updated_at: new Date() })
      .eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// DASHBOARD STATS
// ══════════════════════════════════════════════════════════════

app.get('/stats', auth, async (req, res) => {
  try {
    const { period } = req.query;
    const now = new Date();
    let dateFrom;
    if (period === 'daily') dateFrom = now.toISOString().split('T')[0];
    else if (period === 'weekly') { const w = new Date(now); w.setDate(w.getDate()-7); dateFrom = w.toISOString().split('T')[0]; }
    else if (period === 'quarterly') { const q = new Date(now); q.setMonth(q.getMonth()-3); dateFrom = q.toISOString().split('T')[0]; }
    else { const m = new Date(now.getFullYear(), now.getMonth(), 1); dateFrom = m.toISOString().split('T')[0]; }

    let query = supabase.from('leads').select('id,stage,email_sent_at,lead_date,analyst_id,bdm_id').is('deleted_at', null).gte('lead_date', dateFrom);
    if (req.user.role === 'ra') query = query.eq('analyst_id', req.user.id);
    else if (req.user.role === 'bd') query = query.eq('bdm_id', req.user.id);

    const { data, error } = await query;
    if (error) throw error;

    const total = data.length;
    const emailed = data.filter(l => l.email_sent_at).length;
    const positive = data.filter(l => l.stage === 'Positive' || l.stage === 'Connected').length;
    const negative = data.filter(l => l.stage === 'Negative').length;
    const pending = data.filter(l => l.stage === 'Active').length;
    const rr = total ? Math.round(emailed/total*100) : 0;
    const byStage = {};
    data.forEach(l => { byStage[l.stage] = (byStage[l.stage] || 0) + 1; });

    res.json({ total, emailed, positive, negative, pending, responseRate: rr, byStage, period: period || 'monthly', dateFrom });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// AI EMAIL GENERATION (proxy to Anthropic)
// ══════════════════════════════════════════════════════════════

app.post('/ai/generate-email', auth, async (req, res) => {
  try {
    const { lead, company, template } = req.body;
    if (!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY === 'your_anthropic_api_key_here') {
      // Fallback: fill template manually
      const filled = {
        subject: (template?.subject || 'Opportunity at {{company}}').replace(/{{(\w+)}}/g, (m, k) => ({ fn: lead.first_name, ln: lead.last_name, company: company?.name, ind: company?.industry, pos: lead.position, desig: lead.designation, loc: company?.location, sender: req.user.name })[k] || m),
        body: (template?.body || 'Hi {{fn}},').replace(/{{(\w+)}}/g, (m, k) => ({ fn: lead.first_name, ln: lead.last_name, company: company?.name, ind: company?.industry, pos: lead.position, desig: lead.designation, loc: company?.location, sender: req.user.name })[k] || m)
      };
      return res.json(filled);
    }

    const prompt = `Write a hyper-personalized cold outreach email for a business development executive at Fute Global LLC (a staffing/recruitment firm).\n\nLead: ${lead.first_name} ${lead.last_name}, ${lead.designation} at ${company?.name} (${company?.industry}, ${company?.location})\nPosition they are hiring for: ${lead.position}\n\nWrite a subject line and email body (3 short paragraphs). Tone: professional but warm, direct, no fluff.\nFormat:\nSubject: [subject line]\n\n[email body]`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 600, messages: [{ role: 'user', content: prompt }] })
    });
    const aiData = await response.json();
    const text = aiData.content?.[0]?.text || '';
    const subjectMatch = text.match(/Subject:\s*(.+)/i);
    const subject = subjectMatch ? subjectMatch[1].trim() : `Opportunity at ${company?.name}`;
    const body = text.replace(/^Subject:.+\n*/im, '').trim();
    res.json({ subject, body });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// START SERVER
// ══════════════════════════════════════════════════════════════
app.listen(PORT, () => console.log(`Fute Global LMS API running on port ${PORT}`));
module.exports = app;
