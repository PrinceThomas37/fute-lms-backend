// ============================================================================
// BD MANAGER / RECRUITER WORKFLOWS · INSIGHTS · STATS · BULK ACTIONS
// ----------------------------------------------------------------------------
// Extracted from index.js. Mounted via: app.use(require('./routes/workflows')(ctx));
// Route paths, handler logic and behaviour are unchanged from the original.
// ============================================================================
const express = require('express');

module.exports = (ctx) => {
  const router = express.Router();
  const { supabase, auth, hasRole, today, logActivity, INDUSTRIES, normInd } = ctx;

router.get('/insights/ra/:userId', auth, async (req, res) => {
  try {
    const targetId = req.params.userId;
    if (hasRole(req, 'ra') && !hasRole(req, 'admin', 'ra_lead') && req.user.id !== targetId) return res.status(403).json({ error: 'Forbidden' });
    const now = new Date();
    const todayStr = now.toISOString().split('T')[0];
    const weekAgo = new Date(now); weekAgo.setDate(weekAgo.getDate() - 7);
    const monthAgo = new Date(now); monthAgo.setDate(monthAgo.getDate() - 30);
    const { data: jobs, error } = await supabase.from('jobs').select('id,stage,freshness,industry,timezone,is_duplicate,created_at,created_date').eq('created_by', targetId).is('deleted_at', null).gte('created_at', monthAgo.toISOString());
    if (error) throw error;
    const all = jobs || [];
    const todayJobs = all.filter(j => j.created_date === todayStr);
    const weekJobs = all.filter(j => new Date(j.created_at) >= weekAgo);
    const last7 = {};
    for (let i = 6; i >= 0; i--) { const d = new Date(now); d.setDate(d.getDate() - i); const key = d.toISOString().split('T')[0]; last7[key] = all.filter(j => j.created_date === key).length; }
    const INDUSTRIES = ["Accounting & Finance","Advertising & Public Relations","Agriculture","Airline, Aviation & Transportation","Architecture, Construction & Building Materials","Art, Photography & Journalism","Automotive & Motor Vehicles","Banking & Financial Services","Biotechnology & Pharmaceutical","Broadcasting, Media & Printing","Chemical & Industrial","Computer Hardware & Software","Consulting & Consulting Engineering","Consumer Products & Retail","Credit, Loan, Mortgage & Collections","Defense, Military & Aerospace","Education, Training & Library Science","Electronics & Semiconductor","Employment, Recruiting & Staffing","Energy, Utilities, Oil & Petroleum","Entertainment & Recreation","Environmental","Fashion, Apparel & Textile","Food & Restaurant","Funeral & Cemetery","Government & Civil Service","Healthcare & Health Services","Homebuilding & Real Estate","Hospitality, Hotel & Resort","HVAC","Import & Export","Insurance & Managed Care","Internet & ECommerce","Landscaping","Law Enforcement, Legal & Security","Manufacturing & Manufacturing Engineering","Medical Equipment","Not for Profit & Social Services","Office Supplies & Equipment","Packaging","Sales & Marketing","Securities","Social Media & Wireless Telecommunications","Travel"];
    function normInd(raw) {
      if (!raw) return 'Unknown';
      if (INDUSTRIES.includes(raw)) return raw; // already a known value
      const r = raw.toLowerCase();
      if (r.includes('account')||r.includes('cpa')||r.includes('bookkeep')) return 'Accounting & Finance';
      if (r.includes('advertis')||r.includes('public relation')) return 'Advertising & Public Relations';
      if (r.includes('agricultur')||r.includes('farm')) return 'Agriculture';
      if (r.includes('airline')||r.includes('aviation')||r.includes('transport')||r.includes('logistics')||r.includes('freight')) return 'Airline, Aviation & Transportation';
      if (r.includes('architect')||r.includes('construction')||r.includes('building material')) return 'Architecture, Construction & Building Materials';
      if (r.includes('photo')||r.includes('journalism')||r.includes('creative')) return 'Art, Photography & Journalism';
      if (r.includes('automotive')||r.includes('motor vehicle')||r.includes('automobile')) return 'Automotive & Motor Vehicles';
      if (r.includes('banking')||r.includes('bank ')||r.includes('financial service')) return 'Banking & Financial Services';
      if (r.includes('biotech')||r.includes('pharma')||r.includes('life science')) return 'Biotechnology & Pharmaceutical';
      if (r.includes('broadcast')||r.includes('media')||r.includes('print')||r.includes('publish')||r.includes('television')) return 'Broadcasting, Media & Printing';
      if (r.includes('chemical')||r.includes('industrial')||r.includes('petrochemical')) return 'Chemical & Industrial';
      if (r.includes('software')||r.includes('computer')||r.includes('hardware')||r.includes('technology')||r.includes(' tech')||r.includes(' it ')||r.includes('information tech')||r.includes('saas')||r.includes('cloud')) return 'Computer Hardware & Software';
      if (r.includes('consult')||r.includes('advisory')) return 'Consulting & Consulting Engineering';
      if (r.includes('consumer')||r.includes('retail')||r.includes('ecommerce')) return 'Consumer Products & Retail';
      if (r.includes('credit')||r.includes('loan')||r.includes('mortgage')||r.includes('collection')) return 'Credit, Loan, Mortgage & Collections';
      if (r.includes('defense')||r.includes('military')||r.includes('aerospace')) return 'Defense, Military & Aerospace';
      if (r.includes('education')||r.includes('training')||r.includes('school')||r.includes('university')||r.includes('college')||r.includes('library')) return 'Education, Training & Library Science';
      if (r.includes('electronic')||r.includes('semiconductor')||r.includes('chip')) return 'Electronics & Semiconductor';
      if (r.includes('employ')||r.includes('recruit')||r.includes('staffing')||r.includes('human resource')) return 'Employment, Recruiting & Staffing';
      if (r.includes('energy')||r.includes('utilities')||r.includes('oil ')||r.includes('gas ')||r.includes('petroleum')||r.includes('solar')||r.includes('renewable')) return 'Energy, Utilities, Oil & Petroleum';
      if (r.includes('entertainment')||r.includes('recreation')||r.includes('gaming')||r.includes('sport')) return 'Entertainment & Recreation';
      if (r.includes('environment')||r.includes('sustainability')||r.includes('waste')||r.includes('recycl')) return 'Environmental';
      if (r.includes('fashion')||r.includes('apparel')||r.includes('textile')||r.includes('clothing')) return 'Fashion, Apparel & Textile';
      if (r.includes('food')||r.includes('restaurant')||r.includes('beverage')||r.includes('catering')) return 'Food & Restaurant';
      if (r.includes('funeral')||r.includes('cemetery')||r.includes('mortuary')) return 'Funeral & Cemetery';
      if (r.includes('government')||r.includes('civil service')||r.includes('public sector')||r.includes('municipal')) return 'Government & Civil Service';
      if (r.includes('health')||r.includes('medical')||r.includes('hospital')||r.includes('clinic')||r.includes('wellness')||r.includes('dental')) return 'Healthcare & Health Services';
      if (r.includes('real estate')||r.includes('homebuilding')||r.includes('property')||r.includes('realty')) return 'Homebuilding & Real Estate';
      if (r.includes('hotel')||r.includes('resort')||r.includes('hospitality')||r.includes('lodging')) return 'Hospitality, Hotel & Resort';
      if (r.includes('hvac')||r.includes('heating')||r.includes('cooling')||r.includes('air condition')) return 'HVAC';
      if (r.includes('import')||r.includes('export')) return 'Import & Export';
      if (r.includes('insurance')||r.includes('managed care')) return 'Insurance & Managed Care';
      if (r.includes('internet')||r.includes('online')||r.includes('digital')||r.includes('web ')) return 'Internet & ECommerce';
      if (r.includes('landscap')||r.includes('lawn')||r.includes('garden')) return 'Landscaping';
      if (r.includes('legal')||r.includes('law')||r.includes('attorney')||r.includes('compliance')||r.includes('litigation')||r.includes('law enforce')) return 'Law Enforcement, Legal & Security';
      if (r.includes('manufactur')||r.includes('engineering')||r.includes('mechanical')||r.includes('production')) return 'Manufacturing & Manufacturing Engineering';
      if (r.includes('medical equip')||r.includes('medical device')||r.includes('surgical')) return 'Medical Equipment';
      if (r.includes('nonprofit')||r.includes('not for profit')||r.includes('social service')||r.includes('charity')||r.includes('ngo')) return 'Not for Profit & Social Services';
      if (r.includes('office suppl')||r.includes('stationery')) return 'Office Supplies & Equipment';
      if (r.includes('packag')||r.includes('container')) return 'Packaging';
      if (r.includes('sales')||r.includes('marketing')) return 'Sales & Marketing';
      if (r.includes('securit')||r.includes('investment')||r.includes('hedge fund')||r.includes('private equity')) return 'Securities';
      if (r.includes('social media')||r.includes('wireless')||r.includes('telecom')||r.includes('mobile')) return 'Social Media & Wireless Telecommunications';
      if (r.includes('travel')||r.includes('tourism')) return 'Travel';
      return raw; // keep original if no match
    }
    function breakdown(arr, field) { const map = {}; arr.forEach(j => { const raw = j[field] || ''; const v = field === 'industry' ? normInd(raw) : (raw || 'Unknown'); map[v] = (map[v] || 0) + 1; }); return map; }
    res.json({ total_month: all.length, total_week: weekJobs.length, total_today: todayJobs.length, duplicates: all.filter(j => j.is_duplicate).length, last_7_days: last7, by_industry: breakdown(all,'industry'), by_timezone: breakdown(all,'timezone'), by_freshness: breakdown(all,'freshness'), by_stage: breakdown(all,'stage') });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/insights/bd/:userId', auth, async (req, res) => {
  try {
    const targetId = req.params.userId;
    // BD can only see their own; BD Lead and admin can see any
    if (hasRole(req, 'bd') && !hasRole(req, 'admin', 'bd_lead') && req.user.id !== targetId) return res.status(403).json({ error: 'Forbidden' });

    const now = new Date();
    const todayStr = now.toISOString().split('T')[0];
    const weekAgo = new Date(now); weekAgo.setDate(weekAgo.getDate() - 7);
    const monthAgo = new Date(now); monthAgo.setDate(monthAgo.getDate() - 30);

    // Jobs assigned to this BD Manager
    const { data: jobs } = await supabase.from('jobs')
      .select('id,stage,industry,position,assigned_at,company:companies(name,industry)')
      .eq('assigned_to_bd', targetId)
      .is('deleted_at', null);

    const allJobs = jobs || [];
    function jAt(j) { return j.assigned_at ? j.assigned_at.slice(0, 10) : ''; }

    const todayJobs  = allJobs.filter(j => jAt(j) === todayStr);
    const weekJobs   = allJobs.filter(j => jAt(j) >= weekAgo.toISOString().split('T')[0]);
    const monthJobs  = allJobs.filter(j => jAt(j) >= monthAgo.toISOString().split('T')[0]);

    // Funnel stages
    const convStages    = ['Connected', 'In Discussion'];
    const positiveStage = ['Positive'];
    const negStages     = ['Negative', 'No Response'];
    const oooStage      = ['Out of Office'];
    const converted  = allJobs.filter(j => convStages.includes(j.stage));
    const positive   = allJobs.filter(j => positiveStage.includes(j.stage));
    const negative   = allJobs.filter(j => negStages.includes(j.stage));
    const ooo        = allJobs.filter(j => oooStage.includes(j.stage));
    const future     = allJobs.filter(j => j.stage === 'Future');
    const assigned   = allJobs.filter(j => j.stage === 'Assigned');

    // Emails
    const { data: emails } = await supabase.from('emails')
      .select('id,status,created_at,sent_at')
      .eq('assigned_to', targetId)
      .gte('created_at', monthAgo.toISOString());

    const allEmails   = emails || [];
    const sentEmails  = allEmails.filter(e => e.status === 'sent');
    const pendEmails  = allEmails.filter(e => e.status === 'pending');
    const failEmails  = allEmails.filter(e => e.status === 'failed');

    // Last 7 days — emails sent per day
    const last7emails = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now); d.setDate(d.getDate() - i);
      const key = d.toISOString().split('T')[0];
      last7emails[key] = sentEmails.filter(e => (e.sent_at || e.created_at || '').slice(0, 10) === key).length;
    }

    // Last 7 days — leads assigned per day
    const last7leads = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now); d.setDate(d.getDate() - i);
      const key = d.toISOString().split('T')[0];
      last7leads[key] = allJobs.filter(j => jAt(j) === key).length;
    }

    // Stage breakdown
    const stageBreakdown = {};
    allJobs.forEach(j => { stageBreakdown[j.stage || 'Unknown'] = (stageBreakdown[j.stage || 'Unknown'] || 0) + 1; });

    // Industry breakdown from company data
    const industryBreakdown = {};
    allJobs.forEach(j => {
      const ind = (j.company && j.company.industry) || j.industry || 'Unknown';
      industryBreakdown[ind] = (industryBreakdown[ind] || 0) + 1;
    });

    const convRate     = allJobs.length ? Math.round(converted.length / allJobs.length * 100) : 0;
    const responseRate = allJobs.length ? Math.round((converted.length + positive.length) / allJobs.length * 100) : 0;

    res.json({
      // Volume
      total_all: allJobs.length,
      total_today: todayJobs.length,
      total_week: weekJobs.length,
      total_month: monthJobs.length,
      // Funnel
      assigned: assigned.length,
      positive: positive.length,
      converted: converted.length,
      negative: negative.length,
      ooo: ooo.length,
      future: future.length,
      conv_rate: convRate,
      response_rate: responseRate,
      // Emails
      emails_sent: sentEmails.length,
      emails_sent_today: sentEmails.filter(e => (e.sent_at || e.created_at || '').slice(0, 10) === todayStr).length,
      emails_pending: pendEmails.length,
      emails_failed: failEmails.length,
      // Charts
      last_7_emails: last7emails,
      last_7_leads: last7leads,
      // Breakdowns
      by_stage: stageBreakdown,
      by_industry: industryBreakdown,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/stats', auth, async (req, res) => {
  try {
    const { period } = req.query;
    const now = new Date();
    let dateFrom;
    if (period === 'daily') dateFrom = today();
    else if (period === 'weekly') { const w = new Date(now); w.setDate(w.getDate()-7); dateFrom = w.toISOString().split('T')[0]; }
    else if (period === 'quarterly') { const q = new Date(now); q.setMonth(q.getMonth()-3); dateFrom = q.toISOString().split('T')[0]; }
    else { const m = new Date(now.getFullYear(), now.getMonth(), 1); dateFrom = m.toISOString().split('T')[0]; }
    let query = supabase.from('jobs').select('id,stage,created_by,assigned_to,contacts(id,email_sent_at)').is('deleted_at', null).gte('created_at', dateFrom + 'T00:00:00Z');
    if (!hasRole(req, 'admin')) query = query.or(`created_by.eq.${req.user.id},assigned_to.eq.${req.user.id}`);
    const { data, error } = await query;
    if (error) throw error;
    const total = data.length;
    const emailed = data.filter(j => (j.contacts || []).some(c => c.email_sent_at)).length;
    const byStage = {};
    data.forEach(j => { byStage[j.stage] = (byStage[j.stage] || 0) + 1; });
    res.json({ total, emailed, responseRate: total ? Math.round(emailed/total*100) : 0, byStage, period: period || 'monthly', dateFrom });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/jobs/bulk-stage', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd', 'bd_lead', 'ra_lead')) return res.status(403).json({ error: 'Not allowed' });
    const { job_ids, stage } = req.body;
    if (!Array.isArray(job_ids) || !job_ids.length) return res.status(400).json({ error: 'job_ids required' });
    const validStages = ['Unassigned', 'Assigned', 'Connected', 'Rejected', 'Future', 'In Discussion'];
    if (!validStages.includes(stage)) return res.status(400).json({ error: 'Invalid stage' });
    // BD users can only move leads to post-assignment stages — not back to Unassigned or Assigned
    const bdOnlyStages = ['Connected', 'Rejected', 'Future', 'In Discussion'];
    if (hasRole(req, 'bd', 'bd_lead') && !hasRole(req, 'admin', 'ra_lead') && !bdOnlyStages.includes(stage)) {
      return res.status(403).json({ error: 'BD users cannot set stage to ' + stage });
    }

    const updates = { stage, updated_at: new Date() };
    // If resetting to Unassigned, clear assignment fields so it re-enters the pool
    if (stage === 'Unassigned') {
      updates.assigned_to_bd = null;
      updates.sending_email_id = null;
      updates.assigned_at = null;
    }

    const { error } = await supabase.from('jobs').update(updates).in('id', job_ids);
    if (error) throw error;

    for (const jid of job_ids) await logActivity(jid, null, req.user.id, 'stage_changed', `Stage changed to ${stage}`, null, { stage });

    // If resetting to Unassigned, also delete any pending emails for these jobs
    if (stage === 'Unassigned') {
      await supabase.from('emails').delete().in('job_id', job_ids).eq('status', 'pending');
    }

    res.json({ success: true, updated: job_ids.length, stage });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/jobs/bulk-assign', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'ra_lead')) return res.status(403).json({ error: 'ra_lead or admin only' });
    const { job_ids, assigned_to_bd } = req.body;
    if (!Array.isArray(job_ids) || !job_ids.length) return res.status(400).json({ error: 'job_ids array required' });
    if (!assigned_to_bd) return res.status(400).json({ error: 'assigned_to_bd required' });
    const { data: bd } = await supabase.from('users').select('id,name').eq('id', assigned_to_bd).single();
    if (!bd) return res.status(400).json({ error: 'BD user not found' });

    // Get BD's primary active email ID for sending
    const { data: bdEmails } = await supabase.from('user_emails')
      .select('id,email_address,is_primary')
      .eq('user_id', assigned_to_bd)
      .eq('is_active', true)
      .order('is_primary', { ascending: false });
    const sendingEmailId = (bdEmails && bdEmails.length) ? bdEmails[0].id : null;

    const now = new Date();
    const updatePayload = { assigned_to_bd, assigned_at: now, stage: 'Assigned', updated_at: now };
    if (sendingEmailId) updatePayload.sending_email_id = sendingEmailId;
    const { error } = await supabase.from('jobs').update(updatePayload).in('id', job_ids);
    if (error) throw error;
    for (const jid of job_ids) await logActivity(jid, null, req.user.id, 'bulk_assigned', `Bulk assigned to BD: ${bd.name}`, null, { assigned_to_bd, bd_name: bd.name });
    res.json({ success: true, assigned: job_ids.length, bd_name: bd.name, sending_email_id: sendingEmailId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/jobs/check-duplicates', auth, async (req, res) => {
  try {
    const { emails } = req.body;
    if (!Array.isArray(emails) || !emails.length) return res.json({ duplicates: [] });
    const { data, error } = await supabase.from('contacts').select('email, job_id, job:jobs(id,position,company_id,company:companies(name))').in('email', emails.map(e => e.toLowerCase().trim())).not('email', 'is', null);
    if (error) throw error;
    res.json({ duplicates: data || [] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

  return router;
};
