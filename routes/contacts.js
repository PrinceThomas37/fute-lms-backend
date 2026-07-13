// ============================================================================
// CONTACTS (mutations)
// ----------------------------------------------------------------------------
// Extracted from index.js. Mounted via: app.use(require('./routes/contacts')(ctx));
// Route paths, handler logic and behaviour are unchanged from the original.
//
// GET /jobs/:job_id/contacts stays inline in index.js with the other /jobs
// sub-routes; this module owns the /contacts write endpoints.
//
// events + email-validation are required directly (Node caches each module, so
// these are the same singletons index.js uses — emit reaches the same bus that
// registerSubscribers listens on).
// ============================================================================
const express = require('express');
const { classifyEmailDeliverability } = require('../email-validation');
const { EVENTS, emit } = require('../events');

module.exports = (ctx) => {
  const router = express.Router();
  const { supabase, auth, hasRole, canTouchJob, logActivity, isPermanentFollowupBlock } = ctx;

router.post('/contacts', auth, async (req, res) => {
  try {
    const { job_id, first_name, last_name, designation, email, phone, linkedin, is_primary } = req.body;
    if (!job_id || !first_name) return res.status(400).json({ error: 'job_id and first_name required' });
    if (!(await canTouchJob(req, job_id))) return res.status(403).json({ error: 'Forbidden' });
    const contactRow = { job_id, first_name, last_name: last_name || '', designation, email, phone, linkedin, is_primary: !!is_primary };
    if (email) { try { contactRow.email_status = await classifyEmailDeliverability(email); } catch (_) {} }
    const { data, error } = await supabase.from('contacts').insert(contactRow).select().single();
    if (error) throw error;
    await logActivity(job_id, data.id, req.user.id, 'contact_added', `Contact added: ${first_name} ${last_name || ''}`.trim(), null, null);
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.put('/contacts/:id', auth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('contacts').select('job_id').eq('id', req.params.id).single();
    if (!existing) return res.status(404).json({ error: 'Not found' });
    if (!(await canTouchJob(req, existing.job_id))) return res.status(403).json({ error: 'Forbidden' });
    const fields = ['first_name','last_name','designation','email','phone','linkedin','is_primary','email_status','ooo_until'];
    const updates = { updated_at: new Date() };
    fields.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });
    const { data, error } = await supabase.from('contacts').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    if (req.body.email_status !== undefined && isPermanentFollowupBlock(req.body.email_status)) {
      emit(EVENTS.CONTACT_INVALIDATED, { contactId: req.params.id, jobId: existing.job_id, reason: 'manual', actorUserId: req.user.id });
    }
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.delete('/contacts/:id', auth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('contacts').select('job_id').eq('id', req.params.id).single();
    if (!existing) return res.status(404).json({ error: 'Not found' });
    if (!(await canTouchJob(req, existing.job_id))) return res.status(403).json({ error: 'Forbidden' });
    await supabase.from('contacts').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.patch('/contacts/:id/email-status', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'bd', 'bd_lead')) return res.status(403).json({ error: 'BD role required' });
    const { email_status, ooo_until } = req.body;
    const allowed = ['valid','invalid','deactivated','out_of_office'];
    if (!allowed.includes(email_status)) return res.status(400).json({ error: 'Invalid status' });
    const updates = { email_status, updated_at: new Date() };
    if (email_status === 'out_of_office' && ooo_until) updates.ooo_until = ooo_until;
    if (email_status !== 'out_of_office') updates.ooo_until = null;
    const { data: contact, error } = await supabase.from('contacts').update(updates).eq('id', req.params.id).select('*, job:jobs(id,position,company:companies(name))').single();
    if (error) throw error;
    if (email_status === 'out_of_office' && ooo_until) {
      const contactName = `${contact.first_name || ''} ${contact.last_name || ''}`.trim();
      await supabase.from('reminders').insert({ job_id: contact.job_id, user_id: req.user.id, contact_name: contactName, company_name: contact.job?.company?.name || '', email: contact.email, return_date: ooo_until, reminder_time: '09:00', note: `${contactName} is back from OOO.`, status: 'pending', reminder_type: 'ooo_return', contact_id: contact.id });
      await logActivity(contact.job_id, contact.id, req.user.id, 'ooo_set', `${contactName} marked OOO until ${ooo_until}`, null, { ooo_until });
    }
    if (isPermanentFollowupBlock(email_status)) {
      emit(EVENTS.CONTACT_INVALIDATED, { contactId: contact.id, jobId: contact.job_id, reason: 'manual', actorUserId: req.user.id });
    }
    res.json(contact);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

  return router;
};
