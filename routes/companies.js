// ============================================================================
// COMPANIES
// ----------------------------------------------------------------------------
// Extracted from index.js. Mounted via: app.use(require('./routes/companies')(ctx));
// Route paths, handler logic and behaviour are unchanged from the original.
// ============================================================================
const express = require('express');

module.exports = (ctx) => {
  const router = express.Router();
  const { supabase, auth, hasRole } = ctx;

router.get('/companies', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('companies').select('*').is('deleted_at', null).order('name');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/companies/search', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) return res.json([]);
    const { data, error } = await supabase.from('companies')
      .select('id,name,industry,location,website').ilike('name', `%${q}%`).is('deleted_at', null).limit(8);
    if (error) throw error;
    const result = await Promise.all((data || []).map(async co => {
      const { count } = await supabase.from('jobs').select('id', { count: 'exact', head: true }).eq('company_id', co.id).is('deleted_at', null);
      return { ...co, job_count: count || 0 };
    }));
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/companies/bulk', auth, async (req, res) => {
  try {
    const { companies } = req.body;
    if (!Array.isArray(companies) || !companies.length) return res.status(400).json({ error: 'companies array required' });
    const rows = companies.map(c => ({ name: c.name, website: c.website || null, industry: c.industry || null, location: c.location || null, created_by: req.user.id }));
    const { data, error } = await supabase.from('companies').insert(rows).select('id,name');
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/companies', auth, async (req, res) => {
  try {
    const { name, website, industry, location, size, notes } = req.body;
    if (!name) return res.status(400).json({ error: 'Company name required' });
    const { data, error } = await supabase.from('companies').insert({ name, website, industry, location, size, notes, created_by: req.user.id }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.put('/companies/:id', auth, async (req, res) => {
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

router.delete('/companies/:id', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin')) return res.status(403).json({ error: 'Admin only' });
    await supabase.from('companies').update({ deleted_at: new Date() }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

  return router;
};
