// ============================================================================
// SETTINGS — app_settings (global) + outreach-plan (per-user)
// ----------------------------------------------------------------------------
// Extracted from index.js. Mounted via: app.use(require('./routes/settings')(ctx));
// Route paths, handler logic and behaviour are unchanged from the original.
// resolveTemplate is required directly (Node caches it, so it's the same
// singleton index.js uses).
// ============================================================================
const express = require('express');
const { resolveTemplate } = require('../email-vars');

module.exports = (ctx) => {
  const router = express.Router();
  const { supabase, auth, hasRole } = ctx;

router.get('/app-settings', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('app_settings').select('key,value');
    if (error) throw error;
    const settings = {};
    (data || []).forEach(r => { settings[r.key] = r.value; });
    res.json(settings);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/app-settings', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'admin', 'ra_lead')) return res.status(403).json({ error: 'Admin or RA Lead only' });
    const { key, value } = req.body;
    if (!key || value === undefined) return res.status(400).json({ error: 'key and value required' });
    const { error } = await supabase.from('app_settings').upsert({ key, value, updated_at: new Date() }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true, key, value });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════════════════════════════
// OUTREACH PLAN (per-user)
// ══════════════════════════════════════════════════════════════
router.get('/outreach-plan', auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const keys = [`u_${uid}_fu1_day`,`u_${uid}_fu2_day`,`u_${uid}_tmpl_o1_subject`,`u_${uid}_tmpl_o1_body`,`u_${uid}_tmpl_fu1_subject`,`u_${uid}_tmpl_fu1_body`,`u_${uid}_tmpl_fu2_subject`,`u_${uid}_tmpl_fu2_body`,`u_${uid}_signature_html`,`u_${uid}_random_template_mode`,`u_${uid}_compose_style_preset`];
    const { data } = await supabase.from('app_settings').select('key,value').in('key', keys);
    const plan = {};
    (data || []).forEach(r => { plan[r.key.replace(`u_${uid}_`, '')] = r.value; });

    const tmplFields = ['tmpl_o1_subject', 'tmpl_o1_body', 'tmpl_fu1_subject', 'tmpl_fu1_body', 'tmpl_fu2_subject', 'tmpl_fu2_body'];
    const migrations = [];
    tmplFields.forEach(field => {
      const shortKey = field.replace('tmpl_', '');
      const resolved = resolveTemplate(plan[field], shortKey);
      if (plan[field] && resolved !== plan[field]) {
        plan[field] = resolved;
        migrations.push({ key: `u_${uid}_${field}`, value: resolved });
      }
    });
    if (migrations.length) {
      await supabase.from('app_settings').upsert(
        migrations.map(m => ({ key: m.key, value: m.value, updated_at: new Date() })),
        { onConflict: 'key' }
      );
    }

    res.json(plan);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/outreach-plan', auth, async (req, res) => {
  try {
    if (!hasRole(req, 'bd', 'bd_lead', 'admin')) return res.status(403).json({ error: 'BD role required' });
    const uid = req.user.id;
    const allowed = ['fu1_day','fu2_day','tmpl_o1_subject','tmpl_o1_body','tmpl_fu1_subject','tmpl_fu1_body','tmpl_fu2_subject','tmpl_fu2_body','signature_html','random_template_mode','compose_style_preset'];
    const { key, value } = req.body;
    if (!allowed.includes(key)) return res.status(400).json({ error: 'Invalid key' });
    const fullKey = `u_${uid}_${key}`;
    const { error } = await supabase.from('app_settings').upsert({ key: fullKey, value: String(value), updated_at: new Date() }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true, key: fullKey, value });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

  return router;
};
