// ============================================================================
// GOOGLE OAUTH · GMAIL SEND/READ  — the counterpart to routes/microsoft.js.
// Mounted via: app.use(require('./routes/gmail')(ctx));
// ctx = { supabase, auth, hasRole, provider }  (provider = gmail-provider.js)
//
// Gated: every entry point short-circuits with a clear message when Gmail isn't
// configured (GOOGLE_CLIENT_ID/SECRET unset), so mounting this never affects the
// Microsoft path or startup.
// ============================================================================
const express = require('express');
const jwt = require('jsonwebtoken');

module.exports = (ctx) => {
  const router = express.Router();
  const { supabase, auth, hasRole, provider } = ctx;

  const notConfiguredPage = (res) =>
    res.send(`<scr` + `ipt>window.opener&&window.opener.postMessage({type:'google_oauth_error',error:'Gmail is not configured on the server yet (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET).'},'*');window.close();</scr` + `ipt>`);

  router.get('/auth/google/connect', async (req, res) => {
    try {
      if (!provider.isConfigured()) return notConfiguredPage(res);
      const token = req.query.token || (req.headers.authorization || '').replace('Bearer ', '');
      if (!token) return res.status(401).send('Unauthorized');
      let reqUser;
      try { reqUser = jwt.verify(token, process.env.JWT_SECRET); } catch { return res.status(401).send('Invalid token'); }
      if (!reqUser.roles?.includes('admin') && reqUser.role !== 'admin') return res.status(403).send('Admin only');
      const { userEmailId } = req.query;
      if (!userEmailId) return res.status(400).send('userEmailId required');
      const state = Buffer.from(JSON.stringify({ userEmailId, userId: reqUser.id })).toString('base64');
      res.redirect(provider.authorizeUrl(state));
    } catch (err) { res.status(500).send(err.message); }
  });

  router.get('/auth/google/callback', async (req, res) => {
    let userEmailId = '';
    try {
      if (!provider.isConfigured()) return notConfiguredPage(res);
      const { code, state, error: gErr } = req.query;
      if (gErr) return res.send(`<scr` + `ipt>window.opener&&window.opener.postMessage({type:'google_oauth_error',error:'${gErr}'},'*');window.close();</scr` + `ipt>`);
      if (!code || !state) return res.status(400).send('Missing code or state');
      const parsed = JSON.parse(Buffer.from(decodeURIComponent(state), 'base64').toString());
      userEmailId = parsed.userEmailId; const userId = parsed.userId;

      const tokens = await provider.exchangeCode(code);
      if (tokens.error) return res.send(`<scr` + `ipt>window.opener&&window.opener.postMessage({type:'google_oauth_error',userEmailId:'${userEmailId}',error:${JSON.stringify(tokens.error_description || tokens.error)}},'*');window.close();</scr` + `ipt>`);
      const emailAddress = await provider.getProfileEmail(tokens.access_token);

      // Validate the connected Google account matches the slot before writing.
      const { data: slot } = await supabase.from('user_emails').select('email_address').eq('id', userEmailId).single();
      const expected = (slot?.email_address || '').toLowerCase().trim();
      const actual = (emailAddress || '').toLowerCase().trim();
      if (expected && actual && expected !== actual) {
        const msg = `Wrong account: you signed in as ${emailAddress} but this slot is for ${slot.email_address}. Sign out of Google and retry with the correct account.`;
        return res.send(`<scr` + `ipt>window.opener&&window.opener.postMessage({type:'google_oauth_error',userEmailId:'${userEmailId}',error:${JSON.stringify(msg)}},'*');window.close();</scr` + `ipt>`);
      }

      await supabase.from('gmail_tokens').delete().eq('user_email_id', userEmailId);
      const { error: insErr } = await supabase.from('gmail_tokens').insert({
        user_email_id: userEmailId, user_id: userId, email_address: emailAddress,
        access_token: tokens.access_token, refresh_token: tokens.refresh_token,
        expires_at: new Date(Date.now() + (tokens.expires_in || 3600) * 1000).toISOString(), updated_at: new Date(),
      });
      if (insErr) return res.send(`<scr` + `ipt>window.opener&&window.opener.postMessage({type:'google_oauth_error',userEmailId:'${userEmailId}',error:'DB save failed: ${insErr.message}'},'*');window.close();</scr` + `ipt>`);
      if (!tokens.refresh_token) {
        // Google only returns a refresh_token on first consent; prompt=consent
        // forces it, but warn if somehow absent so it can be re-consented.
        console.warn(`[gmail] no refresh_token returned for ${emailAddress} — re-consent may be needed`);
      }
      await supabase.from('user_emails').update({ platform: 'Gmail', is_active: true }).eq('id', userEmailId);
      res.send(`<scr` + `ipt>window.opener&&window.opener.postMessage({type:'google_oauth_success',userEmailId:'${userEmailId}',email:'${emailAddress}'},'*');window.close();</scr` + `ipt>`);
    } catch (err) {
      console.error('Google OAuth callback error:', err);
      res.send(`<scr` + `ipt>window.opener&&window.opener.postMessage({type:'google_oauth_error',userEmailId:'${userEmailId}',error:${JSON.stringify(err.message)}},'*');window.close();</scr` + `ipt>`);
    }
  });

  router.get('/auth/google/status/:userEmailId', auth, async (req, res) => {
    try {
      const { data } = await supabase.from('gmail_tokens').select('email_address,expires_at').eq('user_email_id', req.params.userEmailId).single();
      if (!data) return res.json({ connected: false, configured: provider.isConfigured() });
      res.json({ connected: true, configured: provider.isConfigured(), email_address: data.email_address, expired: new Date(data.expires_at) < new Date() });
    } catch { res.json({ connected: false, configured: provider.isConfigured() }); }
  });

  router.delete('/auth/google/:userEmailId', auth, async (req, res) => {
    try {
      if (!hasRole(req, 'admin', 'bd_lead')) return res.status(403).json({ error: 'Admin only' });
      await supabase.from('gmail_tokens').delete().eq('user_email_id', req.params.userEmailId);
      await supabase.from('user_emails').update({ is_active: false }).eq('id', req.params.userEmailId);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  return router;
};
