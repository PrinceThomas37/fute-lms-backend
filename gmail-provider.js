// ============================================================================
// Gmail / Google Workspace provider — the counterpart to the Microsoft Graph
// send/read machinery in index.js, so a Gmail mailbox can send, reply, read its
// inbox, and move mail out of spam (warm-up rescue) the same way an Outlook one
// does. Raw REST via fetch, mirroring graphMailRequest — no extra dependency.
//
// SCAFFOLD: fully implemented, but inert until an admin sets GOOGLE_CLIENT_ID /
// GOOGLE_CLIENT_SECRET and Google approves the restricted scopes (gmail.send /
// gmail.modify). `isConfigured()` gates every entry point; the Microsoft path is
// untouched. The final step — dispatching the send loop + warm-up engine to
// this provider by mailbox platform — is intentionally left as its own change
// (see docs), since it can only be tested once a real Gmail mailbox connects.
//
//   ctx = { supabase, google: { clientId, clientSecret, redirectUri, scopes } }
// ============================================================================

function createGmailProvider(ctx) {
  const { supabase, google } = ctx;
  const cfg = google || {};

  const isConfigured = () => !!(cfg.clientId && cfg.clientSecret);
  function requireConfigured() {
    if (!isConfigured()) throw new Error('Gmail is not configured (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET).');
  }

  // ── OAuth ──────────────────────────────────────────────────────────────────
  function authorizeUrl(state) {
    requireConfigured();
    const p = new URLSearchParams({
      client_id: cfg.clientId, response_type: 'code', redirect_uri: cfg.redirectUri,
      scope: cfg.scopes, access_type: 'offline', prompt: 'consent',
      include_granted_scopes: 'true', state,
    });
    return `https://accounts.google.com/o/oauth2/v2/auth?${p}`;
  }
  async function oauthToken(params) {
    const res = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(params),
    });
    return res.json();
  }
  async function exchangeCode(code) {
    requireConfigured();
    return oauthToken({ client_id: cfg.clientId, client_secret: cfg.clientSecret, code, redirect_uri: cfg.redirectUri, grant_type: 'authorization_code' });
  }

  // ── Token (with refresh), mirroring getMicrosoftToken ───────────────────────
  async function getToken(userEmailId) {
    requireConfigured();
    const { data: row, error } = await supabase.from('gmail_tokens').select('*').eq('user_email_id', userEmailId).single();
    if (error || !row) throw new Error('No Gmail token found. Please reconnect this mailbox.');
    if (new Date(row.expires_at).getTime() - Date.now() > 5 * 60 * 1000) return row.access_token;
    const refreshed = await oauthToken({ client_id: cfg.clientId, client_secret: cfg.clientSecret, refresh_token: row.refresh_token, grant_type: 'refresh_token' });
    if (refreshed.error) throw new Error('Gmail token refresh failed: ' + (refreshed.error_description || refreshed.error));
    await supabase.from('gmail_tokens').update({
      access_token: refreshed.access_token,
      expires_at: new Date(Date.now() + refreshed.expires_in * 1000).toISOString(),
      updated_at: new Date(),
    }).eq('user_email_id', userEmailId);
    return refreshed.access_token;
  }

  async function api(token, path, options = {}) {
    const res = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me${path}`, {
      ...options,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...(options.headers || {}) },
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.error?.message || `Gmail API ${res.status}`);
    return data;
  }

  async function getProfileEmail(token) {
    const r = await api(token, '/profile');
    return r.emailAddress || '';
  }

  // ── MIME builder → base64url `raw` for messages.send ────────────────────────
  function base64url(str) {
    return Buffer.from(str, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function buildRaw({ from, to, subject, htmlBody, headers, inReplyTo, references }) {
    const lines = [];
    if (from) lines.push(`From: ${from}`);
    lines.push(`To: ${to}`);
    lines.push(`Subject: ${subject || ''}`);
    lines.push('MIME-Version: 1.0');
    lines.push('Content-Type: text/html; charset="UTF-8"');
    if (inReplyTo) lines.push(`In-Reply-To: ${inReplyTo}`);
    if (references) lines.push(`References: ${references}`);
    for (const [k, v] of Object.entries(headers || {})) lines.push(`${k}: ${v}`);
    lines.push('');
    lines.push(htmlBody || '');
    return base64url(lines.join('\r\n'));
  }

  // ── Send (fresh) ────────────────────────────────────────────────────────────
  async function sendNewMessage(userEmailId, { to, subject, htmlBody, headers, fromAddress }) {
    const token = await getToken(userEmailId);
    const raw = buildRaw({ from: fromAddress, to, subject, htmlBody, headers });
    const r = await api(token, '/messages/send', { method: 'POST', body: JSON.stringify({ raw }) });
    return { messageId: r.id, threadId: r.threadId };
  }

  // ── Send (threaded reply) — pass the parent's Message-ID for proper threading ─
  async function sendThreadReply(userEmailId, { to, subject, htmlBody, headers, fromAddress, threadId, inReplyTo, references }) {
    const token = await getToken(userEmailId);
    const raw = buildRaw({ from: fromAddress, to, subject, htmlBody, headers, inReplyTo, references });
    const body = { raw }; if (threadId) body.threadId = threadId;
    const r = await api(token, '/messages/send', { method: 'POST', body: JSON.stringify(body) });
    return { messageId: r.id, threadId: r.threadId };
  }

  // ── Read ─────────────────────────────────────────────────────────────────────
  async function listMessages(userEmailId, { labelIds, q, maxResults } = {}) {
    const token = await getToken(userEmailId);
    const p = new URLSearchParams();
    (labelIds || []).forEach((l) => p.append('labelIds', l));
    if (q) p.set('q', q);
    p.set('maxResults', String(maxResults || 25));
    const r = await api(token, `/messages?${p}`);
    return r.messages || [];
  }
  async function getMessage(userEmailId, id, { format = 'metadata', metadataHeaders } = {}) {
    const token = await getToken(userEmailId);
    const p = new URLSearchParams({ format });
    (metadataHeaders || []).forEach((h) => p.append('metadataHeaders', h));
    return api(token, `/messages/${id}?${p}`);
  }

  // ── Spam rescue / labels — remove SPAM, add INBOX ───────────────────────────
  async function modifyLabels(userEmailId, id, { add, remove } = {}) {
    const token = await getToken(userEmailId);
    return api(token, `/messages/${id}/modify`, {
      method: 'POST',
      body: JSON.stringify({ addLabelIds: add || [], removeLabelIds: remove || [] }),
    });
  }

  return {
    isConfigured, authorizeUrl, exchangeCode, getToken, getProfileEmail,
    sendNewMessage, sendThreadReply, listMessages, getMessage, modifyLabels,
  };
}

module.exports = { createGmailProvider };
