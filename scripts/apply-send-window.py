#!/usr/bin/env python3
"""Apply send-window gating patch to index.js (idempotent)."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
idx = ROOT / 'index.js'
snippet = (ROOT / 'lib-send-window-snippet.js').read_text()
text = idx.read_text()

# Import / POST / PUT timezone
old_imp = """    const tzMap = {'ny':'EST','nj':'EST','fl':'EST','ma':'EST','pa':'EST','ga':'EST','nc':'EST','sc':'EST','va':'EST','ct':'EST','me':'EST','nh':'EST','vt':'EST','ri':'EST','de':'EST','md':'EST','dc':'EST','oh':'EST','mi':'EST','in':'EST','ky':'EST','wv':'EST','tn':'EST','tx':'CST','il':'CST','mn':'CST','wi':'CST','mo':'CST','ia':'CST','ks':'CST','ne':'CST','sd':'CST','nd':'CST','ok':'CST','la':'CST','ar':'CST','ms':'CST','al':'CST','co':'MST','az':'MST','nm':'MST','ut':'MST','wy':'MST','mt':'MST','id':'MST','ca':'PST','wa':'PST','or':'PST','nv':'PST','ak':'PST','hi':'PST'};
    function getTimezone(location) {
      if (!location) return 'EST';
      const loc = location.toLowerCase();
      for (const [state, tz] of Object.entries(tzMap)) { if (loc.includes(state)) return tz; }
      return 'EST';
    }
    function getFreshness(openedDate, createdDate) {"""
if old_imp in text:
    text = text.replace(old_imp, '    function getFreshness(openedDate, createdDate) {', 1)
text = text.replace('timezone: getTimezone(j.location)', 'timezone: getTimezoneFromLocation(j.location)')

old_post = """    const tzMap = {'ny':'EST','nj':'EST','fl':'EST','ma':'EST','pa':'EST','ga':'EST','nc':'EST','sc':'EST','va':'EST','ct':'EST','tx':'CST','il':'CST','mn':'CST','co':'MST','az':'MST','ca':'PST','wa':'PST','or':'PST'};
    let timezone = 'EST';
    if (location) { const loc = location.toLowerCase(); for (const [s, tz] of Object.entries(tzMap)) { if (loc.includes(s)) { timezone = tz; break; } } }
    let freshness = 'Normal';"""
if old_post in text:
    text = text.replace(old_post, "    const timezone = getTimezoneFromLocation(location);\n    let freshness = 'Normal';", 1)

put_old = "    if (location !== undefined) updates.location = location;\n    if (source !== undefined) updates.source = source;\n    if (job_url !== undefined) updates.job_url = job_url;\n    if (stage !== undefined) {\n      const bdStages = ['Connected','Rejected','Future','In Discussion'];"
put_new = "    if (location !== undefined) {\n      updates.location = location;\n      updates.timezone = getTimezoneFromLocation(location);\n    }\n    if (source !== undefined) updates.source = source;\n    if (job_url !== undefined) updates.job_url = job_url;\n    if (stage !== undefined) {\n      const bdStages = ['Connected','Rejected','Future','In Discussion'];"
if put_old in text and put_new not in text:
    text = text.replace(put_old, put_new, 1)

if 'async function fetchPendingEmailsForUser' not in text:
    text = text.replace(
        'async function autoSendForManager(managerId, host, authHeader) {',
        snippet + '\nasync function autoSendForManager(managerId, host, authHeader) {',
        1,
    )

if 'async function autoSendForManager(managerId) {' not in text:
    start = text.find('async function autoSendForManager(managerId, host, authHeader) {')
    end = text.find("\napp.post('/distribute/execute'", start)
    if start == -1 or end == -1:
        raise SystemExit('autoSend markers not found')
    new_auto = """async function autoSendForManager(managerId) {
  if (activeSendByUser.has(managerId)) {
    console.log(`[AutoSend] Already running for manager ${managerId}, skipping`);
    return;
  }
  activeSendByUser.add(managerId);
  try {
    let pendingEmails = await fetchPendingEmailsForUser(managerId);
    if (!pendingEmails.length) {
      console.log(`[AutoSend] No pending emails yet for manager ${managerId}, retrying in 5s...`);
      await new Promise(r => setTimeout(r, 5000));
      pendingEmails = await fetchPendingEmailsForUser(managerId);
      if (!pendingEmails.length) {
        console.log(`[AutoSend] Still no pending emails for manager ${managerId} after retry — aborting`);
        return;
      }
    }
    const totalCount = pendingEmails.length;
    console.log(`[AutoSend] Starting auto-send of ${totalCount} emails for manager ${managerId}`);
    await setSendProgress(managerId, { active: true, total: totalCount, sent: 0, failed: 0, deferred: 0, current: '', failDetails: [], startedAt: new Date().toISOString(), autoSend: true });

    const { sent, failed, skippedWindow, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(managerId, pendingEmails, { autoSend: true });

    const uniqueContactIds = [...new Set(sentContactIds.filter(Boolean))];
    if (uniqueContactIds.length) await supabase.from('contacts').update({ email_sent_at: today() }).in('id', uniqueContactIds);
    const uniqueJobIds = [...new Set(sentJobIds.filter(Boolean))];
    for (const jid of uniqueJobIds) await logActivity(jid, null, managerId, 'emails_sent', `${sent} email(s) auto-sent via Microsoft`, null, null);

    const windowLabel = `${sendWindow.start}:00–${sendWindow.end}:00 lead local time`;
    await setSendProgress(managerId, {
      active: false, done: true, total: totalCount, sent, failed, deferred: skippedWindow,
      failDetails,
      deferredNote: skippedWindow ? `${skippedWindow} email(s) deferred until ${windowLabel}` : undefined,
      completedAt: new Date().toISOString(), autoSend: true
    });
    setTimeout(() => clearSendProgress(managerId), 300000);
    console.log(`[AutoSend] Completed for manager ${managerId}: ${sent} sent, ${failed} failed, ${skippedWindow} deferred (send window)`);
  } catch (err) {
    console.error(`[AutoSend] Error for manager ${managerId}:`, err.message);
  } finally {
    activeSendByUser.delete(managerId);
  }
}

"""
    text = text[:start] + new_auto + text[end:]

EMAIL_SELECT = "id, to_email, subject, body, contact_id, job_id, from_email, followup_type, follow_up_id, job:jobs(timezone, sending_email_id, sending_email:user_emails!sending_email_id(id,email_address,display_name,platform))"
old_sel = "id, to_email, subject, body, contact_id, job_id, from_email, job:jobs(sending_email_id, sending_email:user_emails!sending_email_id(id,email_address,display_name,platform))"
text = text.replace(f".select('{old_sel}')", f".select('{EMAIL_SELECT}')")

ss_old = """    let sent = 0, failed = 0;
    const failDetails = [], sentContactIds = [], sentJobIds = [];

    console.log(`[SendAll] Starting loop for ${totalCount} emails, userId=${userId}`);
    for (const email of pendingEmails) {
      const userEmailId = email.job?.sending_email_id;
      const sendingEmail = email.job?.sending_email;
      const platform = (sendingEmail?.platform || 'Microsoft').toLowerCase();
      console.log(`[SendAll] Processing email to ${email.to_email}, userEmailId=${userEmailId}, platform=${platform}`);

      if (!userEmailId) {
        failed++;
        failDetails.push({ id: email.id, to: email.to_email, from: email.from_email || '—', error: 'No sending email configured for this job' });
        try { await supabase.from('emails').update({ status: 'failed' }).eq('id', email.id); } catch(_) {}
        await setSendProgress(userId, { active: true, total: totalCount, sent, failed, current: email.to_email, failDetails, startedAt: new Date().toISOString() });
        continue;
      }
      if (platform === 'gmail' || platform === 'google') {
        failed++;
        failDetails.push({ id: email.id, to: email.to_email, from: sendingEmail?.email_address || '—', error: 'Gmail sending not connected yet' });
        try { await supabase.from('emails').update({ status: 'failed' }).eq('id', email.id); } catch(_) {}
        await setSendProgress(userId, { active: true, total: totalCount, sent, failed, current: email.to_email, failDetails, startedAt: new Date().toISOString() });
        continue;
      }
      await setSendProgress(userId, { active: true, total: totalCount, sent, failed, current: email.to_email, failDetails, startedAt: new Date().toISOString() });
      try {
        console.log(`[SendAll] Getting token for userEmailId=${userEmailId}`);
        const accessToken = await getMicrosoftToken(userEmailId);
        console.log(`[SendAll] Token obtained, sending to ${email.to_email}`);
        const sendRes = await fetch('https://graph.microsoft.com/v1.0/me/sendMail', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: { subject: email.subject, body: { contentType: 'Text', content: email.body }, toRecipients: [{ emailAddress: { address: email.to_email } }] }, saveToSentItems: true })
        });
        if (!sendRes.ok) { const e = await sendRes.json().catch(() => ({})); throw new Error(e?.error?.message || `HTTP ${sendRes.status}`); }
        await supabase.from('emails').update({ status: 'sent', sent_at: today() }).eq('id', email.id);
        const todayDate = today();
        const { data: logRow } = await supabase.from('email_send_log').select('emails_sent').eq('user_email_id', userEmailId).eq('send_date', todayDate).single();
        await supabase.from('email_send_log').upsert({ user_email_id: userEmailId, send_date: todayDate, emails_sent: (logRow?.emails_sent || 0) + 1 }, { onConflict: 'user_email_id,send_date' });
        if (email.contact_id) sentContactIds.push(email.contact_id);
        if (email.job_id) sentJobIds.push(email.job_id);
        sent++;
        await setSendProgress(userId, { active: true, total: totalCount, sent, failed, current: email.to_email, failDetails, startedAt: new Date().toISOString() });
        if (sent + failed < totalCount) await randomDelay(1, 120);
      } catch (e) {
        failed++;
        failDetails.push({ id: email.id, to: email.to_email, from: sendingEmail?.email_address || email.from_email || '—', error: e.message });
        try { await supabase.from('emails').update({ status: 'failed' }).eq('id', email.id); } catch(_) {}
        await setSendProgress(userId, { active: true, total: totalCount, sent, failed, current: email.to_email, failDetails, startedAt: new Date().toISOString() });
      }
    }

    const uniqueContactIds = [...new Set(sentContactIds.filter(Boolean))];
    if (uniqueContactIds.length) await supabase.from('contacts').update({ email_sent_at: today() }).in('id', uniqueContactIds);
    const uniqueJobIds = [...new Set(sentJobIds.filter(Boolean))];
    for (const jid of uniqueJobIds) await logActivity(jid, null, userId, 'emails_sent', `${sent} email(s) sent via Microsoft`, null, null);
    await setSendProgress(userId, { active: false, done: true, total: totalCount, sent, failed, failDetails, completedAt: new Date().toISOString() });
    setTimeout(() => clearSendProgress(userId), 60000);
    console.log(`[SendSelected] Completed: ${sent} sent, ${failed} failed`);"""

ss_new = """    console.log(`[SendSelected] Starting ${totalCount} emails, userId=${userId}`);
    const { sent, failed, skippedWindow, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(userId, pendingEmails, { autoSend: false });
    const uniqueContactIds = [...new Set(sentContactIds.filter(Boolean))];
    if (uniqueContactIds.length) await supabase.from('contacts').update({ email_sent_at: today() }).in('id', uniqueContactIds);
    const uniqueJobIds = [...new Set(sentJobIds.filter(Boolean))];
    for (const jid of uniqueJobIds) await logActivity(jid, null, userId, 'emails_sent', `${sent} email(s) sent via Microsoft`, null, null);
    const windowLabel = `${sendWindow.start}:00–${sendWindow.end}:00 lead local time`;
    await setSendProgress(userId, {
      active: false, done: true, total: totalCount, sent, failed, deferred: skippedWindow,
      failDetails,
      deferredNote: skippedWindow ? `${skippedWindow} email(s) deferred until ${windowLabel}` : undefined,
      completedAt: new Date().toISOString()
    });
    setTimeout(() => clearSendProgress(userId), 60000);
    console.log(`[SendSelected] Completed: ${sent} sent, ${failed} failed, ${skippedWindow} deferred`);"""

if ss_old in text:
    text = text.replace(ss_old, ss_new, 1)

pat = r"(app\.post\('/emails/queue-all'[\s\S]*?await setSendProgress\(userId, \{ active: true, total: totalCount, sent: 0, failed: 0, current: '', failDetails: \[\], startedAt: new Date\(\)\.toISOString\(\) \}\);)\s*let sent = 0;\s*let failed = 0;[\s\S]*?console\.log\(`\[SendAll\] Completed: \$\{sent\} sent, \$\{failed\} failed`\); console\.log\(`\[SendAll\] FailDetails:`"
repl = r"""\1

    console.log(`[SendAll] Starting loop for ${totalCount} emails, userId=${userId}`);
    const { sent, failed, skippedWindow, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(userId, pendingEmails, { autoSend: false });
    const uniqueContactIds = [...new Set(sentContactIds.filter(Boolean))];
    if (uniqueContactIds.length) await supabase.from('contacts').update({ email_sent_at: today() }).in('id', uniqueContactIds);
    const uniqueJobIds = [...new Set(sentJobIds.filter(Boolean))];
    for (const jid of uniqueJobIds) await logActivity(jid, null, userId, 'emails_sent', `${sent} email(s) sent via Microsoft`, null, null);
    const windowLabel = `${sendWindow.start}:00–${sendWindow.end}:00 lead local time`;
    await setSendProgress(userId, {
      active: false, done: true, total: totalCount, sent, failed, deferred: skippedWindow,
      failDetails,
      deferredNote: skippedWindow ? `${skippedWindow} email(s) deferred until ${windowLabel}` : undefined,
      completedAt: new Date().toISOString()
    });
    setTimeout(() => clearSendProgress(userId), 60000);
    console.log(`[SendAll] Completed: ${sent} sent, ${failed} failed, ${skippedWindow} deferred`); console.log(`[SendAll] FailDetails:`"""
text2, n = re.subn(pat, repl, text, count=1)
if n:
    text = text2

text = text.replace(
    "job:jobs(id,position,stage,assigned_to_bd,company:companies(name,industry,location),sending_email:user_emails!sending_email_id(id,email_address,display_name))",
    "job:jobs(id,position,stage,timezone,assigned_to_bd,company:companies(name,industry,location),sending_email:user_emails!sending_email_id(id,email_address,display_name))",
    1,
)

needle = "    if (emailsToInsert.length) await supabase.from('emails').insert(emailsToInsert);"
repl_fu = """    if (emailsToInsert.length) {
      await supabase.from('emails').insert(emailsToInsert);
      const fuBdIds = [...new Set(emailsToInsert.map(e => e.sent_by).filter(Boolean))];
      setImmediate(() => {
        fuBdIds.forEach(bdId => autoSendForManager(bdId).catch(e => console.error('[FollowupEngine] autoSend error:', e.message)));
      });
    }"""
if needle in text and 'fuBdIds' not in text:
    text = text.replace(needle, repl_fu, 1)

cron_needle = "}, 60000);\n\n// ══════════════════════════════════════════════════════════════\n// MICROSOFT OAUTH"
cron_add = """}, 60000);

// Retry pending emails when leads enter their local send window (every 20 minutes)
setInterval(() => { retryDeferredPendingSends(); }, 20 * 60 * 1000);
setTimeout(() => { retryDeferredPendingSends(); }, 3 * 60 * 1000);

// ══════════════════════════════════════════════════════════════
// MICROSOFT OAUTH"""
if cron_needle in text and 'retryDeferredPendingSends' not in text.split('MICROSOFT OAUTH')[0][-500:]:
    text = text.replace(cron_needle, cron_add, 1)

idx.write_text(text)
print('OK', 'processPending' in text, 'autoSend managerId)' in text)
