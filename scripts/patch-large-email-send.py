#!/usr/bin/env python3
from pathlib import Path

HELPERS = r'''
function extractEmailDomain(addr) {
  if (!addr || typeof addr !== 'string' || !addr.includes('@')) return '';
  return addr.split('@').pop().toLowerCase().trim();
}

let bulkSendSettingsCache = { loadedAt: 0, delayMin: 30, delayMax: 60, domainMaxPerHour: 8, defaultDailyLimit: 300, maxPerRun: 0 };

async function getBulkSendSettings() {
  if (Date.now() - bulkSendSettingsCache.loadedAt < 60000) return bulkSendSettingsCache;
  let delayMin = 30, delayMax = 60, domainMaxPerHour = 8, defaultDailyLimit = 300, maxPerRun = 0;
  try {
    const { data } = await supabase.from('app_settings').select('key,value').in('key', [
      'send_delay_min_sec', 'send_delay_max_sec', 'domain_max_per_hour',
      'default_daily_send_limit', 'bulk_send_max_per_run'
    ]);
    (data || []).forEach(r => {
      const n = parseInt(r.value, 10);
      if (r.key === 'send_delay_min_sec' && !Number.isNaN(n) && n >= 1 && n <= 300) delayMin = n;
      if (r.key === 'send_delay_max_sec' && !Number.isNaN(n) && n >= 1 && n <= 600) delayMax = n;
      if (r.key === 'domain_max_per_hour' && !Number.isNaN(n) && n >= 1 && n <= 100) domainMaxPerHour = n;
      if (r.key === 'default_daily_send_limit' && !Number.isNaN(n) && n >= 1) defaultDailyLimit = n;
      if (r.key === 'bulk_send_max_per_run' && !Number.isNaN(n) && n >= 0) maxPerRun = n;
    });
  } catch (_) {}
  if (delayMax < delayMin) delayMax = delayMin;
  bulkSendSettingsCache = { loadedAt: Date.now(), delayMin, delayMax, domainMaxPerHour, defaultDailyLimit, maxPerRun };
  return bulkSendSettingsCache;
}

async function getMailboxDelayBounds(userEmailId, settings) {
  let min = settings.delayMin, max = settings.delayMax;
  try {
    const { data } = await supabase.from('app_settings').select('key,value').in('key', [
      `ue_${userEmailId}_send_delay_min`, `ue_${userEmailId}_send_delay_max`
    ]);
    (data || []).forEach(r => {
      const n = parseInt(r.value, 10);
      if (r.key.endsWith('_min') && !Number.isNaN(n) && n >= 1 && n <= 300) min = n;
      if (r.key.endsWith('_max') && !Number.isNaN(n) && n >= 1 && n <= 600) max = n;
    });
  } catch (_) {}
  if (max < min) max = min;
  return { min, max };
}

async function loadMailboxQuotaState(mailboxIds) {
  const settings = await getBulkSendSettings();
  const limits = {}, sentToday = {}, delays = {};
  const ids = [...new Set(mailboxIds.filter(Boolean))];
  if (ids.length) {
    const { data: accounts } = await supabase.from('user_emails').select('id,daily_send_limit').in('id', ids);
    (accounts || []).forEach(a => { limits[a.id] = a.daily_send_limit || settings.defaultDailyLimit; });
    const { data: logs } = await supabase.from('email_send_log').select('user_email_id,emails_sent').eq('send_date', today()).in('user_email_id', ids);
    (logs || []).forEach(l => { sentToday[l.user_email_id] = l.emails_sent || 0; });
    for (const id of ids) {
      delays[id] = await getMailboxDelayBounds(id, settings);
      if (!limits[id]) limits[id] = settings.defaultDailyLimit;
    }
  }
  return { limits, sentToday, delays, settings };
}

function interleaveByMailbox(emails) {
  const buckets = new Map();
  emails.forEach(e => {
    const mb = e.job?.sending_email_id || '_none';
    if (!buckets.has(mb)) buckets.set(mb, []);
    buckets.get(mb).push(e);
  });
  const keys = [...buckets.keys()];
  const out = [];
  let progress = true;
  while (progress) {
    progress = false;
    for (const k of keys) {
      const q = buckets.get(k);
      if (q && q.length) { out.push(q.shift()); progress = true; }
    }
  }
  return out;
}

function domainSendsInLastHour(domainTimestamps, domain) {
  const cutoff = Date.now() - 3600000;
  return (domainTimestamps[domain] || []).filter(t => t > cutoff).length;
}

async function waitForMailboxSlot(mailboxId, lastSendAtByMailbox, delays) {
  if (!mailboxId || !lastSendAtByMailbox[mailboxId]) return;
  const bounds = delays[mailboxId] || { min: 30, max: 60 };
  const waitSec = Math.floor(Math.random() * (bounds.max - bounds.min + 1) + bounds.min);
  const elapsed = (Date.now() - lastSendAtByMailbox[mailboxId]) / 1000;
  const remaining = waitSec - elapsed;
  if (remaining > 0) await new Promise(r => setTimeout(r, remaining * 1000));
}

function buildDeferredNote({ skippedWindow, skippedQuota, skippedDomain, sendWindow }) {
  const parts = [];
  if (skippedWindow) parts.push(`${skippedWindow} waiting for send window (${sendWindow.start}:00–${sendWindow.end}:00 lead local)`);
  if (skippedQuota) parts.push(`${skippedQuota} waiting for mailbox daily limit (resumes tomorrow)`);
  if (skippedDomain) parts.push(`${skippedDomain} waiting for domain send spacing (retry soon)`);
  return parts.length ? parts.join(' · ') : undefined;
}
'''

PROCESS_FN = r'''async function processPendingEmailSends(userId, pendingEmails, opts = {}) {
  const { autoSend = false } = opts;
  const sendWindow = await getSendWindowHours();
  const totalCount = pendingEmails.length;
  let sent = 0, failed = 0, skippedWindow = 0, skippedQuota = 0, skippedDomain = 0;
  const failDetails = [], sentContactIds = [], sentJobIds = [];
  const startedAt = new Date().toISOString();

  const mailboxIds = [...new Set(pendingEmails.map(e => e.job?.sending_email_id).filter(Boolean))];
  const { limits, sentToday, delays, settings } = await loadMailboxQuotaState(mailboxIds);
  const lastSendAtByMailbox = {};
  const domainTimestamps = {};
  let sendAttempts = 0;
  const maxPerRun = settings.maxPerRun || 0;

  const inWindow = [], outWindow = [];
  for (const email of pendingEmails) {
    const leadTz = email.job?.timezone || 'EST';
    if (isInLeadSendWindow(leadTz, new Date(), sendWindow)) inWindow.push(email);
    else outWindow.push(email);
  }
  const ordered = interleaveByMailbox(inWindow).concat(outWindow);

  for (const email of ordered) {
    const leadTz = email.job?.timezone || 'EST';
    const userEmailId = email.job?.sending_email_id;
    const sendingEmail = email.job?.sending_email;
    const platform = (sendingEmail?.platform || 'Microsoft').toLowerCase();

    const progressBase = {
      active: true, total: totalCount, sent, failed,
      deferred: skippedWindow + skippedQuota + skippedDomain,
      deferredWindow: skippedWindow, deferredQuota: skippedQuota, deferredDomain: skippedDomain,
      failDetails, startedAt, autoSend
    };

    if (!isInLeadSendWindow(leadTz, new Date(), sendWindow)) {
      skippedWindow++;
      await setSendProgress(userId, { ...progressBase, current: `${email.to_email} (waiting ${leadTz} send window)` });
      continue;
    }

    if (maxPerRun > 0 && sendAttempts >= maxPerRun) break;

    if (!userEmailId) {
      sendAttempts++;
      failed++;
      failDetails.push({ id: email.id, to: email.to_email, from: email.from_email || '—', error: 'No sending email configured for this job' });
      try { await supabase.from('emails').update({ status: 'failed' }).eq('id', email.id); } catch (_) {}
      await setSendProgress(userId, { ...progressBase, current: email.to_email });
      continue;
    }

    const limit = limits[userEmailId] || sendingEmail?.daily_send_limit || settings.defaultDailyLimit;
    if ((sentToday[userEmailId] || 0) >= limit) {
      skippedQuota++;
      await setSendProgress(userId, { ...progressBase, current: `${email.to_email} (mailbox daily limit ${limit} reached)` });
      continue;
    }

    const domain = extractEmailDomain(email.to_email);
    if (domain && domainSendsInLastHour(domainTimestamps, domain) >= settings.domainMaxPerHour) {
      skippedDomain++;
      await setSendProgress(userId, { ...progressBase, current: `${email.to_email} (domain ${domain} throttled)` });
      continue;
    }

    if (platform === 'gmail' || platform === 'google') {
      sendAttempts++;
      failed++;
      failDetails.push({ id: email.id, to: email.to_email, from: sendingEmail?.email_address || '—', error: 'Gmail sending not connected yet' });
      try { await supabase.from('emails').update({ status: 'failed' }).eq('id', email.id); } catch (_) {}
      await setSendProgress(userId, { ...progressBase, current: email.to_email });
      continue;
    }
    if (!isValidEmail(email.to_email)) {
      sendAttempts++;
      failed++;
      failDetails.push({ id: email.id, to: email.to_email || '(empty)', from: sendingEmail?.email_address || email.from_email || '—', error: `Invalid recipient address: "${email.to_email}" — not an email` });
      try { await supabase.from('emails').update({ status: 'failed' }).eq('id', email.id); } catch (_) {}
      await setSendProgress(userId, { ...progressBase, current: email.to_email });
      continue;
    }

    await waitForMailboxSlot(userEmailId, lastSendAtByMailbox, delays);
    await setSendProgress(userId, { ...progressBase, current: email.to_email });

    try {
      sendAttempts++;
      const accessToken = await getMicrosoftToken(userEmailId);
      const sendRes = await fetch('https://graph.microsoft.com/v1.0/me/sendMail', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: {
            subject: email.subject,
            body: { contentType: 'Text', content: email.body },
            toRecipients: [{ emailAddress: { address: email.to_email } }]
          },
          saveToSentItems: true
        })
      });
      if (!sendRes.ok) {
        const errData = await sendRes.json().catch(() => ({}));
        throw new Error(errData?.error?.message || `HTTP ${sendRes.status}`);
      }
      await supabase.from('emails').update({ status: 'sent', sent_at: today() }).eq('id', email.id);
      const todayDate = today();
      sentToday[userEmailId] = (sentToday[userEmailId] || 0) + 1;
      await supabase.from('email_send_log').upsert(
        { user_email_id: userEmailId, send_date: todayDate, emails_sent: sentToday[userEmailId] },
        { onConflict: 'user_email_id,send_date' }
      );
      lastSendAtByMailbox[userEmailId] = Date.now();
      if (domain) {
        if (!domainTimestamps[domain]) domainTimestamps[domain] = [];
        domainTimestamps[domain].push(Date.now());
      }
      if (email.contact_id) sentContactIds.push(email.contact_id);
      if (email.job_id) sentJobIds.push(email.job_id);
      sent++;
      await setSendProgress(userId, { ...progressBase, sent, current: email.to_email });
    } catch (e) {
      failed++;
      failDetails.push({ id: email.id, to: email.to_email, from: sendingEmail?.email_address || email.from_email || '—', error: e.message });
      try { await supabase.from('emails').update({ status: 'failed' }).eq('id', email.id); } catch (_) {}
      lastSendAtByMailbox[userEmailId] = Date.now();
      await setSendProgress(userId, { ...progressBase, failed, current: email.to_email });
    }
  }

  return { sent, failed, skippedWindow, skippedQuota, skippedDomain, failDetails, sentContactIds, sentJobIds, totalCount, sendWindow };
}
'''


def main():
    p = Path('/workspace/index.js')
    text = p.read_text()

    text = text.replace(
        'sending_email:user_emails!sending_email_id(id,email_address,display_name,platform))',
        'sending_email:user_emails!sending_email_id(id,email_address,display_name,platform,daily_send_limit))',
    )

    marker = """function padHour(h) {
  const hr = h % 12 || 12;
  const ap = h < 12 ? 'AM' : 'PM';
  return `${hr}:00 ${ap}`;
}

const activeSendByUser = new Set();"""
    if marker not in text:
        raise SystemExit('padHour marker missing')
    text = text.replace(marker, """function padHour(h) {
  const hr = h % 12 || 12;
  const ap = h < 12 ? 'AM' : 'PM';
  return `${hr}:00 ${ap}`;
}
""" + HELPERS + "\nconst activeSendByUser = new Set();", 1)

    start = text.find('async function processPendingEmailSends(')
    end = text.find('\nasync function retryDeferredPendingSends()')
    if start < 0 or end < 0:
        raise SystemExit('processPendingEmailSends not found')
    text = text[:start] + PROCESS_FN + text[end:]

    for old, new in [
        (
            """    const { sent, failed, skippedWindow, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(userId, pendingEmails, { autoSend: false });
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
    console.log(`[SendSelected] Completed: ${sent} sent, ${failed} failed, ${skippedWindow} deferred`);""",
            """    const { sent, failed, skippedWindow, skippedQuota, skippedDomain, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(userId, pendingEmails, { autoSend: false });
    const uniqueContactIds = [...new Set(sentContactIds.filter(Boolean))];
    if (uniqueContactIds.length) await supabase.from('contacts').update({ email_sent_at: today() }).in('id', uniqueContactIds);
    const uniqueJobIds = [...new Set(sentJobIds.filter(Boolean))];
    for (const jid of uniqueJobIds) await logActivity(jid, null, userId, 'emails_sent', `${sent} email(s) sent via Microsoft`, null, null);
    const deferredTotal = skippedWindow + skippedQuota + skippedDomain;
    await setSendProgress(userId, {
      active: false, done: true, total: totalCount, sent, failed, deferred: deferredTotal,
      deferredWindow: skippedWindow, deferredQuota: skippedQuota, deferredDomain: skippedDomain,
      failDetails,
      deferredNote: buildDeferredNote({ skippedWindow, skippedQuota, skippedDomain, sendWindow }),
      completedAt: new Date().toISOString()
    });
    setTimeout(() => clearSendProgress(userId), 60000);
    console.log(`[SendSelected] Completed: ${sent} sent, ${failed} failed, deferred window=${skippedWindow} quota=${skippedQuota} domain=${skippedDomain}`);""",
        ),
        (
            """    const { data: pendingEmails, error: fetchErr } = await supabase
      .from('emails')
      .select('id, to_email, subject, body, contact_id, job_id, from_email, followup_type, follow_up_id, job:jobs(timezone, sending_email_id, sending_email:user_emails!sending_email_id(id,email_address,display_name,platform))')
      .eq('sent_by', req.user.id)
      .eq('status', 'pending');
    if (fetchErr) throw fetchErr;
    if (!pendingEmails || !pendingEmails.length) return res.json({ success: true, sent: 0, failed: 0 });""",
            """    const pendingEmails = await fetchPendingEmailsForUser(req.user.id);
    if (!pendingEmails.length) return res.json({ success: true, sent: 0, failed: 0, queued: 0 });""",
        ),
        (
            """    const { sent, failed, skippedWindow, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(userId, pendingEmails, { autoSend: false });
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
    console.log(`[SendAll] Completed: ${sent} sent, ${failed} failed, ${skippedWindow} deferred`); console.log(`[SendAll] FailDetails:`, JSON.stringify(failDetails.slice(0,3)));""",
            """    const { sent, failed, skippedWindow, skippedQuota, skippedDomain, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(userId, pendingEmails, { autoSend: false });
    const uniqueContactIds = [...new Set(sentContactIds.filter(Boolean))];
    if (uniqueContactIds.length) await supabase.from('contacts').update({ email_sent_at: today() }).in('id', uniqueContactIds);
    const uniqueJobIds = [...new Set(sentJobIds.filter(Boolean))];
    for (const jid of uniqueJobIds) await logActivity(jid, null, userId, 'emails_sent', `${sent} email(s) sent via Microsoft`, null, null);
    const deferredTotal = skippedWindow + skippedQuota + skippedDomain;
    await setSendProgress(userId, {
      active: false, done: true, total: totalCount, sent, failed, deferred: deferredTotal,
      deferredWindow: skippedWindow, deferredQuota: skippedQuota, deferredDomain: skippedDomain,
      failDetails,
      deferredNote: buildDeferredNote({ skippedWindow, skippedQuota, skippedDomain, sendWindow }),
      completedAt: new Date().toISOString()
    });
    setTimeout(() => clearSendProgress(userId), 300000);
    console.log(`[SendAll] Completed: ${sent} sent, ${failed} failed, deferred window=${skippedWindow} quota=${skippedQuota} domain=${skippedDomain}`); console.log(`[SendAll] FailDetails:`, JSON.stringify(failDetails.slice(0,3)));""",
        ),
        (
            """    const { sent, failed, skippedWindow, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(managerId, pendingEmails, { autoSend: true });

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
    console.log(`[AutoSend] Completed for manager ${managerId}: ${sent} sent, ${failed} failed, ${skippedWindow} deferred (send window)`);""",
            """    const { sent, failed, skippedWindow, skippedQuota, skippedDomain, failDetails, sentContactIds, sentJobIds, sendWindow } = await processPendingEmailSends(managerId, pendingEmails, { autoSend: true });

    const uniqueContactIds = [...new Set(sentContactIds.filter(Boolean))];
    if (uniqueContactIds.length) await supabase.from('contacts').update({ email_sent_at: today() }).in('id', uniqueContactIds);
    const uniqueJobIds = [...new Set(sentJobIds.filter(Boolean))];
    for (const jid of uniqueJobIds) await logActivity(jid, null, managerId, 'emails_sent', `${sent} email(s) auto-sent via Microsoft`, null, null);

    const deferredTotal = skippedWindow + skippedQuota + skippedDomain;
    await setSendProgress(managerId, {
      active: false, done: true, total: totalCount, sent, failed, deferred: deferredTotal,
      deferredWindow: skippedWindow, deferredQuota: skippedQuota, deferredDomain: skippedDomain,
      failDetails,
      deferredNote: buildDeferredNote({ skippedWindow, skippedQuota, skippedDomain, sendWindow }),
      completedAt: new Date().toISOString(), autoSend: true
    });
    setTimeout(() => clearSendProgress(managerId), 300000);
    console.log(`[AutoSend] Completed for manager ${managerId}: ${sent} sent, ${failed} failed, deferred window=${skippedWindow} quota=${skippedQuota} domain=${skippedDomain}`);""",
        ),
    ]:
        if old not in text:
            raise SystemExit('replacement block missing')
        text = text.replace(old, new, 1)

    p.write_text(text)
    print('OK')


if __name__ == '__main__':
    main()
