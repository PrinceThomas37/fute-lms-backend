// ============================================================================
// Warm-up engine — real Graph sends between our own connected mailboxes so a
// new mailbox builds sender reputation before it's used for outreach (the
// Saleshandy-class warm-up in docs/WARMUP_AND_SEQUENCING_PLAN.md §1).
//
// A separate module, wired from index.js with the Graph helpers it needs
// (they live in index.js): ctx = { supabase, graphMailRequest, getMicrosoftToken,
// emit, EVENTS }. Off by default — a mailbox only participates once an admin
// sets warmup_status='warming' (or opts it in as a receiver).
//
// One tick does three passes:
//   graduate()        — mailboxes past their warm-up duration → 'warmed'
//   replyRescueWave() — each pool mailbox reads warm-up mail, rescues it from
//                       Junk, and replies to keep the conversation going
//   sendWave()        — each warming mailbox sends the day's quota of new
//                       warm-up openers to random pool partners
//
// All warm-up mail carries an `X-Fute-Warmup: <thread_id>` header so it is
// identifiable on read and can be excluded from outreach reply/bounce sweeps
// and analytics. Warm-up sends are counted in warmup_send_log, never
// email_send_log, so they never touch a BD's outreach quota.
// ============================================================================

const { getSetting } = require('./config/settings');

const WARMUP_HEADER = 'X-Fute-Warmup';

// Short, human-ish, link-free content (links early in a warm-up hurt placement).
const OPENERS = [
  { subject: 'Quick question', body: 'Hey — hope your week is going well. Wanted to run something by you when you get a moment. Talk soon!' },
  { subject: 'Checking in', body: 'Hi there, just checking in to see how things are on your end. Let me know if you had a chance to look at that.' },
  { subject: 'Following up', body: 'Hello! Following up on our earlier chat — keen to hear your thoughts whenever you get a sec.' },
  { subject: 'Are you around this week?', body: 'Hi — are you free for a quick call sometime this week? Happy to work around your schedule.' },
  { subject: 'Small update', body: 'Hey, quick update from my side — things are moving along nicely. Will share more soon. Cheers!' },
  { subject: 'Thoughts?', body: 'Hi there, curious what you think about the idea we discussed. No rush at all — just whenever works.' },
  { subject: 'Great chatting', body: 'Hello — really enjoyed our conversation. Let me know if anything else comes to mind on your side.' },
  { subject: 'Plan for next week', body: 'Hi! Putting together a plan for next week and wanted your input. Let me know what suits you.' },
];
const REPLIES = [
  'Thanks for reaching out — this looks good to me. Appreciate you following up!',
  'Sounds great, works on my end. Let me know the next step whenever you are ready.',
  'Perfect, thanks for the note. I will take a look and get back to you shortly.',
  'Good to hear from you! Yes, let us keep this moving. Talk soon.',
  'Appreciate the update — all clear on my side. Thanks again!',
  'Great, thanks. Happy to sync up whenever is convenient for you.',
];
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

function createWarmupEngine(ctx) {
  const { supabase, graphMailRequest, getMicrosoftToken, emit, EVENTS } = ctx;
  let ticking = false;

  const nowIso = () => new Date().toISOString();
  const todayStr = () => new Date().toISOString().split('T')[0];
  function daysSince(dateStr) {
    if (!dateStr) return 0;
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return 0;
    return Math.max(0, Math.floor((Date.now() - d.getTime()) / 86400000));
  }
  const headerValue = (msg, name) =>
    (msg.internetMessageHeaders || []).find(h => (h.name || '').toLowerCase() === name.toLowerCase())?.value || null;

  // Connected + active mailboxes that either warm up or opted in to receive.
  async function poolMailboxes() {
    const { data: mbs } = await supabase.from('user_emails')
      .select('id,email_address,display_name,warmup_status,warmup_start_date,warmup_days,warmup_pool_opt_in,is_active')
      .eq('is_active', true);
    const list = (mbs || []).filter(m => m.warmup_status === 'warming' || m.warmup_pool_opt_in);
    if (!list.length) return [];
    const { data: tokens } = await supabase.from('microsoft_tokens').select('user_email_id').in('user_email_id', list.map(m => m.id));
    const connected = new Set((tokens || []).map(t => t.user_email_id));
    return list.filter(m => connected.has(m.id));
  }

  async function warmupSentToday(mailboxId) {
    const { data } = await supabase.from('warmup_send_log').select('emails_sent').eq('user_email_id', mailboxId).eq('send_date', todayStr()).maybeSingle();
    return data?.emails_sent || 0;
  }
  async function bumpWarmupSendLog(mailboxId) {
    const cur = await warmupSentToday(mailboxId);
    await supabase.from('warmup_send_log').upsert(
      { user_email_id: mailboxId, send_date: todayStr(), emails_sent: cur + 1 },
      { onConflict: 'user_email_id,send_date' }
    );
  }

  // ── Send a fresh warm-up opener from `from` to `to`, recording the thread ──
  async function sendOpener(from, to, targetExchanges) {
    const token = await getMicrosoftToken(from.id);
    const { subject, body } = pick(OPENERS);
    const { data: thread, error } = await supabase.from('warmup_threads').insert({
      from_mailbox_id: from.id, to_mailbox_id: to.id, subject,
      target_exchanges: targetExchanges, status: targetExchanges > 0 ? 'open' : 'done',
      next_actor_mailbox_id: to.id
    }).select('id').single();
    if (error) throw error;

    const draft = await graphMailRequest(token, '/me/messages', {
      method: 'POST',
      body: JSON.stringify({
        subject,
        body: { contentType: 'HTML', content: body },
        toRecipients: [{ emailAddress: { address: to.email_address } }],
        internetMessageHeaders: [{ name: WARMUP_HEADER, value: String(thread.id) }]
      })
    });
    await graphMailRequest(token, `/me/messages/${draft.id}/send`, { method: 'POST' });

    const delayMs = await replyDelayMs();
    await supabase.from('warmup_threads').update({
      conversation_id: draft.conversationId || null, root_message_id: draft.id,
      exchanges: 1, landed_in: 'unknown',
      next_due_at: new Date(Date.now() + delayMs).toISOString(), updated_at: nowIso()
    }).eq('id', thread.id);
    await supabase.from('warmup_messages').insert({ thread_id: thread.id, sender_mailbox_id: from.id, graph_message_id: draft.id, direction: 'out' });
    await bumpWarmupSendLog(from.id);
    return thread.id;
  }

  async function replyDelayMs() {
    const base = await getSetting(supabase, 'warmup_reply_delay_min');
    const jitter = Math.floor(Math.random() * base); // base .. 2*base minutes
    return (base + jitter) * 60 * 1000;
  }

  // ── sendWave: each warming mailbox tops up to its daily ramp target ─────────
  async function sendWave(pool) {
    const [start, step, repliesPer, hardCap] = await Promise.all([
      getSetting(supabase, 'warmup_pool_start'),
      getSetting(supabase, 'warmup_pool_step'),
      getSetting(supabase, 'warmup_replies_per_thread'),
      getSetting(supabase, 'warmup_daily_hard_cap'),
    ]);
    let sent = 0;
    const warming = pool.filter(m => m.warmup_status === 'warming');
    for (const mb of warming) {
      const partners = pool.filter(p => p.id !== mb.id);
      if (!partners.length) continue; // nobody to warm with
      const target = Math.min(hardCap, start + step * daysSince(mb.warmup_start_date));
      const already = await warmupSentToday(mb.id);
      const toSend = Math.max(0, target - already);
      for (let i = 0; i < toSend; i++) {
        const partner = pick(partners);
        try { await sendOpener(mb, partner, repliesPer); sent++; }
        catch (e) { console.error(`[warmup] send from ${mb.email_address} failed: ${e.message}`); break; }
      }
    }
    return sent;
  }

  // ── replyRescueWave: each pool mailbox reads warm-up mail, rescues from Junk,
  //    and replies when it's its turn ─────────────────────────────────────────
  async function replyRescueWave(pool) {
    const log = { replied: 0, rescued: 0 };
    for (const mb of pool) {
      try { await processMailbox(mb, log); }
      catch (e) { console.error(`[warmup] reply/rescue for ${mb.email_address}: ${e.message}`); }
    }
    return log;
  }

  async function processMailbox(mb, log) {
    const token = await getMicrosoftToken(mb.id);
    for (const folder of ['Inbox', 'JunkEmail']) {
      let data;
      try {
        data = await graphMailRequest(token,
          `/me/mailFolders/${folder}/messages?$top=25&$orderby=receivedDateTime desc&$select=id,subject,from,conversationId,internetMessageHeaders`);
      } catch (e) { continue; }
      for (const msg of (data.value || [])) {
        const threadId = headerValue(msg, WARMUP_HEADER);
        if (!threadId) continue;
        const { data: thread } = await supabase.from('warmup_threads').select('*').eq('id', threadId).maybeSingle();
        if (!thread) continue;

        let messageId = msg.id;
        // Rescue from Junk → Inbox: the reputation signal.
        if (folder === 'JunkEmail') {
          try {
            const moved = await graphMailRequest(token, `/me/messages/${msg.id}/move`, { method: 'POST', body: JSON.stringify({ destinationId: 'inbox' }) });
            messageId = moved.id || msg.id;
            log.rescued++;
            await supabase.from('warmup_threads').update({ landed_in: 'junk', rescued: true, updated_at: nowIso() }).eq('id', thread.id);
          } catch (_) {}
        } else if (thread.landed_in === 'unknown' || !thread.landed_in) {
          await supabase.from('warmup_threads').update({ landed_in: 'inbox', updated_at: nowIso() }).eq('id', thread.id);
        }

        // Reply only when it's this mailbox's turn, the thread is still open,
        // and the reply delay has elapsed.
        const due = !thread.next_due_at || new Date(thread.next_due_at).getTime() <= Date.now();
        if (thread.status === 'open' && thread.next_actor_mailbox_id === mb.id && thread.exchanges < thread.target_exchanges && due) {
          try {
            await sendReply(token, messageId, thread.id);
            const nextExchanges = (thread.exchanges || 0) + 1;
            const otherId = thread.from_mailbox_id === mb.id ? thread.to_mailbox_id : thread.from_mailbox_id;
            const done = nextExchanges >= thread.target_exchanges;
            const delayMs = await replyDelayMs();
            await supabase.from('warmup_threads').update({
              exchanges: nextExchanges,
              status: done ? 'done' : 'open',
              next_actor_mailbox_id: done ? null : otherId,
              next_due_at: done ? null : new Date(Date.now() + delayMs).toISOString(),
              updated_at: nowIso()
            }).eq('id', thread.id);
            await supabase.from('warmup_messages').insert({ thread_id: thread.id, sender_mailbox_id: mb.id, graph_message_id: messageId, direction: 'reply' });
            await bumpWarmupSendLog(mb.id);
            log.replied++;
          } catch (e) { console.error(`[warmup] reply in thread ${thread.id}: ${e.message}`); }
        }
      }
    }
  }

  async function sendReply(token, parentMessageId, threadId) {
    const draft = await graphMailRequest(token, `/me/messages/${parentMessageId}/createReply`, { method: 'POST', body: JSON.stringify({}) });
    // internetMessageHeaders is writable while the message is a draft; re-stamp
    // the warm-up header so the recipient can identify the reply too.
    await graphMailRequest(token, `/me/messages/${draft.id}`, {
      method: 'PATCH',
      body: JSON.stringify({
        body: { contentType: 'HTML', content: pick(REPLIES) },
        internetMessageHeaders: [{ name: WARMUP_HEADER, value: String(threadId) }]
      })
    });
    await graphMailRequest(token, `/me/messages/${draft.id}/send`, { method: 'POST' });
  }

  // ── graduate: warming mailboxes past their duration become 'warmed' ─────────
  async function graduate() {
    const { data: warming } = await supabase.from('user_emails')
      .select('id,email_address,warmup_start_date,warmup_days').eq('warmup_status', 'warming');
    let graduated = 0;
    for (const mb of (warming || [])) {
      const days = mb.warmup_days || await getSetting(supabase, 'warmup_pool_days');
      if (daysSince(mb.warmup_start_date) >= days) {
        await supabase.from('user_emails').update({ warmup_status: 'warmed', warmup_graduated_at: nowIso() }).eq('id', mb.id);
        emit(EVENTS.MAILBOX_WARMED, { userEmailId: mb.id, email: mb.email_address });
        graduated++;
      }
    }
    return graduated;
  }

  // Per-mailbox health for the dashboard: inbox-placement rate + volume.
  async function healthScore(mailboxId) {
    const { data: threads } = await supabase.from('warmup_threads')
      .select('landed_in,rescued').eq('from_mailbox_id', mailboxId);
    const list = threads || [];
    const known = list.filter(t => t.landed_in === 'inbox' || t.landed_in === 'junk');
    const inbox = list.filter(t => t.landed_in === 'inbox').length;
    const placement = known.length ? Math.round((inbox / known.length) * 100) : null;
    return { threads: list.length, inbox_placement_pct: placement, rescued: list.filter(t => t.rescued).length };
  }

  // ── One tick: graduate, keep conversations going, then send the day's quota ─
  async function tick() {
    if (ticking) return { skipped: 'already_running' };
    ticking = true;
    const log = { pool: 0, graduated: 0, sent: 0, replied: 0, rescued: 0 };
    try {
      let pool;
      try { pool = await poolMailboxes(); }
      catch (e) {
        if (/warmup_status|warmup_threads|warmup_send_log/.test(e.message || '')) return { off: true };
        throw e;
      }
      log.graduated = await graduate();
      // re-fetch so a just-graduated mailbox stops sending this tick
      if (log.graduated) pool = await poolMailboxes();
      log.pool = pool.length;
      if (pool.length >= 2) {
        const rr = await replyRescueWave(pool);
        log.replied = rr.replied; log.rescued = rr.rescued;
        log.sent = await sendWave(pool);
      }
      if (log.pool) console.log('[warmup] tick:', JSON.stringify(log));
      return log;
    } finally {
      ticking = false;
    }
  }

  return { tick, poolMailboxes, healthScore, graduate, WARMUP_HEADER };
}

module.exports = { createWarmupEngine, WARMUP_HEADER };
