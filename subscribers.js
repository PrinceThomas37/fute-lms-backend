// ============================================================================
// Domain-event subscribers — the "react" half of the event bus.
//
// registerSubscribers(deps) is called ONCE from index.js after the work
// functions exist. Emitters never call these reactions directly; they just
// announce an event and the matching reaction(s) run here. To add new
// behaviour, subscribe to an event here (or in another module) — there is no
// need to touch the code that emits it.
// ============================================================================
const { EVENTS, emit, on, onAny } = require('./events');

function registerSubscribers(deps) {
  const {
    supabase,
    skipActiveFollowUpsForContact,
    autoSendForManager,
    generateEmailsForJobs,
    setSendProgress,
    clearSendProgress,
  } = deps;

  // ── Timeline recorder ── persist every event (best-effort; never blocks a
  // reaction or throws). This is what powers GET /events/recent.
  onAny(async (e) => {
    try {
      await supabase.from('domain_events').insert({
        event: e.event,
        payload: e.payload || {},
        actor_user_id: (e.payload && e.payload.actorUserId) || null,
        created_at: e.ts,
      });
    } catch (err) {
      console.error('[events] recorder failed:', err && err.message);
    }
  });

  // ── A contact went bad (bounce or manual mark-invalid) → cancel its active
  // follow-ups. Previously three call sites poked this directly; now any source
  // of invalidation triggers the same reaction.
  on(EVENTS.CONTACT_INVALIDATED, async (e) => {
    await skipActiveFollowUpsForContact(e.payload.contactId);
  });

  // ── Outreach was queued for a manager → kick the single safe send engine.
  on(EVENTS.OUTREACH_QUEUED, async (e) => {
    await autoSendForManager(e.payload.managerId);
  });

  // ── The follow-up engine queued mail for these BDs → send for each (fired
  // concurrently to match the prior behaviour; autoSendForManager self-guards
  // against concurrent runs for the same manager).
  on(EVENTS.FOLLOWUP_QUEUED, (e) => {
    for (const bdId of (e.payload.bdIds || [])) {
      Promise.resolve(autoSendForManager(bdId))
        .catch(err => console.error('[events] followup autoSend error:', err && err.message));
    }
  });

  // ── Leads were assigned → generate their emails, then announce the outreach
  // is queued (which triggers the send). This is the distribute pipeline, now
  // event-driven. Replicates the prior background generate+send block exactly,
  // including its progress reporting.
  on(EVENTS.LEAD_ASSIGNED, async (e) => {
    const { jobIds, managerId, autoSend } = e.payload;
    // Manual-RA managers: the assignment is recorded (this event) for audit, but
    // no emails are generated or sent — the BD drives outreach by hand.
    if (autoSend === false) {
      console.log(`[AutoSend] Manager ${managerId} is in MANUAL mode — ${(jobIds || []).length} leads assigned, skipping auto generate+send`);
      return;
    }
    try {
      console.log(`[AutoSend] Starting background generate+send for manager ${managerId}, ${(jobIds || []).length} jobs`);
      await setSendProgress(managerId, { active: true, total: 0, sent: 0, failed: 0, current: 'Generating emails...', failDetails: [], startedAt: new Date().toISOString(), autoSend: true });
      const generated = await generateEmailsForJobs(jobIds, managerId);
      console.log(`[AutoSend] Generated ${generated} emails, now sending...`);
      if (generated === 0) {
        console.log(`[AutoSend] No emails generated for manager ${managerId} — check contacts/templates`);
        await setSendProgress(managerId, { active: false, done: true, total: 0, sent: 0, failed: 0, failDetails: [{ error: 'No emails generated — jobs may have no valid contact emails' }], completedAt: new Date().toISOString(), autoSend: true });
        setTimeout(() => clearSendProgress(managerId), 300000);
        return;
      }
      emit(EVENTS.OUTREACH_QUEUED, { managerId });
    } catch (err) {
      console.error('[AutoSend] Background error:', err.message, err.stack);
      await setSendProgress(managerId, { active: false, done: true, total: 0, sent: 0, failed: 1, failDetails: [{ error: `Pipeline error: ${err.message}` }], completedAt: new Date().toISOString(), autoSend: true });
      setTimeout(() => clearSendProgress(managerId), 300000);
    }
  });

  console.log('[events] subscribers registered');
}

module.exports = registerSubscribers;
