# Warm-up Pool + Advanced Sequencing — Build Plan

Goal: merge the two things the owner liked from the tools he was using —
**Saleshandy's mailbox warm-up / deliverability** and **Apollo's sequencing /
outreach** — into one communication section inside Fute LMS, on top of the
engine that already exists here.

This plan is the design contract for two bodies of work:

1. **Warm-up system** — add a mailbox, set it to warm up for N days (default
   25). The system then sends **real** warm-up email between our own connected
   mailboxes over Microsoft Graph, they reply to each other in short
   conversations, rescue each other from spam, and the ramp climbs each day.
   After the set days the mailbox is marked **warmed up** and can be switched to
   outreach. *(Owner's chosen mode: real Graph sends between mailboxes.)*
2. **Sequencing upgrades** — a BD manager picks a **set of leads from any group**
   (Assigned / Connected / Future / Rejected / …), or a **set of candidates for
   any job across stages**, chooses **which "from" mailboxes** the sequence uses,
   and the sends **rotate across those mailboxes**. *(Owner's chosen mode:
   rotate across the selected mailboxes.)*

Both are **additive and off by default** — the same rule the deliverability and
workflow epics followed. Nothing here changes existing send behaviour until an
admin/BD explicitly turns it on for a specific mailbox or lead set.

---

## Part 0 — What already exists (so we build on it, not beside it)

| Piece | Where | State |
|---|---|---|
| Warm-up **ramp** (outreach cap grows from a start by a step/day) | `index.js:375 warmupLimit()` | ✅ ramp only |
| Warm-up admin knobs (`mailbox_warmup_start` 20, `mailbox_warmup_step` 5) | `config/settings.js` | ✅ |
| `user_emails.warmup_start_date`, `.auto_paused_at` | `migrations/006` | ✅ columns exist |
| Graph send (fresh + threaded reply), per-mailbox tokens | `index.js:973 sendMicrosoftNewMessage`, `:990 sendMicrosoftThreadReply`, `getMicrosoftToken` | ✅ |
| Inbox read + folder machinery (immutable ids) | `index.js:928 graphMailRequest`, bounce/reply sweeps `:1953`/`:2023` | ✅ |
| Workflow engine (definitions/steps/enrollments/tick/exit) | `workflow-engine.js`, `routes/wf.js`, `migrations/007` | ✅ |
| **Bulk enroll** endpoint | `routes/wf.js:134 POST /wf/enroll-bulk` | ✅ |
| Email channel (leads), candidate_email channel (submissions) | `index.js:2392` / `:2530` | ✅ |
| Per-job "Start sequence" (select a job's contacts) | `public/js/06-page-leads.js:280`, `09-page-workflows.js` | ✅ |
| Warm-up **pool** (mailboxes emailing each other) | — | ❌ not built |
| Setting to enrol a mailbox in warm-up for N days + graduate | — | ❌ not built |
| **Cross-group** lead selection → sequence | — | ❌ (per-job only today) |
| Choose / **rotate** "from" mailboxes on a sequence | — | ❌ (uses `job.sending_email_id`) |

**Key fact that shapes the warm-up build:** the existing "warm-up" only *caps*
real outreach volume. It never *sends* anything. The owner's picture — mailboxes
auto-emailing each other and holding conversations — is a genuinely new engine.
The good news: every primitive it needs (send, threaded reply, inbox read,
folder move, per-mailbox tokens, a durable tick loop) already exists and is
proven in the send pipeline.

---

# PART 1 — Warm-up System (real Graph sends)

## 1.1 Target behaviour (the owner's spec, made precise)

- Admin opens a mailbox → **"Start warm-up"** → sets **duration** (default 25
  days), **starting emails/day** (default 5), **daily increase** (default +3),
  and **replies per conversation** (default 3).
- Each day the mailbox sends that day's quota of warm-up emails to **other
  mailboxes in the pool**:
  - Day 1: 5 sends · Day 2: 8 · Day 3: 11 · … · Day 25: `5 + 3×24 = 77`.
- Every warm-up email starts a short **conversation**: the receiving mailbox
  **opens it, replies**, the sender replies back — up to `replies_per_thread`
  (default 3) exchanges — and if it landed in **Junk**, the receiver **moves it
  to Inbox and marks it read/not-junk**. That spam-folder rescue is the actual
  reputation signal, exactly like Saleshandy.
- All warm-up traffic is **invisible to the product**: excluded from reply
  detection, bounce sweeps, template analytics, and outreach quota.
- After the set days (or when admin ends it early), the mailbox is marked
  **`warmed`**; the UI offers **"Switch to outreach."**

## 1.2 Data model — `migrations/009_warmup_pool.sql`

All additive (`ADD COLUMN IF NOT EXISTS`, new tables), same safety posture as 006/007.

```sql
-- Warm-up state on the mailbox itself.
ALTER TABLE user_emails ADD COLUMN IF NOT EXISTS warmup_status TEXT;        -- NULL | 'warming' | 'warmed' | 'paused'
ALTER TABLE user_emails ADD COLUMN IF NOT EXISTS warmup_days INT;           -- target duration (e.g. 25)
ALTER TABLE user_emails ADD COLUMN IF NOT EXISTS warmup_pool_opt_in BOOLEAN DEFAULT FALSE; -- may RECEIVE pool mail
ALTER TABLE user_emails ADD COLUMN IF NOT EXISTS warmup_graduated_at TIMESTAMPTZ;
-- (warmup_start_date already exists from 006 — reused as the ramp origin so the
--  outreach cap ramp and the pool ramp share one start date.)

-- One row per warm-up conversation (a sender→receiver thread).
CREATE TABLE IF NOT EXISTS warmup_threads (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  from_mailbox_id UUID NOT NULL REFERENCES user_emails(id) ON DELETE CASCADE,
  to_mailbox_id   UUID NOT NULL REFERENCES user_emails(id) ON DELETE CASCADE,
  conversation_id TEXT,               -- Graph conversationId, for threading replies
  root_message_id TEXT,               -- durable Graph id of the first message
  subject TEXT,
  exchanges INT NOT NULL DEFAULT 0,    -- messages sent so far in this thread
  target_exchanges INT NOT NULL DEFAULT 3,
  landed_in TEXT,                      -- 'inbox' | 'junk' | 'unknown' (as seen by receiver)
  rescued BOOLEAN DEFAULT FALSE,       -- receiver moved it out of Junk
  status TEXT NOT NULL DEFAULT 'open', -- 'open' | 'done'
  next_action TEXT DEFAULT 'reply',    -- whose turn: which side owes the next message
  next_due_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_warmup_threads_from ON warmup_threads(from_mailbox_id, status);
CREATE INDEX IF NOT EXISTS idx_warmup_threads_due  ON warmup_threads(status, next_due_at);

-- Per-message log (audit + health scoring + dedupe against the reply sweep).
CREATE TABLE IF NOT EXISTS warmup_messages (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  thread_id UUID NOT NULL REFERENCES warmup_threads(id) ON DELETE CASCADE,
  sender_mailbox_id UUID REFERENCES user_emails(id) ON DELETE SET NULL,
  graph_message_id TEXT,
  direction TEXT,                      -- 'out' (this mailbox sent) | 'reply'
  landed_in TEXT,
  rescued BOOLEAN DEFAULT FALSE,
  sent_at TIMESTAMPTZ DEFAULT NOW()
);

-- Daily warm-up send counter per mailbox (separate from email_send_log so
-- warm-up volume never touches outreach quota).
CREATE TABLE IF NOT EXISTS warmup_send_log (
  user_email_id UUID NOT NULL REFERENCES user_emails(id) ON DELETE CASCADE,
  send_date DATE NOT NULL,
  emails_sent INT NOT NULL DEFAULT 0,
  PRIMARY KEY (user_email_id, send_date)
);
```

## 1.3 New admin settings (`config/settings.js`, group "Deliverability")

Same schema/get/set pattern as the existing eight knobs — defaults reproduce the
owner's numbers, so nothing is magic-constant.

| key | label | default | min–max |
|---|---|---|---|
| `warmup_pool_start` | Warm-up starting emails/day | 5 | 1–200 |
| `warmup_pool_step` | Warm-up daily increase | 3 | 0–100 |
| `warmup_pool_days` | Default warm-up duration | 25 | 1–120 |
| `warmup_replies_per_thread` | Replies per warm-up conversation | 3 | 0–10 |
| `warmup_reply_delay_min` | Min minutes before an auto-reply | 30 | 1–1440 |
| `warmup_daily_hard_cap` | Absolute safety cap on warm-up sends/mailbox/day | 200 | 1–1000 |

The pool ramp `warmup_pool_start + warmup_pool_step × dayIndex` is a **separate**
curve from the outreach cap ramp (`mailbox_warmup_start/step`). Both start from
`warmup_start_date`; the pool curve decides *how much warm-up mail to send*, the
cap curve decides *how much real outreach is allowed* during warm-up.

## 1.4 The warm-up engine — `warmup-engine.js` (new module, mirrors `workflow-engine.js`)

Domain-blind-ish helper the same way the workflow engine is a separate module
wired from `index.js` (it needs the Graph functions, which live in `index.js`,
so it takes them via a `ctx` like `routes/*` do). Core functions:

- **`poolMailboxes()`** — connected mailboxes (`microsoft_tokens` join
  `user_emails`) that are either `warmup_status='warming'` or
  `warmup_pool_opt_in=true` and active. These are the send/receive partners.
  A warming mailbox **needs ≥1 other pool mailbox** to have anyone to talk to
  (see §1.8 cold-start).
- **`dailyTarget(mailbox)`** = `min(warmup_daily_hard_cap, start + step × daysSince(warmup_start_date))`.
- **`sendWave()`** (runs on the daily tick) — for each `warming` mailbox:
  1. count today's warm-up sends from `warmup_send_log`;
  2. send `target − alreadySent` fresh warm-up emails, each to a **randomly
     chosen** other pool mailbox (avoid always-same-pair; spread across domains);
  3. content is varied, human-ish, from a rotating template bank (short
     subjects/bodies, no links early on — link/image ratio matters for spam
     scoring, which we already model in `deliverability.js`);
  4. **stamp a hidden header** `X-Fute-Warmup: <thread_id>` via Graph
     `internetMessageHeaders` on the draft, plus a subject nonce, so every later
     read can identify warm-up mail with certainty;
  5. record a `warmup_threads` row (`target_exchanges = warmup_replies_per_thread`)
     and the first `warmup_messages` row.
- **`replyWave()`** (same tick) — for each `open` thread whose `next_due_at` is
  past and that still owes exchanges: the mailbox that received the last message
  **reads it, replies** with `sendMicrosoftThreadReply(...)`, increments
  `exchanges`, flips `next_action`/`next_due_at` (jitter of
  `warmup_reply_delay_min`+random). At `exchanges ≥ target_exchanges`, mark
  `status='done'`.
- **`rescueWave()`** (same tick) — for each pool mailbox, list
  `/me/mailFolders/JunkEmail/messages` filtered to warm-up mail (header/subject),
  and for each: `POST /me/messages/{id}/move {destinationId:'inbox'}`, mark read,
  set the thread's `landed_in='junk'`, `rescued=true`. This is the reputation win.
- **`healthScore(mailbox)`** = f(inbox-vs-junk landing rate from `warmup_threads`,
  bounce rate already tracked, volume vs ramp) → 0–100 for the dashboard.
- **`graduate()`** — any `warming` mailbox past `warmup_days` →
  `warmup_status='warmed'`, `warmup_graduated_at=now`, emit `mailbox.warmed`.

**Scheduling:** reuse the existing in-process timer pattern that already runs the
bounce/reply sweeps and the workflow tick in `index.js`. One warm-up tick every
~1–2 h calls `rescueWave → replyWave → sendWave → graduate`. Sends are spread
across ticks (not all at 09:00) so traffic looks organic. *(At multi-instance
scale this moves to the worker queue described in the enterprise plan §9 — same
caveat as every other in-process loop here; fine for now.)*

## 1.5 Isolation from real outreach (critical, non-negotiable)

Warm-up mail flows between our own addresses, so it must never leak into product
signals:

- **Reply sweep** (`sweepMailboxReplies`) — skip any message whose sender is one
  of our own mailboxes OR that carries `X-Fute-Warmup`. (It already only acts on
  rows matched to a `contact`; a warm-up peer isn't a contact, but we add the
  explicit guard so a peer that *is* also a contact can't trip it.)
- **Bounce sweep** — same `X-Fute-Warmup` guard before NDR parsing.
- **Template analytics / deliverability dashboard** — untouched: warm-up sends go
  to `warmup_send_log`, never to the `emails` table, so `/analytics/templates`
  and `/admin/deliverability` counts don't move.
- **Outreach quota** — warm-up sends increment `warmup_send_log` only; the real
  send loop reads `email_send_log`. The two never mix, so warm-up never eats a
  BD's daily outreach allowance (and vice-versa). The outreach cap ramp still
  applies to real sends during warm-up.

## 1.6 API — new endpoints (a `routes/warmup.js` factory, `ctx`-wired like the rest)

| Method | Path | Who | Does |
|---|---|---|---|
| `GET` | `/warmup/mailboxes` | admin/lead | Pool + per-mailbox status, day, target, health, landed-in rates |
| `POST` | `/warmup/:mailboxId/start` | admin | Body `{days, opt_in_receive}` → set `warming`, `warmup_start_date=today`, `warmup_days` |
| `POST` | `/warmup/:mailboxId/pause` · `/resume` | admin | Toggle `warming`↔`paused` |
| `POST` | `/warmup/:mailboxId/stop` | admin | End early → `warmed` (or clear) |
| `POST` | `/warmup/:mailboxId/opt-in` | admin | Join pool as a receiver only (a healthy mailbox that helps others warm) |
| `POST` | `/warmup/tick` | admin | Manual "run warm-up now" (mirrors `/wf/tick`), returns the wave log |
| `GET` | `/warmup/:mailboxId/threads` | admin/lead | Recent conversations for inspection |

Every mutation emits a domain event (`warmup.started`, `mailbox.warmed`, …) onto
the existing bus so the audit timeline gets it for free.

## 1.7 Frontend — Admin → Deliverability, extended (`public/js/08-page-admin.js`)

The "Mailbox health" card already lists mailboxes; extend it:

- Per mailbox: a **Warm-up** control — "Start warm-up" opens a small form
  (duration, start/day, +per day, replies/convo — pre-filled from settings);
  once warming, show **Day X / N**, today's target, a health meter, inbox-vs-spam
  landing %, and **Pause / Stop / Switch to outreach** (enabled at graduation).
- A **pool view**: which mailboxes are warming, which are opt-in receivers, a
  "Run warm-up now" button (calls `/warmup/tick`) with the wave log, mirroring
  the Workflows page's "Run engine now."
- Reuse existing chips/among the current card styling — no new design system.

## 1.8 Prerequisites & cold-start (flagging honestly)

- Warm-up needs **≥2 connected mailboxes** in the pool to have partners. With one
  mailbox there's no one to email; the UI must say so and the engine no-ops
  gracefully.
- Best signal comes from a handful of mailboxes across a few domains (the
  enterprise plan's "seed with ~20–30 Fute mailboxes" note). Document the minimum
  as "connect at least 2–3 mailboxes before warming any."
- **Real sends = real consequences**: warm-up traffic hits real inboxes and
  counts toward Microsoft per-mailbox send limits. The `warmup_daily_hard_cap`
  and the existing send-window throttle keep this bounded; still, this is the one
  module where a live mailbox is genuinely used, so it ships as a **draft PR with
  a manual checklist** (same rule as the live-send pipeline) and is verified on
  one real test-mailbox pair before wider use.

## 1.9 Waves (each its own PR, verified, additive)

1. **Migration 008 + settings** — columns/tables/knobs, engine inert. Verify:
   `node --check`, settings unit test, boot smoke (engine off with no data).
2. **`warmup-engine.js` send + thread model** — `sendWave`/`replyWave` writing to
   the warm-up tables; hidden-header tagging; **no** rescue yet. Verify against a
   throwaway Supabase (route-mount + dependency check pattern already used in
   `test/backend-smoke.mjs`).
3. **Isolation guards** — reply/bounce sweep `X-Fute-Warmup` exclusion; assert
   warm-up peers never create `emails` rows or move analytics.
4. **`rescueWave` + health + graduation** — junk→inbox move, `landed_in`,
   `mailbox.warmed`.
5. **`routes/warmup.js` + timer wiring** — endpoints, hourly tick, events.
6. **Frontend warm-up controls** — verified by real nav clicks (the §3-#79.3
   "reachability is part of done" lesson).
7. **Live pilot** — draft PR + `MANUAL_CHECKLIST.md` entry: warm one real
   test-mailbox pair, confirm sends/replies/rescue/graduation end-to-end.

---

# PART 2 — Advanced Sequencing (cross-group selection + mailbox rotation)

## 2.1 What exists vs. the gap

The engine and bulk-enroll are done. Two gaps:

1. **Selection is per-job.** You start a sequence from inside one job
   (`06-page-leads.js:280`). The owner wants to select **leads across many jobs**
   filtered by group, or **candidates across stages**, and sequence them at once.
2. **From-mailbox is fixed to `job.sending_email_id`** (`index.js:2402`) /
   recruiter primary (`:2538`). The owner wants to **choose the "from" mailboxes**
   and have sends **rotate** across them.

## 2.2 Cross-group lead selection (Leads page)

- Add a **selection mode** to the Leads list: a checkbox per lead row, honoring
  the current group/stage filter (Unassigned / Assigned / Connected / Rejected /
  Future / In Discussion / Qualified). A sticky action bar shows **"Sequence N
  leads."** "Select all in this group / first X" covers the owner's "select x'
  number of those leads."
- Clicking it opens the existing **Start-sequence** modal
  (`09-page-workflows.js` `wfEnrollSelectionInto`), extended with a **from-mailbox
  picker** (§2.3).
- **Which contact of each lead?** Default to the lead's **primary contact**
  (`contacts.is_primary`), with a "include all eligible contacts" toggle. Items
  posted to `/wf/enroll-bulk` become `{entity_id: contactId, job_id, contact_id}`
  per selected contact.
- **Stage guard:** hand-picking a Rejected/Future lead is a deliberate act, so
  those enrollments must not be silently skipped by the email channel's
  `job.stage !== 'Assigned'` guard. Bulk-enroll from the Leads page sets
  `metadata.any_stage = true`; the email channel honors
  `cfg.any_stage || enrollment.metadata.any_stage` (one-line change at
  `index.js:2398`).

## 2.3 From-mailbox choice + rotation (the core new mechanic)

- `/wf/enroll-bulk` gains an optional **`from_mailbox_ids: [uuid,…]`**.
- When present, the bulk enroller **round-robins** the mailboxes across the batch:
  enrollment *i* gets `metadata.from_mailbox_id = from_mailbox_ids[i % n]`. Each
  lead's whole sequence (initial + follow-ups) then sends from **one** assigned
  mailbox, but the **batch is spread** across all chosen mailboxes — this is the
  Apollo/Saleshandy rotation, and keeping one mailbox per lead preserves reply
  **threading** (follow-ups thread off the same Sent item).
- **Email channel change** (`index.js:2392`): resolve the mailbox as
  `enrollment.metadata.from_mailbox_id` (load from `user_emails`) **else**
  `job.sending_email` (today's behaviour) — a pure superset, so existing
  enrollments are unchanged.
- Same idea for **`candidate_email`** (`index.js:2530`): prefer
  `metadata.from_mailbox_id`, else `recruiterSendingMailbox(recruiterId)`.
- Rotation still respects each mailbox's own **warm-up cap, auto-pause, and
  quota** (the channel already checks these per send) — so a sequence can even
  rotate across mailboxes that are mid-warm-up without exceeding their ramps.
- **Validation:** chosen mailboxes must be active + connected
  (`microsoft_tokens`); the picker only offers those, and the endpoint re-checks.

## 2.4 Candidate cross-stage selection (recruiting side)

- The engine already sequences **submissions** (`candidate_email`,
  `recruiter_task`, `submission_stage_move`). Add the same **selection surface**
  on the candidate/BD workflow page (`public/js/25-workflow-bd.js` already has a
  per-job candidate multi-select): let a BD pick candidates **across submission
  stages** (Sourced / Screening / Submitted to BDM / … / Placed) **for a chosen
  job order**, then Start-sequence with the from-mailbox picker.
- Items become `{entity_id: submissionId}` with `entity_type:'submission'` — the
  bulk endpoint already supports this shape.

## 2.5 Backend changes summary (small, surgical)

| File | Change |
|---|---|
| `routes/wf.js` | `/wf/enroll-bulk`: accept `from_mailbox_ids`, validate active+connected, round-robin assign `metadata.from_mailbox_id`; accept `any_stage` → `metadata.any_stage` |
| `index.js:2392` (email channel) | Prefer `enrollment.metadata.from_mailbox_id`; honor `enrollment.metadata.any_stage` |
| `index.js:2530` (candidate_email) | Prefer `enrollment.metadata.from_mailbox_id` |
| `routes/wf.js` `/wf/enrollments` | Return the assigned `metadata.from_mailbox_id` (+ address) so the UI can show "sending from" per enrollment |

Rotation *choice* rides in the existing `workflow_enrollments.metadata JSONB`,
but making the **live send loop** actually authenticate with the rotated mailbox
needs a per-email override the loop reads: `migrations/008_email_sending_override.sql`
adds `emails.sending_email_id` (nullable → falls back to `job.sending_email_id`,
so every existing row is unchanged). The workflow email channel pins the queued
row to the chosen mailbox; the send loop resolves it best-effort (a missing
column just means no rotation, never a break). **Status: shipped** — see the PR.

## 2.6 Frontend changes summary

| File | Change |
|---|---|
| `public/js/06-page-leads.js` | Lead-row selection mode + "Sequence N leads" action bar (group-aware, select-first-X) |
| `public/js/09-page-workflows.js` | From-mailbox multi-select in the Start-sequence modal; "rotate across N mailboxes" summary; pass `from_mailbox_ids`, `any_stage` to `/wf/enroll-bulk`; show "from" per enrollment |
| `public/js/25-workflow-bd.js` | Cross-stage candidate selection for a job order → same Start-sequence modal |
| `public/js/22-api.js` | (if needed) surface connected sending mailboxes for the picker |

## 2.7 Waves (each its own PR)

1. **Backend rotation + stage bypass** — `enroll-bulk` `from_mailbox_ids` +
   `any_stage`, channel resolution changes. Verify with the dependency-check
   pattern (sign a JWT, enroll a 2-mailbox batch, assert round-robin assignment
   and that the email channel reads the assigned mailbox).
2. **Leads cross-group selection UI** — verified by real nav clicks across groups.
3. **From-mailbox picker + rotation UI** — including the per-enrollment "sending
   from" readout.
4. **Candidate cross-stage selection UI.**

Because the backend gap is tiny, Part 2 ships **much faster** than Part 1 and is
low-risk (no live mailbox pilot needed — sends still go through the proven
pending-email pipeline; only *which* mailbox is chosen changes).

---

# PART 3 — Suggested PR order (interleaved so value lands early)

| # | PR | Part | Risk |
|---|---|---|---|
| 1 | Sequencing: rotation + stage bypass (backend) | 2.1 | low |
| 2 | Sequencing: Leads cross-group selection UI | 2.2 | low |
| 3 | Sequencing: from-mailbox picker + rotation UI | 2.3 | low |
| 4 | Sequencing: candidate cross-stage selection | 2.4 | low |
| 5 | Warm-up: migration 008 + settings | 1.9 | low |
| 6 | Warm-up: engine send/reply model + isolation guards | 1.9 | med |
| 7 | Warm-up: rescue + health + graduation | 1.9 | med |
| 8 | Warm-up: routes + timer + admin UI | 1.9 | med |
| 9 | Warm-up: **live pilot** (draft PR + manual checklist) | 1.9 | high (live mailboxes) |

Sequencing (1–4) delivers the Apollo-style outreach upgrade quickly and safely;
warm-up (5–9) builds the Saleshandy replacement behind it, ending with a
supervised live pilot on one real mailbox pair before anyone warms a production
inbox.

---

# PART 4 — Open decisions (surface before coding each part)

1. **Warm-up content bank** — canned varied snippets to start; optionally route
   through the existing `/ai/generate-*` endpoints for more organic bodies (costs
   AI credits per warm-up mail — probably not worth it; canned is standard).
2. **Pool scope** — pool is currently all of Fute's own connected mailboxes.
   When multi-tenancy lands (enterprise plan §D), the pool must be shared *and*
   org-isolation-aware; for now single-org is fine.
3. **Which contacts on a lead** get sequenced by default — primary only
   (recommended) vs. all eligible. Picked at build time of PR #2 unless owner
   prefers otherwise.
4. **Rotation granularity** — per-lead mailbox assignment (recommended, preserves
   threading) vs. per-send rotation. Plan assumes per-lead.

---

*Compiled 2026-07-14 for `princethomas37/fute-lms-backend`, branch
`claude/email-warmup-sequencing-7dbhmv`. Additive, off-by-default, one verified
PR per wave — same conventions as the deliverability and workflow epics.*
