# Enterprise Lead Generation + Outreach Engine — Feasibility & Build Plan

Goal: evolve the current single-org LMS into an enterprise product that
(a) generates leads automatically from US job boards, finds POCs and their
emails, and runs the outreach sequence end-to-end ("Automatic RA engine"),
(b) replaces SalesHandy-class tooling — mailbox warm-up, health monitoring,
deliverability "cure" recommendations, full conversation tracking with AI
notes/summaries, and (c) gives org admins minute, structured visibility into
what every user is doing.

Scope also includes: an in-app dialer (Twilio/Dialpad/RingCentral-class) with
auto-record → transcribe → AI summary into notes, a full who/what/when audit
trail across every action, the recruiter ATS (shared candidate pool linked
many-to-many with jobs), and operating at **1000–2000+ seats**.

Verdict up front: **feasible, and roughly 40% already exists.** The sending +
deliverability core (the hard part SalesHandy sells) is built and merged, and
the candidate-pool ↔ job-pool ATS workflow is already live in
`bd_recruiter_routes.js`. The genuinely new work is: lead-source ingestion +
contact enrichment (external data providers, not scraping), the inter-mailbox
warm-up pool, Gmail sending, the dialer, multi-tenancy, and — for the
1000–2000-seat target — a platform hardening pass (queue/Redis/SSO/SOC 2)
described in §9.

---

## 0. Target architecture — "pour data in, the workflow runs it"

The operating model to build toward: an org adds **data** (users, mailboxes,
phone numbers, leads, POCs, candidates) and picks/edits a **workflow design**;
the platform executes the work. Architecturally that is four layers:

```
┌─ DATA ────────────────────────────────────────────────────────────────┐
│ orgs · users · mailboxes · numbers · leads · POCs · candidates ·      │
│ templates    (you add these; nothing else is configuration-by-code)   │
└──────────────────────────┬────────────────────────────────────────────┘
┌─ WORKFLOW ENGINE ────────▼────────────────────────────────────────────┐
│ workflow_definitions  — declarative steps per org:                    │
│   step = { channel, delay, template, conditions, exit_rules }         │
│   e.g. day0 email → day2 follow-up → day3 BD call+LinkedIn task →     │
│        day5 follow-up 2 → exit on reply/bounce/opt-out               │
│ workflow_enrollments — one state machine per contact-in-workflow      │
│ scheduler/queue advances due steps; every transition emits an event   │
└──────────────────────────┬────────────────────────────────────────────┘
┌─ CHANNEL ADAPTERS ───────▼────────────────────────────────────────────┐
│ mailProvider (Graph ✅ / Gmail ⬜) · dialerProvider (Twilio ⬜ / …)    │
│ linkedin-touch (task+prefill) · reminders ✅ · warm-up pool ⬜        │
│ enrichment (Apollo-class) ⬜ · job-source feeds ⬜                    │
└──────────────────────────┬────────────────────────────────────────────┘
┌─ EVENT SPINE ────────────▼────────────────────────────────────────────┐
│ every action/transition → domain_events (append-only)                 │
│ → timelines · my-day · leadership rollups · audit export              │
└───────────────────────────────────────────────────────────────────────┘
```

**The one missing keystone:** today the workflow is **hard-coded** — follow-up
types `fu1`/`fu2`, the day-3 reminder, stage moves are all baked into
`index.js` logic. Everything else on this plan plugs into the engine, but the
engine itself must be extracted first: move the cadence into
`workflow_definitions` rows and per-contact `workflow_enrollments`, so an org
(or we) can change "3 emails + 1 call" to "2 emails + 2 calls + LinkedIn"
without a deploy. Once that exists, every Part-2 capability (dialer, warm-up,
auto-sourcing) is *just another channel adapter or data feeder* — not a new
system.

### Two-bake plan

**Bake 1 — finish the half we have (make the core fully baked):**
1. Extract the workflow engine (declarative definitions + enrollment state
   machine) from the hard-coded fu1/fu2/day-3 logic — keep today's cadence as
   the default seeded workflow so behaviour doesn't change.
   **→ v1 SHIPPED on this branch**: `migrations/007_workflow_engine.sql`
   (organizations + definitions/steps/enrollments/step_runs),
   `workflow-engine.js` (domain-blind core: channel registry, context
   loaders, enroll/tick/exit), `routes/wf.js` (`/wf/*` API), wired in
   `index.js` with four channels (email, bd_touch, reminder, stage_move),
   reply/unsubscribe/bounce exits, and an hourly tick. Additive and off by
   default: nothing auto-enrolls; the seeded "Standard Sales Outreach"
   workflow mirrors today's cadence and runs only for explicit
   `POST /wf/enroll`. The legacy fu1/fu2 engine is untouched; migrating the
   distribute pipeline onto engine enrollments is the follow-up step once
   the engine is validated in production.
2. Finish the mailbox layer: Gmail send/read (stub today) behind the
   `mailProvider` interface.
3. Platform correctness at >1 instance: job queue + Redis state + durable
   event consumption (§9 items 1–3).
4. Multi-tenancy (`org_id` + RLS) — the container everything sits in.
5. Audit coverage: every mutating route emits an event; my-day + leadership
   views (Module G).
6. ATS finishing: dedupe, resume parsing, real search (Module F gaps).

*Definition of done for Bake 1:* onboard a second organization with **zero
code changes** — create org, add users/mailboxes/leads/candidates, pick a
workflow, and the machine runs it end-to-end with full audit visibility.

**Bake 2 — new capabilities, each a plug-in to the baked core:**
warm-up pool (B2) · health/cure (B3) · dialer (E) · conversation sync +
AI summaries (B4) · auto-RA sourcing + enrichment (A) · enterprise access
(SSO/SCIM/SOC 2, §9 item 6).

Bake 1 ≈ Phases 1–2 of §10; Bake 2 ≈ Phases 3–5. The phase estimates stand.

### How to see it work (UI shipped on this branch)

The Workflows UI lives in `public/app.js` (Workflows nav page + job-card
integration). To realize it end-to-end:

1. Apply `migrations/007_workflow_engine.sql` in Supabase (idempotent; seeds
   the default org + "Standard Sales Outreach" workflow). Until then the
   engine is inert and "Run engine now" reports `engine off`.
2. Deploy the branch. Log in as admin/lead → **Workflows** in the sidebar:
   workflow cards with step chains + live enrollment stats, the builder
   ("+ New workflow" / Edit — cadence changes with zero deploys), the
   enrollments table (filter, pause/resume/exit, per-step History), and
   "Run engine now" with the tick log.
3. Open a lead → contact card → **Enroll**. A chip appears
   (`workflow · step x/y · status`) with pause/exit links.
4. Run the engine (or wait for the hourly tick): the initial email lands in
   the Email → Pending queue and sends through the normal engine; the chip
   advances; the BD-touch step creates the call/LinkedIn reminder.
5. Reply from the test inbox → within a sweep cycle the enrollment flips to
   `exited · replied` — visible on the Workflows page, the chip, and the
   events timeline.

---

## 1. What already exists (merged on `main`)

| Capability | Where | State |
|---|---|---|
| Threaded sending engine (Microsoft Graph), send windows, per-mailbox daily caps, throttle | `index.js` (Graph section) | ✅ production |
| Follow-up sequences (fu1/fu2), double-send guard, reminder sends | `index.js`, `routes/workflows.js` | ✅ |
| Reply detection sweep → auto-stop sequence, stage → Connected | reply sweep + `contacts.replied_at` | ✅ |
| Suppression list + opt-out enforcement | `migrations/006`, `/suppression` | ✅ |
| Bounce sweep + per-mailbox bounce-rate auto-pause | `deliverability.js` | ✅ |
| Warm-up **ramp** (cap grows 20 + 5/day from `warmup_start_date`) | `index.js:381` | ✅ ramp only |
| Email verification: MX, disposable block; role/catch-all soft flags; pluggable paid-verifier hook (`VERIFY_API_KEY`) | `email-validation.js` | ✅ heuristic tier |
| Spam content pre-check | `/emails/spam-check` | ✅ |
| Deliverability dashboard (bounce %, reply %, per-mailbox health) | `/admin/deliverability` | ✅ |
| Emergency stop (global + per-BD-manager) | `/admin/sending/*` | ✅ |
| Lead → BD distribution engine | `/distribute/*` | ✅ |
| BD/recruiter pipeline (job orders, submissions, stage gates) | `bd_recruiter_routes.js` | ✅ |
| Per-user insights (RA + BD), activity log, domain-events timeline | `routes/workflows.js`, `/events/recent` | ✅ basic |
| JD parser (non-AI), AI email/summary generation endpoints | `jd-parser.js`, `/ai/*` | ✅ |
| Reminders (incl. OOO-return auto-reminders) | `/reminders` | ✅ |
| Gmail sending | `index.js:2081` | ❌ stub ("not connected yet") |
| Warm-up **pool** (mailboxes emailing each other) | — | ❌ explicitly deferred in `DELIVERABILITY_PLAN.md` |
| Automatic lead sourcing / contact discovery | — | ❌ RAs enter jobs manually (`/jobs/bulk`, `/parse-jd`) |
| Multi-tenancy (other orgs, their mailboxes, isolation) | — | ❌ single-org today |

---

## 2. Module A — Automatic RA engine (lead gen → POC → email → sequence)

Target daily loop, per org:

```
source jobs → dedupe → enrich company → find POCs + emails → verify →
auto-create lead + contacts → generate personalized email → queue in sequence →
follow-ups → day-3 BD task: call / LinkedIn touch (prefilled message + profile link)
```

### A1. Job sourcing (new `lead-sources` module)
- **Do not scrape Indeed directly.** Indeed has no public jobs API for this use,
  actively blocks bots, and its ToS prohibits scraping — an enterprise product
  cannot ship on that foundation. Use licensed data instead:
  - Aggregated job-posting APIs (e.g. Coresignal, TheirStack, Apify-managed
    actors with compliance posture, JSearch/RapidAPI tier for pilot) — these
    cover Indeed/LinkedIn/board postings as *data feeds*.
  - Direct ATS feeds (Greenhouse/Lever/Workday public postings) are free and
    ToS-clean — strong signal for staffing leads.
- New tables: `lead_sources` (org, provider, query config: keywords, locations,
  industries, freshness), `sourced_jobs_raw` (payload, hash for dedupe, status:
  new/duplicated/promoted/rejected).
- Daily cron: pull → hash-dedupe against existing `jobs` (company+title+location)
  → run existing `jd-parser` on the description → create `jobs` rows exactly as
  a manual RA would (`created_by` = system user), stage `New`.
- **Complexity: Medium.** The ingestion plumbing is straightforward; provider
  selection/contracting is the real work. ~2–3 weeks eng once a provider is chosen.

### A2. POC + email discovery (new `enrichment` module)
- Provider-backed (Apollo.io / Hunter / People Data Labs) behind one interface:
  `findPOCs(companyDomain, roles[]) → [{name, title, email, linkedin_url, confidence}]`.
  Apollo is the pragmatic first pick: one API does company match, people search
  by title (HR/TA/Hiring Manager), email + LinkedIn URL.
- Results feed the existing `contacts` table (it already has `linkedin`,
  `email_status`, `deliverability_flags`) → existing verification pipeline runs
  as-is (MX/disposable hard block, role/catch-all soft flag, paid-verifier hook).
- Per-org credit budgeting + caching (`enrichment_cache` keyed by domain) so the
  same company isn't paid for twice across orgs.
- **Complexity: Medium.** ~2 weeks eng. Ongoing cost: enrichment credits are the
  main COGS of the product (price it into the "Automatic RA" tier).

### A3. Auto-sequencing + day-3 BD task
- Auto-generated leads flow into the **existing** distribute → generate →
  queue → follow-up machinery unchanged.
- New: on sequence start, schedule a `reminders` row (type `bd_touch`, day 3)
  for the assigned BD with: contact name, company, the job, **LinkedIn profile
  link (already stored on the contact)**, and an AI-prefilled connection/InMail
  message (`/ai/generate-email` variant with a short-message template).
- **LinkedIn constraint (hard):** LinkedIn's API does not permit automated
  InMail/message sending, and bots get accounts banned. So the product does
  exactly what was described: it *prepares* the touch — profile deep link +
  ready-to-paste message + one-click "mark done / log outcome" — and the BD
  manually sends it. This is the same compromise every compliant competitor makes.
- **Complexity: Low.** ~1 week; reminders + contacts.linkedin + AI endpoints all exist.

### A4. Manual RA vs Automatic RA — the two org modes
- `organizations.ra_mode: 'manual' | 'auto' | 'hybrid'`.
- **Manual**: today's flow, unchanged — RAs source and enter leads.
- **Auto**: A1–A3 run on cron; RA screen becomes a *review queue* (approve /
  reject sourced leads before they enter distribution — recommended default so
  quality stays controllable; a "fully hands-off" toggle can come later).
- **Hybrid**: auto-sourcing fills the pool, RAs still add manually.

## 3. Module B — SalesHandy replacement (warm-up, health, cure)

### B1. Mailbox connection (multi-provider)
- Orgs connect *their own* mailboxes via OAuth: Microsoft Graph (exists) +
  **Gmail API (must build — currently a stub)**. `googleapis` is already a
  dependency; needs OAuth consent flow, token storage/refresh, send + thread +
  inbox-read parity with the Graph functions. Abstract both behind one
  `mailProvider` interface so the send loop stays provider-agnostic.
- **Complexity: Medium-High.** ~3 weeks incl. Google OAuth verification
  (Google's app review for gmail.send/read scopes takes weeks — start early;
  restricted-scope review requires a security assessment at scale).

### B2. Warm-up pool (3-week sequence)
- The piece explicitly deferred from the deliverability epic. Every mailbox
  connected to the platform (across all tenant orgs, opted-in) joins a shared
  pool. Daily cron:
  - each warming mailbox sends N pool-mails (N follows the existing ramp curve,
    3 weeks ≈ 20 → 120/day) with human-ish varied content + reply probability;
  - receiving pool mailboxes **open, reply, mark not-spam, and rescue from the
    spam folder** via the provider API (Graph: move message; Gmail: remove SPAM
    label) — this is the actual signal that trains reputation;
  - all warm-up traffic tagged with a hidden header so it's excluded from
    analytics and reply detection.
- Tables: `warmup_pool_members`, `warmup_exchanges` (sender, receiver, sent_at,
  landed_in: inbox/spam/other, rescued, replied).
- Health score per mailbox = f(inbox-placement rate from pool data, bounce rate,
  spam-folder rate, blacklist status, volume vs ramp).
- **Cold-start note:** a pool needs members. Seed with Fute-owned mailboxes
  (~20–30 across a few domains) until tenant volume takes over.
- **Complexity: High.** ~4–6 weeks. This is the core of the SalesHandy
  replacement and the riskiest module — build it after B1 so both providers
  participate.

### B3. Health monitoring + "cure" engine
- Nightly per-mailbox/domain checks:
  - **DNS**: SPF / DKIM / DMARC record validation (pure DNS lookups, free);
  - **Blacklists**: DNSBL queries (Spamhaus, Barracuda, etc. — free tier);
  - **Placement**: warm-up pool inbox-vs-spam rates (B2 data);
  - existing bounce-rate + auto-pause signals.
- "Cure" = rules engine mapping findings → prescriptions with severity:
  missing DMARC → exact record to add; spam placement rising → auto-lower ramp,
  raise warm-up ratio, pause cold sends for X days; blacklisted → delist links +
  pause. Each cure is a tracked task (issued → acknowledged → resolved → verified).
- **Complexity: Medium.** ~2–3 weeks, mostly rules + dashboard surface on top of
  `/admin/deliverability`.

### B4. Conversation tracking + AI notes/summaries
- Extend the reply sweep from "detect first reply" to **full thread sync**:
  store every inbound/outbound message per conversation (`conversation_messages`
  keyed by provider conversation/thread id — threading ids are already stored).
- Per thread: AI note + running summary (extend `/ai/generate-summary`),
  sentiment/intent tag (interested / not now / objection / unsubscribe),
  regenerated on each new inbound message.
- Surfacing: each user sees notes/summaries **only for mailboxes they own or are
  assigned**; org admins see all (feeds Module C).
- **Complexity: Medium.** ~2–3 weeks. Storage growth is the thing to watch —
  keep bodies trimmed to the new-content part (quote-stripping).

## 4. Module C — Org-wide visibility ("Bhimakavack-style", finer-grained)

Foundations exist (`activity_log`, `domain_events`, `/insights/ra|bd`,
`/events/recent`). Gaps to close:

- **Coverage**: emit events from *every* action — sends, replies, stage moves,
  reminders done/missed, LinkedIn touches logged, cures resolved, logins,
  approvals. One taxonomy: `actor / verb / object / job / org / timestamp`.
- **Rollups**: nightly `user_daily_stats` materialization (leads sourced,
  emails sent, reply rate, touches completed, response SLA) so dashboards don't
  scan raw events (keeps Supabase egress down — same concern as the recent
  caching work).
- **Views**: org admin → team → user drill-down; per-user timeline (minute
  level); per-mailbox story (warm-up day, health, volume, replies); exception
  feed (missed day-3 touches, unanswered replies > 24h, mailboxes degrading).
- **Complexity: Medium.** ~2–3 weeks on top of existing event bus.

## 5. Module E — Built-in dialer (call → record → transcribe → summarize → note)

Target: click a lead's number anywhere in the UI (or work through an
auto-advancing call queue), the call happens inside our interface, is recorded,
transcribed, AI-summarized, and the summary lands on the job/POC timeline
automatically.

### E1. Provider abstraction
- One `dialerProvider` interface (mirror of the `mailProvider` pattern):
  `startCall`, `endCall`, `getRecording`, webhook handlers. Adapters:
  - **Twilio (build first)** — usage-based pricing, global carrier coverage
    (US + India + intl numbers), Voice JS SDK gives a WebRTC softphone in the
    browser, recording + transcription APIs built in. No per-seat licence.
  - **Dialpad / RingCentral (adapters later)** — for orgs that already own
    seats there; their CTI/embed APIs surface click-to-dial and pull call
    events + recordings into our timeline. They carry carrier compliance for us.
- Per-org dialer config: provider, caller-ID numbers, recording on/off,
  recording-consent message.

### E2. In-app softphone + call queue ("power dialer")
- Browser softphone (Twilio Voice SDK) docked in the app; click-to-dial from
  lead/contact/candidate cards; after-call wrap-up form (disposition + note).
- **Daily call queue**: the system lines up the numbers (new leads, day-3
  touches, callbacks due) and auto-advances to the next call when the user
  finishes wrap-up.
- **Compliance constraint (hard, same class as the LinkedIn one):** fully
  automatic machine-initiated dialing is an "autodialer" under TCPA (US) and
  triggers TRAI/DLT rules in India. We ship **progressive dialing** — the
  queue is automatic, but each call fires on the agent being ready/one click —
  not unattended robo-dialing. Recording consent: play a disclosure and honor
  two-party-consent states via a per-state/per-country rule table.

### E3. Recording → summary pipeline
- Call ends → provider webhook → fetch recording → transcribe (Twilio Voice
  Intelligence, or Deepgram/Whisper behind a flag) → `/ai/generate-summary`
  variant produces the note (outcome, objections, next step) → auto-append to
  the job/contact timeline + `calls` table (duration, disposition, recording
  URL, transcript, summary) → emit `call.completed` on the event bus.
- **Complexity: High overall.** ~4–6 weeks for Twilio softphone + queue +
  recording/summary pipeline; Dialpad/RingCentral adapters ~1–2 weeks each
  after. Number procurement + telecom compliance runs in parallel.

## 6. Module F — Recruiter ATS: candidate pool ↔ job pool

**Largely already built** in `bd_recruiter_routes.js` — this was the
BD-manager/recruiter workflow module:
- Shared org-wide **candidate pool** (`candidates` table, `CN-` codes, search,
  skills/experience/resume_url fields) — the "cloud" pool described.
- **Many-to-many linkage exists**: `submissions` joins candidates ↔ job orders;
  one candidate → many jobs, one job → many candidates; a unique constraint
  already blocks duplicate candidate-in-same-job.
- Stage pipeline (Sourced → Screening → Submitted to BDM → Submitted to Client
  → Interview → Offer → Placed) with the BDM approval gate, plus
  `submission_activity` audit per move and recruiter assignment scoping.

Remaining gaps to make it enterprise-grade:
- **Resume parsing + bulk import** (upload → extract name/email/phone/skills —
  reuse `jd-parser`'s skill dictionaries for the skills side).
- **Candidate dedupe** on email/phone at insert, with merge flow.
- **Real search**: Postgres full-text + skill/tag filters (ILIKE-only today).
- Candidate-side timeline (every job they've been submitted to, calls, notes) —
  falls out of the audit layer below.
- **Complexity: Medium — ~2–3 weeks**, because the hard schema/workflow part is done.

## 7. Module G — Full audit trail ("every change recorded, shown to user and leadership")

The requirement: every action — note added, call made, email sent/received,
stage moved, reminder set/done, login — recorded with who/what/when and
visible at the right level.

- Foundations exist: `activity_log`, `domain_events` + event bus,
  `submission_activity`. The gap is **coverage and uniformity**, not plumbing.
- One rule: **every mutating endpoint emits a domain event** (`actor / verb /
  object / job / org / timestamp`). Enforce with a thin wrapper so new routes
  can't forget. Events are append-only (no update/delete) = audit-grade.
- Three read surfaces from the same stream:
  1. **Entity timeline** — everything on this job / POC / candidate, in order;
  2. **My day** — the user's own activity (drives the daily-workflow home
     screen: leads to review, emails to send, calls queued, reminders due);
  3. **Leadership** — org → team → user drill-down, exception feeds (missed
     day-3 touches, replies unanswered > 24 h, idle users), nightly
     `user_daily_stats` rollups so dashboards never scan raw events.
- **Complexity: Medium — ~2–3 weeks**, mostly sweeping existing routes onto the
  bus + the rollup job + UI.

## 8. Module D — Multi-tenancy (the structural prerequisite)

Today the system is single-org. Selling either mode to other organizations requires:

- `organizations` table; `org_id` on users, jobs, companies, contacts, emails,
  templates, settings, mailboxes, events — with Supabase RLS per org.
- Org-scoped settings: send windows, ramp curve, sequences, templates, ra_mode.
- Roles stay as-is but scoped (`admin` → org admin; add `platform_admin` for Fute).
- Billing hooks per tier: **Manual RA** (bring your own leads, full outreach +
  warm-up + visibility) vs **Automatic RA** (adds sourcing + enrichment; priced
  with credit allowances since enrichment is metered COGS).
- **Complexity: High** — not intellectually hard but it touches every table and
  query, and mistakes leak data across customers. ~3–4 weeks + careful review.
  **Do this before onboarding org #2**, not after.

---

## 9. Scaling to 1000–2000+ users per org (the honest architecture answer)

Feature-wise nothing above changes at 2000 seats. Architecturally, several
things that are fine today become the bottleneck, and enterprise buyers add
non-feature requirements:

1. **Stateless, horizontally scaled API.** Today: one Node process holding
   in-memory state (send-progress mirror, pause flags, caches). Multi-instance
   deployment needs that state in **Redis**, and sticky assumptions removed.
2. **Real job queue.** The cron loops (send loop, sweeps, warm-up pool,
   dialer webhooks, transcription, rollups) run in-process today — two
   instances would double-send. Move background work to a queue with worker
   processes (**BullMQ/Redis** or `pg-boss`), idempotent jobs, retries,
   dead-letter visibility.
3. **Durable event bus.** The in-process `events.js` bus doesn't cross
   instances. Domain events already persist to Postgres — subscribers should
   consume from the durable stream (listen/notify or the queue), not memory.
4. **Database at volume.** 2000 users × events/emails/calls = tens of millions
   of rows/yr: partition `domain_events`/`emails`/`calls` by month, rollup
   tables for every dashboard (never aggregate raw at read time), read
   replicas for analytics, connection pooling (pgBouncer — Supabase provides).
5. **Real-time layer.** Softphone events, queue counters, live timelines →
   WebSocket/SSE service backed by Redis pub/sub, not the current polling
   (which was already causing egress cost pain at ~10 users).
6. **Enterprise access requirements** — at 1000+ seats these are *sales
   blockers, not nice-to-haves*: **SSO (SAML/OIDC), SCIM user provisioning,
   granular RBAC** (org → BU → team → user), IP allowlisting, audit-log
   export, data-retention policies, and a **SOC 2 Type II** program
   (recordings + candidate PII + mailbox access make this unavoidable; GDPR/
   Indian DPDP compliance for global orgs).
7. **Observability + limits**: per-org rate limiting, tracing, error budgets,
   status page — buyers this size ask for uptime SLAs.

None of this is exotic — it's the standard mid-size SaaS hardening pass — but
it is **~2–3 months of dedicated platform work** layered across the phases,
plus the (calendar-heavy, ongoing) SOC 2 effort.

## 10. Suggested sequencing (revised with dialer, ATS hardening, scale)

| Phase | Scope | Est. |
|---|---|---|
| 1 | D Multi-tenancy + B1 Gmail/Graph mailbox connect (file Google review day 1) + platform groundwork (Redis, job queue, stateless API) | 6–8 wks |
| 2 | B2 warm-up pool + B3 health/cure engine + G audit-trail coverage & rollups | 6–7 wks |
| 3 | E dialer (Twilio softphone, queue, record→summarize pipeline) + B4 conversation sync/summaries | 6–8 wks |
| 4 | A1–A4 automatic RA engine + F ATS hardening (resume parsing, dedupe, search) | 5–6 wks |
| 5 | Scale/enterprise hardening completion: SSO/SCIM, partitioning, real-time layer, SOC 2 runway | 6–8 wks (overlaps 2–4) |

Roughly **7–9 months with a small team (3–4 engineers)** to the full
2000-seat-ready vision; **4–5 months to a sellable SalesHandy-replacement +
outreach product** for smaller orgs (end of Phase 2/3). Every phase ends
sellable — don't wait for Phase 5 to start pilots with mid-size customers.

## 11. Risks / hard constraints (flagging honestly)

1. **Indeed scraping is not viable for a commercial product** — licensed feeds
   or ATS sources instead (A1). Budget for data cost.
2. **LinkedIn automation is prohibited** — we prepare the touch, the BD sends it.
   Position this as a feature (compliant, no banned accounts), because it is.
3. **Google OAuth restricted-scope review** is the long pole for Gmail — file early.
4. **Warm-up pool cold start** — seed with Fute-owned mailboxes.
5. **Enrichment cost per lead** is real COGS — meter it, cache it, price it in.
6. **Provider sending caps** (Graph/Gmail per-day, per-minute) — the existing
   throttle/window machinery already handles this; keep it per-provider.
7. **Unattended auto-dialing is regulated** (TCPA in the US, TRAI/DLT in
   India): ship progressive dialing (agent-ready, one-click) with a per-region
   recording-consent rule table — not machine-initiated robo-calls.
8. **Call recordings + candidate PII raise the compliance bar** — retention
   policies, encryption at rest, and SOC 2 stop being optional at enterprise
   seat counts; start the program early because it's calendar-bound.
