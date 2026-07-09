# Enterprise Lead Generation + Outreach Engine — Feasibility & Build Plan

Goal: evolve the current single-org LMS into an enterprise product that
(a) generates leads automatically from US job boards, finds POCs and their
emails, and runs the outreach sequence end-to-end ("Automatic RA engine"),
(b) replaces SalesHandy-class tooling — mailbox warm-up, health monitoring,
deliverability "cure" recommendations, full conversation tracking with AI
notes/summaries, and (c) gives org admins minute, structured visibility into
what every user is doing.

Verdict up front: **feasible, and roughly 40% already exists.** The sending +
deliverability core (the hard part SalesHandy sells) is built and merged. The
genuinely new work is: lead-source ingestion + contact enrichment (external
data providers, not scraping), the inter-mailbox warm-up pool, Gmail sending,
multi-tenancy, and a richer conversation/visibility layer.

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

## 5. Module D — Multi-tenancy (the structural prerequisite)

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

## 6. Suggested sequencing

| Phase | Scope | Est. |
|---|---|---|
| 1 | D Multi-tenancy + B1 Gmail/Graph mailbox connect (start Google review immediately) | 5–6 wks |
| 2 | B2 warm-up pool + B3 health/cure engine | 5–6 wks |
| 3 | B4 conversation sync + AI notes/summaries; C visibility rollups/dashboards | 4–5 wks |
| 4 | A1–A4 automatic RA engine (provider contracts in parallel from Phase 1) | 4–5 wks |

Roughly **4.5–5.5 months of focused build** to the full vision, with sellable
milestones at the end of every phase (Phase 1+2 alone = a SalesHandy
alternative; Phase 4 completes the auto-RA differentiator).

## 7. Risks / hard constraints (flagging honestly)

1. **Indeed scraping is not viable for a commercial product** — licensed feeds
   or ATS sources instead (A1). Budget for data cost.
2. **LinkedIn automation is prohibited** — we prepare the touch, the BD sends it.
   Position this as a feature (compliant, no banned accounts), because it is.
3. **Google OAuth restricted-scope review** is the long pole for Gmail — file early.
4. **Warm-up pool cold start** — seed with Fute-owned mailboxes.
5. **Enrichment cost per lead** is real COGS — meter it, cache it, price it in.
6. **Provider sending caps** (Graph/Gmail per-day, per-minute) — the existing
   throttle/window machinery already handles this; keep it per-provider.
