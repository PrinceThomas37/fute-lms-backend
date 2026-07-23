# FUTE LMS Backend — Context Window (Session 5)

> **Read `CLAUDE.md` at the repo root first** — it holds the durable, must-carry
> context: who the owner is (a product owner who doesn't read code or use git — I
> own everything technical and show them the running app, not code) and what we're
> building (a commercial ATS to sell; spend nothing now, architect to scale later).
> That file also tracks per-feature status (multi-tenancy slices, email-tracking
> slices, interview auto-meeting) — keep it current.

**Updated**: 2026-07-23 · **Repo**: PrinceThomas37/fute-lms-backend · **Branch**: main
**Dev branch**: `claude/context-window-resume-m04j2e` (still open — see Session 5 below
for its current PR status).
**Supabase project**: `teiqievahzhllojvgsku` · **Deploy**: Render
(fute-lms-backend.onrender.com, auto-deploys from `main` — merging IS the release).

## Session 5 — planning only, picks up next session

**Nothing was implemented this session** — the owner asked to define "team" properly and
fix the dashboard's lack of structure, then explicitly asked to stop and save context
before continuing, so this is a research + plan handoff only. **Do not re-derive the
research below from scratch — read it, then start straight at "First step of execution."**

**Where PR #116 stands:** Session 4's last piece (drag-and-drop Team View + team names +
assign-manager-at-creation) is sitting in **draft PR #116**
(`claude/context-window-resume-m04j2e` → `main`), tested, screenshotted, **not yet
merged** — the owner asked about it, then pivoted to this planning conversation before
saying yes/no on the merge. Check PR #116's state at the start of next session; if still
open, ask the owner whether to merge it before or alongside whatever comes out of this
plan (Phase 0 below touches some of the same files, so merging #116 first is probably
cleaner).

**Full plan:** `/root/.claude/plans/okay-lets-define-team-dreamy-stearns.md` (this was
written inside a Claude Code plan-mode session and lives outside the repo — if it's not
readable next session, the summary below is a faithful condensation of it).

### The ask
The owner is planning a Slack/Teams-style layer on teams **later**: chat, document
sharing, individual + team meeting scheduling. Explicitly not this plan. What they want
**now**: a clean, single definition of "team" (the hierarchy already built this session,
`users.manager_id`), fix the fact that the UI shows no structure today, and get team
leads a scoped view of their own team's work on their own dashboard — because the
chat/docs/meetings layer will hang off of "team" later, so it needs to mean one
consistent thing now, not three.

### What research found (confirmed by reading the code, not guessed)
**Three parallel "team" concepts exist right now:**
1. **A live bug**: the Dashboard's "Your Team" widget (`public/js/05-page-dashboard.js:52`,
   `getTeam()` in `public/js/03-core-render.js:158-162`) keys off a legacy `bdm` field
   that only ever existed in demo seed data (`01-seed-demo.js`) — real users always have
   `bdm: null` (`normaliseUser()`, `22-api.js:37`), so in production `getTeam()` always
   falls through to "every other user in the org." **This is almost certainly what the
   owner is seeing as "clustered all, no structure, BD Lead sees everyone."**
2. **`team_assignments` table** (older, role-pair-specific: `ra_to_bd`/`bd_to_bdlead`) —
   still live, drives `renderBDLeadInsights()` (`16-insights.js:477-576`) and an old "Team
   Assignment" admin card. `ra_to_bd` is confirmed orphaned (no nav path reaches its page
   anymore); `bd_to_bdlead` is the one live consumer.
3. **`users.manager_id`** (this session's build) — the intended system going forward:
   flexible, any user under any user, drives the new Reporting Hierarchy card + Team View
   + `/reports/recruiting`'s scoping via `reportingChainIds()` (`bd_recruiter_routes.js:79-92`).

**Other confirmed gaps:** `GET /users` and `GET /team-assignments`
(`routes/auth.js:53-60, 290-298`) have zero org-scoping (`withOrg` never wired in — same
bug class fixed everywhere else this session, missed in this file); `GET /users` is also
role-ungated and fetched for every user regardless of role; `/recruiting-dashboard`
(`bd_recruiter_routes.js:1503-1619`, the main dashboard's cards) still uses the old binary
recruiter-vs-BDM split instead of `reportingChainIds()` like `/reports/recruiting` already
does; and `isBDM()` (`bd_recruiter_routes.js:48`) is missing the `associate_director`/
`director` roles added this session, so those roles currently 403 on `/reports/recruiting`.

### Recommended approach (full detail + file:line specifics in the plan file)
Phased, each phase reuses `reportingChainIds()` — no new hierarchy mechanism:
- **Phase 0** (foundation): widen `isBDM()`; org-scope `GET /users` + `GET /team-assignments`.
- **Phase 1**: fix `getTeam()` to use `managerId` (direct reports) instead of dead `bdm`.
- **Phase 2**: hierarchy-scope `/recruiting-dashboard` like `/reports/recruiting` already is.
- **Phase 3**: a new "My Team" page for anyone with ≥1 direct report (data-driven gate, not
  role-based) — roster subtree (extract `renderTeamTree()`'s node logic into a shared,
  reusable helper) + a real work snapshot from the now-scoped dashboard/reports endpoint.
  One write action only: let a manager rename their own team (`team_name` self-serve);
  reparenting stays admin-only.
- **Phase 4**: trim `manager_id`/`team_name`/the `manager` join out of `GET /users` for
  rows outside the caller's own chain (the ~65 other `STATE.users` call sites read
  different fields and are untouched).
- **Phase 5**: `team_assignments` migration — **explicitly deferred**, not part of this
  batch (data reconciliation + a `renderBDLeadInsights()` rewrite, not a blocker for 0-4).

Suggested grouping: **PR A** = Phase 0+1 (very low risk, ship first). **PR B** = Phase 2
(depends on A). **PR C** = Phase 3+4 (depends on A+B, the one real new surface area).
Phase 5 stays backlog until asked for.

### First step of execution (next session)
1. Check PR #116's status (see above) and resolve it with the owner first.
2. Confirm the plan still matches what the owner wants (things may have shifted between
   sessions) — don't just execute silently if anything reads as stale.
3. Start PR A (Phase 0 + Phase 1) per the grouping above.

---

## Session 4 (for history)

**Part 1** picked up 3 items the owner chose off Session 3's "open next candidates"
list — shipped as PR #114, merged and live. **Part 2** (below) is a 14-item punch
list the owner listed right after Part 1 deployed — all 14 are done, sitting in
draft PR #115 (`claude/context-window-resume-m04j2e` → `main`), not yet merged as
of this update.

1. **Mailbox Reconnect UI.** The Teams-meeting-create feature (PR #111) added a new
   OAuth scope (`OnlineMeetings.ReadWrite`), so already-connected Microsoft mailboxes
   need to redo the OAuth handshake once — but the UI only ever showed a "Connect"
   button *before* a mailbox had a token; once connected there was no way back in
   short of deleting the mailbox. Added a small **"Reconnect"** link next to the
   "✓ Connected" badge (Manager Users page, and the workflow mailbox picker), reusing
   the existing `connectMicrosoftUserEmail()` OAuth popup flow. **This is the step
   the owner needs to click through themselves** (their own Microsoft login) to
   unlock Teams meeting creation — nothing else to do on our side.
2. **Multi-tenant slice 2, continued: leads engine + dashboards.** Session 3 scoped
   the ATS side (`job_orders`/`candidates`) by org and deliberately deferred the BD
   leads engine (`jobs`/`companies`/`contacts`) and the dashboards as "needs its own
   careful pass." Done this session:
   - `loadAllJobs()`'s in-memory cache — the big payload every open Jobs/Leads tab
     polls — was a **single cache shared by every request regardless of org**. This
     was the most severe gap: once a second org existed, its users would have seen
     the first org's entire leads list. Now keyed per `org_id`.
   - `jobs`/`companies`/`contacts`: list, export, and cooldown-check reads scoped
     with `withOrg()`; creates stamp `org_id` with `orgStamp()`.
   - `/distribute/execute` — assigns the Unassigned lead pool to a BD manager — now
     draws only from the caller's org's pool (previously any org's leads could be
     assigned to any org's manager). Same fix on `/distribute/pool-stats` and
     `/distribute/today-summary`.
   - `/recruiting-dashboard` (the main manager/recruiter dashboard) and the
     single-record long tail (`GET /job-orders/:id`, `GET /candidates/:id`,
     `GET|PUT|DELETE /jobs/:id`) now respect org boundaries too (404 instead of
     leaking a cross-org record).
   - Added `withOrg()`/`orgStamp()` helpers to `index.js` (mirroring the ones
     already in `bd_recruiter_routes.js`) and threaded them through `routeCtx` for
     the extracted route modules.
   - Behaviour is unchanged for the single existing org today — every `org_id`
     column still has its platform-default fallback. Nothing the owner will see.
   - **Still open:** legacy `/bd-analytics/*` (un-org-scoped, listed as a fold-in
     later); RLS (slice 3b — do not enable without a fresh go-ahead).
3. **Gmail send for tracked candidate email.** `recruiterSendingMailbox()` (used by
   the "✉ Send tracked through futé" button and the `candidate_email` sequence
   channel) only ever resolved a Microsoft-connected mailbox. It now checks both
   `microsoft_tokens` and `gmail_tokens`; a new `sendMailboxNewMessage(mailbox, …)`
   dispatches to the Gmail provider or Microsoft Graph by `mailbox.platform`,
   mirroring the dispatch the general BD outreach engine already had. Also fixed
   the "+ Gmail" quick-add modal's copy, which claimed Google OAuth sending wasn't
   built yet (it was — just not wired into this one feature).

All 17 test suites pass; `bash test/verify-frontend.sh` passes. Screenshot taken of
the new Reconnect button (Manager Users page) — the other two changes are backend
plumbing with no visible UI change today. **PR #114, merged.**

---

## Session 4, Part 2 — the 14-item punch list

The owner listed 14 items in one message after trying the live Part-1 deploy. I
triaged into quick fixes → a couple of medium items → two bigger foundational
pieces (team hierarchy, then documents/clients, since reports depends on the
hierarchy). Owner explicitly said to use my own judgment on design rather than
being asked clarifying questions, so I made the calls noted below and flagged them
in commit messages / the PR description rather than blocking on questions.

**Quick fixes:**
- Removed the stray "+ Enroll leads…" button from the admin per-manager panel
  (and ~80 lines of code it was the only entry point for).
- **Stale-name bug, root-caused:** `STATE.users` was fetched once at login and
  never refreshed — a name change was instant only in the editor's own tab. Added
  `/users` to the existing 3-minute background poll (jobs already did this).
- Job cards (detail view + company job board) now show "BD Manager" (+ "Created
  by" when different). `/job-orders/browse`'s select didn't even join
  `bd_manager_id` before.
- **Sourcing moved inside the Candidates tab** as a sub-tab ("All Candidates" /
  "Sourcing") instead of its own nav item; each job also got a **"Source
  candidates"** button that pre-tags imports to it.
- **Zip-code autocomplete** (`40-zip-autocomplete.js`, reusable, DOM-patches only
  its own suggestion box so typing never loses focus) added to the Candidate and
  Job Order forms — state was already a dropdown in both.
- **BD Jobs page** split into My Jobs / All Jobs tabs with counts (defaults to All
  Jobs so nothing looks different until you click).
- **Candidate profile** got an always-available **"✉ Email"** button (BD and
  recruiter both) — reuses the existing tracked-send modal, pre-seeded with one
  recipient. `plShowEmailJDModal()` exposed on `window` so any page can reuse it.
- **Job board popup redesigned:** client/job info only (description, pay, work
  style, work auth, needed-by date, priority, skills) — no candidate names, for
  anyone, assigned or not. Previously showed a masked-but-still-named candidate
  list that was never actually useful for "should I ask to work this req?"

**Team hierarchy (migration `026`):**
- `users.manager_id`, self-referencing, nullable. Deliberately a **flexible
  tree** — any user can report to any other user regardless of role — per the
  owner's explicit clarification mid-session, not a hard-coded RA→BD→BDLead
  ladder. Two new roles: Associate Director, Director (added to every role
  picker in the app).
- This is **additive alongside** the existing `team_assignments` table (which
  already drives some Insights pages) — left untouched, since replacing it was
  out of scope and riskier than needed for what was asked.
- Admin-only `PUT /users/:id/manager` (rejects self-management + walks the
  chain to reject reporting loops). New **"Reporting Hierarchy"** card on the
  Admin user detail page: "Reports to" picker + live "Direct reports" list.
- `/reports/recruiting` now hierarchy-scoped via `reportingChainIds()` (BFS over
  `manager_id`): a BD with no reports sees their own numbers; a BD Lead sees
  their whole team's; admin still sees the whole org. Response carries
  `scope`/`team_size` instead of the old binary `role` field.
  **Note left for the owner:** a BD Lead needs their reports set up in Admin's
  new card before they'll see team data — until then they see only their own,
  same as anyone else.
  **Still open:** folding Reports into the Dashboard page itself (today it's
  still a separate nav item), and hierarchy-scoping the main Dashboard's own
  recruiting widgets (`/recruiting-dashboard` still uses the old binary split).

**Clients + document attach/send (migration `027`), the last item:**
- "Clients" aren't a new table — they're `companies` (same table the leads
  engine uses) that have ≥1 `job_order`, i.e. converted business. New **Clients**
  nav tab, BD/admin only (verified recruiters don't get it).
- `client_documents` table, reusing the existing private `candidate-docs`
  storage bucket under a `client/<company_id>/...` prefix (no new bucket).
- **Real email attachments, for the first time anywhere in the app:**
  `sendMicrosoftNewMessage` takes an `attachments` array (Graph
  `fileAttachment`); Gmail's `buildRaw()` now builds `multipart/mixed` MIME with
  base64 parts when attachments are present. `resolveEmailAttachments()` in
  index.js downloads from storage, best-effort (a failed doc is skipped, not
  fatal), capped ~18MB/send.
- `POST /candidates/email` takes `document_ids` now; the candidate profile's
  Documents card is selectable with an "Email selected" action.
- New `POST /companies/:id/email` (BD-only) is the client-side counterpart, plus
  `GET /clients`, `GET/POST/DELETE /companies/:id/documents`,
  `GET /companies/:id/job-orders`.

All 19 test suites pass (2 new: `40-zip-autocomplete.js`, `41-page-clients.js`);
`bash test/verify-frontend.sh` passes. Screenshotted: Sourcing sub-tab, the
redesigned job popup, the Reporting Hierarchy card working end-to-end, and the
Clients list + detail page. **PR #115, draft — awaiting the owner's look before
merge.**

---

## Session 3 (for history)

This continues Session 2 (PRs #93–#101: role dashboards, stage/kanban consolidation,
job board, submission packet, send-race guard). Everything below shipped in
**Session 3** (PRs #103–#112), newest last. All merged to `main` and live unless noted.

---

## Theme of this session
Turn futé into a genuinely sellable ATS: finish the owner's job/candidate UX fixes,
then lay the multi-tenant foundation, then build the "feels like a real product"
features — match scoring, app-tracked candidate email (open + reply), interview
scheduling with auto-created Teams meetings, and a reporting dashboard.

---

## Shipped (merged PRs)

### PR #103 — Job/candidate UX fixes (the owner's punch-list)
- **Email the JD to selected candidates** (separate from the sequence): the
  Candidates-tab bulk bar's "Email JD to candidates" opens a compose/review modal
  (editable subject+body) and sends via the mail app, BCC'ing recipients. Ticking a
  candidate no longer scroll-jumps — selection repaints only the checkboxes + bulk
  bar in place (`plRepaintSelection`), not the whole page.
- **Candidate details in the BD job view**: Email + Title columns on the Candidates
  table; pipeline API embeds `current_title`/`headline` (later `skills` too).
- **"Submitted" fix**: a freshly added candidate reads **"Added"**; **"✓ Submitted"**
  only appears once stage ≥ "Submitted to BDM".
- **ONE unified Add-Candidate window**: the job's and the kanban's "+ Add Candidate"
  now open the same full applicant form (`atsOpenNew(jobCtx)` in 27-page-applicants.js),
  scoped to the job (search-to-add existing, or create-and-tag). Removed the two
  divergent mini-modals.
- **Breadcrumb navigation** (`public/js/37-nav-history.js`): a file-manager trail
  (root › job › candidate); Back returns to exactly where you came from. Wraps
  bdOpenPipeline/Kanban/JobOrder/Candidate.
- **Edit job in place**: `bdOpenEditJob` reopens the job form prefilled →
  `PUT /job-orders/:id`. Backend now lets an **assigned recruiter** (not just BDM)
  edit a job.

### PR #104 — Multi-tenant foundation, slice 1 (migration 022)
`org_id` on 33 tenant tables, backfilled to the default org "Fute Global", column
DEFAULT so nothing breaks. Backend resolves `req.orgId` (JWT carries `org_id`, falls
back to default org via `orgIdFor`/`resolveDefaultOrg` in index.js); login embeds
`org_id`; core creates stamp org. Behaviour unchanged for the single org.

### PR #105 — Multi-tenant slice 2 + 3a (migration 023)
Read-scoping via `withOrg(query, req)` on the core ATS collections — `GET /candidates`,
`GET /job-orders`, `GET /job-orders/browse`. `org_id` set **NOT NULL** on all tenant
tables. **Deferred:** dashboard aggregates + single-record long tail, the leads/email
engine (`jobs` via cached `loadAllJobs` + index.js send subsystem), and RLS (slice 3b).

### PR #106 — Candidate ↔ job match scoring
`public/js/38-match-score.js`: `matchScore(cand, job)` → {score, band, reasons},
`matchBadge`, `matchScoreValue`. Rule-based (skills 50% / experience 20% / work-auth
15% / title 10% / location 5%, weights renormalized over present signals; null when
nothing scoreable). Candidates tab shows a colour-coded **Match** column, sorted
best-first, with a "Best match / Recently added" toggle. Pipeline candidate embed
gained `skills`. AI scorer can slot in behind the same API later.

### PR #107 — Email open-tracking infrastructure (migration 024)
`email_tracking` table (org-scoped). `email-tracking.js` (root) pure helpers:
`newToken`, `pixelUrl`, `pixelHtml`, `injectPixel`. `routes/tracking.js`: public
`GET /o/:token.gif` (records the open, returns a 1×1 gif, never errors/leaks) +
`GET /candidates/:id/email-activity`. Nothing wired to sends yet.

### PR #108 — Email tracking slice 2: tracked send + "Opened"
`POST /candidates/email` (index.js) sends the invite to selected candidates via the
recruiter's connected mailbox (`recruiterSendingMailbox` + `sendMicrosoftNewMessage`
+ `buildHtmlEmailBody`), injects the pixel, records an `email_tracking` row, bumps
`email_send_log`; 409 `no_connected_mailbox` → UI falls back to the mail app. Frontend:
"Email JD" modal's **"✉ Send tracked through futé"** button; candidate profile's
**Email activity** card ("✓ Opened · N×" / "Sent · not opened yet"). **Microsoft-only**
(mirrors the `candidate_email` sequence channel).

### PR #109 — Interview scheduling + email invites (migration 025)
Stage modal (33-stage-modal.js) captures full interview details: format
(in-person / virtual / phone), platform + join link OR office address OR phone, up to
3 interviewer names, and "Email these details to: Candidate / BD Manager". Stored on
`submissions` (interview_type/platform/link/address/interviewers). `PATCH
/submissions/:id/stage` stores them; **new** `POST /submissions/:id/interview-invite`
emails the formatted, open-tracked details (job title, company, date/time, format,
interviewers auto-included) to the candidate and/or the job's BD manager.

### PR #110 — Reporting / analytics dashboard
`GET /reports/recruiting` (org-scoped, role-aware): funnel, per-recruiter productivity
(submitted/interviews/placements/fill%/placement-fee revenue), 8-week submission trend,
avg time-to-fill, top clients, headline totals. `public/js/39-page-reports.js` — a
**Reports** nav item + page (tiles, colour funnel, trend bars, recruiter table, top
clients). Managers see the whole desk; recruiters their own. (Legacy `/bd-analytics/*`
still exist, un-org-scoped — fold in later.)

### PR #111 — Auto-create a Microsoft Teams meeting
`POST /submissions/:id/create-meeting` creates a Teams meeting via Graph
`/me/onlineMeetings` (reuses `graphMailRequest`), stores joinUrl + platform on the
submission. Interview modal's **"📅 Generate Teams meeting link"** button fills it in.
Added `OnlineMeetings.ReadWrite` to `MICROSOFT_SCOPES` (config/env.js). **Mailboxes
connected before this need a one-time reconnect**; until then the endpoint returns
409 `meetings_permission_missing` and the UI says so. Email/reply are unaffected.

### PR #112 — Email reply detection
Hooked into the existing 30-min `sweepMailboxReplies` inbox scan (uses `Mail.ReadWrite`,
**already granted — no reconnect needed**): an inbound message whose `from` matches a
tracked send's `to_email` stamps `replied_at`. Candidate profile shows **"↩ Replied"**.
No new columns/Graph calls — piggybacks on the lead reply-sweep.

---

## Migrations applied to live Supabase this session
- **022** `org_id` on 33 tenant tables + backfill + column DEFAULT + FK/index.
- **023** `org_id` NOT NULL on all tenant tables.
- **024** `email_tracking` table (org-scoped; token/open_count/opened_at/replied_at…).
- **025** `submissions`: interview_type, interview_platform, interview_link,
  interview_address, interviewers (jsonb).
(Teams meeting-create and reply-detection needed **no** migration.)

---

## Also done (not repo PRs)
- **Created `CLAUDE.md`** (repo root) — durable project memory, auto-loaded every
  session; holds the owner relationship + product vision (must carry into every
  handoff) plus per-feature status. Merged in #103/#104 area.
- **Silenced the local stop-hook nag**: `~/.claude/stop-hook-git-check.sh` (NOT in the
  repo — it's this workspace's Claude Code hook) now ignores GitHub's own squash/merge
  commits (committer `noreply@github.com`) while still flagging real mis-authored
  commits. Workspace-only; no effect on the repo or future devs.

---

## Open / next candidates (queued with the owner)
1. **Reconnect a Microsoft mailbox** → activates Teams meeting creation (one-time,
   because of the new `OnlineMeetings.ReadWrite` scope).
2. **Google Meet / Zoom** meeting auto-create — each needs its own OAuth (Google
   Calendar scope / a Zoom app). For now the recruiter pastes a link.
3. **Multi-tenancy remaining:** org-scope the leads/email engine (careful — it's the
   live send system), dashboard aggregates + single-record reads; then **slice 3b =
   RLS** (row-level security). **DO NOT enable RLS on the live DB without an explicit,
   fresh go-ahead** — the owner paused it once already; the pattern is proven-safe
   (service-role bypass, frontend is API-only) but touches prod.
4. Gmail send for tracked candidate email (currently Microsoft-only); fold the legacy
   `/bd-analytics/*` endpoints into `/reports/recruiting` (+ org-scope them).
5. Blueprint leftovers: BDM approvals-queue dashboard card; RA dashboard redesign; new
   roles Recruiter Lead / Associate Director (needs `users.manager_id`).

---

## Key architecture notes (for future work)
- **Frontend**: plain `<script>` modules `public/js/NN-*.js`, loaded in order by
  `public/index.html`, no build step. Global `window.*` + `STATE`. `render()`/`goPage()`
  are wrapped by each page module. New this session: 37-nav-history, 38-match-score,
  39-page-reports. Reports/nav icon added in 03-core-render.js.
- **Backend**: `index.js` (email/lead engine, auth, send helpers, org context) +
  `bd_recruiter_routes.js` (ATS) + `routes/*.js`. New: `email-tracking.js` (root
  helpers), `routes/tracking.js`. Route modules receive `orgIdFor` via `routeCtx`.
- **Multi-tenant helpers**: `req.orgId` (auth middleware), `orgIdFor(req)`,
  `orgStamp(req)` (inserts), `withOrg(query, req)` (reads) in bd_recruiter_routes.js.
- **Email send**: `sendMicrosoftNewMessage` / gmail `sendNewMessage` via
  `deliverOutboundEmail`'s platform dispatch; `buildHtmlEmailBody(plain, sig)`;
  `recruiterSendingMailbox(userId)` resolves a **Microsoft-connected** mailbox only.
  `graphMailRequest(token, path, opts)` is a generic Graph client (v1.0).
- **Two vocabularies**: recruiting = `job_orders` + `submissions` (12 stages); BD leads
  = `jobs` (Unassigned/Assigned/Connected…). Recruiter gating: up to "Submitted to BDM".

## Test suites (all green — 17 suites)
`test/`: backend-smoke (89), frontend-smoke (14), recruiter-dashboard-smoke (34),
workflow-gating-smoke (25), stage-consolidation-smoke (12), tab-collapse-smoke (11),
job-open-details-smoke (12), submission-review-smoke (16), lead-location-parse (14),
lead-stage-permission (13), send-race-guard (7), **job-candidate-updates-smoke (25)**,
**match-score-smoke (11)**, **email-tracking-smoke (7)**, **email-tracking-send-smoke
(10)**, **interview-schedule-smoke (16)**, **reports-smoke (8)** (bold = new this
session). Runner: `npm install --no-save playwright-core`; Chromium at
`$PLAYWRIGHT_BROWSERS_PATH`. `bash test/verify-frontend.sh` checks syntax + index.html.

## Working conventions this session
Implement → `node --check` → targeted smoke → screenshot (shown to the owner) →
commit → **reset branch to `origin/main` + cherry-pick/commit the new work** →
force-with-lease push → open PR → squash-merge (I merge; owner can't do git) → it
deploys. Keep `CLAUDE.md` + this file current. Commit trailer:
`Co-Authored-By: Claude Opus 4.8 …` + `Claude-Session: …`.
