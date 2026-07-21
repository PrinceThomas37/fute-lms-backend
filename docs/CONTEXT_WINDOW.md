# FUTE LMS Backend — Context Window (Session 2)

> **Read `CLAUDE.md` at the repo root first** — it holds the durable, must-carry
> context: who the owner is (a product owner who doesn't read code or use git — I
> own everything technical and show them the running app, not code) and what we're
> building (a commercial ATS to sell; spend nothing now, architect to scale later).


**Updated**: 2026-07-21 · **Repo**: PrinceThomas37/fute-lms-backend · **Branch**: main
**Dev branch this session**: `claude/continue-previous-session-20021c` (rebased onto main each PR)
**Supabase project**: `teiqievahzhllojvgsku` · **Deploy**: Render (fute-lms-backend.onrender.com)

This continues the prior context (14 tasks: pipeline, stage modal, kanban, resume
parsing, posting JD, role dashboards — all previously merged). Below is everything
shipped in **this** session, newest last. All work is frontend (`public/js/*.js`,
plain `<script>` modules, no build step) unless noted.

---

## Theme of this session
Make the app **role-relevant** (each user sees only their workflow), then fix the
recruiter/BDM ATS flow end-to-end, then squash bugs found in real use.

---

## Shipped (merged PRs)

### PR #93 — Role-relevant recruiter dashboard
- Pure recruiters (`recruiter` role, none of admin/bd/bd_lead/ra_lead) get a native
  `renderRecruiterDashboard()` in `05-page-dashboard.js`: banner (subs week/month, in
  interview, placements), desk tiles, **My candidate pipeline** by stage, **Upcoming
  interviews**, Reminders. No lead-gen widgets (Your Team, Response trend, Industry
  breakdown, lead Pipeline overview). Leads nav item hidden for pure recruiters.
- `getTeam` leads table excludes pure recruiters (all-zero rows were noise).
- `34-recruiting-dashboard.js` injected "my desk" strip is managers-only now.
- Built from `GET /recruiting-dashboard` (shared 60s cache).

### PR #93 (same) — "My jobs" card on recruiter dashboard
- `/recruiting-dashboard` (recruiter view) returns `jobs_assigned` (week/month/
  quarter/total from `recruiter_assignments.assigned_at`) and `top_jobs` (5 assigned
  jobs ranked by team submissions in last 14 days). `renderRecruiterJobsCard`.

### PR #93 (same) — Company-wide job board + assignment requests
- `GET /job-orders/browse`: every recruiter sees every job (client, location, status,
  priority, assigned recruiter names, submission count, `assigned_to_me`, `my_request`).
- Candidate contacts **masked** until assigned: `GET /job-orders/:id/submissions`
  returns `{ masked:true, submissions }` (name/title/stage only) for unassigned recruiters.
- Migration **020** `assignment_requests` table. `POST /job-orders/:id/request-assignment`,
  `GET /assignment-requests`, `POST /assignment-requests/:id/decide` (BDM approve creates
  the `recruiter_assignments` row). New `public/js/35-job-board.js` ("All Jobs" nav item,
  masked modal, BDM **Assignment requests** card).

### PR #93 (same) — docs/ROLE_UX_BLUEPRINT.md
Per-role design spec (recruiter, BD manager, BD lead, RA, RA lead, admin) + product
decisions: **milestones not quotas**; next-in-line manager sets them; proposed roles
Recruiter Lead + Associate Director; needs `users.manager_id`.

### PR #94 — Convert-to-Job City/State prefill
`bdOpenNewJob` read `lead.state`/`lead.city` which don't exist on a lead (leads only
store a combined `location` string). Added `parseLeadLocation()` splitting "City, ST" /
"City, State", mapping abbreviations to full state names (form's State `<select>` needs
full names). `25-workflow-bd.js`. Test `lead-location-parse-smoke.mjs`.

### PR #95 — Lead stage revert (BD couldn't move Connected→Assigned)
`PUT /jobs/:id` stage matrix only let RA Lead/Admin write "Assigned", so BD/BD Lead
picking it silently no-op'd (200, nothing written). Added "Assigned" to bdStages;
extracted `resolveLeadStageUpdate(hasRole, req, stage)` (pure fn); unauthorized stage
now returns explicit 403 instead of silent success. `routes/jobs.js`. Test
`lead-stage-permission.mjs`.

### PR #96 — Unify stage changes to ONE control + notes modal
- `33-stage-modal.js`: exports single 12-stage list/colors (`ATS_STAGE_LIST`/
  `ATS_STAGE_COLORS`). Modal header shows explicit **[current] → [target]** confirmation;
  **Note is required** on every stage change.
- `28-page-pipeline.js`: removed divergent `pipeline_status` vocabulary + the
  no-confirmation **Promote** button. One "Stage" dropdown drives all via `plMove()`:
  promoted rows open the modal directly; un-promoted rows silent-promote to "Sourced"
  then open the same modal.
- Real **futé letterhead** in `36-resume-format.js` (green logo base64 + Dallas footer
  "8111 Lyndon B. Johnson Freeway, Suite 1340, Dallas, TX 75251", brand green #2E7D32).
- Tests `stage-consolidation-smoke.mjs`, updated `workflow-gating-smoke.mjs`.

### PR #96 (same) — Collapse job tabs
Pipeline + Submissions merged into one **"Candidates"** tab (Candidates / Board / Job
details). Ported bulk sequence + Email JD. `bdOpenSubmissions()` aliases to
`bdOpenPipeline()` so all entry points land on Candidates. Test `tab-collapse-smoke.mjs`.

### PR #97 — Delete dead code
Removed `public/js/29-page-submissions.js` (unreachable after the collapse) + its
`<script>` tag. `bdOpenSubmissions` alias moved into `28-page-pipeline.js`.

### PR #98 — "Job not found" + job details header
- `joById()` only searches `STATE.bd.jobOrders` (populated by My Jobs list). Opening a
  job from the All Jobs board or the dashboard top-jobs card left it empty → "Job not
  found". `bdOpenPipeline` now calls `ensureJobOrder(jid)` → fetches `GET /job-orders/:id`
  when missing.
- `renderJobSummaryCard(j)` shows job description/pay/location/work-auth/skills FIRST,
  above the candidates table, for everyone. Test `job-open-details-smoke.mjs`.

### PR #99 — Submission packet + BDM review + add-candidate cleanup + robust job details
1. **Format resume attaches to packet**: `atsFormatResumeFile(file, {onFormatted})` +
   `atsFormattedDocDataUri` (UTF-8 safe base64). Submit-to-BDM uploads BOTH original +
   formatted `.doc`; `submission_details` records both filenames.
2. **BDM review before approve**: `bdViewSubmission(sid)` modal (25-workflow-bd.js) shows
   `submission_details` + attached resume docs, with Approve→Client / Reject inside.
   Awaiting-approval candidate is now clickable + View button.
3. **Add-Candidate**: no default candidate list; opens on create form; search-to-reuse
   only shows matches on query (≥2 chars). `plOpenAdd` stops pre-fetching the pool.
4. `renderJobSummaryCard` always renders (placeholder description when blank).
   Test `submission-review-smoke.mjs`.

### PR #100 — Format Resume crash `f.skills.map is not a function`
Parser (`resume-parser.js`) returns `skills` as a **comma-separated string**; formatter
called `.map`. Added `skillsArray()` normalization. Also fixed field-name mismatch:
formatter read `f.name`/`f.years_experience` but parser returns **`full_name`**/
**`experience_years`** (was silently showing "Candidate"). Now reads full_name/
experience_years/current_title. `36-resume-format.js`. Tests updated to real parser shape.

### PR #101 — Duplicate email sends (send race)  ← latest
Reported: assign 10 leads → click "Send all pending" → each POC emailed twice. Live DB
showed ONE row per recipient but two Outlook messages = send race, not generation dup.
- Root cause: `processPendingEmailSends` (index.js) dispatched then marked `status='sent'`
  with **no atomic claim**; `POST /emails/queue-all` ran without the `activeSendByUser`
  lock. Concurrent runs (double-click, or manual send-all overlapping auto-send/20-min
  `retryDeferredPendingSends`) both dispatched the same pending row.
- Fix: **atomic claim** before dispatch — conditional update `pending→sending`
  (`.eq('id',...).eq('status','pending').select()`); if 0 rows, skip (already claimed).
  Success→sent, failure→failed, deferred-followup→released back to pending. Plus
  `queue-all` now acquires/releases `activeSendByUser`.
- Verified live: first claim returns row, second returns nothing. Test `send-race-guard.mjs`.
- **Caveat**: does not un-send already-sent duplicates. Offered to list who was double-emailed.

---

## Also done (not code PRs)
- **Deleted all candidates + job_orders** from live DB per user request (kept the 1,252
  BD leads in the separate `jobs` table). Note schema trap: BD leads live in `jobs`;
  recruiting postings live in `job_orders`. 2 orphaned resume blobs remain in the
  `candidate-docs` storage bucket (DB rows gone) — harmless, manual cleanup optional.

## Migrations applied to live Supabase this session
- **020** `assignment_requests` (job_order_id, recruiter_id, status, note, decided_by/at)
- **021** `submissions.submission_details` (JSONB) + `submissions.rejection_reason` (TEXT)
  *(021 was from earlier stage-gating work; both live.)*

---

## Key architecture notes (for future work)
- **Frontend**: plain `<script>` modules in `public/js/NN-*.js`, loaded in order by
  `public/index.html`. Global `window.*` namespace (no bundler). `render()` /`goPage()`
  are wrapped by each page module. State on global `STATE` (`STATE.bd`, `STATE.jb`, etc.).
- **Stage vocabulary (recruiting)**: 12 stages `Sourced, Screening, Submitted to BDM,
  Submitted to Client, Interview Scheduled, Interview Completed, Offer, Confirmation,
  Placement, Rejected, Not Joined, On Hold`. Single source `ATS_STAGE_LIST` (33-stage-modal.js).
- **Lead vocabulary (BD/RA, table `jobs`)**: Unassigned, Assigned, Connected, Rejected,
  Future, In Discussion — DIFFERENT from recruiting stages. Don't conflate.
- **Recruiter gating**: recruiters change stages only up to "Submitted to BDM"; BD owns
  everything after (enforced in `PATCH /submissions/:id/stage` + the stage modal).
- **Roles**: `userHasRole(u,role)` / `userHasAnyRole(u,...)`; roles in `u.roles[]` (fallback `u.role`).
- **Email send**: `processPendingEmailSends(userId, pending, opts)` is the ONE send loop
  (used by manual `queue-all` and `autoSendForManager`/`retryDeferredPendingSends`).
  Per-email atomic claim now guarantees no double-dispatch.

## Test suites (all green as of PR #101)
`test/`: backend-smoke (89), frontend-smoke (14), recruiter-dashboard-smoke (34),
workflow-gating-smoke (25), stage-consolidation-smoke (12), tab-collapse-smoke (10),
job-open-details-smoke (12), submission-review-smoke (16), lead-location-parse (14),
lead-stage-permission (13), send-race-guard (7). Runner needs
`npm install --no-save playwright-core`; Chromium at `$PLAYWRIGHT_BROWSERS_PATH`.
`bash test/verify-frontend.sh` checks per-file syntax + index.html consistency.

## Open / next candidates
- BDM **approvals queue** card on the dashboard (blueprint phase 1, still to build).
- RA dashboard redesign (target-milestone banner, lead-outcome card).
- New roles Recruiter Lead / Associate Director + `users.manager_id` (needs product input).
- Candidates list still shows full contact details to any recruiter (only the job-board
  is masked) — decide if that should be locked too.
- Real letterhead is wired; if a richer template is provided, swap in 36-resume-format.js.

## Working conventions this session
- Each change: implement → `node --check` → targeted browser/DB test → screenshot → commit
  → **rebase branch onto latest origin/main** (`git checkout -B <branch> origin/main`) →
  force-with-lease push → open PR (draft then ready) → squash-merge. Prior PRs are merged,
  so the dev branch restarts from main each time.
- Commit trailer: `Co-Authored-By: Claude ...` + `Claude-Session: https://claude.ai/code/session_01P2jfTWrUuDqJbzKNMzp9UC`.
