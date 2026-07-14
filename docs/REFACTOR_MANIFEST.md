# Refactor Manifest

Fute Global LMS — the full record of the modularization and admin-control
effort on `princethomas37/fute-lms-backend`, branch
`claude/frontend-refactor-test-lj6feb`. Compiled 2026-07-14.

**At a glance:** 14 PRs merged (#67–#80) · `index.js` 3,649 → 2,615 lines ·
frontend 1 file → 26 files · backend route modules 4 → 15 · test files 0 → 7.

## Contents

0. [Why this happened](#0-why-this-happened)
1. [Frontend split (Phase 1)](#1-frontend-split--phase-1)
2. [Backend modularization](#2-backend-modularization)
3. [Admin control features](#3-admin-control-features)
4. [Current architecture map](#4-current-architecture-map)
5. [Deliberately deferred](#5-deliberately-deferred)
6. [Conventions established](#6-conventions-established)
7. [How to pick this back up](#7-how-to-pick-this-back-up)

## 0. Why this happened

The app — a lead-management system for a staffing firm, built entirely
through prior AI sessions — had grown into a shape that was getting harder to
change safely: an 8,740-line frontend file and a 3,649-line backend entry
point, both holding every concern at once. The owner brought in a developer
for a second opinion, who wrote two guides (`FRONTEND_REFACTORING_GUIDE.md`,
`BACKEND_REFACTORING_GUIDE.md`) prescribing the same core method for both
sides:

- **Reorganize before you change behavior.** Split first, prove nothing
  moved, then improve one seam at a time.
- **Never touch the whole thing at once.** Every increment is small enough
  to verify completely before the next one starts.
- **Every route needs its own authorization check** — the Supabase client
  uses a service-role key that bypasses row-level security, so the
  application layer is the only gate.

The instruction given at the start: refactor the frontend, test it, and only
move to the backend if that went well. It did — and the backend work led
naturally into a third phase the owner asked for directly: turning the admin
account into an actual control tower over other users' work, not just a
parallel account doing the same things.

## 1. Frontend split — Phase 1

**PR #67 · merged**

`public/app.js` (8,740 lines — global `STATE`, 336 `window.*` functions, 279
inline `onclick` handlers, string-built HTML) became 26 files under
`public/js/`, loaded by `index.html` in strict numbered order. They remain
**ordered classic scripts sharing one global scope** — not ES modules yet —
which is precisely what let the split be proven safe rather than just
carefully done:

- **Byte-for-byte proof** — the 26 files concatenated in load order
  reproduce the original file exactly, character for character.
- **Per-file syntax check** — each file parses standalone, since the
  browser loads every `<script>` independently.
- **Headless-browser smoke test** (`test/frontend-smoke.mjs`, via the app's
  own client-side guest mode) — boots the app, logs in, and walks
  Dashboard, Leads, Email, Reminders, Insights, and Profile across BD, RA,
  and RA-Lead roles. 14/14, zero console errors.

Since then, feature work (the admin tools in §3) has added roughly 365 lines
on top of the original split — the total is now 9,105 lines across the same
26 files.

### Not done — Phase 2 of the guide

The guide's end state is real ES modules, a controlled
`getState`/`setState` store, `textContent`/DOM construction instead of
string-built `innerHTML`, event listeners instead of inline `onclick`, and a
demo/production split for guest mode. None of that has started — it was
deliberately deferred as a bigger, separate body of work, to be done one
module at a time once there's a habit of testing before every change.

## 2. Backend modularization

**Ten increments, PRs #68–#77, each its own PR**

The repo already had a working pattern for this — `routes/auth.js`,
`routes/microsoft.js`, `routes/wf.js`, `routes/workflows.js` were extracted
before this session began, each a factory function that takes a shared `ctx`
object (`supabase`, `auth`, `hasRole`, helpers) and returns an Express
router. Every increment below follows that exact convention: handler bodies
moved **verbatim**, only `app.*` became `router.*`.

| PR | What moved | Notes |
|----|------------|-------|
| #68 | Companies, reminders, contacts | First extraction; established the pattern for this session |
| #69 | `config/env.js` | Startup validation for 3 required secrets; un-hardcoded the Microsoft OAuth redirect URI (fell back to the old value) |
| #70 | `middleware/authorize.js` | `hasRole`, `notGuest`, `canTouchJob`, `requireRole` — centralized, since the service-role key needs app-level authz everywhere |
| #71 | Settings routes | `/app-settings`, `/outreach-plan` |
| #72 | Deliverability (read-only) | Suppression list, spam pre-check, template analytics, health overview |
| #73 | AI + events | `/ai/generate-*`, `/events/recent` |
| #74 | **Jobs** | Largest, most interconnected. The in-memory jobs cache stayed in `index.js` (shared with cache-invalidation middleware); route order preserved exactly, including a pre-existing quirk |
| #75 | Email reads | List, counts, send-progress, manual mark-sent, edit/delete a draft — the live send-*triggering* routes stayed inline on purpose |
| #76 | Form-support lookups | Industries, zip-code lookup, duplicate-email check |
| #77 | Distribution reads | Pool stats, today-summary, per-manager RA-mode config |

### What's still inline — by design

The live email send pipeline and its controls never moved. This is the one
tier where local testing can't prove real behavior (no live Microsoft Graph
credentials in a test harness), and a mistake here risks mis-sending or
double-sending customer email:

```
POST /emails/generate            POST /emails/send-selected
POST /emails/queue-all           POST /emails/reminder-send
POST /emails/retry-pending-window POST /distribute/execute
POST /distribute/generate-ratio  POST /follow-ups/run
POST /admin/bounce-sweep         POST /admin/reply-sweep
POST /admin/mailbox/:id/resume   POST /admin/sending/pause|resume
GET  /admin/sending/status       GET  /sending/my-status
GET  /jobs/:job_id/activity
```

### How each increment was actually verified

Since there's no live database in this environment, verification leaned on a
repeatable pattern rather than one-off checks: boot `index.js` against a
throwaway, *unreachable* Supabase URL, then confirm —

- every extracted route responds `401` without a token (proves it's
  mounted — a missing route would 404 instead), and still-inline routes are
  unaffected;
- a **dependency check** — sign a real JWT and call the route with a role
  that reaches past auth: if a helper wasn't wired through `ctx`/`require`
  correctly, that surfaces immediately as a fast `ReferenceError`, not a
  slow database timeout;
- the global guest-write-block re-confirmed on every moved *write* route
  (guest tokens still get `403`).

`test/backend-smoke.mjs` grew from a handful of checks to **39 assertions**
across the whole session, re-run before every commit.

## 3. Admin control features

The owner's own words: *"I feel the control is very very low… I should have
all run, pause, stop buttons for every workflow in other users."*

Rather than guess at the scope of "control everything," the work was split
into four concrete, scoped pieces — each reusing existing, already-tested
endpoints wherever the data was already available, to keep backend risk near
zero for three of the four.

### #78 — Delete pending emails, one manager or all · merged

Admin picks email type (outreach / FU1 / FU2) and an optional time cutoff,
previews the exact count, then deletes. Only `status = 'pending'` rows are
ever touched — sent mail and reminders are untouchable by this tool. New
endpoint: `POST /admin/emails/purge-pending`.

### #79.1 — System Settings: 8 hardcoded numbers made editable · merged

Backed by `config/settings.js` — a schema (label, description, unit,
min/max, default) plus a cached, validated get/set, mirroring
`config/env.js`'s pattern. Every default matches the number that was
previously baked into the code, so nothing changes until an admin edits a
value; a settings-store hiccup falls back to that same default rather than
risk the send pipeline.

| Setting | Was hardcoded at | Group |
|---------|-------------------|-------|
| Company re-add cooldown | 21 days | Leads |
| RA self-edit window | 24 hours | Leads |
| Mailbox warm-up starting cap | 20 / day | Deliverability |
| Mailbox warm-up daily increase | +5 / day | Deliverability |
| Bounce-rate auto-pause threshold | 5% | Deliverability |
| Bounce-rate minimum sample | 20 sent | Deliverability |
| Workflow step retry limit | 3 attempts | Workflows |
| Workflow engine batch size | 200 / tick | Workflows |

### #79.2 — Unified per-user Control Center · merged

Admin → click a BD/BD-Lead manager → one card showing: sending status with
pause/resume, RA mode with a switch, pending-queue counts with a delete
shortcut, and active workflow enrollments with pause/resume/stop — all four
previously required visiting four different pages. **Zero backend
changes** — pure recombination of endpoints already built this session.

### #79.3 — Fix: the delete-pending UI (#78) was unreachable · bug found in review

Caught by the owner asking "where do I actually go for this?" The original
button lived on a page with *no sidebar link and nothing anywhere that
navigated to it* — built and tested by injecting state directly rather than
clicking through a fresh session. Fixed by moving the entry points onto the
Admin page, which the sidebar always links to, then re-verified via genuine
nav clicks, not shortcuts.

### #80 — Enroll another manager's leads, on their behalf · merged

Control Center → "+ Enroll leads…" opens a picker of that manager's own
leads (excludes anything already mid-sequence), then hands off to the
existing "Start sequence" flow. The manager does nothing — admin picks the
leads and the sequence. **Zero backend changes**; the eligible-leads list is
computed client-side from data the page already had loaded.

## 4. Current architecture map

Everything below is on `main` as of this writing.

```text
config/
  env.js         — required secrets, startup validation
  settings.js    — the 8 admin-editable numbers
middleware/
  authorize.js   — hasRole · notGuest · canTouchJob · requireRole
routes/          — 15 files: auth · microsoft · wf · workflows (pre-existing)
                   companies · reminders · contacts · settings · deliverability
                   ai · events · jobs · emails · lookups · distribution (this session)
index.js         — 2,615 lines: Express setup, the live send pipeline, background timers
public/js/       — 26 ordered files, 01…26 — see public/js/README.md for the full map
test/
  backend-smoke.mjs    — 39 assertions: boot + route-mount + dependency checks
  frontend-smoke.mjs   — 14 steps: headless-browser walk of every major screen
  authorize.mjs, config-env.mjs, settings.mjs   — unit tests for the 3 new config/ modules
  verify-frontend.sh   — dependency-free syntax + load-order check
  MANUAL_CHECKLIST.md  — what can't be proven without a live database
```

## 5. Deliberately deferred

- **The live send pipeline extraction** — `generate` / `send-selected` /
  `queue-all` / `distribute/execute` and their neighbors (§2). Much of
  what's left in `index.js` is genuinely core send-loop machinery the guide
  itself says should eventually move to a *worker process*, not just a
  route file — a bigger architectural step, not a same-shape extraction.
- **Frontend Phase 2** — ES modules, a controlled state store, safe DOM
  rendering, real event listeners, guest/production separation. The split
  in §1 built the seams; nothing has walked through them yet.
- **Worker-process background jobs** — the guide's recommendation to
  replace in-process timers with a queue + atomic database claims, so
  multiple web instances can't duplicate a send. Not started.

## 6. Conventions established

- **New backend route group** → a factory function taking the shared
  `ctx`, handlers moved verbatim, mounted in `index.js`'s `routeCtx` block.
- **Every extraction ships with proof**, not just a diff: boot smoke + a
  dependency check that actually executes the handler, before it's ever
  committed.
- **Anything that touches live data and can't be proven locally** (a real
  database write, a real send) goes up as a **draft PR** with a
  manual-checklist entry, for the owner to verify against production before
  merging.
- **Reuse before you build** — three of the four admin-control features
  shipped with zero backend changes by recombining endpoints already built
  and tested that same session.
- **Reachability is part of "done."** A feature that works when state is
  injected directly isn't proven until it's been clicked to from the real
  sidebar nav — §3's #79.3 is the reminder of what happens when that step
  is skipped.
- **Branch discipline** — one designated branch throughout; reset onto
  `main` only after a PR merges; never rewrite already-merged history
  (GitHub's own merge commits show as "Unverified" by a local
  committer-email check three separate times this session — correctly left
  alone each time, since they're already GPG-signed by GitHub itself).

## 7. How to pick this back up

```bash
git fetch origin main
git checkout -B claude/frontend-refactor-test-lj6feb origin/main

# dependency-free — no test framework, no live database needed
bash test/verify-frontend.sh
node test/backend-smoke.mjs
node test/frontend-smoke.mjs      # needs: npm install --no-save playwright-core
node test/authorize.mjs && node test/config-env.mjs && node test/settings.mjs
```

The next honest options, in rough order of size: continue the send-pipeline
extraction (§5, needs explicit sign-off given the risk); start Frontend
Phase 2 one module at a time; or keep building admin-control features — the
pattern in §6 scales to whatever comes next.

| | |
|---|---|
| PRs merged | 14 (#67 → #80) |
| `index.js` size | −28% |
| Backend smoke | 39 / 39 |
| Frontend smoke | 14 / 14 |
