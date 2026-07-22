# futé — project memory (read me first, every session)

> **This section is not optional and must be carried into every context window / handoff.**
> If you are summarizing this project for a future session, copy the two sections
> below ("Who I'm working with" and "What we're building") verbatim.

## Who I'm working with

The owner is the **product owner and the end user** — not an engineer.

- They **do not read code** and **do not use git/GitHub**. Never ask them to review a
  diff, read code, resolve a merge, mark a PR ready, or operate GitHub. That work is
  mine, fully.
- They evaluate the product the way a customer would: **by using it** — does it look
  right, feel right, make sense, and actually work? So the things I hand them are the
  **running app, screenshots, and plain-English explanations** — never code.
- **My role is everything behind the system:** coder, planner, architect, tester,
  release engineer. I own the branches, PRs, and (once they've approved a change by
  reacting to it) the merge and the deploy. I confirm before doing something
  outward-facing or hard to reverse, but I don't push code chores onto them.
- I am expected to be **proactive**: after doing what was asked, suggest what else is
  worth building — product trends and high-leverage technical bets — always in plain
  language, framed as choices they can react to, not code.

**The working loop:** I build on the dev branch → I show them (screenshots / the live
app / a short summary) → they react as a user → we iterate → when they're happy, I
merge and deploy so they can use the real thing → I tell them plainly what's now live.

## What we're building

futé is a **recruiting ATS + lead-management platform being built to sell
commercially** (SaaS), competitive with the established ATS products (Ceipal,
Bullhorn, and the like). Every decision is a product decision in service of that.

**Build philosophy: spend nothing now, scale later.** Prefer free tiers and infra we
already have. Don't add paid services unless they clearly earn it. But make the
**architecture** choices now that are cheap today and expensive to retrofit later, so
we never have to rewrite to grow (see "Growth bets" below).

---

## The stack (so it isn't re-derived each time)

- **Backend:** Node/Express — `index.js` (email/lead engine) + `bd_recruiter_routes.js`
  (ATS: candidates, pipeline, submissions, job orders). Plus assorted `*.js` engines
  (mailmerge, warmup, jd-parser, resume-parser).
- **Data:** Supabase (Postgres + storage bucket `candidate-docs`). Project
  `teiqievahzhllojvgsku`. Migrations in `migrations/`.
- **Frontend:** plain `<script>` modules in `public/js/NN-*.js`, loaded in order by
  `public/index.html`. **No build step, no bundler.** Global `window.*` + `STATE`.
  `render()` / `goPage()` are wrapped by each page module.
- **Deploy:** Render (`fute-lms-backend.onrender.com`), auto-deploys from `main`.
  → Merging to `main` IS the release. That's how the owner gets to try things live.
- **Tests:** `test/*.mjs` Playwright smokes that serve `public/` statically and drive
  the real modules in headless Chromium (guest login, inject `STATE`, assert on
  render output). `bash test/verify-frontend.sh` checks syntax + index.html.
  Run: `npm install --no-save playwright-core`; Chromium at `$PLAYWRIGHT_BROWSERS_PATH`.
- **Two vocabularies, don't conflate:** recruiting postings live in `job_orders`
  (12 ATS stages: Sourced … Placement); BD leads live in `jobs` (Unassigned,
  Assigned, Connected, …). Recruiter gating: recruiters move a candidate only up to
  "Submitted to BDM"; BD owns the later stages.

## Working conventions

- Implement → `node --check` → targeted smoke test → screenshot → commit → push to the
  session's dev branch → open a **draft PR** → when the owner approves, merge + let it
  deploy. Keep commits/PRs clean; the owner won't read them, but future-me and buyers'
  auditors might.
- Keep a session summary in `docs/CONTEXT_WINDOW.md` and keep **this file** current —
  it is the durable memory.

## Growth bets (cost ~nothing now, scale later) — pick from these proactively

Ordered by "cheapest to do now vs. most painful to retrofit":

1. **Multi-tenancy (the big one).** Design so one deployment can serve many client
   companies: a tenant/`org_id` on every ATS table + query scoping. Free to add now,
   very expensive to retrofit — and it's the thing that makes futé *sellable* to more
   than one customer. Highest-leverage architectural bet.
   - **Slice 1 DONE** (migration `022`): `org_id` on 33 tenant tables, backfilled to
     the default org "Fute Global", with a column DEFAULT so nothing breaks. Backend
     resolves `req.orgId` (JWT carries `org_id`; falls back to the default org), and
     the core creates (candidates, job orders, pipeline, submissions, new users)
     stamp it. Behaviour is unchanged for the single existing org.
   - **Slice 2 IN PROGRESS:** the core ATS collection reads are now org-scoped via
     a `withOrg(query, req)` helper — `GET /candidates`, `GET /job-orders`,
     `GET /job-orders/browse`. Still to scope: the recruiting dashboard aggregates,
     single-record long tail, and the **leads engine** (`jobs` table via the shared
     cached `loadAllJobs` + the email subsystem in index.js) — deliberately deferred
     because it's the live, actively-used email system and needs its own careful pass.
   - **Slice 3a DONE** (migration `023`): `org_id` is now `NOT NULL` on all tenant
     tables (safe — every row backfilled + column DEFAULT).
   - **Slice 3b DEFERRED by owner decision:** enabling RLS (row-level security) with
     org-keyed / service-role policies to close the anon-key exposure. Proven-safe
     pattern (already live on 8 tables; frontend is API-only) but touches the live
     prod DB, so hold it until closer to onboarding a second org. **Do NOT enable RLS
     on the live DB without an explicit, fresh go-ahead.**
2. **Configurable roles & permissions per org** — we already have roles; make them
   data so different customers can mirror their own org charts.
3. **App-tracked candidate email** (not just `mailto:`): route candidate emails through
   the sending subsystem we already have → open/reply tracking = a real selling point,
   no new infra.
   - **Slice 1 DONE** (migration `024`): open-tracking *infrastructure* — an
     `email_tracking` table (org-scoped), a public pixel endpoint `GET /o/:token.gif`
     (records opens, returns a 1×1 gif, never errors), a `GET /candidates/:id/
     email-activity` read endpoint, and pure helpers in `email-tracking.js`
     (`newToken`/`pixelHtml`/`injectPixel`). Wired into `routes/tracking.js`. Nothing
     writes tracking rows yet — the live send path is untouched.
   - **Slice 2 DONE:** `POST /candidates/email` sends the invite to selected
     candidates via the recruiter's connected mailbox (reuses `recruiterSendingMailbox`
     + `sendMicrosoftNewMessage` + `buildHtmlEmailBody`), injects the pixel, records an
     `email_tracking` row per recipient, bumps `email_send_log`; returns 409
     `no_connected_mailbox` so the UI falls back to the mail app. Frontend: the
     "Email JD" modal's **"✉ Send tracked through futé"** button (mail-app kept as
     fallback); the candidate profile shows an **Email activity** card ("✓ Opened · N×"
     / "Sent · not opened yet") from `GET /candidates/:id/email-activity`.
     **Caveat:** send path is Microsoft-only for now (mirrors the existing
     `candidate_email` channel; `recruiterSendingMailbox` only checks `microsoft_tokens`).
     Gmail send = a small follow-up (check `gmail_tokens` + dispatch by `platform`).
   - **Slice 3 DONE:** reply detection — hooked into the existing 30-min
     `sweepMailboxReplies` inbox scan (uses `Mail.ReadWrite`, already granted, so NO
     reconnect needed): an inbound message whose `from` matches a tracked send's
     `to_email` stamps `replied_at`. Candidate profile Email-activity card shows
     **"↩ Replied"** (green). No new columns/Graph calls — reuses the lead sweep.
   - **Interview scheduling (related, DONE):** the stage modal captures full
     interview details — format (in-person / virtual / phone), platform + join link
     or office address, up to 3 interviewer names — stored on `submissions`
     (migration `025`). `POST /submissions/:id/interview-invite` emails the formatted,
     open-tracked details to the candidate and/or the BD manager (job title, company,
     date/time, format, interviewers auto-included).
   - **Teams meeting auto-create DONE:** `POST /submissions/:id/create-meeting`
     creates a Microsoft Teams meeting via Graph `/me/onlineMeetings` and stores the
     joinUrl on the submission; the interview modal's **"Generate Teams meeting
     link"** button fills it in. Added `OnlineMeetings.ReadWrite` to the MS OAuth
     scopes — **mailboxes connected before this need a one-time reconnect**; until
     then the endpoint returns 409 `meetings_permission_missing` and the UI says so.
     **Next:** Google Meet (needs a Google Calendar scope/connection); Zoom (new OAuth).
4. **Candidate ↔ JD match scoring / ranking** — we already parse resumes and JDs; add a
   match score (AI when a key is set, rule-based fallback). On-trend differentiator.
5. **Reporting/analytics** — funnel, time-to-fill, recruiter productivity. We already
   store the data; surfacing it is a sales lever.
   - **DONE:** a **Reports** page (`39-page-reports.js`, nav item) from one org-scoped
     endpoint `GET /reports/recruiting` — headline totals, pipeline funnel, 8-week
     submission trend, recruiter-productivity table (with fill % + placement-fee
     revenue), avg time-to-fill and top clients. Managers see the whole desk;
     recruiters see only their own. (Legacy `/bd-analytics/*` endpoints still exist,
     un-org-scoped — fold in later.)
6. **CSV import/export + a small public API** — buyers need to migrate in and integrate.
7. **Audit trail everywhere** — generalize the submission activity log; buyers want
   accountability.
8. **Mobile-friendly / PWA polish** — recruiters live on phones; cheap CSS work.
9. **Billing later, stubbed now (Stripe)** — leave a seam for self-serve signup +
   subscription so it plugs in without a rewrite.

These are options to offer the owner in plain language — not a mandate to build them
unasked.
