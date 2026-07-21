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
2. **Configurable roles & permissions per org** — we already have roles; make them
   data so different customers can mirror their own org charts.
3. **App-tracked candidate email** (not just `mailto:`): route candidate emails through
   the sending subsystem we already have → open/reply tracking = a real selling point,
   no new infra.
4. **Candidate ↔ JD match scoring / ranking** — we already parse resumes and JDs; add a
   match score (AI when a key is set, rule-based fallback). On-trend differentiator.
5. **Reporting/analytics** — funnel, time-to-fill, recruiter productivity. We already
   store the data; surfacing it is a sales lever.
6. **CSV import/export + a small public API** — buyers need to migrate in and integrate.
7. **Audit trail everywhere** — generalize the submission activity log; buyers want
   accountability.
8. **Mobile-friendly / PWA polish** — recruiters live on phones; cheap CSS work.
9. **Billing later, stubbed now (Stripe)** — leave a seam for self-serve signup +
   subscription so it plugs in without a rewrite.

These are options to offer the owner in plain language — not a mandate to build them
unasked.
