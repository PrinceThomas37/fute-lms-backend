# Role-Based UX Blueprint — one product, six desks

**Status**: Draft for review · 2026-07-20
**Principle**: Every pixel a user sees should belong to *their* workflow, use *their*
vocabulary, and surface *their* numbers — the ones their performance is measured on.
A screen is done when it answers "what should I do next?" for that person without
them thinking.

This document specifies, per role: the mission, the sidebar (exact items, exact
order, exact labels), the dashboard (exact cards, exact words), the primary action
on each screen, terminology, empty states, and what still has to be built in the
system to make it real.

---

## 0. The company workflow (who hands off to whom)

```
RA sources leads ──▶ RA Lead assigns/QCs ──▶ BD outreach (email sequences)
                                                   │
                                     lead becomes "Connected"
                                                   │
                                  BD converts lead → Job Order
                                                   │
                              BD/BDM assigns recruiters to the job
                                                   │
              Recruiter sources candidates → submits → "Submitted to BDM"
                                                   │
                       BDM approves → "Submitted to Client" → Interview
                                                   │
                              Offer → Confirmation → PLACEMENT  ✓
```

Every role lives on one segment of this pipe. The UI for each role shows their
segment big, the neighbouring hand-off points small, and everything else not at all.

**Vocabulary rule** (applies everywhere — nav, cards, buttons, toasts):

| Role speaks about… | Words on their screens | Words that must never appear |
|---|---|---|
| RA / RA Lead | leads, companies, contacts, assignment | candidates, submissions, placements |
| BD / BD Lead | leads, outreach, response, jobs, approvals | (they bridge both worlds — both OK) |
| Recruiter | jobs, candidates, submissions, interviews, placements | leads, response rate, industry breakdown |
| Admin | everything, plus users, accounts, deliverability | — |

---

## 1. RECRUITER  ✅ (shipped — reference implementation)

**Mission**: fill assigned jobs with candidates. **Measured on**: submissions/week,
interviews, placements, rejection rate.

- **Sidebar**: Dashboard · My Jobs · All Jobs · Candidates · Sourcing · Email · Reminders ·
  My Profile (no Leads — shipped)
- **All Jobs** (✅ shipped): company-wide job board. Every recruiter sees every job —
  title, client, location, status, priority, who's on it, submission activity — and a
  *Request assignment* button. Candidates on unassigned jobs show name/title/stage
  only; **contact details (email, phone, resume) unlock on assignment** (masked
  server-side). Requests land on the BD Manager's dashboard as an
  **Assignment requests** card with *Assign* / *Decline*.
- **Dashboard** (shipped): greeting banner (subs week/month, in interview, placements)
  → desk tiles → **My jobs** card (assigned-timeline counts, top-5 by team activity,
  "All my jobs →") → **My candidate pipeline** by stage → **Recent rejections**
  (candidate + BD's reason, framed "for context, not a scorecard" — see §9.4)
  → **Upcoming interviews** → Reminders.
- **Stage ownership is gated, not just conventional** (✅ shipped): a recruiter can
  move a candidate through Sourced → Screening → **Submitted to BDM** and no further.
  Every stage from Submitted to Client onward (interview, offer, confirmation,
  placement, rejection) is BD-only — enforced server-side, and the stage modal
  won't even open a blocked move client-side. Recruiters still *see* later stages
  on their pipeline card; they just can't change them.
- **Submit to BD Manager is a hand-off form, not a dropdown** (✅ shipped): moving to
  "Submitted to BDM" opens a modal mirroring the company's submission-details
  template — applicant name, email, mobile, home phone, work auth, current
  location, relocation, availability, and a required "Submission Comment
  (important)" — plus resume attach and a "Format resume" action (§6 below). The
  comment is mandatory; submission won't go through without it.
- **Primary actions**: My Jobs → open job → *Add candidate* → move through stages to
  *Submit to BD Manager* (opens the hand-off form above).
- **Still to build**:
  - Interview-day view: "You have 2 interviews today" strip pinned above tiles.
  - Per-recruiter goal setting as milestones, not quotas (§9.1) — needs `user_goals`.

## 2. BD MANAGER (`bd`)

**Mission**: turn leads into clients and jobs; keep the recruiting desk moving.
**Measured on**: response/positive rates, jobs opened, submissions reaching clients,
placements (revenue).

- **Sidebar**: Dashboard · Leads · Jobs · Candidates · Sourcing · Email · Reminders ·
  My Insights · My Profile. (Current layout is right; "Jobs" should carry an
  **Awaiting approval** badge — count of `Submitted to BDM`.)
- **Dashboard** (redesign in progress):
  1. Banner: keep lead stats (leads, emails, response, positive) — this IS their number.
  2. **Assignment requests card** (✅ shipped): recruiters browsing All Jobs (§1) can
     ask to be put on a job; requests land here with *Assign* / *Decline*.
  3. **Approvals queue card — still the #1 remaining change.** "Awaiting your
     approval (3)" with candidate, job, recruiter, waiting-time; inline
     *Approve → Client* / *Reject* buttons (endpoint exists). An approval sitting
     3+ days turns amber. This is the BDM's most time-sensitive daily action and
     today it hides inside job detail.
  4. **Recruiting desk strip** (exists, keep): Active Jobs, At Client, In Interview,
     Offers, Placements, Subs Week/Month.
  5. **My recruiting team — performance card** (✅ shipped): per recruiter — subs,
     interviews, offers, **placements, and revenue** (job_orders.placement_fee
     attributed to each placement), plus a total-revenue rollup. This is the
     "next-in-line manager sees revenue + placements for people under them" answer
     (§9.5). Still open: scoping to *only the recruiters actually under this
     manager* once §10's reporting-line field exists — today it shows every
     recruiter company-wide, since that binding doesn't exist yet.
  6. **Jobs needing attention**: jobs with 0 submissions in 14 days, or no recruiter
     assigned ("cold jobs"). *Assign recruiter* button inline.
  7. Response trend + Industry breakdown (keep — these are lead-gen tools).
  8. Reminders (keep).
- **Rejection is BD's duty** (✅ shipped): moving a submission to "Rejected" requires
  a reason (free text — "it depends on a lot," per product, so no fixed enum). The
  reason travels with the submission and surfaces on the recruiter's own dashboard
  as context, never as a performance judgment (§9.4).
- **Primary actions**: Leads → *Convert to Job*; Jobs → *Assign recruiter*, *Approve
  submission*; Dashboard → *Assign*/*Decline* a request, *Approve* from the (still
  to build) approvals queue.
- **Still to build**: approvals-queue endpoint (`GET /submissions?stage=Submitted to BDM`
  scoped to their jobs, with waiting-time), cold-jobs query.

## 3. BD TEAM LEAD (`bd_lead`)

**Mission**: BD Manager's job + accountable for the whole BD desk.
**Measured on**: team response/positive rates, team pipeline value, desk placements.

- **Sidebar**: same as BD + Team Insights + Deliverability (current — correct).
- **Dashboard**: BD dashboard, with the team card defaulting to **all BD managers +
  their teams** (click-through "view as" exists). Add a **Desk comparison** row:
  each BDM with leads → connected → jobs → placements so the funnel shows where
  each manager's pipeline leaks.
- **Still to build**: desk-comparison aggregate endpoint; everything else exists.

## 4. RESEARCH ANALYST (`ra`)

**Mission**: find and enter quality leads. **Measured on**: leads/day, quality
(how many get worked/connected), duplicates avoided.

- **Sidebar**: Dashboard · Leads · Insights · My Profile (current — correct.
  No Email, no Reminders, no recruiting pages — also correct today).
- **Dashboard** (redesign — today they see the BD-shaped dashboard):
  1. Banner: **Leads today / this week / this month** + daily-target progress
     ("14 / 20 today") — needs `user_goals`, until then show streak ("3 days ≥ target").
  2. **What happened to my leads** — the motivating card RAs never get: of your
     leads, how many were emailed, connected, positive, became jobs. Words:
     "Your leads → 82 emailed · 12 responded · 3 became jobs". Needs a
     lead-outcome endpoint scoped to `created_by = me`.
  3. **Duplicates & quality flags**: "2 of your leads this week were merged as
     duplicates" with links to learn what to avoid.
  4. **My BD Manager** row (exists in team card — keep, one row only).
  5. NO response-rate trend, NO industry breakdown (they don't run outreach) —
     replace industry chart with **"Industries you've been sourcing"** — same chart,
     reframed label, computed from *their* leads. (Fine to keep component, change title.)
- **Primary actions**: *+ New Lead* (entry form) — should also be a banner button
  on the dashboard; today it lives only inside Leads.

## 5. RA TEAM LEAD (`ra_lead`)

**Mission**: keep lead flow high and clean; distribute work.
**Measured on**: team leads/day vs. target, assignment turnaround, lead quality.

- **Sidebar**: Dashboard · Leads · Assign Leads · Insights · Deliverability · My Profile
  (current — correct; consider whether Deliverability really belongs to RA Lead or
  should be Admin/BD Lead only — **open question**).
- **Dashboard**:
  1. Banner: team leads today vs. daily target, unassigned count.
  2. **Unassigned leads card** — "23 leads waiting for assignment" + *Assign now* →
     Assign Leads page. This is their approvals-queue equivalent: the time-sensitive
     daily action, front and centre.
  3. **My RA team** (exists): per-RA leads today/week + last-entry time ("Spencer —
     last lead 4h ago" catches idle time). Needs last-entry timestamp in the team query.
  4. Team lead-outcome funnel (same endpoint as RA card #2, team-scoped).
- **Primary action**: *Assign leads*.

## 6. ADMIN

**Mission**: run the platform: users, accounts, deliverability, oversight of both desks.

- **Sidebar**: Dashboard · Leads · Assign Leads · Jobs · Candidates · Sourcing ·
  Email · Admin · Deliverability · Insights · Reminders · My Profile (current superset
  is acceptable — admins are power users; do not slim this down at the cost of reach).
- **Dashboard**: today it's the BD view with an all-user team table — acceptable,
  plus two additions:
  1. **Org funnel strip** at top: Leads → Connected → Jobs → Subs → Interviews →
     Placements (this period). One glance = company health.
  2. **System health card**: email accounts connected/erroring, bounce alerts,
     users never logged in. (Data exists across admin/deliverability pages;
     surface the red flags only.)

---

## 7. Global design rules (every role, every screen)

1. **Top-left card = the user's most time-sensitive action** (recruiter: interviews
   today; BDM: approvals; RA Lead: unassigned leads; RA: today's target).
2. **A metric appears only if the viewer can influence it.** No response-rate for
   recruiters; no placements for RAs.
3. **Counts on nav items only when actionable** (Leads badge = today's new for RA;
   Jobs badge = awaiting approval for BDM; Reminders badge = pending).
4. **Empty states teach the workflow**: say who/what feeds this screen and offer the
   next action ("No jobs on your desk yet — your BD manager assigns them to you").
   Never a bare "No data".
5. **Buttons name the hand-off, not the mechanics**: *Approve → Client*, *Submit to
   BDM*, *Convert to Job* — the label tells you where the work goes next.
6. **Page titles match nav labels match toasts** — one vocabulary per role (see §0).
7. **Click-through everywhere a number appears**: a count you can't click to see the
   underlying list is a dead end.

## 8. Build order (proposed)

| Phase | What | Why first | Status |
|---|---|---|---|
| 1 | BDM approvals-queue card + Jobs badge | Most time-sensitive daily action in the org | Not started |
| — | Recruiter stage gating, Submit-to-BDM form, rejection reasons, recruiting-team revenue/placements card, resume preview, resume formatter, All Jobs board | Explicit product asks (§9.3–8) | ✅ Shipped |
| 2 | RA dashboard (target banner, lead-outcome card) | Largest headcount, worst current fit | Not started |
| 3 | Cold-jobs card + true manager-scoped team table | Needs §10's manager_id first | Not started |
| 4 | RA Lead unassigned-card + idle-RA timestamps | Small delta on existing pages | Not started |
| 5 | Admin org-funnel + system-health cards | Oversight, lowest urgency | Not started |
| 6 | `user_goals` table + milestone-progress banners (RA + recruiter) | Needs the manager-sets-milestones UI (§9.2) | Not started |
| 7 | Real letterhead asset swapped into the resume formatter | Waiting on the brand asset | Blocked on asset |

## 9. Decisions from product (2026-07-20)

1. **Targets are milestones, not quotas.** Progress UI must read as motivation —
   "7 of 10 this week 🎯", milestone celebrations on crossing — never as
   enforcement. No red "behind target" states, no failure language. Copy tone:
   reach for it, don't answer for it.
2. **The next-in-line manager sets milestones** for the people under them
   (RA Lead → RAs, BDM/Recruiter Lead → recruiters, Associate Director → leads).
   `user_goals` needs `set_by` and period; the settings UI lives on the manager's
   team page, not in Admin.
3. **Company-wide job visibility for recruiters** — shipped (see §1 All Jobs):
   browse all jobs, masked candidate contacts until assigned, request-assignment
   loop through the BDM dashboard.
4. **Rejection reasons are BD's duty, free-text, and never a recruiter scorecard**
   — shipped. "It depends on a lot" (product's words), so no fixed enum; a note is
   attached to every rejection. Shown alongside the recruiter's own period stats
   (subs/interviews/etc. for the week, month, or any range) as context for *why*,
   explicitly not as a performance measure — see the recruiter dashboard's
   "Recent rejections… for context, not a scorecard" card.
5. **Next-in-line managers see revenue + placements** for the people under (or
   assigned to) them — shipped on the BD Manager dashboard's "My recruiting team"
   card (subs, interviews, offers, placements, revenue per recruiter, total
   revenue rollup). Revenue is `job_orders.placement_fee` attributed to each
   placement. True "people under them" scoping needs §10's manager_id field —
   until then this shows every recruiter, since recruiters aren't bound to one BDM.
6. **Stage ownership: BD schedules interviews and owns everything past BD
   submission.** A recruiter can change a submission's stage only up to
   "Submitted to BDM" — enforced both in the stage-change endpoint and the stage
   modal (a recruiter literally cannot open a blocked stage). Submitting to the
   BD Manager is a dedicated hand-off form matching the company's existing
   submission-details email template (applicant name/contact/work-auth/location/
   relocation/availability + a required "Submission Comment (important)"), with
   resume attach built in — shipped, see §1.
7. **Resume → formatted submission document** — shipped as a first pass: parses
   the uploaded resume (txt/pdf/docx, reusing the existing resume-parser), lays
   it out under a letterhead, and offers a live preview with Word and PDF
   download. **The real letterhead asset is still needed** — the current
   letterhead is a placeholder brand bar (`public/js/36-resume-format.js`,
   `LETTERHEAD_TOP`/`LETTERHEAD_BOTTOM`); swap it in as soon as it's provided.
8. **Resume preview on the candidate profile** — shipped. PDFs render inline via
   an embedded viewer; other formats fall back to the extracted resume text
   (`candidates.resume_text`) captured at parse time, with a download link when
   no text was captured.

## 10. Extended org structure (proposed — pending product detail)

The role system (`users.roles[]`) can host new profiles without schema change.
Proposed next roles, to be specified with product before building:

- **Recruiter Lead (`recruiter_lead`)**: runs a team of recruiters. Sees: team
  submissions/interviews/placements per recruiter, workload balance (jobs per
  recruiter), idle alerts, and sets recruiter milestones. Can reassign jobs
  within the team (assignment stays BDM-approved). Dashboard = recruiter
  dashboard + "My recruiting team" card.
- **Associate Director (`assoc_director`)**: oversight across desks. Sees the
  entire work detail of the BDs and recruiters in their span: org funnel,
  desk-by-desk comparison, any team member's dashboard (view-as, read-only),
  milestone-setting for the leads under them. No day-to-day action buttons —
  their screens are analysis-first.
- Hierarchy needs one new field: `users.manager_id` (who is my next-in-line),
  which also drives who may set whose milestones (§9.2) and who appears in
  whose team cards — replacing today's role-pair conventions (`bdm` field).

## 11. Open questions (answers would sharpen, not block)

1. **RA quality signal**: is "lead became a job" the right quality metric for RAs,
   or is "lead got a response" fairer (jobs depend on BD skill too)?
2. **Deliverability for RA Lead**: do RA Leads actually manage sending accounts, or
   should that page be BD Lead/Admin only?
3. **New-role spans**: for Recruiter Lead / Associate Director — who reports to
   whom exactly, and which decisions are theirs alone? (Feeds §10.) In particular:
   is a recruiter bound to exactly one BD Manager, or can any BDM assign any
   recruiter to any job (today's actual behavior)? This decides whether §2's "My
   recruiting team" card can ever scope down from "every recruiter" to "my
   recruiters."
4. **Letterhead asset**: the resume formatter (§9.7) needs the real letterhead
   (logo, colors, footer/contact block) to replace the current placeholder.
5. **Job-board contact masking scope**: All Jobs masks candidate contacts on jobs
   a recruiter isn't assigned to (§1). The general Candidates list still shows
   full contact details to any recruiter — should that also be locked to "only
   candidates on your own jobs," or is the shared candidate pool intentionally
   open to every recruiter?

## 12. Bugs found and fixed in passing

- **My Profile page was silently broken for every user.** `30-page-candidate.js`
  declared `window.renderProfile = function(){...}` for the *candidate* profile
  view, which — because plain `<script>` globals share one namespace — overwrote
  `10-page-modals.js`'s `renderProfile()`, the actual My Profile / account page.
  Every user opening "My Profile" saw "No candidate loaded." instead of their
  account page. Fixed by renaming the candidate-profile function to
  `renderCandidateProfile` (its one call site, `paintProfile()`, updated to
  match). Covered by a regression check in `test/workflow-gating-smoke.mjs`.
