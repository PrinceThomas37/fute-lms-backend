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

- **Sidebar**: Dashboard · My Jobs · Candidates · Sourcing · Email · Reminders · My Profile
  (no Leads — shipped)
- **Dashboard** (shipped): greeting banner (subs week/month, in interview, placements)
  → desk tiles → **My jobs** card (assigned-timeline counts, top-5 by team activity,
  "All my jobs →") → **My candidate pipeline** by stage → **Upcoming interviews** → Reminders.
- **Primary actions**: My Jobs → open job → *Add candidate / Submit to BDM*.
- **Still to build**:
  - Interview-day view: "You have 2 interviews today" strip pinned above tiles.
  - Rejection-reason breakdown ("why my candidates get rejected") — needs
    `rejection_reason` on submissions.
  - Per-recruiter goal setting (e.g. 10 subs/week) so the banner can show progress
    toward target instead of bare counts. Needs `user_goals` table.

## 2. BD MANAGER (`bd`)

**Mission**: turn leads into clients and jobs; keep the recruiting desk moving.
**Measured on**: response/positive rates, jobs opened, submissions reaching clients,
placements (revenue).

- **Sidebar**: Dashboard · Leads · Jobs · Candidates · Sourcing · Email · Reminders ·
  My Insights · My Profile. (Current layout is right; "Jobs" should carry an
  **Awaiting approval** badge — count of `Submitted to BDM`.)
- **Dashboard** (redesign):
  1. Banner: keep lead stats (leads, emails, response, positive) — this IS their number.
  2. **Approvals queue card — the #1 change.** "Awaiting your approval (3)" with
     candidate, job, recruiter, waiting-time; inline *Approve → Client* / *Reject*
     buttons (endpoint exists). An approval sitting 3+ days turns amber. This is the
     BDM's most time-sensitive daily action and today it hides inside job detail.
  3. **Recruiting desk strip** (exists, keep): Active Jobs, At Client, In Interview,
     Offers, Placements, Subs Week/Month.
  4. **My team card** (exists): RA rows with lead stats — but split into two tables:
     "Lead-gen team" (RAs, lead stats) and "Recruiting team" (recruiters — subs,
     interviews, placements from `/bd-analytics/recruiters`, endpoint exists, no UI).
  5. **Jobs needing attention**: jobs with 0 submissions in 14 days, or no recruiter
     assigned ("cold jobs"). *Assign recruiter* button inline.
  6. Response trend + Industry breakdown (keep — these are lead-gen tools).
  7. Reminders (keep).
- **Primary actions**: Leads → *Convert to Job*; Jobs → *Assign recruiter*, *Approve
  submission*; Dashboard → *Approve* from the queue card.
- **Still to build**: approvals-queue endpoint (`GET /submissions?stage=Submitted to BDM`
  scoped to their jobs, with waiting-time), cold-jobs query, recruiter table UI.

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

| Phase | What | Why first |
|---|---|---|
| 1 | BDM approvals-queue card + Jobs badge | Most time-sensitive daily action in the org |
| 2 | RA dashboard (target banner, lead-outcome card) | Largest headcount, worst current fit |
| 3 | BDM recruiting-team table + cold-jobs card | Endpoint exists; closes the manager loop |
| 4 | RA Lead unassigned-card + idle-RA timestamps | Small delta on existing pages |
| 5 | Admin org-funnel + system-health cards | Oversight, lowest urgency |
| 6 | `user_goals` table + target-progress banners (RA + recruiter) | Needs product input on targets |

## 9. Open questions (answers would sharpen, not block)

1. **Targets**: do RAs/recruiters have official daily/weekly quotas today (e.g. 20
   leads/day, 10 subs/week)? Who sets them — admin, or each lead/manager?
2. **BDM ↔ recruiter reporting**: is a recruiter attached to one BD manager, or do
   all recruiters work all BDMs' jobs? (Affects whose numbers appear in whose team card.)
3. **Deliverability for RA Lead**: do RA Leads actually manage sending accounts, or
   should that page be BD Lead/Admin only?
4. **Rejection reasons**: does the business track *why* clients reject candidates?
   If yes, adding `rejection_reason` unlocks the recruiter quality card.
5. **Revenue**: are placement fees tracked well enough that BDM/Admin dashboards
   should show ₹/$ value instead of counts?
6. **Interview logistics**: who actually schedules interviews — recruiter or BDM?
   (Decides where scheduling UI lives.)
7. **RA quality signal**: is "lead became a job" the right quality metric for RAs,
   or is "lead got a response" fairer (jobs depend on BD skill too)?
