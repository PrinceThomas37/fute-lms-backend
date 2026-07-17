# Fute Global LMS — ATS / Recruiting Workflow Plan

**Design contract · rev. 2026-07-16**
Repo `princethomas37/fute-lms-backend` · branch `claude/ats-recruiting-workflow-7pzaul`

This is the plan-first design document for the **recruiting phase** of the platform — the
Applicant Tracking System (ATS) that picks up *after* a lead becomes a job and runs candidates
through to placement. Modeled on the Ceipal screens the owner shared, and built to **extend** the
recruiting spine that already exists rather than replace it.

Nothing here is built yet. Every slice below ships **additive and off by default**, one verified
PR at a time, in the house style of the earlier plan docs (`WARMUP_AND_SEQUENCING_PLAN.md`,
`ENTERPRISE_OUTREACH_PLAN.md`).

---

## 0. Decisions locked with the owner

| # | Decision | Choice |
|---|---|---|
| 1 | Pipeline vs Submission modeling | **Two layers (Ceipal-faithful)** — a tagging/**pipeline** record and a separate **submission** record, each with its own ID |
| 2 | Duplicate detection | **Full name + (email OR phone)**, **warn-and-offer**: surface the existing candidate and let the user open/reuse — never silently duplicate, never hard-block |
| 3 | This turn | **Plan doc first**; building starts only on the owner's approval |

---

## 1. Where the recruiting workflow sits

```
LEAD (jobs row)  ──convert (Connected)──▶  JOB ORDER (job_orders)  ──assign──▶  RECRUITER(S)
                                                     │
                                                     ▼
                    CANDIDATE DATABASE ──tag──▶ PIPELINE ──promote──▶ SUBMISSION ──▶ PLACEMENT
                     (shared pool, CN-)        (per job, PL-)        (per job, SB-)
```

- A **lead** lives in the `jobs` table (the leads pipeline: Active → Connected → …).
- When a lead reaches **Connected**, a BD Manager **converts** it into a **job order**
  (`job_orders`, code `JOB-####`). This already works.
- The BD Manager **assigns recruiters** to the job order (`recruiter_assignments`). Already works.
- Recruiters (and BD Managers) then **source candidates** — add them to the shared candidate
  database, **tag** them into a job's **pipeline**, and **promote** the good ones to a
  **submission**, which then advances through the client-facing lifecycle to **placement**.

The recruiting phase is everything from "job order exists" rightward.

---

## 2. What already exists (extend, don't rebuild)

The prior sessions built a working skeleton. It is **live but nearly empty** (0 candidates,
0 submissions, 1 test job order), so we can extend the schema freely — no backfill risk.

**Backend — `bd_recruiter_routes.js`** (mounted from `index.js`):

| Table / RPC | Purpose | Status |
|---|---|---|
| `job_orders` | Job/req created from a Connected lead. `JOB-####`, full field set (client, skills, pay, location, work_auth, …) | ✅ solid, keep |
| `recruiter_assignments` | recruiter ↔ job order (unique, upsert) | ✅ keep |
| `candidates` | Shared pool, `CN-####`. **Thin** — name, email, phone, location, title, skills, years, resume_url, source | ⚠ extend |
| `submissions` | candidate ↔ job, single `stage` lifecycle, BDM-gated "Submitted to Client" | ⚠ extend + split |
| `submission_activity` | Stage-change / action log | ✅ keep, reuse |
| `next_id(prefix)` | Generates `LD-` / `JOB-` / `CN-` codes | ✅ keep, add `PL-`/`SB-` |
| `/bd-analytics/*` | Recruiter scorecard + funnel | ✅ keep, extend |

**Frontend — `public/js/25-workflow-bd.js`**: job list, My Jobs, job detail, a Kanban
pipeline, recruiter assignment, and an "Add Candidate" modal (search pool *or* create-new,
already usable by both BD and recruiter roles).

**Roles** (`middleware/authorize.js`): `hasRole` supports both a legacy single `role` and a
`roles[]` array. Recruiting uses `recruiter`, `bd`, `bd_lead`, `admin`. The gate
"only a BD Manager may move a candidate into *Submitted to Client*" is already enforced.

> ⚠ **The recruiting tables have no committed DDL** — they were applied straight to the live
> Supabase. Slice 0 fixes that (reproducibility) before we change anything.

---

## 3. Gap analysis vs. the Ceipal screens

| # | Ceipal capability | Today | Plan |
|---|---|---|---|
| 1 | **Applicants database** — a top-nav grid of every candidate (ID, name, email, mobile, city, source, status, job title, ownership, work auth, created by/on) | Candidates only appear inside a modal | New **Applicants** page (Slice 1) |
| 2 | **Duplicate catch** on add (email/phone + name) | `POST /candidates` inserts blindly | Dedup endpoint + warn-and-offer (Slice 1) |
| 3 | **Rich candidate fields** (work auth, employer, availability, notice period, current CTC, bill/pay rate, ownership, applicant status, split location) | ~10 thin fields | Extended `candidates` schema (Slice 1) |
| 4 | **Pipeline vs Submissions** — two separate per-job lists, each with its own ID | One `submissions` table | New `candidate_pipeline` layer (Slice 2) + extended submissions (Slice 3) |
| 5 | **Per-job tabbed grids** with exact columns | Kanban only | Pipeline tab (Slice 2) + Submissions tab (Slice 3) |
| 6 | **Candidate profile** — lifecycle bar, notes, documents | None | Profile page (Slice 4) + notes/docs (Slice 5) |
| 7 | Resume parsing, job-board sourcing | None | Future phases (§9) |

---

## 4. Target data model

All new columns/tables are **additive** and created with `IF NOT EXISTS`. IDs use the existing
`next_id()` code generator for consistency (prefixed `CN-`/`PL-`/`SB-`). *(Ceipal uses plain
integers for Pipeline/Submission IDs; we keep prefixed codes for readability but can switch to a
bare sequence if the owner prefers the exact Ceipal look.)*

### 4.1 `candidates` — the shared pool (extend)

Keep every existing column; add the ATS field set:

| Group | New columns |
|---|---|
| Name | `first_name`, `last_name` (keep `full_name` as canonical/display) |
| Contact | `mobile` (alias of `phone`), `alt_phone`, `linkedin_url` |
| Location | `city`, `state`, `country`, `zip` (keep `current_location` for legacy) |
| Work eligibility | `work_authorization`, `clearance` |
| Employment | `current_employer`, `headline`/desired job title, `experience_years` (exists) |
| Availability | `availability`, `notice_period` |
| Money | `current_ctc`, `expected_ctc`, `bill_rate`, `pay_rate`, `pay_type`, `pay_currency` |
| Classification | `applicant_status` (New lead / Active / Do-Not-Call / Placed / Blacklisted), `source` (exists), `tags[]` |
| Ownership | `owner_id` (the "Ownership" column) — defaults to creator |
| Resume | `resume_url` (exists), `resume_filename`, `resume_text` (parsed, later) |
| Dedup helpers | `email_norm`, `phone_norm` (normalized, indexed — see §5) |
| Audit | `created_by` (exists), `updated_by` |

### 4.2 `candidate_pipeline` — the tagging layer (NEW)

One row per (candidate **tagged into** a job order). This is Ceipal's **Pipeline** tab.

```
id                UUID PK
pipeline_code     TEXT   -- PL-####
candidate_id      UUID  -> candidates(id)
job_order_id      UUID  -> job_orders(id)
pipeline_status   TEXT   -- Tagged | Contacted | Interested | Screening | Shortlisted
                         --  | Moved to Submission | Not Interested | Rejected
work_auth_snap    TEXT   -- snapshot at tag time (grid shows per-tag values)
bill_rate         TEXT
pay_rate          TEXT
employer_name     TEXT
availability      TEXT
notice_period     TEXT
current_ctc       TEXT
source            TEXT
notes             TEXT
tagged_by         UUID  -> users(id)     -- "Tagged By"
tagged_at         TIMESTAMPTZ            -- "Tagged On"
submission_id     UUID  -> submissions(id)  -- set when promoted
deleted_at        TIMESTAMPTZ
UNIQUE (candidate_id, job_order_id) WHERE deleted_at IS NULL
```

Grid columns (from the owner's spec): **Pipeline ID · Applicant Name · Pipeline Status ·
Work Authorization · Mobile · Location · Country · Experience · Source · Resume · Bill Rate ·
Pay Rate · Employer Name · Availability · Notice Period · Current CTC · Tagged By · Tagged On**
— every one is covered by the pipeline row joined to the candidate.

### 4.3 `submissions` — the submission layer (extend)

The existing table becomes Ceipal's **Submissions** tab. Add:

```
submission_code    TEXT   -- SB-####
pipeline_id        UUID  -> candidate_pipeline(id)  -- origin (nullable: direct submit)
application_status TEXT   -- replaces/absorbs `stage`, expanded set (§4.4)
revision_status    TEXT   -- N/A | Revised | Reformatted …
bill_rate          TEXT
pay_rate           TEXT
employer_name      TEXT
availability       TEXT
notice_period      TEXT
submitted_by       UUID  -> users(id)    -- "Submitted By"
submitted_at       TIMESTAMPTZ           -- "Submitted On"
```

Keep `stage`, `bdm_approved_at/by`, `submitted_rate`, `notes`, `submission_activity`.
`stage` and `application_status` are unified on one canonical list so the existing Kanban and
BDM gate keep working (table is empty, so no data migration).

Grid columns: **Submission ID · Applicant Name · Work Authorization · Mobile · Location ·
Country · Experience · Source · Resume · Revision Status · Application Status · Outlook MSG ·
Bill Rate · Pay Rate · Employer Name · Availability · Submitted On/By** — all covered.

### 4.4 Canonical submission lifecycle (application_status)

Mirrors the candidate-profile progress bar, keeping the existing BDM gate:

```
Waiting for Evaluation → Submitted to BDM → [gate] Submitted to Client
    → Interview Scheduled → Interview Completed → Offer → Confirmation → Placement
Terminal / side: Rejected · Not Joined · On Hold
```

The profile progress bar **Pipeline → Submission → Client Submission → Interview →
Confirmation → Placement → Not Joined** is a *derived milestone view* built from
`candidate_pipeline.tagged_at`, `submissions.submitted_at`, and the timestamped status changes
in `submission_activity`.

### 4.5 `candidate_notes` (NEW) & `candidate_documents` (NEW)

```
candidate_notes(id, candidate_id, job_order_id?, note_type['job_posting'|'applicant_reference'],
                body, created_by, created_at)
candidate_documents(id, candidate_id, doc_type['resume'|'other'], filename, url,
                    uploaded_by, uploaded_at, deleted_at)
```

Matches the profile page's **Notes** (Job Posting / Applicant Reference tabs) and **Documents**
sections. Files go to a Supabase Storage bucket.

---

## 5. Duplicate detection (owner's requirement)

**Rule:** a candidate is a suspected duplicate when
`normalized full name matches` **AND** (`email matches` **OR** `phone matches`).

- **Normalization:** email → `lower(trim())`; phone → digits only, last 10 (`phone_norm`);
  name → `lower(trim())` collapsed whitespace. Stored as `email_norm` / `phone_norm` with
  indexes for fast lookup.
- **Endpoint:** `GET /candidates/check-duplicate?full_name=&email=&phone=` → `{ matches: [...] }`.
- **On create:** `POST /candidates` runs the same check server-side. Unless the request carries
  `force: true`, a hit returns **HTTP 409** with the matching candidate(s) instead of inserting.
- **UX (warn-and-offer):** the add form shows *"Possible existing candidate: **Jane Doe · CN-1042**
  — Open · Tag to this job · Create anyway."* The user never silently makes a copy and is never
  hard-blocked.
- **Same guard** applies when tagging into a pipeline (can't tag the same candidate to a job
  twice — enforced by the unique index) and when submitting.

---

## 6. Endpoints

**Candidates**
- `GET /candidates` — server-side pagination + filters (status, source, state, work auth, owner, q)
- `GET /candidates/:id` — full profile (candidate + pipelines + submissions + notes + documents)
- `POST /candidates` — dedup + `force` flag, full field set, `owner_id` default = creator
- `PUT /candidates/:id` — edit all fields
- `GET /candidates/check-duplicate` — dedup probe
- `DELETE /candidates/:id` — soft delete

**Pipeline (tagging)**
- `GET /job-orders/:id/pipeline` — the Pipeline-tab grid
- `POST /pipeline` — tag a candidate to a job (recruiter scoped to assigned jobs)
- `PATCH /pipeline/:id/status` — change pipeline status
- `POST /pipeline/:id/promote` — create a submission from a pipeline row
- `DELETE /pipeline/:id`

**Submissions (extend existing)**
- `GET /job-orders/:id/submissions` — the Submissions-tab grid (extended columns)
- `POST /submissions` — accept `pipeline_id` (promote) or `candidate_id` (direct); sets `SB-` code
- `PATCH /submissions/:id/status` — advance lifecycle (keeps the BDM "Submitted to Client" gate)
- `DELETE /submissions/:id`

**Notes / Documents**
- `GET|POST /candidates/:id/notes`
- `GET|POST /candidates/:id/documents` (upload to Storage)

**Analytics** — extend `/bd-analytics/funnel` and `/bd-analytics/recruiters` to count tagged
(pipeline) and submitted separately.

RBAC throughout: BD/BD-Lead/Admin unrestricted; recruiters scoped to their assigned job orders
for pipeline/submission writes; "Submitted to Client" stays BDM-gated.

---

## 7. Frontend pages

1. **Applicants** (new top-nav, like Ceipal) — grid: Applicant ID · Name · Email · Mobile ·
   City · State · Source · Applicant Status · Job Title · Ownership · Work Authorization ·
   Created By · Created On. Search + filters + server pagination. `+ New` (with dedup),
   row → profile, bulk "Add to Job".
2. **Job page → Pipeline tab** — the pipeline grid + `+ Add to Pipeline` (search DB or
   create-new, both with dedup) + status change + promote-to-submission.
3. **Job page → Submissions tab** — the submissions grid + `+ Submit Candidate`
   (promote from pipeline, or direct) + lifecycle advance (BDM gate on Submitted to Client).
   *(The existing Kanban stays as an alternate view of the same submissions.)*
4. **Candidate profile** — header, lifecycle progress bar (per job), all fields (editable),
   pipelines & submissions across every job, Notes (two tabs), Documents, activity log.

Follows the modular `public/js/NN-*.js` pattern; likely `26-page-applicants.js`,
`27-job-pipeline-tabs.js`, `28-candidate-profile.js` (numbers TBD).

---

## 8. Build slices (one verified PR each · additive · off by default)

| Slice | Deliverable | Migration |
|---|---|---|
| **0** | **Baseline** — commit DDL of the existing live recruiting tables + `next_id()` (reproducibility, no behavior change) | `011_ats_recruiting_baseline.sql` |
| **1** | **Candidate database + dedup + Applicants page** — extended `candidates`, dedup endpoint + warn-and-offer, the Applicants grid, add-from-both-sides with `CN-` IDs and ownership | `012_candidates_ats_fields.sql` |
| **2** | **Pipeline (tagging) layer** — `candidate_pipeline` + endpoints + job-page **Pipeline tab** grid + Add-to-Pipeline | `013_candidate_pipeline.sql` |
| **3** | **Submissions grid + lifecycle** — extend `submissions`, job-page **Submissions tab** grid, promote pipeline→submission, keep BDM gate | `014_submissions_ats_fields.sql` |
| **4** | **Candidate profile page** — lifecycle bar, per-job history, editable overview | — |
| **5** | **Notes & Documents** — `candidate_notes` + `candidate_documents` + Supabase Storage resume upload | `015_candidate_notes_documents.sql` |
| **6** | **Taxonomies & filter polish** — work-auth / source / applicant-status lookups, advanced filter panel | — |

Slice 1 is the foundation the owner emphasized ("a place where candidates can be added for both
BD manager and recruiter side with individual candidate ID"). Each slice ends with backend +
frontend smoke tests, mirroring the existing `test/` harness.

---

## 9. Future phases (noted, not scheduled)

- **Resume parsing** — reuse the `jd-parser.js` infrastructure to parse uploaded resumes into
  candidate fields (`resume_text`, skills, experience).
- **Job-board sourcing** — an **Indeed** MCP connector is available in this environment
  (`search_jobs`, `get_resume`); later, source candidates directly into the pool.
- **Duplicate-merge tooling** — merge two candidate records (beyond detect-and-warn).
- **Hotlists / talent pools** — saved candidate groups, re-marketing.
- **Candidate outreach from the profile** — the submission-channel sequencing already exists
  (§ warm-up/sequencing work); wire "start sequence" from the candidate profile.
- **Interview scheduling** — a **Google Calendar** connector is available; schedule interviews
  from a submission.
- **Placement → onboarding handoff** — once "Placement" is reached.

---

## 10. Conventions held

Additive & off by default · one verified PR per slice · the branch reset onto `main` after each
merge (never restacking merged history) · every write gated by role · recruiters scoped to
assigned jobs · "Submitted to Client" BDM-gated · dedup warns, never silently duplicates.

---

*Fute Global LMS · `princethomas37/fute-lms-backend` · branch `claude/ats-recruiting-workflow-7pzaul` ·
compiled from the working session on 2026-07-16.*
