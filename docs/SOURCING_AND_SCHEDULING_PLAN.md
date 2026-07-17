# Fute Global LMS — Sourcing Connectors & Interview Scheduling Plan

**Design record · rev. 2026-07-17**
Repo `princethomas37/fute-lms-backend` · branch `claude/ats-recruiting-workflow-7pzaul`

Extends the ATS (candidate DB → pipeline → submission → lifecycle → profile) with two capabilities:
1. **Sourcing connectors** — pull candidates from job boards / people databases into our candidate database.
2. **Interview scheduling** — book interviews on Google Meet, Microsoft Teams, or Zoom from a submission.

Built the same way as the rest of the app: **additive, off by default, one verified slice per PR.**

---

## 0. The credential reality (read first)

Legitimate candidate sourcing is **API-gated**, not scrapeable — and scraping job boards violates their ToS,
is unreliable, and risks account bans, so we do **not** build scrapers. Each board is a **provider** the admin
configures with authorized credentials. What that takes varies a lot:

| Provider | Access needed | Status here |
|---|---|---|
| **CSV / file import** | none | ✅ **built now** — export from any board, import with dedup |
| **Apollo** | Apollo API key (already on the Integrations page) | 🔌 scaffolded — real connector when key added |
| **Indeed** | Indeed employer/API account | 🔌 scaffolded |
| **Monster / CareerBuilder / Dice** | paid account + API credentials | 🔌 scaffolded |
| **LinkedIn** | **LinkedIn Talent Solutions partner status** (not just a key) | 🔌 scaffolded, gated on partner approval |

The framework normalizes every provider to one shape and one import path, so a new board is a small adapter,
not a rebuild. **CSV import is the universal fallback** and works for every board today.

---

## 1. Sourcing framework

```
PROVIDER (csv · apollo · indeed · linkedin · monster · careerbuilder · dice)
        │  search() / parse()
        ▼
SOURCING_CANDIDATES (staging)  ──review + dedup──▶  CANDIDATES (our DB)  ──optional──▶  job PIPELINE
```

- **Provider registry** (`config/sourcing.js`) — id, label, kind (`file` | `api`), availability, credential note.
  `file` (CSV) is always available; `api` providers report `needs_credentials` until wired + keyed.
- **Staging table** `sourcing_candidates` — everything pulled from a source lands here first with the raw
  payload, normalized fields, and a **duplicate flag** (matched against `candidates` by the same rule as the
  ATS: full name + email-or-phone). Nothing touches the real database until the recruiter imports it.
- **Import** reuses the ATS candidate-create path — same `CN-` ids, same dedup (warn/skip/force), same owner —
  and can **tag the imported candidate straight onto a job's pipeline** in one step.

### Endpoints (Slice A — built)
- `GET  /sourcing/providers` — registry + availability.
- `POST /sourcing/import-file` — normalized rows (parsed client-side from CSV/XLSX) → staged with batch dedup.
- `GET  /sourcing/staged` — the review grid (filter by provider / status; duplicates flagged).
- `POST /sourcing/staged/:id/import` — import one (honors dedup unless `force`; optional `job_order_id` to tag).
- `POST /sourcing/import-selected` — bulk import.
- `DELETE /sourcing/staged/:id` — discard.
- `POST /sourcing/search` — provider people-search; returns `needs_credentials` for unconfigured API providers.

### Frontend (Slice A — built)
- A **Sourcing** page: provider cards, **CSV/XLSX import** (parsed in-browser via the bundled XLSX lib, headers
  auto-mapped), and a **staging review grid** — duplicates badged, select + **Import** (optionally tag to a job),
  or discard.

### Later slices
- **B — Apollo connector**: real people-search against the Apollo API using the Integrations key.
- **C — Indeed / Monster / CareerBuilder / Dice**: per-board adapters as credentials arrive.
- **D — LinkedIn**: gated on Talent Solutions partner access.

---

## 2. Interview scheduling (next slice)

A pluggable **meeting provider** attached to a submission, mirroring the sourcing design:

| Provider | Mechanism | Builds on |
|---|---|---|
| **Google Meet** | Calendar event with a Meet link (Calendar API) | existing Google OAuth scaffold |
| **Microsoft Teams** | Outlook/Teams online meeting (Graph API) | existing Microsoft Graph integration |
| **Zoom** | Zoom meeting (Zoom API) | new Zoom app (server-to-server OAuth) |

- **Data model** `interviews` — submission_id, provider, join_url, event_id, scheduled_start/end, timezone,
  interviewer(s), candidate/attendees, status, created_by.
- **Flow**: from a submission → "Schedule interview" → pick provider + time + attendees → creates the event and
  the meeting link → stores it → advances the submission to **Interview Scheduled** and drops the join link onto
  the submission + candidate profile. Reminders reuse the existing reminders/notification plumbing.
- Each provider is **inert until its OAuth app is configured**; the picker only offers connected providers.

---

## 3. Conventions

Additive & off by default · legitimate API connectors only (no scraping) · one verified PR per slice · dedup and
candidate-ownership reuse the ATS rules · every provider secret admin-only and masked (via the Integrations store).

---

*Fute Global LMS · `princethomas37/fute-lms-backend` · compiled 2026-07-17.*
