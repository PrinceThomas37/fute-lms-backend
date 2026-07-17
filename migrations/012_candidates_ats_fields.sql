-- ============================================================================
-- 012 — Candidate ATS fields + duplicate-detection helpers
--
-- Slice 1 of docs/ATS_RECRUITING_PLAN.md: widen the shared candidate pool to the
-- full Ceipal-style field set, and add normalized generated columns so duplicate
-- detection (full name + email-or-phone) is a fast, consistent index lookup that
-- can never drift from whatever the app happens to write.
--
-- Additive and safe: every column is ADD COLUMN IF NOT EXISTS. The candidates
-- table is empty in production, so the generated columns backfill instantly.
-- ============================================================================

-- ── Names ────────────────────────────────────────────────────────────────────
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS first_name TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS last_name  TEXT;

-- ── Contact ──────────────────────────────────────────────────────────────────
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS alt_phone    TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS linkedin_url TEXT;

-- ── Location (split; current_location kept for legacy) ───────────────────────
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS city    TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS state   TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS country TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS zip     TEXT;

-- ── Work eligibility ─────────────────────────────────────────────────────────
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS work_authorization TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS clearance          TEXT;

-- ── Employment / headline ────────────────────────────────────────────────────
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS current_employer TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS headline         TEXT;  -- desired / display job title

-- ── Availability ─────────────────────────────────────────────────────────────
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS availability  TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS notice_period TEXT;

-- ── Money ────────────────────────────────────────────────────────────────────
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS current_ctc  TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS expected_ctc TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS bill_rate    TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS pay_rate     TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS pay_type     TEXT;   -- Hourly | Yearly
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS pay_currency TEXT DEFAULT 'USD';

-- ── Classification / ownership ───────────────────────────────────────────────
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS applicant_status TEXT DEFAULT 'New lead';
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS tags             TEXT[];
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS owner_id         UUID REFERENCES users(id) ON DELETE SET NULL;

-- ── Resume ───────────────────────────────────────────────────────────────────
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS resume_filename TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS resume_text     TEXT;  -- parsed later (future phase)

-- ── Audit ────────────────────────────────────────────────────────────────────
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS updated_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- ── Normalized generated columns for duplicate detection ─────────────────────
-- name_norm : lower-cased, whitespace-collapsed full name
-- email_norm: lower-cased / trimmed email ('' when null)
-- phone_norm: last 10 digits of the phone ('' when null / no digits)
-- All expressions are IMMUTABLE, so STORED generated columns are valid.
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS name_norm TEXT
  GENERATED ALWAYS AS (lower(btrim(regexp_replace(coalesce(full_name, ''), '\s+', ' ', 'g')))) STORED;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS email_norm TEXT
  GENERATED ALWAYS AS (lower(btrim(coalesce(email, '')))) STORED;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS phone_norm TEXT
  GENERATED ALWAYS AS (right(regexp_replace(coalesce(phone, ''), '[^0-9]', '', 'g'), 10)) STORED;

-- Dedup lookup indexes (name + email / name + phone), and browse filters.
CREATE INDEX IF NOT EXISTS candidates_name_norm_idx  ON candidates (name_norm)  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS candidates_email_norm_idx ON candidates (email_norm) WHERE deleted_at IS NULL AND email_norm <> '';
CREATE INDEX IF NOT EXISTS candidates_phone_norm_idx ON candidates (phone_norm) WHERE deleted_at IS NULL AND phone_norm <> '';
CREATE INDEX IF NOT EXISTS candidates_status_idx     ON candidates (applicant_status) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS candidates_owner_idx      ON candidates (owner_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS candidates_source_idx     ON candidates (source) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS candidates_state_idx      ON candidates (state) WHERE deleted_at IS NULL;
