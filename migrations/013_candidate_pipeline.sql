-- ============================================================================
-- 013 — Candidate pipeline (the tagging layer)
--
-- Slice 2 of docs/ATS_RECRUITING_PLAN.md: the Ceipal "Pipeline" tab. A candidate
-- is TAGGED into a job order (lightweight sourcing bucket) before being promoted
-- to a formal submission. Distinct from `submissions` and carries its own PL- id,
-- pipeline status, and per-tag snapshot of rate / availability / employer fields.
--
-- Additive and off by default: no existing behaviour changes until a candidate is
-- tagged. Idempotent (IF NOT EXISTS).
-- ============================================================================

INSERT INTO id_sequences (prefix, last_value) VALUES ('PL', 0)
ON CONFLICT (prefix) DO NOTHING;

CREATE TABLE IF NOT EXISTS candidate_pipeline (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pipeline_code TEXT UNIQUE,
  candidate_id UUID NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  job_order_id UUID NOT NULL REFERENCES job_orders(id) ON DELETE CASCADE,
  pipeline_status TEXT NOT NULL DEFAULT 'Tagged',
  -- per-tag snapshot (the grid shows values captured at tag time, editable later)
  work_auth_snap TEXT,
  bill_rate TEXT,
  pay_rate TEXT,
  employer_name TEXT,
  availability TEXT,
  notice_period TEXT,
  current_ctc TEXT,
  source TEXT,
  notes TEXT,
  tagged_by UUID REFERENCES users(id) ON DELETE SET NULL,
  tagged_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  submission_id UUID REFERENCES submissions(id) ON DELETE SET NULL,  -- set when promoted
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

-- One live tag per candidate per job order.
CREATE UNIQUE INDEX IF NOT EXISTS candidate_pipeline_cand_job_uidx
  ON candidate_pipeline (candidate_id, job_order_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS candidate_pipeline_job_idx     ON candidate_pipeline (job_order_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS candidate_pipeline_cand_idx    ON candidate_pipeline (candidate_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS candidate_pipeline_status_idx  ON candidate_pipeline (pipeline_status) WHERE deleted_at IS NULL;
