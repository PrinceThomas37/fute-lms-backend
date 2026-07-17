-- ============================================================================
-- 014 — Submission ATS fields + lifecycle (the Ceipal "Submissions" tab)
--
-- Slice 3 of docs/ATS_RECRUITING_PLAN.md. A submission is a candidate formally
-- put forward on a job order (distinct from the pipeline tag). This widens it to
-- the Ceipal submission grid: SB- code, revision status, per-submission rate /
-- employer / availability snapshot, and who submitted it and when. `pipeline_id`
-- links back to the pipeline row it was promoted from (nullable for direct adds).
--
-- The `stage` column continues to serve as the canonical application status
-- (the lifecycle is unified on one field so the kanban and the BDM approval gate
-- keep working). Additive and idempotent; the table is empty in production.
-- ============================================================================

INSERT INTO id_sequences (prefix, last_value) VALUES ('SB', 0)
ON CONFLICT (prefix) DO NOTHING;

ALTER TABLE submissions ADD COLUMN IF NOT EXISTS submission_code TEXT;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS pipeline_id     UUID REFERENCES candidate_pipeline(id);
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS revision_status TEXT;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS bill_rate       TEXT;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS pay_rate        TEXT;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS employer_name   TEXT;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS availability    TEXT;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS notice_period   TEXT;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS submitted_by    UUID REFERENCES users(id);
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS submitted_at    TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS submissions_code_key     ON submissions (submission_code);
CREATE INDEX        IF NOT EXISTS submissions_pipeline_idx ON submissions (pipeline_id) WHERE deleted_at IS NULL;
