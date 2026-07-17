-- ============================================================================
-- 018 — Workflow refinements
--
-- Owner feedback pass on the ATS workflow:
--
-- 1. The Pipeline tab must show EVERY candidate on a job with their stage —
--    candidates added straight to the board created a submission but no
--    pipeline row, so the Pipeline tab looked empty. Backfill a pipeline row
--    for every submission that lacks one and link any unlinked pairs; the app
--    now also creates the pipeline row on direct submission adds.
--
-- 2. Stage changes carry richer context: a sub-stage (4–5 per stage), and for
--    interview stages a date/time + location. Notes ride the existing
--    submission_activity log; reminders reuse the reminders table.
-- ============================================================================

-- ── 2. submission stage context ─────────────────────────────────────────────
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS sub_stage          TEXT;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS interview_at       TIMESTAMPTZ;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS interview_location TEXT;

-- ── 1a. link pipeline rows that match an existing submission ────────────────
UPDATE candidate_pipeline cp
SET submission_id = sub.id, pipeline_status = 'Moved to Submission', updated_at = now()
FROM submissions sub
WHERE cp.submission_id IS NULL AND cp.deleted_at IS NULL AND sub.deleted_at IS NULL
  AND sub.candidate_id = cp.candidate_id AND sub.job_order_id = cp.job_order_id;

-- ── 1b. backfill a pipeline row for submissions that have none ──────────────
DO $$
DECLARE s RECORD;
BEGIN
  FOR s IN
    SELECT sub.id, sub.candidate_id, sub.job_order_id, sub.recruiter_id, sub.created_at
    FROM submissions sub
    WHERE sub.deleted_at IS NULL
      AND NOT EXISTS (
        SELECT 1 FROM candidate_pipeline cp
        WHERE cp.candidate_id = sub.candidate_id
          AND cp.job_order_id = sub.job_order_id
          AND cp.deleted_at IS NULL)
  LOOP
    INSERT INTO candidate_pipeline
      (pipeline_code, candidate_id, job_order_id, pipeline_status, submission_id, tagged_by, tagged_at)
    VALUES
      (next_id('PL'), s.candidate_id, s.job_order_id, 'Moved to Submission', s.id, s.recruiter_id, s.created_at);
  END LOOP;
END $$;
