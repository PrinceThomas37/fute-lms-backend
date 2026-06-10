-- Track which outreach style variant (v1–v5) was used per contact so FU1/FU2 match O1.
ALTER TABLE emails
  ADD COLUMN IF NOT EXISTS template_variant TEXT;

ALTER TABLE follow_ups
  ADD COLUMN IF NOT EXISTS template_variant TEXT;

CREATE INDEX IF NOT EXISTS idx_emails_job_contact_variant
  ON emails(job_id, contact_id, template_variant)
  WHERE status = 'sent' AND followup_type IS NULL;
