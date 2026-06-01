-- Email threading columns for Microsoft Graph in-thread follow-ups (FU1/FU2).
-- Run in Supabase SQL Editor before relying on threaded follow-up sends.

ALTER TABLE emails
  ADD COLUMN IF NOT EXISTS graph_message_id TEXT,
  ADD COLUMN IF NOT EXISTS conversation_id TEXT,
  ADD COLUMN IF NOT EXISTS in_reply_to_graph_message_id TEXT,
  ADD COLUMN IF NOT EXISTS followup_type TEXT;

CREATE INDEX IF NOT EXISTS idx_emails_graph_message_id ON emails(graph_message_id) WHERE graph_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_emails_job_contact_followup ON emails(job_id, contact_id, followup_type, status);

-- Follow-ups: allow scheduling only after outreach is sent
ALTER TABLE follow_ups
  ALTER COLUMN outreach_sent_at DROP NOT NULL,
  ALTER COLUMN followup1_due_date DROP NOT NULL,
  ALTER COLUMN followup2_due_date DROP NOT NULL;
