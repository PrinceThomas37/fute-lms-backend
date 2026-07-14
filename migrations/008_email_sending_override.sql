-- ============================================================================
-- 008_email_sending_override.sql
-- Per-email sending-mailbox override, for sequence "from"-mailbox ROTATION.
--
-- Today the send loop authenticates with the JOB's sending_email_id, so every
-- email for a job goes from the same mailbox. To let a sequence rotate across a
-- chosen set of "from" mailboxes (spreading volume, Apollo/Saleshandy-style),
-- each queued email can name its own sending mailbox. When this column is NULL
-- (every existing row), the send loop falls back to job.sending_email_id — so
-- behaviour is unchanged until a sequence sets it.
--
-- Additive and safe: one nullable column + FK. Nothing existing is altered.
-- Apply in: Supabase -> SQL Editor (or Supabase MCP apply_migration).
-- ============================================================================

ALTER TABLE emails ADD COLUMN IF NOT EXISTS sending_email_id UUID REFERENCES user_emails(id);
CREATE INDEX IF NOT EXISTS idx_emails_sending_email_id ON emails (sending_email_id);
