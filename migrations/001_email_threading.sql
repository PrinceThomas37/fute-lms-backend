-- Email threading for Microsoft Graph follow-up replies
-- Run in Supabase → SQL Editor

ALTER TABLE emails ADD COLUMN IF NOT EXISTS graph_message_id TEXT;
ALTER TABLE emails ADD COLUMN IF NOT EXISTS conversation_id TEXT;
ALTER TABLE emails ADD COLUMN IF NOT EXISTS in_reply_to_graph_message_id TEXT;

CREATE INDEX IF NOT EXISTS idx_emails_job_contact_sent ON emails(job_id, contact_id) WHERE status = 'sent';
CREATE INDEX IF NOT EXISTS idx_emails_graph_message ON emails(graph_message_id) WHERE graph_message_id IS NOT NULL;

COMMENT ON COLUMN emails.graph_message_id IS 'Microsoft Graph message id in Sent Items — used to reply in-thread for follow-ups';
COMMENT ON COLUMN emails.conversation_id IS 'Outlook conversation id for the thread';
COMMENT ON COLUMN emails.in_reply_to_graph_message_id IS 'Parent Graph message id when this row is a follow-up reply';
