-- ============================================================================
-- 010_gmail_tokens.sql
-- OAuth token store for Gmail / Google Workspace mailboxes — the mirror of
-- microsoft_tokens, so a Gmail mailbox can send/read the same way an Outlook
-- one does. Additive; nothing else changes. Gmail sending stays unavailable
-- until GOOGLE_CLIENT_ID/SECRET are set and Google approves the restricted
-- scopes — this table just gives the tokens somewhere to live.
-- Apply in: Supabase -> SQL Editor (or Supabase MCP apply_migration).
-- ============================================================================

CREATE TABLE IF NOT EXISTS gmail_tokens (
  user_email_id UUID PRIMARY KEY REFERENCES user_emails(id) ON DELETE CASCADE,
  user_id UUID,
  email_address TEXT,
  access_token TEXT,
  refresh_token TEXT,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE gmail_tokens ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_all_gmail_tokens" ON gmail_tokens;
CREATE POLICY "service_all_gmail_tokens" ON gmail_tokens FOR ALL TO service_role USING (true) WITH CHECK (true);
