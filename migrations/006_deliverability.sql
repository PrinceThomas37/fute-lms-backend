-- ============================================================================
-- 006_deliverability.sql
-- Data model for the deliverability & reply-rate epic. All additive: a new
-- table plus IF NOT EXISTS columns. Nothing existing is altered, so applying
-- this changes no current behaviour on its own.
-- Apply in: Supabase -> SQL Editor (or Supabase MCP apply_migration).
-- ============================================================================

-- Global opt-out / never-mail list.
CREATE TABLE IF NOT EXISTS suppression_list (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT NOT NULL,
  reason TEXT,                 -- 'unsubscribe' | 'manual' | 'complaint' | 'hard_bounce'
  source TEXT,                 -- 'reply' | 'admin' | 'ndr'
  note TEXT,
  created_by UUID,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_suppression_email ON suppression_list (lower(email));
ALTER TABLE suppression_list ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_all_suppression" ON suppression_list
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Reply tracking on contacts. (Role/disposable flags are pure functions of the
-- address and computed on the fly, so they need no column.)
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS replied_at TIMESTAMPTZ;
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS reply_snippet TEXT;
CREATE INDEX IF NOT EXISTS idx_contacts_replied_at ON contacts (replied_at);

-- Mailbox warm-up ramp + bounce-rate auto-pause.
ALTER TABLE user_emails ADD COLUMN IF NOT EXISTS warmup_start_date DATE;
ALTER TABLE user_emails ADD COLUMN IF NOT EXISTS auto_paused_at TIMESTAMPTZ;
