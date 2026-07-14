-- ============================================================================
-- 009_warmup_pool.sql
-- Mailbox WARM-UP POOL — real Graph sends between our own connected mailboxes,
-- short auto-reply conversations, and spam-folder rescue, so a new mailbox
-- builds sender reputation before it's used for outreach (the Saleshandy-class
-- warm-up described in docs/WARMUP_AND_SEQUENCING_PLAN.md §1).
--
-- Additive and OFF BY DEFAULT: no mailbox warms until an admin starts it
-- (warmup_status = 'warming'); nothing here changes existing behaviour on its
-- own. Warm-up traffic is tagged with an X-Fute-Warmup header and kept out of
-- outreach analytics, reply/bounce detection, and outreach quota.
-- Apply in: Supabase -> SQL Editor (or Supabase MCP apply_migration).
-- ============================================================================

-- ── Warm-up state on the mailbox itself ─────────────────────────────────────
-- (warmup_start_date + auto_paused_at already exist from migration 006; the
--  start date is reused as the ramp origin so the outreach-cap ramp and the
--  pool ramp share one start.)
ALTER TABLE user_emails ADD COLUMN IF NOT EXISTS warmup_status TEXT;               -- NULL | 'warming' | 'warmed' | 'paused'
ALTER TABLE user_emails ADD COLUMN IF NOT EXISTS warmup_days INT;                  -- target duration, e.g. 25
ALTER TABLE user_emails ADD COLUMN IF NOT EXISTS warmup_pool_opt_in BOOLEAN DEFAULT FALSE; -- may RECEIVE pool mail even when not warming
ALTER TABLE user_emails ADD COLUMN IF NOT EXISTS warmup_graduated_at TIMESTAMPTZ;

-- ── One row per warm-up conversation (a sender -> receiver thread) ───────────
CREATE TABLE IF NOT EXISTS warmup_threads (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  from_mailbox_id UUID NOT NULL REFERENCES user_emails(id) ON DELETE CASCADE,
  to_mailbox_id   UUID NOT NULL REFERENCES user_emails(id) ON DELETE CASCADE,
  conversation_id TEXT,                    -- Graph conversationId, for threading replies
  root_message_id TEXT,                    -- durable Graph id of the first message
  subject TEXT,
  exchanges INT NOT NULL DEFAULT 0,        -- messages sent so far in this thread
  target_exchanges INT NOT NULL DEFAULT 3, -- how many back-and-forth messages this thread should have
  landed_in TEXT,                          -- 'inbox' | 'junk' | 'unknown' (as seen by the receiver)
  rescued BOOLEAN DEFAULT FALSE,           -- receiver moved it out of Junk into Inbox
  status TEXT NOT NULL DEFAULT 'open',     -- 'open' | 'done'
  next_actor_mailbox_id UUID REFERENCES user_emails(id) ON DELETE SET NULL, -- whose turn to reply next
  next_due_at TIMESTAMPTZ,                 -- earliest time the next reply may be sent
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_warmup_threads_from ON warmup_threads(from_mailbox_id, status);
CREATE INDEX IF NOT EXISTS idx_warmup_threads_due  ON warmup_threads(status, next_due_at);

-- ── Per-message log (audit + health scoring) ────────────────────────────────
CREATE TABLE IF NOT EXISTS warmup_messages (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  thread_id UUID NOT NULL REFERENCES warmup_threads(id) ON DELETE CASCADE,
  sender_mailbox_id UUID REFERENCES user_emails(id) ON DELETE SET NULL,
  graph_message_id TEXT,
  direction TEXT,                          -- 'out' (thread opener) | 'reply'
  landed_in TEXT,
  rescued BOOLEAN DEFAULT FALSE,
  sent_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_warmup_messages_thread ON warmup_messages(thread_id);

-- ── Daily warm-up send counter per mailbox ──────────────────────────────────
-- Separate from email_send_log so warm-up volume never touches outreach quota.
CREATE TABLE IF NOT EXISTS warmup_send_log (
  user_email_id UUID NOT NULL REFERENCES user_emails(id) ON DELETE CASCADE,
  send_date DATE NOT NULL,
  emails_sent INT NOT NULL DEFAULT 0,
  PRIMARY KEY (user_email_id, send_date)
);

ALTER TABLE warmup_threads ENABLE ROW LEVEL SECURITY;
ALTER TABLE warmup_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE warmup_send_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_all_warmup_threads"  ON warmup_threads  FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_all_warmup_messages" ON warmup_messages FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_all_warmup_send_log" ON warmup_send_log FOR ALL TO service_role USING (true) WITH CHECK (true);
