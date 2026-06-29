-- ============================================================================
-- 005_domain_events.sql
-- The visible timeline for the in-process event bus. Every domain event
-- (lead.assigned, email.sent, email.bounced, contact.invalidated, ...) is
-- recorded here so the interconnected reactions can be inspected/replayed.
-- Apply in: Supabase -> SQL Editor (or via the Supabase MCP apply_migration).
-- ============================================================================
CREATE TABLE IF NOT EXISTS domain_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  event TEXT NOT NULL,
  payload JSONB,
  actor_user_id UUID,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_domain_events_created_at ON domain_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_domain_events_event ON domain_events(event);

ALTER TABLE domain_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_all_domain_events" ON domain_events
  FOR ALL TO service_role USING (true) WITH CHECK (true);
