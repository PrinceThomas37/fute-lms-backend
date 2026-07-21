-- 024_email_tracking.sql
-- Email open/reply tracking — slice 1 (infrastructure only; nothing wired into
-- the live send path yet). A new, additive table: one row per tracked outbound
-- message, updated when the recipient opens (via the tracking pixel) or replies.
-- Org-scoped for multi-tenancy, consistent with migrations 022/023.
CREATE TABLE IF NOT EXISTS email_tracking (
  id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  token         text UNIQUE NOT NULL,               -- opaque id embedded in the pixel URL
  channel       text NOT NULL DEFAULT 'candidate',  -- 'candidate' | 'lead'
  candidate_id  uuid,
  job_order_id  uuid,
  lead_id       uuid,
  to_email      text,
  subject       text,
  sent_by       uuid,                               -- users.id of the sender
  mailbox_email text,                               -- mailbox the message was sent from
  org_id        uuid,
  sent_at       timestamptz DEFAULT now(),
  opened_at     timestamptz,                        -- first open
  last_open_at  timestamptz,
  open_count    integer NOT NULL DEFAULT 0,
  replied_at    timestamptz,                        -- reserved for the reply-tracking slice
  created_at    timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_email_tracking_candidate ON email_tracking (candidate_id);
CREATE INDEX IF NOT EXISTS idx_email_tracking_job       ON email_tracking (job_order_id);
CREATE INDEX IF NOT EXISTS idx_email_tracking_org       ON email_tracking (org_id);

-- Default org_id to the platform's default org (same transitional pattern as 022).
DO $$
DECLARE default_org uuid;
BEGIN
  SELECT id INTO default_org FROM organizations ORDER BY created_at ASC LIMIT 1;
  IF default_org IS NOT NULL THEN
    EXECUTE format('ALTER TABLE email_tracking ALTER COLUMN org_id SET DEFAULT %L', default_org);
  END IF;
END $$;
