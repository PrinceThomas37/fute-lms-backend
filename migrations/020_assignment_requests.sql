-- 020: assignment requests — a recruiter browsing the company-wide job board
-- can ask the BD team to be put on a job; the BDM approves (which creates the
-- recruiter_assignments row) or declines.

CREATE TABLE IF NOT EXISTS assignment_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_order_id UUID NOT NULL REFERENCES job_orders(id),
  recruiter_id UUID NOT NULL REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'pending',           -- pending | approved | declined
  note TEXT,
  decided_by UUID REFERENCES users(id),
  decided_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- one live request per recruiter per job (re-request allowed after a decision)
CREATE UNIQUE INDEX IF NOT EXISTS uq_assignment_request_pending
  ON assignment_requests(job_order_id, recruiter_id) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_assignment_requests_status
  ON assignment_requests(status);
