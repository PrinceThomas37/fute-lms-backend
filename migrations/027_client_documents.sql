-- 027_client_documents.sql
-- Document storage for clients (companies with at least one job order),
-- mirroring candidate_documents. Reuses the existing private 'candidate-docs'
-- storage bucket under a client/<company_id>/... path prefix rather than a
-- new bucket. Org-scoped like every other tenant table.
CREATE TABLE IF NOT EXISTS client_documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id UUID NOT NULL REFERENCES companies(id),
  doc_type TEXT DEFAULT 'other',
  filename TEXT NOT NULL,
  storage_path TEXT NOT NULL,
  content_type TEXT,
  size_bytes INTEGER,
  uploaded_by UUID REFERENCES users(id),
  uploaded_at TIMESTAMPTZ DEFAULT now(),
  deleted_at TIMESTAMPTZ,
  org_id UUID REFERENCES organizations(id)
);
CREATE INDEX IF NOT EXISTS client_documents_company_idx ON client_documents (company_id);
CREATE INDEX IF NOT EXISTS client_documents_org_idx ON client_documents (org_id);

-- email_tracking gets a channel:'client' counterpart to candidate_id/job_order_id.
ALTER TABLE email_tracking ADD COLUMN IF NOT EXISTS company_id uuid;
CREATE INDEX IF NOT EXISTS idx_email_tracking_company ON email_tracking (company_id);

DO $$
DECLARE default_org uuid;
BEGIN
  SELECT id INTO default_org FROM organizations ORDER BY created_at ASC LIMIT 1;
  IF default_org IS NOT NULL THEN
    EXECUTE format('ALTER TABLE client_documents ALTER COLUMN org_id SET DEFAULT %L', default_org);
  END IF;
END $$;
