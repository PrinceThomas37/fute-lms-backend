-- ============================================================================
-- 015 — Candidate notes & documents
--
-- Slice 5 of docs/ATS_RECRUITING_PLAN.md: the profile's Notes tabs (Job Posting /
-- Applicant Reference) and the Documents section (résumé + other files). Files
-- live in a private Supabase Storage bucket ('candidate-docs'); this table stores
-- the metadata + storage path, and the app serves them via short-lived signed
-- URLs. Additive and idempotent.
-- ============================================================================

CREATE TABLE IF NOT EXISTS candidate_notes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  candidate_id UUID NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  job_order_id UUID REFERENCES job_orders(id) ON DELETE SET NULL,
  note_type TEXT NOT NULL DEFAULT 'applicant_reference',   -- job_posting | applicant_reference
  body TEXT NOT NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS candidate_notes_cand_idx ON candidate_notes (candidate_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS candidate_documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  candidate_id UUID NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  doc_type TEXT NOT NULL DEFAULT 'resume',                 -- resume | cover_letter | other
  filename TEXT NOT NULL,
  storage_path TEXT NOT NULL,                              -- path within the 'candidate-docs' bucket
  content_type TEXT,
  size_bytes BIGINT,
  uploaded_by UUID REFERENCES users(id) ON DELETE SET NULL,
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS candidate_documents_cand_idx ON candidate_documents (candidate_id) WHERE deleted_at IS NULL;

-- Private storage bucket for résumés / documents (Supabase). The backend uses the
-- service role, so it reads/writes regardless of RLS and hands out signed URLs.
INSERT INTO storage.buckets (id, name, public)
VALUES ('candidate-docs', 'candidate-docs', false)
ON CONFLICT (id) DO NOTHING;
