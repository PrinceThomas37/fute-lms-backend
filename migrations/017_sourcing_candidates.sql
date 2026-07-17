-- ============================================================================
-- 017 — Sourcing candidates (staging)
--
-- Slice A of docs/SOURCING_AND_SCHEDULING_PLAN.md: candidates pulled from a
-- source (CSV/file today; job-board APIs later) land here first with their raw
-- payload and a duplicate flag, then get reviewed and imported into `candidates`
-- (reusing the ATS dedup + candidate-create path). Nothing touches the real
-- database until a recruiter imports it. Additive and idempotent.
-- ============================================================================

CREATE TABLE IF NOT EXISTS sourcing_candidates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT NOT NULL,                 -- csv | apollo | indeed | linkedin | monster | careerbuilder | dice | manual
  external_id TEXT,                       -- provider's id for the person, if any
  full_name TEXT,
  first_name TEXT,
  last_name TEXT,
  email TEXT,
  phone TEXT,
  current_title TEXT,
  current_employer TEXT,
  location TEXT,
  city TEXT,
  state TEXT,
  country TEXT,
  work_authorization TEXT,
  experience_years NUMERIC,
  skills TEXT,
  source_url TEXT,                        -- link to the profile on the source board
  resume_url TEXT,
  raw JSONB,                              -- full provider payload
  status TEXT NOT NULL DEFAULT 'new',     -- new | imported | discarded
  dup_candidate_id UUID REFERENCES candidates(id) ON DELETE SET NULL,       -- likely existing match
  imported_candidate_id UUID REFERENCES candidates(id) ON DELETE SET NULL,  -- set on import
  imported_at TIMESTAMPTZ,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sourcing_candidates_status_idx   ON sourcing_candidates (status);
CREATE INDEX IF NOT EXISTS sourcing_candidates_provider_idx ON sourcing_candidates (provider);
CREATE INDEX IF NOT EXISTS sourcing_candidates_creator_idx  ON sourcing_candidates (created_by);
