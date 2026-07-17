-- ============================================================================
-- 011 — ATS / recruiting baseline (reproducibility)
--
-- The recruiting spine (job_orders, candidates, submissions, submission_activity,
-- recruiter_assignments) and the next_id() code generator were applied directly
-- to the live Supabase by earlier sessions and never had committed DDL. This
-- migration captures them so a fresh database can be stood up from the migrations
-- folder alone.
--
-- Everything is IF NOT EXISTS / idempotent, so on the live database (where these
-- objects already exist) it is a no-op. Foreign keys mirror the live schema,
-- which uses ON DELETE NO ACTION throughout (the app soft-deletes via deleted_at,
-- so cascade rules are intentionally not relied on). See docs/ATS_RECRUITING_PLAN.md §2.
-- ============================================================================

-- ── ID generator ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS id_sequences (
  prefix TEXT PRIMARY KEY,
  last_value BIGINT NOT NULL DEFAULT 0
);

INSERT INTO id_sequences (prefix, last_value) VALUES
  ('LD', 0), ('JOB', 0), ('CN', 0)
ON CONFLICT (prefix) DO NOTHING;

-- Human-readable ids: next_id('CN') -> 'CN-00042'. Creates the prefix on demand.
CREATE OR REPLACE FUNCTION public.next_id(p_prefix text)
RETURNS text
LANGUAGE plpgsql
AS $function$
DECLARE
  v_next bigint;
BEGIN
  UPDATE id_sequences
     SET last_value = last_value + 1
   WHERE prefix = p_prefix
  RETURNING last_value INTO v_next;

  IF v_next IS NULL THEN
    -- prefix not seeded yet — create it on the fly
    INSERT INTO id_sequences (prefix, last_value) VALUES (p_prefix, 1)
    ON CONFLICT (prefix) DO UPDATE SET last_value = id_sequences.last_value + 1
    RETURNING last_value INTO v_next;
  END IF;

  RETURN p_prefix || '-' || lpad(v_next::text, 5, '0');
END;
$function$;

-- ── Job orders (a lead converted into a working req) ─────────────────────────
CREATE TABLE IF NOT EXISTS job_orders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_code TEXT UNIQUE,
  source_lead_id UUID REFERENCES jobs(id),
  lead_code TEXT,
  company_id UUID REFERENCES companies(id),
  job_title TEXT NOT NULL,
  client TEXT,
  client_job_id TEXT,
  client_manager TEXT,
  end_client TEXT,
  job_description TEXT,
  positions INTEGER DEFAULT 1,
  job_type TEXT,
  emp_level TEXT,
  work_auth TEXT,
  remote TEXT,
  clearance TEXT,
  priority TEXT DEFAULT 'Normal',
  status TEXT NOT NULL DEFAULT 'Active',
  country TEXT,
  state TEXT,
  city TEXT,
  zip TEXT,
  start_date DATE,
  end_date DATE,
  duration TEXT,
  placement_fee TEXT,
  req_docs TEXT,
  pay_cur TEXT DEFAULT 'USD',
  pay_min TEXT,
  pay_max TEXT,
  primary_skills TEXT,
  secondary_skills TEXT,
  exp_min TEXT,
  exp_max TEXT,
  industry TEXT,
  domain TEXT,
  degree TEXT,
  languages TEXT,
  job_category TEXT,
  comments TEXT,
  bd_manager_id UUID REFERENCES users(id),
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS job_orders_job_code_key ON job_orders (job_code);
CREATE INDEX IF NOT EXISTS job_orders_company_idx ON job_orders (company_id);
CREATE INDEX IF NOT EXISTS job_orders_bd_manager_idx ON job_orders (bd_manager_id);
CREATE INDEX IF NOT EXISTS job_orders_source_lead_idx ON job_orders (source_lead_id);
CREATE INDEX IF NOT EXISTS job_orders_status_idx ON job_orders (status) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS job_orders_state_idx ON job_orders (state) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS job_orders_job_type_idx ON job_orders (job_type) WHERE deleted_at IS NULL;

-- ── Recruiter assignments (recruiter ↔ job order) ────────────────────────────
CREATE TABLE IF NOT EXISTS recruiter_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_order_id UUID NOT NULL REFERENCES job_orders(id),
  recruiter_id UUID NOT NULL REFERENCES users(id),
  assigned_by UUID REFERENCES users(id),
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS recruiter_assignments_uidx ON recruiter_assignments (job_order_id, recruiter_id);
CREATE INDEX IF NOT EXISTS recruiter_assignments_recruiter_idx ON recruiter_assignments (recruiter_id);

-- ── Candidates (shared pool) ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS candidates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  candidate_code TEXT UNIQUE,
  full_name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  current_location TEXT,
  current_title TEXT,
  skills TEXT,
  experience_years NUMERIC,
  resume_url TEXT,
  source TEXT,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS candidates_name_idx ON candidates (lower(full_name)) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS candidates_email_idx ON candidates (lower(email)) WHERE deleted_at IS NULL;

-- ── Submissions (candidate ↔ job order, pipeline stage + BDM gate) ───────────
CREATE TABLE IF NOT EXISTS submissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  candidate_id UUID NOT NULL REFERENCES candidates(id),
  job_order_id UUID NOT NULL REFERENCES job_orders(id),
  recruiter_id UUID REFERENCES users(id),
  stage TEXT NOT NULL DEFAULT 'Sourced',
  submitted_rate TEXT,
  notes TEXT,
  bdm_approved_at TIMESTAMPTZ,
  bdm_approved_by UUID REFERENCES users(id),
  stage_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS submissions_candidate_joborder_uidx
  ON submissions (candidate_id, job_order_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS submissions_job_order_idx ON submissions (job_order_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS submissions_recruiter_idx ON submissions (recruiter_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS submissions_stage_idx ON submissions (stage) WHERE deleted_at IS NULL;

-- ── Submission activity log ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS submission_activity (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  submission_id UUID REFERENCES submissions(id),
  job_order_id UUID REFERENCES job_orders(id),
  recruiter_id UUID REFERENCES users(id),
  action TEXT,
  old_stage TEXT,
  new_stage TEXT,
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS submission_activity_job_order_idx ON submission_activity (job_order_id);
CREATE INDEX IF NOT EXISTS submission_activity_recruiter_idx ON submission_activity (recruiter_id);
