-- 023_org_id_not_null.sql
-- Slice 3a (safe guardrail only — RLS lock-down intentionally deferred): make
-- org_id mandatory on tenant tables. Every existing row is already backfilled
-- (0 NULLs) and the column DEFAULT keeps future inserts non-null even if a code
-- path forgets to set it, so this cannot fail or change behaviour. Applied to the
-- live Supabase project on 2026-07-21.
DO $$
DECLARE
  t text;
  tenant_tables text[] := ARRAY[
    'users','companies','jobs','contacts','emails','follow_ups','reminders',
    'activity_log','email_send_log','job_orders','candidates','submissions',
    'recruiter_assignments','submission_activity','candidate_pipeline',
    'candidate_notes','candidate_documents','sourcing_candidates','assignment_requests',
    'team_assignments','user_emails','reviews','reports','warmup_threads',
    'warmup_messages','warmup_send_log','workflow_definitions','workflow_enrollments',
    'workflow_steps','workflow_step_runs','email_templates','recruiting_lookups',
    'suppression_list'
  ];
BEGIN
  FOREACH t IN ARRAY tenant_tables LOOP
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=t AND column_name='org_id') THEN
      EXECUTE format('ALTER TABLE public.%I ALTER COLUMN org_id SET NOT NULL', t);
    END IF;
  END LOOP;
END $$;
