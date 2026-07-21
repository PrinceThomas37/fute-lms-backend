-- 022_multi_tenant_foundation.sql
-- Multi-tenant foundation (slice 1): give every tenant-scoped table an org_id,
-- backfilled to the existing default organization. Additive + nullable + a column
-- DEFAULT of the default org, so existing code (which does not yet set org_id)
-- keeps writing valid rows and read behaviour is unchanged until scoping is wired
-- on top. Applied to the live Supabase project on 2026-07-21.
DO $$
DECLARE
  default_org uuid;
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
  SELECT id INTO default_org FROM organizations ORDER BY created_at ASC LIMIT 1;
  IF default_org IS NULL THEN
    INSERT INTO organizations (name, slug) VALUES ('Fute Global','fute') RETURNING id INTO default_org;
  END IF;

  FOREACH t IN ARRAY tenant_tables LOOP
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=t) THEN
      EXECUTE format('ALTER TABLE public.%I ADD COLUMN IF NOT EXISTS org_id uuid', t);
      EXECUTE format('UPDATE public.%I SET org_id = %L WHERE org_id IS NULL', t, default_org);
      EXECUTE format('ALTER TABLE public.%I ALTER COLUMN org_id SET DEFAULT %L', t, default_org);
      EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON public.%I (org_id)', 'idx_'||t||'_org', t);
      BEGIN
        EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (org_id) REFERENCES organizations(id)', t, t||'_org_fk');
      EXCEPTION WHEN duplicate_object THEN NULL;
      END;
    END IF;
  END LOOP;
END $$;
