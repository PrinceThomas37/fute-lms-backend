-- ============================================================================
-- 007 — Workflow engine (platform core)
--
-- The declarative workflow layer described in docs/ENTERPRISE_OUTREACH_PLAN.md
-- §0: cadences live as DATA (definitions + steps), execution state lives per
-- entity (enrollments), and every executed step is recorded (step_runs).
--
-- Platform seams for the "runs the whole organization" direction:
--   - organizations: every workflow row carries org_id from day one, so
--     multi-tenancy later is a backfill + RLS, not a schema rewrite.
--   - workflow_definitions.domain: 'sales' today; 'delivery', 'ops', 'hr',
--     'finance' later ride the same engine.
--   - workflow_enrollments.entity_type/entity_id: generic — contacts today,
--     candidates/jobs/employees/invoices later.
--
-- Additive and off by default: nothing enrolls automatically. The seeded
-- default workflow mirrors today's hard-coded cadence but only runs for
-- explicitly enrolled entities; the legacy fu1/fu2 engine is untouched.
-- ============================================================================

CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  settings JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workflow_definitions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  domain TEXT NOT NULL DEFAULT 'sales',           -- sales | delivery | ops | hr | finance …
  name TEXT NOT NULL,
  description TEXT,
  entity_type TEXT NOT NULL DEFAULT 'contact',    -- contact | candidate | job | …
  trigger_event TEXT,                             -- future auto-enroll hook (event name); NULL = manual enroll only
  status TEXT NOT NULL DEFAULT 'draft',           -- draft | active | archived
  is_default BOOLEAN DEFAULT FALSE,
  version INT DEFAULT 1,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wf_def_org_status ON workflow_definitions(org_id, status);

CREATE TABLE IF NOT EXISTS workflow_steps (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workflow_id UUID NOT NULL REFERENCES workflow_definitions(id) ON DELETE CASCADE,
  step_order INT NOT NULL,
  name TEXT NOT NULL,
  channel TEXT NOT NULL,                          -- email | bd_touch | reminder | stage_move | (call, webhook … later)
  delay_days INT NOT NULL DEFAULT 0,              -- days after the PREVIOUS step ran (step 1: after enrollment)
  config JSONB DEFAULT '{}',                      -- channel-specific: template_key/subject/body/thread, note/message, to_stage …
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (workflow_id, step_order)
);

CREATE TABLE IF NOT EXISTS workflow_enrollments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workflow_id UUID NOT NULL REFERENCES workflow_definitions(id) ON DELETE CASCADE,
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL,
  entity_id UUID NOT NULL,
  job_id UUID REFERENCES jobs(id) ON DELETE CASCADE,        -- sales-domain context (nullable for other domains)
  contact_id UUID REFERENCES contacts(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'active',          -- active | paused | completed | exited | failed
  current_step_order INT NOT NULL DEFAULT 0,      -- last executed step (0 = none yet)
  next_step_due_date DATE,
  exit_reason TEXT,                               -- replied | unsubscribed | invalidated | manual | entity_missing …
  enrolled_by UUID REFERENCES users(id),
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_wf_enr_due ON workflow_enrollments(status, next_step_due_date);
CREATE INDEX IF NOT EXISTS idx_wf_enr_entity ON workflow_enrollments(entity_type, entity_id);
-- One ACTIVE enrollment per workflow + entity + job context.
CREATE UNIQUE INDEX IF NOT EXISTS uq_wf_enr_active
  ON workflow_enrollments(workflow_id, entity_type, entity_id, COALESCE(job_id, '00000000-0000-0000-0000-000000000000'::uuid))
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS workflow_step_runs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  enrollment_id UUID NOT NULL REFERENCES workflow_enrollments(id) ON DELETE CASCADE,
  workflow_id UUID REFERENCES workflow_definitions(id) ON DELETE CASCADE,
  step_id UUID REFERENCES workflow_steps(id) ON DELETE SET NULL,
  step_order INT,
  channel TEXT,
  outcome TEXT NOT NULL,                          -- done | skipped | failed
  detail JSONB DEFAULT '{}',
  run_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wf_runs_enrollment ON workflow_step_runs(enrollment_id);

-- ── Seeds (idempotent) ───────────────────────────────────────────────────────
INSERT INTO organizations (name, slug)
SELECT 'Fute Global', 'fute'
WHERE NOT EXISTS (SELECT 1 FROM organizations WHERE slug = 'fute');

-- Default sales workflow = today's cadence as data. Active, but nothing
-- enrolls into it automatically — behaviour is unchanged until an explicit
-- POST /wf/enroll.
INSERT INTO workflow_definitions (org_id, domain, name, description, entity_type, status, is_default)
SELECT o.id, 'sales', 'Standard Sales Outreach',
       'Initial email → follow-up 1 (+2d) → BD call & LinkedIn touch (+1d) → follow-up 2 (+2d). Exits on reply, unsubscribe, or bounce.',
       'contact', 'active', TRUE
FROM organizations o
WHERE o.slug = 'fute'
  AND NOT EXISTS (SELECT 1 FROM workflow_definitions WHERE name = 'Standard Sales Outreach');

INSERT INTO workflow_steps (workflow_id, step_order, name, channel, delay_days, config)
SELECT w.id, s.step_order, s.name, s.channel, s.delay_days, s.config::jsonb
FROM workflow_definitions w
CROSS JOIN (VALUES
  (1, 'Initial outreach email', 'email',    0, '{"template_key":"initial","thread":false}'),
  (2, 'Follow-up email 1',      'email',    2, '{"template_key":"fu1","thread":true}'),
  (3, 'BD call + LinkedIn touch','bd_touch',1, '{"note":"Call the POC about this role and connect on LinkedIn.","message":"Hi {{first_name}}, I emailed you about the {{position}} role at {{company}} — would love to connect and discuss how we can help fill it."}'),
  (4, 'Follow-up email 2',      'email',    2, '{"template_key":"fu2","thread":true}')
) AS s(step_order, name, channel, delay_days, config)
WHERE w.name = 'Standard Sales Outreach'
  AND NOT EXISTS (SELECT 1 FROM workflow_steps WHERE workflow_id = w.id);
