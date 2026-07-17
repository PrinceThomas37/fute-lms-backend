-- ============================================================================
-- 016 — Recruiting lookups (managed taxonomies)
--
-- Slice 6 of docs/ATS_RECRUITING_PLAN.md: move the ATS reference lists
-- (work authorization, source, applicant status, availability, pay type) out of
-- hard-coded arrays into a table an admin can extend without a code change. The
-- frontend loads these and falls back to its built-in defaults if unavailable.
--
-- Pipeline/submission STATUSES are deliberately NOT here — those drive workflow
-- logic (the BDM gate, the lifecycle) and stay in code. Additive and idempotent.
-- ============================================================================

CREATE TABLE IF NOT EXISTS recruiting_lookups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  category TEXT NOT NULL,   -- work_authorization | source | applicant_status | availability | pay_type
  value TEXT NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS recruiting_lookups_cat_val_uidx ON recruiting_lookups (category, lower(value));
CREATE INDEX IF NOT EXISTS recruiting_lookups_cat_idx ON recruiting_lookups (category) WHERE is_active;

INSERT INTO recruiting_lookups (category, value, sort_order)
SELECT category, value, (ord - 1)
FROM (VALUES
  ('work_authorization','US Citizen',1),('work_authorization','Green Card',2),('work_authorization','GC EAD',3),
  ('work_authorization','H1B',4),('work_authorization','H4 EAD',5),('work_authorization','OPT EAD',6),
  ('work_authorization','CPT',7),('work_authorization','TN',8),('work_authorization','L2 EAD',9),
  ('work_authorization','E3',10),('work_authorization','Canada Citizen',11),('work_authorization','Canada PR',12),
  ('work_authorization','Other',13),
  ('source','Monster',1),('source','CareerBuilder',2),('source','LinkedIn',3),('source','Indeed',4),
  ('source','Dice',5),('source','Naukri',6),('source','ZipRecruiter',7),('source','Referral',8),
  ('source','Career Site',9),('source','Job Board',10),('source','Vendor',11),('source','Manual',12),
  ('applicant_status','New lead',1),('applicant_status','Active',2),('applicant_status','Submitted',3),
  ('applicant_status','Interviewing',4),('applicant_status','Placed',5),('applicant_status','Do Not Call',6),
  ('applicant_status','Blacklisted',7),('applicant_status','Inactive',8),
  ('availability','Immediate',1),('availability','1 week',2),('availability','2 weeks',3),
  ('availability','3 weeks',4),('availability','1 month',5),('availability','Notice period',6),
  ('pay_type','Hourly',1),('pay_type','Yearly',2)
) AS t(category, value, ord)
ON CONFLICT (category, lower(value)) DO NOTHING;
