-- ============================================================================
-- 019 — Anonymized posting JD
--
-- A job order keeps two descriptions: the internal one (client-identifying)
-- and `posting_description` — a sanitized rewrite with the company name and
-- identifying details removed, safe to publish on job boards. Generated via
-- POST /job-orders/:id/posting-jd (AI rewrite with a rule-based fallback),
-- editable and saved by the BDM. Additive and idempotent.
-- ============================================================================

ALTER TABLE job_orders ADD COLUMN IF NOT EXISTS posting_description TEXT;
