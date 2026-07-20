-- 021: submission hand-off details + rejection reasons
-- submission_details: the form a recruiter fills when submitting a candidate
-- to the BD Manager (name, contacts, work auth, location, relocation,
-- availability, comment) — the template the BDM forwards to the client.
-- rejection_reason: BD's duty — why a candidate was rejected (client feedback,
-- BDM decision…), variable free text.

ALTER TABLE submissions ADD COLUMN IF NOT EXISTS submission_details JSONB;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS rejection_reason TEXT;
