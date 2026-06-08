-- Add jobs.research JSON column for RA research notes (idempotent)
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS research JSONB DEFAULT NULL;
