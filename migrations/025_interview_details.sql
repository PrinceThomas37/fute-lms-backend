-- 025_interview_details.sql
-- Richer interview scheduling on submissions. Additive columns alongside the
-- existing interview_at / interview_location. Applied to the live project.
ALTER TABLE submissions
  ADD COLUMN IF NOT EXISTS interview_type     text,   -- 'in_person' | 'virtual' | 'phone'
  ADD COLUMN IF NOT EXISTS interview_platform text,   -- virtual: 'Microsoft Teams' | 'Google Meet' | 'Zoom' | 'Other'
  ADD COLUMN IF NOT EXISTS interview_link     text,   -- join URL / dial-in / meeting id
  ADD COLUMN IF NOT EXISTS interview_address  text,   -- office address for in-person
  ADD COLUMN IF NOT EXISTS interviewers       jsonb;  -- array of 1-3 interviewer names
