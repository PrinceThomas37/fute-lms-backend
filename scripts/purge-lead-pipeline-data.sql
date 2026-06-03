-- Purge lead pipeline data for a fresh assign/send cycle.
-- KEEPS: users, user_emails, microsoft_tokens, team_assignments, app_settings (templates, FU day settings).
-- RUN IN: Supabase → SQL Editor (service role / postgres). Review counts first.

BEGIN;

-- Optional: preview counts
-- SELECT 'emails' t, COUNT(*) FROM emails
-- UNION ALL SELECT 'follow_ups', COUNT(*) FROM follow_ups
-- UNION ALL SELECT 'jobs', COUNT(*) FROM jobs;

DELETE FROM emails;
DELETE FROM follow_ups;
DELETE FROM reminders;
DELETE FROM activity_log;
DELETE FROM contacts;
DELETE FROM jobs;
DELETE FROM companies;
DELETE FROM email_send_log;

DELETE FROM app_settings WHERE key LIKE 'send_progress_%';
DELETE FROM app_settings WHERE key = 'last_followup_run';

COMMIT;
