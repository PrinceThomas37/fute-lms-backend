-- Clear stuck pending follow-up emails (e.g. interrupted during deploy)
-- Run in Supabase → SQL Editor. Review counts in step 1 before step 2.

-- 1) PREVIEW — how many are stuck?
SELECT followup_type, COUNT(*) AS cnt
FROM emails
WHERE status = 'pending'
GROUP BY followup_type
ORDER BY followup_type;

-- 2) DELETE pending follow-ups only (keeps pending outreach if any)
DELETE FROM emails
WHERE status = 'pending'
  AND followup_type IN ('fu1', 'fu2');

-- 3) Reset follow_ups marked "sent" when no sent email exists (old engine queued but never mailed)
UPDATE follow_ups fu
SET followup1_sent_at = NULL
WHERE followup1_sent_at IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM emails e
    WHERE e.job_id = fu.job_id
      AND e.contact_id = fu.contact_id
      AND e.followup_type = 'fu1'
      AND e.status = 'sent'
  );

UPDATE follow_ups fu
SET followup2_sent_at = NULL,
    status = CASE WHEN followup1_sent_at IS NOT NULL THEN 'active' ELSE status END
WHERE followup2_sent_at IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM emails e
    WHERE e.job_id = fu.job_id
      AND e.contact_id = fu.contact_id
      AND e.followup_type = 'fu2'
      AND e.status = 'sent'
  );

-- 4) Clear stuck "sending…" progress bars in the app
DELETE FROM app_settings
WHERE key LIKE 'send_progress_%';
