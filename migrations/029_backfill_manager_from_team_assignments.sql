-- 029_backfill_manager_from_team_assignments.sql
-- Reconciles the older team_assignments table (assignment_type='bd_to_bdlead')
-- into the newer, general users.manager_id reporting hierarchy (migration 026),
-- so "who's on whose team" has one source of truth going forward. Every place
-- that reads "team" now uses manager_id (Dashboard, My Team, Admin org chart,
-- Team Insights) — this migration carries forward any bd_to_bdlead pairings an
-- admin made before manager_id existed, so nobody's team silently empties out.
--
-- Safety: only fills manager_id where it is currently NULL. Never overwrites a
-- manager_id an admin already set via the Reporting Hierarchy / Admin org chart
-- UI. Rows where the two sources actively disagree (manager_id already set to
-- someone OTHER than the bd_to_bdlead manager) are left untouched — run the
-- SELECT below first to review those before deciding by hand.

-- Conflicts to review manually — nothing here is modified automatically:
--   SELECT u.id, u.name, u.manager_id AS current_manager_id,
--          ta.manager_id AS bd_to_bdlead_manager_id
--   FROM users u
--   JOIN team_assignments ta ON ta.member_id = u.id AND ta.assignment_type = 'bd_to_bdlead'
--   WHERE u.manager_id IS NOT NULL AND u.manager_id <> ta.manager_id;

UPDATE users u
SET manager_id = ta.manager_id, updated_at = now()
FROM team_assignments ta
WHERE ta.member_id = u.id
  AND ta.assignment_type = 'bd_to_bdlead'
  AND u.manager_id IS NULL
  AND u.deleted_at IS NULL;
