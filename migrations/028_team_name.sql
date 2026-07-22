-- 028_team_name.sql
-- A friendly label for the team a user leads (e.g. "East Coast Sales"),
-- shown on the Admin "Team View" drag-and-drop org chart next to whoever
-- has direct reports. Purely cosmetic — the actual hierarchy is
-- users.manager_id (migration 026); this is just a name for a subtree.
ALTER TABLE users ADD COLUMN IF NOT EXISTS team_name TEXT;
