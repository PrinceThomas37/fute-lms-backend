-- 026_user_hierarchy.sql
-- Flexible reporting hierarchy: any user can be assigned to report to any
-- other user, regardless of role — not a fixed ladder. This is the
-- foundation for the "Team creation" admin UI and hierarchy-scoped reports
-- (a manager sees their own data plus everyone under them in the chain).
-- Self-referencing, nullable, no default — existing users are simply
-- unassigned (no manager) until an admin sets one. Nothing reads this
-- column yet, so this migration changes no behaviour on its own.
ALTER TABLE users ADD COLUMN IF NOT EXISTS manager_id UUID REFERENCES users(id);
CREATE INDEX IF NOT EXISTS users_manager_idx ON users (manager_id);
