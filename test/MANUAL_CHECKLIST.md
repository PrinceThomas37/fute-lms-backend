# Manual verification checklist — frontend split (Phase 1)

The automated checks (`test/verify-frontend.sh` and `test/frontend-smoke.mjs`)
cover load order, per-file syntax, and guest-mode rendering of every major
screen. Because guest mode is client-side only, the items below cover the
**backend-connected** paths a headless smoke test cannot reach. Run them once
against a real login before merging.

Behavior must be **identical** to before the split — this was a pure
reorganization, so anything that differs is a regression.

## Boot & auth
- [ ] App loads with no console errors (real login, not guest).
- [ ] Email/password sign-in works; session persists on refresh (sessionStorage).
- [ ] Sign out clears the session and returns to the login screen.

## Core feature screens (per role)
- [ ] Dashboard renders with live data.
- [ ] Leads list loads, filters, pagination, and search work.
- [ ] Job detail modal opens; stage changes save and persist after refresh.
- [ ] Add Job (RA entry form) and Add Contact save correctly.
- [ ] Email page: compose, template variables, send/queue behave as before.
- [ ] Mail merge modal + engine produce the same output.
- [ ] Workflows: definitions, builder, and enrollment/"Start sequence" work.
- [ ] Reminders create/complete correctly.
- [ ] Admin panel + Manager Users (add/edit user, assignments) work.
- [ ] Deliverability dashboard loads.
- [ ] Assign Leads (RA Lead) bulk assignment works.
- [ ] Insights pages (RA, BD Manager, BD Lead) render.
- [ ] Email Accounts page loads and connect/disconnect flows work.
- [ ] Import (xlsx) still works — confirm the CDN xlsx library loads.

## Background behavior
- [ ] Background polling still refreshes jobs/emails as before.
- [ ] Send-progress bar appears for BD users.
- [ ] Guest mode still works and remains read-only (writes blocked by backend).

## Admin: delete pending emails (one manager / all managers)
Reachable via: sidebar **Admin** → click a BD/BD-Lead user → **Control Center**
card → "Delete pending…" (one manager), or sidebar **Admin** → header →
"Delete pending (all managers)…" (all at once). (Earlier revisions of this
feature put it on a "Manager Users" page with no nav link to it — fixed; both
buttons now live on the Admin page, which the sidebar always links to.)
- [ ] Preview count matches what's actually in the manager's pending queue.
- [ ] Deleting only selected types/time removes exactly those and nothing else.
- [ ] Sent emails and reminders are never affected.

## Admin: Control Center (per-user, on the Admin page's user detail view)
- [ ] Only shows for BD / BD Lead users (not RA/Recruiter/Admin-only accounts).
- [ ] Sending status matches the manager's real state; Pause/Resume here matches
      the existing Assign Leads / Admin emergency-stop controls (same backend flag).
- [ ] RA Mode Switch matches the existing toggle in the Admin BD-tab list row.
- [ ] Pending queue counts (total + by type) match what "Delete pending emails…"
      previews for that manager.
- [ ] Active sequence enrollments list shows this manager's leads only (not other
      managers'); Pause/Resume/Stop here matches the Workflows page's own controls
      on the same enrollment.
- [ ] ↻ Refresh reloads the queue counts and enrollments without a full page reload.

## Admin: enroll another manager's leads in a sequence
Reachable via: sidebar **Admin** → click a BD/BD-Lead user → **Control Center**
card → **"+ Enroll leads…"**.
- [ ] Picker lists only that manager's leads (not other managers').
- [ ] A lead already in an active/paused sequence is correctly excluded from the list.
- [ ] Select-all and individual checkboxes both update the "selected" count and
      enable/disable Continue correctly.
- [ ] Continue hands off to the existing "Start sequence" modal with the right
      lead count; picking or building a sequence there enrolls exactly the
      selected leads (verify in Workflows → Enrollments) without the manager
      having done anything themselves.

## Admin: System Settings (operational numbers)
- [ ] Admin (not RA-Lead) sees the "System Settings" button on the Admin page.
- [ ] Current values shown match the previous hardcoded defaults (21 / 24 / 20 / 5 / 5 / 20 / 3 / 200).
- [ ] Saving a changed value persists — reopening the modal shows the new value.
- [ ] Behavior actually changes: e.g. lower the company cooldown to 1 day and confirm
      an RA can re-add a company after 1 day instead of 21; raise the workflow tick
      batch and confirm more enrollments process per tick.
- [ ] An out-of-range or non-numeric value is rejected with a clear message and nothing saves.
