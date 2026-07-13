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
- [ ] Preview count matches what's actually in the manager's pending queue.
- [ ] Deleting only selected types/time removes exactly those and nothing else.
- [ ] Sent emails and reminders are never affected.

## Admin: System Settings (operational numbers)
- [ ] Admin (not RA-Lead) sees the "System Settings" button on the Admin page.
- [ ] Current values shown match the previous hardcoded defaults (21 / 24 / 20 / 5 / 5 / 20 / 3 / 200).
- [ ] Saving a changed value persists — reopening the modal shows the new value.
- [ ] Behavior actually changes: e.g. lower the company cooldown to 1 day and confirm
      an RA can re-add a company after 1 day instead of 21; raise the workflow tick
      batch and confirm more enrollments process per tick.
- [ ] An out-of-range or non-numeric value is rejected with a clear message and nothing saves.
