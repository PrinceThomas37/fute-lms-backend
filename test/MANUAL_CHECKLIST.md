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

## Sequencing: cross-group selection + "from"-mailbox rotation
Requires **migration `008_email_sending_override.sql`** applied (adds
`emails.sending_email_id`). Without it, rotation silently falls back to each
job's default mailbox — nothing breaks, but sends won't actually rotate.
Reachable via: sidebar **Leads** → tick leads across any stage group → sticky
**"▶ Sequence selected"** bar; or a **job detail** / **BD job** candidate
multi-select → **Start sequence**.
- [ ] The Leads list shows a checkbox column + "select all matching" for
      BD / BD-Lead / Admin only (not RA); leads with no contact email aren't selectable.
- [ ] Selecting leads across different stages (e.g. Connected + Future + Rejected)
      and starting a sequence enrolls all of them (verify in Workflows → Enrollments);
      the email step does **not** skip the non-Assigned ones (any_stage in effect).
- [ ] The Start-sequence modal lists sending mailboxes with a connected/not-connected
      badge; a plain BD sees only their own, admin/leads see all.
- [ ] Picking 2+ "from" mailboxes then Start: enrollments show "✉ <mailbox>" and the
      addresses **round-robin** across the batch (enrollment 1→mbA, 2→mbB, 3→mbA…).
- [ ] Run the engine (Workflows → Run sequence now): each lead's email actually
      **sends from its assigned mailbox** (check the recipient's From header / the
      mailbox's Sent Items), not the job's default mailbox.
- [ ] Follow-ups (fu1/fu2) for a rotated lead thread from the **same** assigned
      mailbox as its initial email.
- [ ] Picking **no** mailbox falls back to each lead's job default (unchanged behaviour).
- [ ] Candidate side (BD job → Candidates → select across stages → Start sequence)
      rotates the recruiter's chosen mailboxes the same way.

## Warm-up pool (real Graph sends between mailboxes)
Requires **migration `009_warmup_pool.sql`** applied. This tier sends **real
email** from real mailboxes, so verify on a **test-mailbox pair first** — never
on a production inbox until confirmed. Reachable via: sidebar **Deliverability**
→ **Warm-up pool** card. Off by default until an admin starts a mailbox.
- [ ] "Warm-up pool" card lists active mailboxes with a connected/not-connected
      state; "Start warm-up" only offered for connected Microsoft mailboxes, admin only.
- [ ] Start warm-up on **two** connected test mailboxes (duration e.g. 2 days) →
      both show "Warming · day 1/N".
- [ ] "▶ Run warm-up now" (or wait for the tick): each warming mailbox sends the
      day's quota (starts at `warmup_pool_start`, +`warmup_pool_step`/day) to the
      other pool mailbox — confirm the messages actually arrive.
- [ ] Every warm-up message carries an `X-Fute-Warmup` header (check message
      source) and does **not** appear as a reply/bounce in Deliverability stats,
      template analytics, or stop any real sequence.
- [ ] The receiving mailbox **replies** within the delay window; conversations
      run up to `warmup_replies_per_thread` exchanges then stop.
- [ ] A warm-up message landing in **Junk** is moved to **Inbox** (rescued) and
      the mailbox's inbox-placement % reflects it.
- [ ] Warm-up sends increment `warmup_send_log` only — a BD's outreach daily quota
      (`email_send_log`) is untouched.
- [ ] Pause / Resume / Graduate work; past the duration the mailbox auto-graduates
      to **✓ Warmed** and stops sending warm-up mail.
- [ ] Graph specifics to confirm on the pilot: custom `internetMessageHeaders`
      survive send + are readable on the received copy; `createReply` + PATCH
      header + send threads correctly; `/messages/{id}/move` to `inbox` rescues.
- [ ] With only **one** connected mailbox, warm-up no-ops gracefully (nothing to
      exchange with) and says so.

## Admin: System Settings (operational numbers)
- [ ] Admin (not RA-Lead) sees the "System Settings" button on the Admin page.
- [ ] Current values shown match the previous hardcoded defaults (21 / 24 / 20 / 5 / 5 / 20 / 3 / 200).
- [ ] Saving a changed value persists — reopening the modal shows the new value.
- [ ] Behavior actually changes: e.g. lower the company cooldown to 1 day and confirm
      an RA can re-add a company after 1 day instead of 21; raise the workflow tick
      batch and confirm more enrollments process per tick.
- [ ] An out-of-range or non-numeric value is rejected with a clear message and nothing saves.
