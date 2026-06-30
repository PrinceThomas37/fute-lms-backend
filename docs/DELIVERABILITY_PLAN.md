# Deliverability & Reply-Rate Improvement Plan

Goal: move from a solid *sending* engine toward a world-class outreach system,
targeting **higher reply rate** and **better deliverability** — without changing
any behaviour that already works. Every new capability is **additive and off by
default** (it only acts once data flows in: an empty suppression list blocks
nothing, an unset warm-up date keeps today's static limit, etc.).

Domain nuance baked in: in *recruiting* outreach, role inboxes (`hr@`,
`careers@`) are often the **intended** target, so deeper verification only
**flags** role/catch-all addresses — it never auto-blocks them. Only truly dead
addresses (no MX / disposable) are hard-skipped.

## Data model — `migrations/006_deliverability.sql`
- `suppression_list` (email unique, reason, source, created_by) — global opt-out.
- `contacts.replied_at`, `contacts.reply_snippet` — reply tracking.
- `contacts.deliverability_flags JSONB` — `{role, catch_all, disposable}` soft signals.
- `user_emails.warmup_start_date DATE` — when set, daily limit ramps.
- `user_emails.auto_paused_at TIMESTAMPTZ` — set when bounce-rate auto-pause trips.

## Waves (each verified + committed independently)

### 1. Suppression list + opt-out enforcement
- `isSuppressed(email)` checked at generation and again in the send loop.
- `GET/POST/DELETE /suppression` to view/add/remove (admin/lead).
- Feeds from the reply sweep (unsubscribe replies) and manual adds.

### 2. Reply detection → auto-stop sequence (biggest reply-rate win)
- New `sweepMailboxReplies()` reusing the existing Graph inbox machinery
  (`graphMailRequest`, the bounce-sweep pattern in `index.js`).
- A genuine inbound reply from a contact → set `contacts.replied_at`, move the
  job stage to `Connected` (if still `Assigned`), cancel active follow-ups
  (reuse `skipActiveFollowUpsForContact`), emit `contact.replied`.
- If the reply text is an opt-out ("unsubscribe", "remove me", "stop") → add to
  `suppression_list` and emit `contact.unsubscribed`.
- Runs on the same schedule as the bounce sweep; cursor in `app_settings`
  (`reply_sweep_since_${userEmailId}`).

### 3. Deeper verification (`email-validation.js`)
- Hard block: no-MX (existing) + **disposable domains** (static list).
- Soft flag only (never blocks): **role accounts** (`hr@`, `info@`, …) and
  **catch-all** domains. Stored in `contacts.deliverability_flags`.

### 4. Warm-up ramp
- `effectiveDailyLimit(mailbox)` = static limit when `warmup_start_date` is null
  (no change); otherwise `min(base, START + STEP * daysSinceStart)`.
- Used wherever the per-mailbox daily cap is read in the send path.

### 5. Per-mailbox bounce-rate auto-pause
- After each bounce sweep, compute per-mailbox bounce rate over a recent window
  (from `emails`); if above threshold (default 5%, min sample), set
  `auto_paused_at`, emit `mailbox.autopaused`. The send loop treats an
  auto-paused mailbox like an inactive one. Cleared manually or on resume.

### 6. Spam content pre-check
- `scoreEmailContent(subject, body)` heuristic (spam words, link/image ratio,
  ALL-CAPS, length, excessive punctuation) → `{score, warnings[]}`.
- `POST /emails/spam-check`; surfaced as a non-blocking warning in compose.

### 7. Analytics
- `GET /analytics/templates` — reply rate per `template_variant` (closes the A/B
  loop now that replies are tracked).
- `GET /admin/deliverability` — bounce %, reply %, suppression count, and
  per-mailbox health (warm-up day, auto-pause, sent/bounced).

### 8. Frontend (`public/app.js`)
- Deliverability health view; suppression management; compose spam-check warning;
  reply / warm-up / auto-pause indicators on the relevant cards.

## Explicitly deferred (need external services / bigger design)
- **SMTP-level catch-all & mailbox-existence verification** — needs a paid
  verifier (ZeroBounce/NeverBounce). Wave 3 leaves a pluggable hook
  (`VERIFY_API_KEY`); heuristic layer ships now.
- **Full automated warm-up pool** (mailboxes auto-emailing each other) — Wave 4
  ships the *ramp*; the inter-mailbox warm-up exchange is a separate project.

## Safety / non-regression
- All schema changes are `ADD COLUMN IF NOT EXISTS` / new tables — nothing
  existing is altered.
- New gates are no-ops until data exists (empty suppression list, null warm-up
  date, no auto-pause).
- Verified per wave with `node --check` + a full module load test; the live send
  path keeps its existing window/quota/throttle/threading logic intact.

## Verification (end-to-end, after migration applied)
- Reply sweep: send to a test address that replies → follow-ups stop, stage
  flips to Connected, `contact.replied` on `/events/recent`.
- Suppression: add an address → it's skipped at send.
- Warm-up: set `warmup_start_date` → effective cap ramps daily.
- Bounce auto-pause: simulate bounces past threshold → mailbox auto-pauses.
- Spam-check: `POST /emails/spam-check` returns warnings for a spammy body.
- Dashboards return correct aggregates.
