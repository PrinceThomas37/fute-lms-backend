# AGENTS.md

## Cursor Cloud specific instructions

### Project Overview

Fute Global LLC Lead Management Software (LMS) — a monolithic Node.js/Express backend (`index.js`) serving a single-page frontend (`public/index.html`). No build step, no TypeScript, no test framework.

### Running the Application

```bash
npm run dev   # or: node index.js
```

Server starts on `PORT` (default 3000). Health check: `GET /api/health` or `GET /health`.

### Environment Variables

Copy `env.example` to `.env`. Required for full functionality:

| Variable | Required | Notes |
|----------|----------|-------|
| `SUPABASE_URL` | Yes | Supabase project URL |
| `SUPABASE_SERVICE_KEY` | Yes | Service role key (bypasses RLS) |
| `JWT_SECRET` | Yes | For signing auth tokens |
| `PORT` | No | Defaults to 3000 |
| `ANTHROPIC_API_KEY` | No | AI features degrade gracefully without it |

Without real Supabase credentials, the server starts but all DB operations return "fetch failed". Health endpoints and static file serving still work.

### Key Gotchas

- **No lockfile**: `npm install` resolves fresh every time. Consider committing `package-lock.json` for reproducibility.
- **No linter or test framework**: There are no `eslint`, `prettier`, or test scripts configured in `package.json`.
- **No build step**: The frontend is a single vanilla HTML file with inline CSS/JS — no bundler, no transpilation.
- **Guest mode**: The app supports a guest bypass (`Authorization: Bearer guest`) that provides read-only BD-role access without hitting Supabase auth.
- **Route paths**: API routes do NOT use an `/api/` prefix (except health). Routes are `/users`, `/companies`, `/jobs`, `/contacts`, `/emails`, etc.
- **Database schema**: `schema.sql` is meant to run in Supabase SQL Editor. Seed password for all users is `Fute@2024`.
- **Large single files**: `index.js` is ~2180 lines, `public/index.html` is ~6260 lines.

### Testing Without Supabase

For local testing without Supabase credentials:
1. Set any value for `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` in `.env`
2. The server will start and serve the frontend
3. Guest login works (renders full UI with zero data)
4. Generate test JWTs locally using the `JWT_SECRET` from `.env`
