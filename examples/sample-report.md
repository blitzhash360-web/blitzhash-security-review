# Security review: demo vibe-coded app (fake keys)

**Score: 0/100 (grade F)**: 8 critical · 7 high · 6 medium · 2 low

Scanned 13 files. Read-only: nothing was changed and no secret values are shown in this report.

## 🔴 Critical: fix before anyone else uses the app (8)

### 1. Stripe live secret key written in the code

- **Where:** `app/api/checkout/route.ts:2`
- **Why it matters:** Anyone who can read this repo (or the built app, if this file ships to the browser) can use this key as you.
- **Fix:** Move it to an environment variable on your host, then rotate the key in the provider dashboard. Deleting the line is not enough: it stays in git history.
- Check: `SR01`

### 2. .env.local is committed to git

- **Where:** `.env.local`
- **Why it matters:** It holds 3 value(s). Everyone with repo access, and anyone if the repo is ever public, gets them.
- **Fix:** Run `git rm --cached .env.local`, add it to .gitignore, and rotate every secret it held. Use your host's environment settings instead.
- Check: `SR02`

### 3. Secret exposed to the browser: NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY

- **Where:** `.env.local`
- **Why it matters:** The NEXT_PUBLIC_ prefix bakes the value into the JavaScript every visitor downloads. Anyone can open DevTools and copy it.
- **Fix:** Rename it without the public prefix, use it only in server code (API route, server action, edge function), and rotate the key.
- Check: `SR03`

### 4. Admin/secret key used in browser code

- **Where:** `components/AdminPanel.tsx:4`
- **Why it matters:** This file runs in the visitor's browser, so any key or admin client it uses is public.
- **Fix:** Move this call to a server route or Supabase Edge Function and call that from the page instead.
- Check: `SR04`

### 5. Stripe webhook does not verify the signature

- **Where:** `app/api/webhooks/stripe/route.ts`
- **Why it matters:** Anyone can POST a fake "payment succeeded" event to this URL and unlock paid features for free.
- **Fix:** Read the raw body and call `stripe.webhooks.constructEvent(rawBody, signature, STRIPE_WEBHOOK_SECRET)`; reject the request if it throws.
- Check: `SR05`

### 6. Table "payments" has Row Level Security off

- **Where:** `supabase/migrations/20261001120000_init.sql:9`
- **Why it matters:** With Supabase, the anon key in your app can read and change every row of a table without RLS.
- **Fix:** Add `alter table public.payments enable row level security;` and policies that check `auth.uid()`. Test as a logged-out and a second user.
- Check: `SR06`

### 7. next@15.1.3: Next.js version affected by the React Server Components remote code execution bug

- **Where:** `package.json`
- **Why it matters:** CVE-2025-66478 / CVE-2025-55182 (React2Shell). Version taken from package.json (no lockfile entry). Details: https://nextjs.org/blog/CVE-2025-66478
- **Fix:** Upgrade next to 15.1.9 or later, rebuild and redeploy.
- Check: `SR16`

### 8. next@15.1.3: Next.js version where middleware auth checks can be skipped with one header

- **Where:** `package.json`
- **Why it matters:** CVE-2025-29927. Version taken from package.json (no lockfile entry). Details: https://github.com/advisories/GHSA-f82v-jwr5-mffw
- **Fix:** Upgrade next to 15.2.3 or later, rebuild and redeploy.
- Check: `SR16`

## 🟠 High: fix before launch (7)

### 1. Policy lets anyone update on "profiles"

- **Where:** `supabase/migrations/20261001120000_init.sql:7`
- **Why it matters:** `using (true)` / `with check (true)` means any visitor, logged in or not, passes this rule.
- **Fix:** Replace `true` with an ownership check such as `auth.uid() = user_id`, and limit the policy `to authenticated`.
- Check: `SR06`

### 2. SQL built from a template string

- **Where:** `app/api/projects/route.ts:11`
- **Why it matters:** If any ${...} value comes from the user, they can rewrite the query (SQL injection) and read or delete data.
- **Fix:** Use parameters (`$1`, `?`) or your ORM's tagged `sql` template instead of string building.
- Check: `SR07`

### 3. API route changes data without checking who is calling

- **Where:** `app/api/checkout/route.ts`
- **Why it matters:** Anyone on the internet can call this endpoint directly (no login needed) and change or delete data.
- **Fix:** At the top of the handler, get the logged-in user (e.g. `supabase.auth.getUser()`) and return 401 if there is none; then check they own the record.
- Check: `SR09`

### 4. API route changes data without checking who is calling

- **Where:** `app/api/generate/route.ts`
- **Why it matters:** Anyone on the internet can call this endpoint directly (no login needed) and change or delete data.
- **Fix:** At the top of the handler, get the logged-in user (e.g. `supabase.auth.getUser()`) and return 401 if there is none; then check they own the record.
- Check: `SR09`

### 5. API route changes data without checking who is calling

- **Where:** `app/api/projects/route.ts`
- **Why it matters:** Anyone on the internet can call this endpoint directly (no login needed) and change or delete data.
- **Fix:** At the top of the handler, get the logged-in user (e.g. `supabase.auth.getUser()`) and return 401 if there is none; then check they own the record.
- Check: `SR09`

### 6. No rate limiting on AI, email or login endpoints

- **Where:** `app/api/generate/route.ts`
- **Why it matters:** A script can call this thousands of times a minute: a surprise AI/email bill, spam sent from your domain, or password guessing.
- **Fix:** Add a per-IP and per-user limit (e.g. Upstash Ratelimit, Cloudflare/Vercel WAF rule) and a spend cap on the provider account.
- Check: `SR11`

### 7. CORS allows any website, with cookies

- **Where:** `lib/cors.ts:2`
- **Why it matters:** Any site a logged-in user visits can make requests as them and read the answers.
- **Fix:** Allow only your own domains (an explicit list), never `*` together with credentials.
- Check: `SR12`

## 🟡 Medium: fix soon (6)

### 1. Raw HTML inserted into the page

- **Where:** `app/notes/[id]/page.tsx:2`
- **Why it matters:** If this HTML includes anything a user typed (or an AI generated), it can run scripts in other users' sessions (XSS).
- **Fix:** Render text normally, or sanitize with DOMPurify before inserting HTML.
- Check: `SR08`

### 2. Request body used without validation

- **Where:** `app/api/checkout/route.ts`
- **Why it matters:** Unchecked input lets people send unexpected fields (e.g. `role: "admin"`, negative prices) straight into your database.
- **Fix:** Define a schema (zod or similar) and `safeParse` the body; only pass the fields you expect.
- Check: `SR10`

### 3. Request body used without validation

- **Where:** `app/api/generate/route.ts`
- **Why it matters:** Unchecked input lets people send unexpected fields (e.g. `role: "admin"`, negative prices) straight into your database.
- **Fix:** Define a schema (zod or similar) and `safeParse` the body; only pass the fields you expect.
- Check: `SR10`

### 4. Request body used without validation

- **Where:** `app/api/projects/route.ts`
- **Why it matters:** Unchecked input lets people send unexpected fields (e.g. `role: "admin"`, negative prices) straight into your database.
- **Fix:** Define a schema (zod or similar) and `safeParse` the body; only pass the fields you expect.
- Check: `SR10`

### 5. Missing security headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options / frame-ancestors, X-Content-Type-Options

- **Where:** project-wide
- **Why it matters:** These headers stop clickjacking, content sniffing and many XSS payloads. Scanners and enterprise buyers check them first.
- **Fix:** Set them in next.config `headers()`, vercel.json, `_headers` (Netlify/Cloudflare Pages) or your server (helmet for Express).
- Check: `SR13`

### 6. Redirect target taken from the URL

- **Where:** `app/auth/callback/route.ts:5`
- **Why it matters:** An attacker can send your users a real-looking login link that lands them on a phishing site.
- **Fix:** Only allow relative paths that start with a single `/`, or check against a list of your own domains.
- Check: `SR14`

## ⚪ Low: good hygiene (2)

### 1. Internal error details sent to the client

- **Where:** `app/api/generate/route.ts:10`
- **Why it matters:** Stack traces and database errors tell attackers your table names and libraries.
- **Fix:** Log the error on the server; return a generic message and an error ID.
- Check: `SR15`

### 2. No lockfile committed

- **Where:** project-wide
- **Why it matters:** Without a lockfile every install can pull different (possibly compromised) package versions.
- **Fix:** Commit package-lock.json / pnpm-lock.yaml and use `npm ci` in CI.
- Check: `SR16`

## What this review can't see

These checks read your code. They can't see your live configuration, so also check:

- Supabase dashboard: RLS on every table *in production*, auth settings (email confirmation, leaked-password protection), storage bucket privacy.
- Your host: which environment variables are set where, preview deployments that are public, old deployments still online.
- Business logic: can user A see or edit user B's data by changing an ID in the URL? Test it with two accounts.
- Spend caps on OpenAI/Anthropic, Stripe, email and hosting accounts.

## Going to production? What this doesn't cover

A scanner finds the common, obvious mistakes. A real launch also needs: a manual review of auth and data access paths, testing with real accounts and roles, secret rotation and history cleanup, WAF and bot protection, backups you have actually restored, monitoring and alerting, and load and cost testing.

Want a senior team to check it before real users arrive? Free assessment at https://blitzhash.com

---
_Generated by [BlitzHash Security Review](https://github.com/blitzhash360-web/blitzhash-security-review). Heuristic checks: confirm each finding before acting on it._
