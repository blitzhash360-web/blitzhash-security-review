// Security checks. Each finding names a file and line, never a secret value.
import { checkKnownAdvisories } from './deps.mjs';

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];

// Secret patterns (kind only is ever reported).
const SECRET_PATTERNS = [
  ['Stripe live secret key', /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}/],
  ['Stripe test secret key', /\bsk_test_[0-9a-zA-Z]{20,}/],
  ['Stripe webhook signing secret', /\bwhsec_[0-9a-zA-Z]{24,}/],
  ['OpenAI API key', /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{32,}/],
  ['AWS access key ID', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['GitHub token', /\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{30,}/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['Slack token', /\bxox[abposr]-[0-9A-Za-z-]{20,}/],
  ['Resend API key', /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/],
  ['Private key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/],
  ['Database URL with password', /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s'"/]+:[^@\s'"]{6,}@[^\s'"]+/],
];
const PLACEHOLDER = /(x{6,}|\.\.\.|your[_-]|example|placeholder|changeme|<[^>]+>|\$\{)/i;

function jwtRole(token) {
  try {
    const part = token.split('.')[1];
    const json = JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    return json.role || null;
  } catch { return null; }
}

const isTest = (p) => /(^|\/)(__tests__|tests?|spec|e2e|cypress|playwright)\//.test(p) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(p);
const isClientFile = (f) => /^\s*['"]use client['"]/m.test(f.text.slice(0, 400)) || (/(^|\/)(components|hooks)\//.test(f.path) && /\.(jsx|tsx|vue|svelte)$/.test(f.path) && !/['"]use server['"]|server-only/.test(f.text.slice(0, 400)));
const isViteSpa = (scan) => scan.pkgs.some((p) => (p.json.dependencies?.vite || p.json.devDependencies?.vite) && !(p.json.dependencies?.next));
const isApiRoute = (p) => /(^|\/)(app\/(.*\/)?api\/.*\/route\.[cm]?[jt]s|pages\/api\/.*\.[cm]?[jt]s|server\/api\/.*\.[cm]?[jt]s|api\/.*\.[cm]?[jt]s|supabase\/functions\/[^/]+\/index\.ts)$/.test(p);

function lineOf(f, idx) { return f.text.slice(0, idx).split('\n').length; }
function eachMatch(f, re, cb) {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  let m;
  while ((m = g.exec(f.text))) { cb(m, lineOf(f, m.index)); if (m[0].length === 0) g.lastIndex++; }
}

export function runChecks(scan) {
  const out = [];
  const add = (sev, id, title, loc, why, fix) => out.push({ severity: sev, id, title, file: loc?.file || null, line: loc?.line || null, why, fix });
  const code = scan.files.filter((f) => f.code && !isTest(f.path));
  const allText = scan.files.filter((f) => !isTest(f.path));

  // SR01 hard-coded secrets
  for (const f of allText) {
    if (/(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(f.path)) continue;
    f.lines.forEach((ln, i) => {
      if (ln.length > 2000) return;
      for (const [kind, re] of SECRET_PATTERNS) {
        const m = re.exec(ln);
        if (m && !PLACEHOLDER.test(m[0])) {
          const live = /live|Private key|Database|AWS|GitHub|OpenAI|Anthropic/.test(kind);
          add(live ? 'critical' : 'high', 'SR01', `${kind} written in the code`, { file: f.path, line: i + 1 },
            'Anyone who can read this repo (or the built app, if this file ships to the browser) can use this key as you.',
            'Move it to an environment variable on your host, then rotate the key in the provider dashboard. Deleting the line is not enough: it stays in git history.');
          break;
        }
      }
      // Supabase service_role JWT
      for (const t of ln.match(/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g) || []) {
        if (jwtRole(t) === 'service_role') add('critical', 'SR01', 'Supabase service_role key written in the code', { file: f.path, line: i + 1 },
          'The service_role key skips every Row Level Security rule. Whoever has it can read and delete your whole database.',
          'Remove it, keep it only in server-side environment variables, and roll the key in Supabase (Project Settings → API).');
      }
    });
  }

  // SR02 env files committed / not ignored
  const gitignore = scan.files.find((f) => f.path === '.gitignore');
  const ignoresEnv = gitignore && /^\s*\/?\.env(\*|\.\*|\.local)?\s*$/m.test(gitignore.text);
  for (const e of scan.envFiles.filter((x) => !x.example)) {
    const withValues = e.names.filter((n) => n.hasValue).length;
    if (scan.tracked?.has(e.path) && withValues) {
      add('critical', 'SR02', `${e.path} is committed to git`, { file: e.path }, `It holds ${withValues} value(s). Everyone with repo access, and anyone if the repo is ever public, gets them.`,
        `Run \`git rm --cached ${e.path}\`, add it to .gitignore, and rotate every secret it held. Use your host's environment settings instead.`);
    } else if (!ignoresEnv && withValues) {
      add('high', 'SR02', `.gitignore does not exclude ${e.path}`, { file: '.gitignore' }, 'One `git add .` away from publishing your keys.',
        'Add `.env*` and `!.env.example` to .gitignore.');
    }
  }

  // SR03 secrets exposed to the browser through public env prefixes
  const SECRETISH = /(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|DATABASE_URL|_TOKEN$|OPENAI|ANTHROPIC|STRIPE_SECRET|RESEND|SENDGRID|TWILIO_AUTH|AWS_SECRET|WEBHOOK)/;
  const PUBLIC = /^(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)/;
  const seen = new Set();
  const flagPublic = (name, loc) => {
    if (!PUBLIC.test(name) || !SECRETISH.test(name.replace(PUBLIC, '')) || /PUBLISHABLE|ANON|SITE_KEY|PUBLIC_KEY$/.test(name) || seen.has(name)) return;
    seen.add(name);
    add('critical', 'SR03', `Secret exposed to the browser: ${name}`, loc,
      `The ${name.match(PUBLIC)[1]} prefix bakes the value into the JavaScript every visitor downloads. Anyone can open DevTools and copy it.`,
      'Rename it without the public prefix, use it only in server code (API route, server action, edge function), and rotate the key.');
  };
  for (const e of scan.envFiles) for (const n of e.names) flagPublic(n.name, { file: e.path });
  for (const f of code) eachMatch(f, /(?:process\.env\.|import\.meta\.env\.)([A-Z][A-Z0-9_]+)/, (m, line) => flagPublic(m[1], { file: f.path, line }));

  // SR04 service_role / admin client used in browser code
  const spa = isViteSpa(scan);
  for (const f of code) {
    const client = isClientFile(f) || (spa && /^src\//.test(f.path) && !/(^|\/)(server|api|functions)\//.test(f.path));
    if (!client) continue;
    let hit = false;
    eachMatch(f, /SERVICE_ROLE|serviceRole|auth\.admin\.|STRIPE_SECRET_KEY|new Stripe\(/, (m, line) => {
      if (hit) return; hit = true;
      add('critical', 'SR04', 'Admin/secret key used in browser code', { file: f.path, line },
        'This file runs in the visitor\'s browser, so any key or admin client it uses is public.',
        'Move this call to a server route or Supabase Edge Function and call that from the page instead.');
    });
  }

  // SR05 Stripe webhook without signature verification
  for (const f of code.filter((x) => /webhook/i.test(x.path) && /stripe/i.test(x.text))) {
    if (!/constructEvent(Async)?\s*\(|webhooks\.signature|verifyHeader/.test(f.text)) {
      add('critical', 'SR05', 'Stripe webhook does not verify the signature', { file: f.path },
        'Anyone can POST a fake "payment succeeded" event to this URL and unlock paid features for free.',
        'Read the raw body and call `stripe.webhooks.constructEvent(rawBody, signature, STRIPE_WEBHOOK_SECRET)`; reject the request if it throws.');
    }
  }
  for (const f of code.filter((x) => /webhook/i.test(x.path) && !/stripe/i.test(x.text) && isApiRoute(x.path))) {
    if (!/signature|hmac|verify|svix|timingSafeEqual|x-hub-signature|secret/i.test(f.text)) {
      add('high', 'SR05', 'Webhook endpoint with no signature check', { file: f.path },
        'Without a signature check, anyone who finds the URL can send fake events.',
        'Verify the provider\'s signature header (HMAC with your webhook secret) before trusting the payload.');
    }
  }

  // SR06 database access rules (Supabase/Postgres migrations, Firebase rules)
  const sqlFiles = scan.files.filter((f) => /\.sql$/.test(f.path));
  const sqlAll = sqlFiles.map((f) => f.text).join('\n');
  for (const f of sqlFiles) {
    eachMatch(f, /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?([a-z_][a-z0-9_]*)"?\s*\(/i, (m, line) => {
      if (/^(schema_migrations|_prisma_migrations)$/i.test(m[1])) return;
      if (/\bauth\.|storage\./i.test(f.text.slice(Math.max(0, m.index - 20), m.index))) return;
      const rls = new RegExp(`alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:"?public"?\\.)?"?${m[1]}"?\\s+enable\\s+row\\s+level\\s+security`, 'i');
      if (!rls.test(sqlAll)) add('critical', 'SR06', `Table "${m[1]}" has Row Level Security off`, { file: f.path, line },
        'With Supabase, the anon key in your app can read and change every row of a table without RLS.',
        `Add \`alter table public.${m[1]} enable row level security;\` and policies that check \`auth.uid()\`. Test as a logged-out and a second user.`);
    });
    eachMatch(f, /create\s+policy\s+"?([^"\n]+?)"?\s+on\s+(?:"?public"?\.)?"?([a-z_][a-z0-9_]*)"?([\s\S]*?);/i, (m, line) => {
      const body = m[3];
      const cmd = (/for\s+(select|insert|update|delete|all)/i.exec(body)?.[1] || 'all').toLowerCase();
      const open = /using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(body);
      if (open && cmd !== 'select') add('high', 'SR06', `Policy lets anyone ${cmd === 'all' ? 'write' : cmd} on "${m[2]}"`, { file: f.path, line },
        '`using (true)` / `with check (true)` means any visitor, logged in or not, passes this rule.',
        'Replace `true` with an ownership check such as `auth.uid() = user_id`, and limit the policy `to authenticated`.');
      else if (open && !/to\s+authenticated/i.test(body) && !/public|published|catalog|plans|products/i.test(m[2]))
        add('medium', 'SR06', `"${m[2]}" is readable by everyone`, { file: f.path, line },
          'Anyone with your public anon key can download this whole table.', 'If that is not intended, restrict the policy to the row owner or `to authenticated`.');
    });
    eachMatch(f, /insert\s+into\s+storage\.buckets[^;]*\btrue\b/i, (m, line) => add('medium', 'SR06', 'Public storage bucket', { file: f.path, line },
      'Every file in a public bucket can be fetched by anyone who guesses or finds the URL.', 'Make the bucket private and serve files with signed URLs unless they really are public assets.'));
  }
  for (const f of scan.files.filter((x) => /(firestore|storage|database)\.rules$|\.rules$/.test(x.path))) {
    eachMatch(f, /allow\s+(?:read|write|read\s*,\s*write)\s*(?::\s*if\s+true|;)/, (m, line) => add('critical', 'SR06', 'Firebase rules allow everyone', { file: f.path, line },
      'These rules let anyone read or overwrite your data.', 'Require `request.auth != null` and match `request.auth.uid` to the document owner.'));
  }

  // SR07 injection: SQL / command / eval
  for (const f of code) {
    eachMatch(f, /\.(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\(\s*`[^`]*\$\{/, (m, line) => add('high', 'SR07', 'SQL built from a template string', { file: f.path, line },
      'If any ${...} value comes from the user, they can rewrite the query (SQL injection) and read or delete data.',
      'Use parameters (`$1`, `?`) or your ORM\'s tagged `sql` template instead of string building.'));
    eachMatch(f, /\.(?:query|execute)\(\s*['"][^'"]*['"]\s*\+\s*/, (m, line) => add('high', 'SR07', 'SQL built by string concatenation', { file: f.path, line },
      'Concatenating input into SQL allows SQL injection.', 'Pass values as query parameters.'));
    eachMatch(f, /\b(?:exec|execSync)\(\s*`[^`]*\$\{|\beval\(\s*(?:req|request|body|params|query|input)/, (m, line) => add('high', 'SR07', 'Shell command or eval built from input', { file: f.path, line },
      'A crafted value can run any command on your server.', 'Use `execFile` with an argument array (no shell) and never eval user input.'));
    eachMatch(f, /new Function\(\s*(?:req|request|body|input)/, (m, line) => add('high', 'SR07', 'Code built from input with new Function', { file: f.path, line }, 'Lets a visitor run code on your server.', 'Remove it; parse data with JSON.parse or a schema instead.'));
  }

  // SR08 XSS sinks
  for (const f of code) eachMatch(f, /dangerouslySetInnerHTML|\bv-html=|\.innerHTML\s*=(?!=)|\{@html\s/, (m, line) => {
    if (/DOMPurify|sanitize/i.test(f.text)) return;
    add('medium', 'SR08', 'Raw HTML inserted into the page', { file: f.path, line },
      'If this HTML includes anything a user typed (or an AI generated), it can run scripts in other users\' sessions (XSS).',
      'Render text normally, or sanitize with DOMPurify before inserting HTML.');
  });

  // SR09 auth on API routes that change data
  const AUTH = /getUser\(|getSession\(|getServerSession|auth\(\)|currentUser\(|getAuth\(|verifyIdToken|jwtVerify|jwt\.verify|getToken\(|requireUser|requireAuth|withAuth|clerk|authorization|x-api-key|verifySignature|constructEvent|isAuthenticated|getClaims\(/i;
  const middleware = scan.files.find((f) => /(^|\/)(src\/)?middleware\.[jt]s$/.test(f.path) && /api/.test(f.text) && AUTH.test(f.text));
  for (const f of code.filter((x) => isApiRoute(x.path) && !/webhook|cron|health|og|public/i.test(x.path))) {
    const writes = /export\s+(?:async\s+)?(?:function|const)\s+(POST|PUT|PATCH|DELETE)\b|req\.method\s*===?\s*['"](POST|PUT|PATCH|DELETE)|\.(?:insert|update|delete|upsert)\(/.test(f.text);
    if (writes && !AUTH.test(f.text) && !middleware) add('high', 'SR09', 'API route changes data without checking who is calling', { file: f.path },
      'Anyone on the internet can call this endpoint directly (no login needed) and change or delete data.',
      'At the top of the handler, get the logged-in user (e.g. `supabase.auth.getUser()`) and return 401 if there is none; then check they own the record.');
  }
  for (const f of code) eachMatch(f, /jwt\.decode\(|algorithms\s*:\s*\[\s*['"]none['"]/, (m, line) => {
    if (/jwt\.verify|jwtVerify/.test(f.text)) return;
    add('high', 'SR09', 'Token read without verifying its signature', { file: f.path, line }, 'Decoding a JWT does not prove it is real; anyone can forge one.', 'Use `jwt.verify` / `jose.jwtVerify` with your secret or the provider\'s JWKS.');
  });
  for (const f of code) eachMatch(f, /(?:cookies\(\)\.set|res\.cookie|setCookie)\(([^)]*)\)/, (m, line) => {
    if (/session|token|auth|jwt/i.test(m[1]) && !/httpOnly\s*:\s*true/i.test(f.text)) add('medium', 'SR09', 'Session cookie without httpOnly', { file: f.path, line },
      'Any script on the page (including an XSS bug or a bad npm package) can steal the session.', 'Set `{ httpOnly: true, secure: true, sameSite: "lax" }` on auth cookies.');
  });

  // SR10 input validation
  const VALIDATE = /\bz\.|zod|yup|valibot|joi|ajv|superstruct|typebox|safeParse|\.parse\(/;
  for (const f of code.filter((x) => isApiRoute(x.path) && !/webhook/i.test(x.path))) {
    if (/(?:req|request)\.(?:json\(\)|body|formData\(\))/.test(f.text) && !VALIDATE.test(f.text)) add('medium', 'SR10', 'Request body used without validation', { file: f.path },
      'Unchecked input lets people send unexpected fields (e.g. `role: "admin"`, negative prices) straight into your database.',
      'Define a schema (zod or similar) and `safeParse` the body; only pass the fields you expect.');
  }

  // SR11 rate limiting on expensive / abusable endpoints
  const RATE = /ratelimit|rate-limit|rateLimit|limiter|throttle|upstash|slowDown|@arcjet|turnstile|hcaptcha|recaptcha/i;
  const anyRate = scan.files.some((f) => RATE.test(f.text) && !isTest(f.path) && !/package-lock/.test(f.path));
  if (!anyRate) {
    const costly = code.find((f) => isApiRoute(f.path) && /openai|anthropic|generateText|streamText|chat\.completions|resend|sendgrid|nodemailer|twilio|signInWithOtp|signUp|resetPasswordForEmail/i.test(f.text));
    if (costly) add('high', 'SR11', 'No rate limiting on AI, email or login endpoints', { file: costly.path },
      'A script can call this thousands of times a minute: a surprise AI/email bill, spam sent from your domain, or password guessing.',
      'Add a per-IP and per-user limit (e.g. Upstash Ratelimit, Cloudflare/Vercel WAF rule) and a spend cap on the provider account.');
  }

  // SR12 CORS
  for (const f of code) {
    eachMatch(f, /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]|origin\s*:\s*(?:['"]\*['"]|true)\b/, (m, line) => {
      const creds = /credentials\s*:\s*true|Allow-Credentials['"]?\s*[,:]\s*['"]?true/i.test(f.text);
      add(creds ? 'high' : 'medium', 'SR12', creds ? 'CORS allows any website, with cookies' : 'CORS allows any website', { file: f.path, line },
        creds ? 'Any site a logged-in user visits can make requests as them and read the answers.' : 'Any website can call this API from a visitor\'s browser. Fine for truly public data, risky for anything else.',
        'Allow only your own domains (an explicit list), never `*` together with credentials.');
    });
  }

  // SR13 security headers
  const HEADER_SRC = scan.files.filter((f) => /(^|\/)(next\.config\.[cm]?[jt]s|vercel\.json|_headers|netlify\.toml|middleware\.[jt]s|nginx\.conf|wrangler\.toml|server\.[jt]s|app\.[jt]s|index\.[jt]s)$/.test(f.path) || /helmet/.test(f.text));
  const hdr = HEADER_SRC.map((f) => f.text).join('\n');
  const isWebApp = scan.pkgs.some((p) => Object.keys({ ...p.json.dependencies, ...p.json.devDependencies }).some((d) => /^(next|vite|react|vue|svelte|astro|express|nuxt|@remix-run)/.test(d)));
  if (isWebApp && !/helmet\(/.test(hdr)) {
    const missing = [['Content-Security-Policy', /Content-Security-Policy/i], ['Strict-Transport-Security', /Strict-Transport-Security/i], ['X-Frame-Options / frame-ancestors', /X-Frame-Options|frame-ancestors/i], ['X-Content-Type-Options', /X-Content-Type-Options/i]].filter(([, re]) => !re.test(hdr)).map(([n]) => n);
    if (missing.length) add(missing.length >= 3 ? 'medium' : 'low', 'SR13', `Missing security headers: ${missing.join(', ')}`, null,
      'These headers stop clickjacking, content sniffing and many XSS payloads. Scanners and enterprise buyers check them first.',
      'Set them in next.config `headers()`, vercel.json, `_headers` (Netlify/Cloudflare Pages) or your server (helmet for Express).');
  }

  // SR14 open redirect
  for (const f of code) eachMatch(f, /redirect\(\s*(?:searchParams\.get|req\.query\.|request\.nextUrl\.searchParams\.get|url\.searchParams\.get)\(?\s*['"]?(?:next|redirect|returnTo|url|to|callback)/, (m, line) => {
    add('medium', 'SR14', 'Redirect target taken from the URL', { file: f.path, line },
      'An attacker can send your users a real-looking login link that lands them on a phishing site.', 'Only allow relative paths that start with a single `/`, or check against a list of your own domains.');
  });

  // SR15 leaking errors
  for (const f of code.filter((x) => isApiRoute(x.path))) eachMatch(f, /(?:json|send)\(\s*\{[^}]*\b(?:err|error|e)\.(?:stack|message)\b/, (m, line) => add('low', 'SR15', 'Internal error details sent to the client', { file: f.path, line },
    'Stack traces and database errors tell attackers your table names and libraries.', 'Log the error on the server; return a generic message and an error ID.'));

  // SR16 dependencies
  for (const a of checkKnownAdvisories(scan)) add(a.severity, 'SR16', `${a.pkg}@${a.version}: ${a.title}`, { file: a.source },
    `${a.id}. ${a.declared ? 'Version taken from package.json (no lockfile entry).' : 'Version from package-lock.json.'} Details: ${a.url}`,
    `Upgrade ${a.pkg} to ${a.fixedIn} or later, rebuild and redeploy.`);
  if (scan.pkgs.length && !scan.hasLockfile) add('low', 'SR16', 'No lockfile committed', null,
    'Without a lockfile every install can pull different (possibly compromised) package versions.', 'Commit package-lock.json / pnpm-lock.yaml and use `npm ci` in CI.');

  return dedupe(out).sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.id.localeCompare(b.id) || String(a.file).localeCompare(String(b.file)) || (a.line || 0) - (b.line || 0));
}

function dedupe(list) {
  const seen = new Set();
  return list.filter((f) => { const k = `${f.id}|${f.title}|${f.file}|${f.line}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

export function score(findings) {
  const w = { critical: 25, high: 10, medium: 4, low: 1 };
  const s = Math.max(0, 100 - findings.reduce((n, f) => n + w[f.severity], 0));
  const grade = s >= 90 ? 'A' : s >= 75 ? 'B' : s >= 60 ? 'C' : s >= 40 ? 'D' : 'F';
  return { score: s, grade };
}
