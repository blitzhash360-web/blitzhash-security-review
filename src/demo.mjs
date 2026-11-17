// security-review-ignore-file (deliberately insecure demo content)
// Builds a small, deliberately insecure "vibe-coded" app in a temp folder for the demo and tests.
// Fake keys are assembled at runtime so this source file never contains anything that looks like a real secret.
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';

const fake = (prefix, n) => prefix + 'DEMO0NOTREAL'.padEnd(n, '0');
export const FAKE_STRIPE = fake('sk_' + 'live_', 32);
export const FAKE_OPENAI = fake('sk-' + 'proj-', 40);

export function buildDemoApp(dir = mkdtempSync(join(tmpdir(), 'bh-secreview-demo-'))) {
  const app = join(dir, 'vibe-app');
  const files = {
    'package.json': JSON.stringify({ name: 'vibe-app', private: true, dependencies: { next: '15.1.3', react: '19.0.0', 'react-dom': '19.0.0', stripe: '^17.0.0', openai: '^4.70.0', '@supabase/supabase-js': '^2.45.0' } }, null, 2),
    '.gitignore': 'node_modules\n.next\n',
    '.env.local': `NEXT_PUBLIC_SUPABASE_URL=https://demo.supabase.co\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=demo-value-not-real\nOPENAI_API_KEY=${FAKE_OPENAI}\n`,
    'next.config.js': 'module.exports = { reactStrictMode: true };\n',
    'app/api/checkout/route.ts': `import Stripe from 'stripe';\nconst stripe = new Stripe('${FAKE_STRIPE}');\n\nexport async function POST(req: Request) {\n  const { priceId } = await req.json();\n  const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: [{ price: priceId, quantity: 1 }], success_url: '/thanks' });\n  return Response.json({ url: session.url });\n}\n`,
    'app/api/webhooks/stripe/route.ts': `import { db } from '@/lib/db';\n// Stripe sends payment events here\nexport async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === 'checkout.session.completed') {\n    await db.from('profiles').update({ plan: 'pro' }).eq('email', event.data.object.customer_email);\n  }\n  return new Response('ok');\n}\n`,
    'app/api/projects/route.ts': `import { pool } from '@/lib/pg';\n\nexport async function POST(req: Request) {\n  const body = await req.json();\n  await pool.query('insert into projects (name, owner) values ($1, $2)', [body.name, body.owner]);\n  return Response.json({ ok: true });\n}\n\nexport async function DELETE(req: Request) {\n  const id = new URL(req.url).searchParams.get('id');\n  await pool.query(\`delete from projects where id = \${id}\`);\n  return Response.json({ ok: true });\n}\n`,
    'app/api/generate/route.ts': `import OpenAI from 'openai';\nconst openai = new OpenAI();\n\nexport async function POST(req: Request) {\n  try {\n    const { prompt } = await req.json();\n    const r = await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: prompt }] });\n    return Response.json({ text: r.choices[0].message.content });\n  } catch (error: any) {\n    return Response.json({ error: error.message, stack: error.stack }, { status: 500 });\n  }\n}\n`,
    'app/auth/callback/route.ts': `import { redirect } from 'next/navigation';\nexport async function GET(request: Request) {\n  const url = new URL(request.url);\n  // after login, send the user back where they came from\n  redirect(url.searchParams.get('next') ?? '/');\n}\n`,
    'components/AdminPanel.tsx': `'use client';\nimport { createClient } from '@supabase/supabase-js';\n\nconst admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);\n\nexport function AdminPanel() {\n  const ban = (id: string) => admin.auth.admin.deleteUser(id);\n  return <button onClick={() => ban('x')}>Ban user</button>;\n}\n`,
    'app/notes/[id]/page.tsx': `export default async function Note({ note }: { note: { html: string } }) {\n  return <article dangerouslySetInnerHTML={{ __html: note.html }} />;\n}\n`,
    'lib/cors.ts': `export const corsHeaders = {\n  'Access-Control-Allow-Origin': '*',\n  'Access-Control-Allow-Credentials': 'true',\n};\n`,
    'supabase/migrations/20261001120000_init.sql': `create table public.profiles (\n  id uuid primary key references auth.users,\n  email text,\n  plan text default 'free'\n);\nalter table public.profiles enable row level security;\ncreate policy "profiles are editable" on public.profiles for update using (true);\n\ncreate table public.payments (\n  id bigserial primary key,\n  user_id uuid,\n  amount_cents int\n);\n`,
  };
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(app, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, text);
  }
  try {
    const g = (...a) => execFileSync('git', ['-C', app, ...a], { stdio: 'ignore' });
    g('init', '-q'); g('add', '-A'); g('-c', 'user.name=demo', '-c', 'user.email=demo@example.invalid', 'commit', '-qm', 'vibe-coded MVP');
  } catch { /* git optional */ }
  return app;
}
