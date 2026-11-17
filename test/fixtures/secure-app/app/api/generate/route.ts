import OpenAI from 'openai';
import { z } from 'zod';
import { ratelimit } from '@/lib/ratelimit';
import { supabaseServer } from '@/lib/server';
const openai = new OpenAI();
const Body = z.object({ prompt: z.string().max(2000) });
export async function POST(req: Request) {
  const supabase = await supabaseServer();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response('Unauthorized', { status: 401 });
  const { success } = await ratelimit.limit(user.id);
  if (!success) return new Response('Too many requests', { status: 429 });
  const parsed = Body.safeParse(await req.json());
  if (!parsed.success) return new Response('Bad request', { status: 400 });
  try {
    const r = await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: parsed.data.prompt }] });
    return Response.json({ text: r.choices[0].message.content });
  } catch (err) {
    console.error(err);
    return Response.json({ error: 'Generation failed' }, { status: 500 });
  }
}
