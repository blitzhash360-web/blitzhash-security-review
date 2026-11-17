import { z } from 'zod';
import { supabaseServer } from '@/lib/server';
const Body = z.object({ name: z.string().min(1).max(80) });
export async function POST(req: Request) {
  const supabase = await supabaseServer();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response('Unauthorized', { status: 401 });
  const parsed = Body.safeParse(await req.json());
  if (!parsed.success) return new Response('Bad request', { status: 400 });
  await supabase.from('projects').insert({ name: parsed.data.name, owner: user.id });
  return Response.json({ ok: true });
}
