create table public.projects (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users,
  name text not null
);
alter table public.projects enable row level security;
create policy "owners read" on public.projects for select to authenticated using (auth.uid() = owner);
create policy "owners write" on public.projects for insert to authenticated with check (auth.uid() = owner);
