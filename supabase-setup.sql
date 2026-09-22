-- Worship Roster App — initial schema + RLS policies
-- Run this once in the Supabase SQL Editor.

-- 1. Profiles: one row per signed-up team member, mirrors auth.users
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  campus text not null check (campus in ('EM', 'GW')),
  role text not null default 'member' check (role in ('admin', 'member')),
  roles text[] not null default '{}',
  vocal_part text check (vocal_part in ('melody', 'harmony')),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- Anyone signed in can read all profiles (needed for roster generation + team views)
create policy "profiles are readable by any signed-in user"
  on public.profiles for select
  to authenticated
  using (true);

-- A user can insert their own profile row (during signup)
create policy "users can insert their own profile"
  on public.profiles for insert
  to authenticated
  with check (id = auth.uid());

-- A user can update their own profile; admins can update anyone's
create policy "users update own profile, admins update any"
  on public.profiles for update
  to authenticated
  using (
    id = auth.uid()
    or exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin')
  );

-- 2. Availability: away dates per person per month
create table public.availability (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(id) on delete cascade,
  month_id text not null,
  away_dates text[] not null default '{}',
  submitted_at timestamptz not null default now(),
  unique (profile_id, month_id)
);

alter table public.availability enable row level security;

-- Team-wide read access (away dates visible to everyone, per requirements)
create policy "availability is readable by any signed-in user"
  on public.availability for select
  to authenticated
  using (true);

-- A user can only write their own availability
create policy "users manage their own availability"
  on public.availability for insert
  to authenticated
  with check (profile_id = auth.uid());

create policy "users update their own availability"
  on public.availability for update
  to authenticated
  using (profile_id = auth.uid());

-- 3. Roster: generated assignments per month per campus
create table public.roster (
  id text primary key, -- e.g. '2026-09_EM'
  month_id text not null,
  campus text not null check (campus in ('EM', 'GW')),
  assignments jsonb not null default '{}',
  flags jsonb not null default '{}',
  generated_at timestamptz not null default now(),
  generated_by uuid references public.profiles(id)
);

alter table public.roster enable row level security;

-- Readable by any signed-in user
create policy "roster is readable by any signed-in user"
  on public.roster for select
  to authenticated
  using (true);

-- Only admins can write (insert/update) the roster
create policy "only admins can insert roster"
  on public.roster for insert
  to authenticated
  with check (
    exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin')
  );

create policy "only admins can update roster"
  on public.roster for update
  to authenticated
  using (
    exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin')
  );

-- Explicit grants: RLS policies only take effect once the role has the
-- underlying table privilege. Supabase normally sets this up automatically,
-- but run this if you hit "permission denied for table X" despite RLS
-- policies looking correct.
grant usage on schema public to authenticated, anon;
grant select, insert, update, delete on public.profiles to authenticated;
grant select, insert, update, delete on public.availability to authenticated;
grant select, insert, update, delete on public.roster to authenticated;

-- service_role must also have explicit grants for admin scripts (e.g. bulk import)
-- that use the Supabase Admin API / service role key. service_role normally
-- bypasses RLS, but still needs the underlying table privilege.
grant usage on schema public to service_role;
grant select, insert, update, delete on public.profiles to service_role;
grant select, insert, update, delete on public.availability to service_role;
grant select, insert, update, delete on public.roster to service_role;
