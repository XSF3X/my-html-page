-- Consolidated schema for Account Vault (username/password only)
create extension if not exists pgcrypto;
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated, service_role;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text,
  phone text,
  display_name text not null default '',
  role text not null default 'member' check (role in ('member', 'admin')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists profiles_username_lower_uidx
  on public.profiles (lower(username)) where username is not null;

create table if not exists public.cards (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  payload_cipher text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint cards_payload_size check (char_length(payload_cipher) <= 250000)
);
create index if not exists cards_user_updated_idx on public.cards(user_id, updated_at desc);

alter table public.profiles enable row level security;
alter table public.cards enable row level security;
revoke all on public.profiles from anon, authenticated;
revoke all on public.cards from anon, authenticated;
grant select (id, username, phone, display_name, role, created_at, updated_at) on public.profiles to authenticated;
grant update (display_name, updated_at) on public.profiles to authenticated;
grant select, insert, update, delete on public.cards to authenticated;

create or replace function private.is_admin()
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'admin'
  );
$$;
revoke all on function private.is_admin() from public;
grant execute on function private.is_admin() to authenticated;

create or replace function private.handle_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare
  v_username text;
begin
  v_username := nullif(lower(new.raw_user_meta_data ->> 'username'), '');
  if v_username is null or v_username !~ '^[a-z0-9][a-z0-9._-]{2,29}$' then
    raise exception 'User accounts must be created by the vault administrator';
  end if;
  insert into public.profiles (id, phone, username, display_name, role)
  values (new.id, new.phone, v_username, coalesce(new.raw_user_meta_data ->> 'display_name', ''), 'member')
  on conflict (id) do update set
    phone = excluded.phone,
    username = coalesce(public.profiles.username, excluded.username),
    display_name = case when public.profiles.display_name = '' then excluded.display_name else public.profiles.display_name end;
  return new;
end;
$$;
revoke all on function private.handle_new_user() from public;

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile
after insert on auth.users for each row execute function private.handle_new_user();

create table if not exists private.admin_setup_gate (
  id integer primary key check (id = 1),
  state text not null check (state in ('not_started', 'in_progress', 'complete')),
  updated_at timestamptz not null default now()
);
insert into private.admin_setup_gate(id, state) values (1, 'not_started')
on conflict (id) do nothing;
revoke all on private.admin_setup_gate from public, anon, authenticated;

create or replace function public.claim_admin_setup()
returns boolean language plpgsql security definer set search_path = ''
as $$
begin
  update private.admin_setup_gate
  set state='in_progress', updated_at=now()
  where id=1 and state='not_started'
    and not exists (select 1 from public.profiles where role='admin');
  return found;
end;
$$;
create or replace function public.finish_admin_setup()
returns boolean language plpgsql security definer set search_path = ''
as $$
begin
  update private.admin_setup_gate
  set state='complete', updated_at=now()
  where id=1 and state='in_progress'
    and exists (select 1 from public.profiles where role='admin');
  return found;
end;
$$;
create or replace function public.release_admin_setup()
returns boolean language plpgsql security definer set search_path = ''
as $$
begin
  update private.admin_setup_gate
  set state='not_started', updated_at=now()
  where id=1 and state='in_progress'
    and not exists (select 1 from public.profiles where role='admin');
  return found;
end;
$$;
revoke all on function public.claim_admin_setup() from public, anon, authenticated;
revoke all on function public.finish_admin_setup() from public, anon, authenticated;
revoke all on function public.release_admin_setup() from public, anon, authenticated;
grant execute on function public.claim_admin_setup() to service_role;
grant execute on function public.finish_admin_setup() to service_role;
grant execute on function public.release_admin_setup() to service_role;

drop policy if exists profiles_select_self_or_admin on public.profiles;
create policy profiles_select_self_or_admin on public.profiles for select to authenticated
using ((id = (select auth.uid())) or (select private.is_admin()));
drop policy if exists profiles_update_display_name_self on public.profiles;
create policy profiles_update_display_name_self on public.profiles for update to authenticated
using (id = (select auth.uid())) with check (id = (select auth.uid()));
drop policy if exists cards_select_owner on public.cards;
create policy cards_select_owner on public.cards for select to authenticated
using (user_id = (select auth.uid()));
drop policy if exists cards_insert_owner on public.cards;
create policy cards_insert_owner on public.cards for insert to authenticated
with check (user_id = (select auth.uid()));
drop policy if exists cards_update_owner on public.cards;
create policy cards_update_owner on public.cards for update to authenticated
using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
drop policy if exists cards_delete_owner on public.cards;
create policy cards_delete_owner on public.cards for delete to authenticated
using (user_id = (select auth.uid()));
