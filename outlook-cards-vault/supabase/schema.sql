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
as $fn$
 select exists (select 1 from public.profiles p where p.id=(select auth.uid()) and p.role='admin');
$fn$;
revoke all on function private.is_admin() from public;
grant execute on function private.is_admin() to authenticated;

create table if not exists private.user_create_permits (
  username text primary key,
  token_hash text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
revoke all on private.user_create_permits from public, anon, authenticated;

create table if not exists private.admin_setup_gate (
  id integer primary key check (id = 1),
  state text not null check (state in ('not_started', 'in_progress', 'complete')),
  secret_hash text,
  updated_at timestamptz not null default now()
);
insert into private.admin_setup_gate(id, state, secret_hash)
values (1, 'not_started', '014fd4854fbd644fa9bbd8f63c0439ac39b77102d7a188cd892fef0576e50ced')
on conflict (id) do nothing;
revoke all on private.admin_setup_gate from public, anon, authenticated;

create or replace function public.claim_admin_setup(p_secret_hash text)
returns boolean language plpgsql security definer set search_path = ''
as $fn$
begin
 update private.admin_setup_gate set state='in_progress', updated_at=now()
 where id=1 and state='not_started' and secret_hash=p_secret_hash
 and not exists (select 1 from public.profiles where role='admin');
 return found;
end;
$fn$;
create or replace function public.finish_admin_setup()
returns boolean language plpgsql security definer set search_path = ''
as $fn$
begin
 update private.admin_setup_gate set state='complete', secret_hash=null, updated_at=now()
 where id=1 and state='in_progress'
 and exists (select 1 from public.profiles where role='admin');
 return found;
end;
$fn$;
create or replace function public.release_admin_setup()
returns boolean language plpgsql security definer set search_path = ''
as $fn$
begin
 update private.admin_setup_gate set state='not_started', updated_at=now()
 where id=1 and state='in_progress'
 and not exists (select 1 from public.profiles where role='admin');
 return found;
end;
$fn$;

create or replace function public.issue_user_create_permit(p_username text, p_token_hash text)
returns boolean language plpgsql security definer set search_path = ''
as $fn$
begin
 if p_username !~ '^[a-z0-9][a-z0-9._-]{2,29}$' or p_token_hash !~ '^[0-9a-f]{64}$' then return false; end if;
 delete from private.user_create_permits where expires_at <= now();
 insert into private.user_create_permits(username, token_hash, expires_at)
 values (p_username, p_token_hash, now() + interval '5 minutes')
 on conflict (username) do update set token_hash=excluded.token_hash, expires_at=excluded.expires_at, created_at=now();
 return true;
end;
$fn$;
create or replace function public.release_user_create_permit(p_username text, p_token_hash text)
returns boolean language plpgsql security definer set search_path = ''
as $fn$
begin
 delete from private.user_create_permits where username=p_username and token_hash=p_token_hash;
 return found;
end;
$fn$;

revoke all on function public.claim_admin_setup(text) from public, anon, authenticated;
revoke all on function public.finish_admin_setup() from public, anon, authenticated;
revoke all on function public.release_admin_setup() from public, anon, authenticated;
revoke all on function public.issue_user_create_permit(text,text) from public, anon, authenticated;
revoke all on function public.release_user_create_permit(text,text) from public, anon, authenticated;
grant execute on function public.claim_admin_setup(text) to service_role;
grant execute on function public.finish_admin_setup() to service_role;
grant execute on function public.release_admin_setup() to service_role;
grant execute on function public.issue_user_create_permit(text,text) to service_role;
grant execute on function public.release_user_create_permit(text,text) to service_role;

create or replace function private.handle_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $fn$
declare
 v_username text;
 v_token text;
 v_token_hash text;
 v_permitted text;
begin
 v_username := nullif(lower(new.raw_user_meta_data ->> 'username'), '');
 v_token := coalesce(new.raw_user_meta_data ->> 'provision_token', '');
 if v_username is null or v_username !~ '^[a-z0-9][a-z0-9._-]{2,29}$' then
   raise exception 'User accounts must be created by the vault administrator';
 end if;
 if length(v_token) < 32 then raise exception 'User creation must be authorized by the vault administrator'; end if;
 v_token_hash := encode(public.digest(v_token, 'sha256'), 'hex');
 delete from private.user_create_permits
 where username=v_username and token_hash=v_token_hash and expires_at > now()
 returning username into v_permitted;
 if v_permitted is null then raise exception 'User creation permit is missing, expired, or invalid'; end if;
 insert into public.profiles (id, phone, username, display_name, role)
 values (new.id, null, v_username, coalesce(new.raw_user_meta_data ->> 'display_name', ''), 'member')
 on conflict (id) do update set
  username=coalesce(public.profiles.username,excluded.username),
  display_name=case when public.profiles.display_name='' then excluded.display_name else public.profiles.display_name end;
 return new;
end;
$fn$;
revoke all on function private.handle_new_user() from public;
drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile after insert on auth.users
for each row execute function private.handle_new_user();

drop policy if exists profiles_select_self_or_admin on public.profiles;
create policy profiles_select_self_or_admin on public.profiles for select to authenticated
using ((id=(select auth.uid())) or (select private.is_admin()));
drop policy if exists profiles_update_display_name_self on public.profiles;
create policy profiles_update_display_name_self on public.profiles for update to authenticated
using (id=(select auth.uid())) with check (id=(select auth.uid()));
drop policy if exists cards_select_owner on public.cards;
create policy cards_select_owner on public.cards for select to authenticated
using (user_id=(select auth.uid()));
drop policy if exists cards_insert_owner on public.cards;
create policy cards_insert_owner on public.cards for insert to authenticated
with check (user_id=(select auth.uid()));
drop policy if exists cards_update_owner on public.cards;
create policy cards_update_owner on public.cards for update to authenticated
using (user_id=(select auth.uid())) with check (user_id=(select auth.uid()));
drop policy if exists cards_delete_owner on public.cards;
create policy cards_delete_owner on public.cards for delete to authenticated
using (user_id=(select auth.uid()));
