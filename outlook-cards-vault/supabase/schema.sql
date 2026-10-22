-- خزنة الحسابات متعددة المستخدمين
create extension if not exists pgcrypto;
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;
create table if not exists public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 phone text,
 display_name text not null default '',
 role text not null default 'member' check (role in ('member','admin')),
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create table if not exists public.cards (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references auth.users(id) on delete cascade,
 payload_cipher text not null,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 constraint cards_payload_size check (char_length(payload_cipher) <= 250000)
);
create index if not exists cards_user_updated_idx on public.cards(user_id,updated_at desc);
alter table public.profiles enable row level security;
alter table public.cards enable row level security;
revoke all on public.profiles from anon, authenticated;
revoke all on public.cards from anon, authenticated;
grant select (id,phone,display_name,role,created_at,updated_at) on public.profiles to authenticated;
grant update (display_name,updated_at) on public.profiles to authenticated;
grant select,insert,update,delete on public.cards to authenticated;
create or replace function private.is_admin() returns boolean language sql stable security definer set search_path = '' as $$
 select exists(select 1 from public.profiles p where p.id=(select auth.uid()) and p.role='admin');
$$;
revoke all on function private.is_admin() from public;
grant execute on function private.is_admin() to authenticated;
create or replace function private.handle_new_user() returns trigger language plpgsql security definer set search_path = '' as $$
begin
 insert into public.profiles(id,phone,display_name,role) values(new.id,new.phone,coalesce(new.raw_user_meta_data->>'display_name',''),'member')
 on conflict(id) do update set phone=excluded.phone;
 return new;
end;
$$;
revoke all on function private.handle_new_user() from public;
drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile after insert on auth.users for each row execute function private.handle_new_user();
drop policy if exists profiles_select_self_or_admin on public.profiles;
create policy profiles_select_self_or_admin on public.profiles for select to authenticated using ((id=(select auth.uid())) or (select private.is_admin()));
drop policy if exists profiles_update_display_name_self on public.profiles;
create policy profiles_update_display_name_self on public.profiles for update to authenticated using (id=(select auth.uid())) with check (id=(select auth.uid()));
drop policy if exists cards_select_owner on public.cards;
create policy cards_select_owner on public.cards for select to authenticated using (user_id=(select auth.uid()));
drop policy if exists cards_insert_owner on public.cards;
create policy cards_insert_owner on public.cards for insert to authenticated with check (user_id=(select auth.uid()));
drop policy if exists cards_update_owner on public.cards;
create policy cards_update_owner on public.cards for update to authenticated using (user_id=(select auth.uid())) with check (user_id=(select auth.uid()));
drop policy if exists cards_delete_owner on public.cards;
create policy cards_delete_owner on public.cards for delete to authenticated using (user_id=(select auth.uid()));
