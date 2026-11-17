-- Zge : à exécuter dans Supabase > SQL Editor
-- Peut être relancé autant de fois que nécessaire (aucune donnée n'est supprimée).
-- Réglage requis : Authentication > Providers > Email > désactiver "Confirm email"
-- (Si Supabase demande confirmation pour "drop policy", c'est normal : les règles sont recréées juste après.)

/* ---------- tables ---------- */

create table if not exists profiles (
  id  text primary key,
  uid uuid not null unique references auth.users(id) on delete cascade,
  pub jsonb not null
);

create table if not exists chats (
  id      text primary key,
  members text[] not null
);

create table if not exists key_offers (
  chat_id text not null references chats(id) on delete cascade,
  to_id   text not null,
  from_id text not null,
  iv      text not null,
  data    text not null,
  primary key (chat_id, to_id)
);

create table if not exists messages (
  id         bigint generated always as identity primary key,
  chat_id    text not null references chats(id) on delete cascade,
  from_id    text not null,
  to_id      text not null,
  iv         text not null,
  data       text not null,
  created_at timestamptz not null default now()
);

create table if not exists notices (
  id         bigint generated always as identity primary key,
  to_id      text not null,
  chat_id    text not null,
  kind       text not null,
  who        text,
  created_at timestamptz not null default now()
);

-- colonnes ajoutées par la 2e version (sans effet si déjà là)
alter table messages add column if not exists fid text;
alter table messages add column if not exists idx int;
alter table messages add column if not exists n   int;

/* ---------- contraintes (anciennes versions retirées, puis recréées) ---------- */

alter table profiles drop constraint if exists profiles_id_check;
alter table profiles drop constraint if exists profiles_id_fmt;
alter table profiles add  constraint profiles_id_fmt check (id ~ '^[0-9]{9}$');

alter table chats drop constraint if exists chats_id_check;
alter table chats drop constraint if exists chats_id_fmt;
alter table chats drop constraint if exists chats_members_check;
alter table chats drop constraint if exists chats_members_size;
alter table chats add  constraint chats_id_fmt      check (id ~ '^[0-9a-f]{64}$');
alter table chats add  constraint chats_members_size check (array_length(members, 1) between 2 and 21);

alter table key_offers drop constraint if exists key_offers_data_check;
alter table key_offers drop constraint if exists key_offers_data_len;
alter table key_offers add  constraint key_offers_data_len check (length(data) < 1000);

alter table messages drop constraint if exists messages_data_check;
alter table messages drop constraint if exists messages_check;
alter table messages drop constraint if exists messages_fid_check;
alter table messages drop constraint if exists messages_data_len;
alter table messages drop constraint if exists messages_fid_fmt;
alter table messages add  constraint messages_fid_fmt  check (fid is null or fid ~ '^[0-9a-f]{16}$');
alter table messages add  constraint messages_data_len check (
  (fid is null and length(data) < 20000) or (fid is not null and length(data) < 800000)
);

alter table notices drop constraint if exists notices_kind_check;
alter table notices drop constraint if exists notices_kind_fmt;
alter table notices add  constraint notices_kind_fmt check (kind in ('clear', 'del', 'purge'));

create index if not exists messages_to_id_idx on messages (to_id);
create index if not exists notices_to_id_idx  on notices (to_id);

/* ---------- identité ---------- */

create or replace function public.me() returns text
language sql stable security definer set search_path = public as
$$ select id from public.profiles where uid = auth.uid() $$;

/* ---------- règles d'accès ---------- */

alter table profiles   enable row level security;
alter table chats      enable row level security;
alter table key_offers enable row level security;
alter table messages   enable row level security;
alter table notices    enable row level security;

drop policy if exists p_sel on profiles;
drop policy if exists p_ins on profiles;
drop policy if exists p_upd on profiles;
create policy p_sel on profiles for select to authenticated using (true);
create policy p_ins on profiles for insert to authenticated with check (uid = auth.uid());
create policy p_upd on profiles for update to authenticated using (uid = auth.uid()) with check (uid = auth.uid());

drop policy if exists c_sel on chats;
drop policy if exists c_ins on chats;
create policy c_sel on chats for select to authenticated using (public.me() = any(members));
create policy c_ins on chats for insert to authenticated with check (public.me() = any(members));

drop policy if exists k_sel on key_offers;
drop policy if exists k_del on key_offers;
drop policy if exists k_ins on key_offers;
create policy k_sel on key_offers for select to authenticated using (to_id = public.me());
create policy k_del on key_offers for delete to authenticated using (to_id = public.me());
create policy k_ins on key_offers for insert to authenticated with check (
  from_id = public.me() and exists (
    select 1 from public.chats c
    where c.id = key_offers.chat_id and public.me() = any(c.members) and key_offers.to_id = any(c.members)
  )
);

drop policy if exists m_sel on messages;
drop policy if exists m_del on messages;
drop policy if exists m_ins on messages;
create policy m_sel on messages for select to authenticated using (to_id = public.me());
create policy m_del on messages for delete to authenticated using (to_id = public.me());
create policy m_ins on messages for insert to authenticated with check (
  from_id = public.me() and exists (
    select 1 from public.chats c
    where c.id = messages.chat_id and public.me() = any(c.members) and messages.to_id = any(c.members)
  )
);

drop policy if exists n_sel on notices;
drop policy if exists n_del on notices;
create policy n_sel on notices for select to authenticated using (to_id = public.me());
create policy n_del on notices for delete to authenticated using (to_id = public.me());

/* ---------- quitter / supprimer / vider / supprimer le compte ---------- */

create or replace function public._leave(p_chat text, p_me text) returns void
language plpgsql security definer set search_path = public as $$
declare
  mem text[];
  o   text;
begin
  select c.members into mem from public.chats c where c.id = p_chat;
  if mem is null or not (p_me = any(mem)) then
    return;
  end if;
  mem := array_remove(mem, p_me);

  delete from public.messages   where chat_id = p_chat and (to_id = p_me or from_id = p_me);
  delete from public.key_offers where chat_id = p_chat and to_id = p_me;

  if coalesce(array_length(mem, 1), 0) < 2 then
    -- discussion à deux (ou groupe réduit à une personne) : tout disparaît chez l'autre
    foreach o in array mem loop
      insert into public.notices (to_id, chat_id, kind) values (o, p_chat, 'del');
    end loop;
    delete from public.chats where id = p_chat;
  else
    -- groupe : la personne part, ses messages sont retirés chez les autres
    update public.chats set members = mem where id = p_chat;
    foreach o in array mem loop
      insert into public.notices (to_id, chat_id, kind, who) values (o, p_chat, 'purge', p_me);
    end loop;
  end if;
end $$;

create or replace function public.leave_chat(p_chat text) returns void
language plpgsql security definer set search_path = public as $$
begin
  perform public._leave(p_chat, public.me());
end $$;

create or replace function public.clear_chat(p_chat text) returns void
language plpgsql security definer set search_path = public as $$
declare
  mem text[];
  o   text;
  v   text := public.me();
begin
  select c.members into mem from public.chats c where c.id = p_chat;
  if mem is null or v is null or not (v = any(mem)) then
    return;
  end if;
  delete from public.messages where chat_id = p_chat;
  foreach o in array mem loop
    if o <> v then
      insert into public.notices (to_id, chat_id, kind) values (o, p_chat, 'clear');
    end if;
  end loop;
end $$;

create or replace function public.delete_account() returns void
language plpgsql security definer set search_path = public, auth as $$
declare
  v text := public.me();
  c text;
begin
  if v is null then
    return;
  end if;
  for c in select ch.id from public.chats ch where v = any(ch.members) loop
    perform public._leave(c, v);
  end loop;
  delete from public.messages where from_id = v or to_id = v;
  delete from public.notices  where to_id = v;
  delete from auth.users where id = auth.uid();
end $$;

revoke all on function public._leave(text, text) from public, anon, authenticated;
revoke all on function public.leave_chat(text)   from public, anon;
revoke all on function public.clear_chat(text)   from public, anon;
revoke all on function public.delete_account()   from public, anon;
grant execute on function public.leave_chat(text)   to authenticated;
grant execute on function public.clear_chat(text)   to authenticated;
grant execute on function public.delete_account()   to authenticated;

/* ---------- temps réel (ajoute chaque table seulement si elle n'y est pas déjà) ---------- */

do $$
declare t text;
begin
  foreach t in array array['messages', 'key_offers', 'chats', 'notices'] loop
    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t
    ) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;
