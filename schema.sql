-- Zge : à exécuter dans Supabase > SQL Editor
-- Réglage requis : Authentication > Providers > Email > désactiver "Confirm email"
--
-- Si tu as déjà exécuté la première version, lance d'abord ceci :
--   drop table if exists notices, messages, key_offers, chats, profiles cascade;

create table profiles (
  id  text primary key check (id ~ '^[0-9]{9}$'),
  uid uuid not null unique references auth.users(id) on delete cascade,
  pub jsonb not null
);

create table chats (
  id      text primary key check (id ~ '^[0-9a-f]{64}$'),
  members text[] not null check (array_length(members, 1) between 2 and 21)
);

-- clé de conversation chiffrée, supprimée dès que le receveur l'a récupérée
create table key_offers (
  chat_id text not null references chats(id) on delete cascade,
  to_id   text not null,
  from_id text not null,
  iv      text not null,
  data    text not null check (length(data) < 1000),
  primary key (chat_id, to_id)
);

-- messages et morceaux de fichiers chiffrés, supprimés dès que le receveur les a récupérés
create table messages (
  id         bigint generated always as identity primary key,
  chat_id    text not null references chats(id) on delete cascade,
  from_id    text not null,
  to_id      text not null,
  iv         text not null,
  data       text not null,
  fid        text check (fid ~ '^[0-9a-f]{16}$'),
  idx        int,
  n          int,
  created_at timestamptz not null default now(),
  check ((fid is null and length(data) < 20000) or (fid is not null and length(data) < 800000))
);
create index on messages (to_id);

-- ordres de nettoyage pour les autres appareils (supprimés dès qu'ils sont lus)
create table notices (
  id         bigint generated always as identity primary key,
  to_id      text not null,
  chat_id    text not null,
  kind       text not null check (kind in ('clear', 'del', 'purge')),
  who        text,
  created_at timestamptz not null default now()
);
create index on notices (to_id);

create function public.me() returns text
language sql stable security definer set search_path = public as
$$ select id from profiles where uid = auth.uid() $$;

alter table profiles   enable row level security;
alter table chats      enable row level security;
alter table key_offers enable row level security;
alter table messages   enable row level security;
alter table notices    enable row level security;

create policy p_sel on profiles for select to authenticated using (true);
create policy p_ins on profiles for insert to authenticated with check (uid = auth.uid());
create policy p_upd on profiles for update to authenticated using (uid = auth.uid()) with check (uid = auth.uid());

create policy c_sel on chats for select to authenticated using (me() = any(members));
create policy c_ins on chats for insert to authenticated with check (me() = any(members));

create policy k_sel on key_offers for select to authenticated using (to_id = me());
create policy k_del on key_offers for delete to authenticated using (to_id = me());
create policy k_ins on key_offers for insert to authenticated with check (
  from_id = me() and exists (
    select 1 from chats c where c.id = chat_id and me() = any(c.members) and to_id = any(c.members)
  )
);

create policy m_sel on messages for select to authenticated using (to_id = me());
create policy m_del on messages for delete to authenticated using (to_id = me());
create policy m_ins on messages for insert to authenticated with check (
  from_id = me() and exists (
    select 1 from chats c where c.id = chat_id and me() = any(c.members) and to_id = any(c.members)
  )
);

create policy n_sel on notices for select to authenticated using (to_id = me());
create policy n_del on notices for delete to authenticated using (to_id = me());

-- quitter / supprimer une discussion (fonction interne)
create function public._leave(p_chat text, p_me text) returns void
language plpgsql security definer set search_path = public as $$
declare m text[]; o text;
begin
  select members into m from chats where id = p_chat;
  if m is null or not (p_me = any(m)) then return; end if;
  m := array_remove(m, p_me);
  delete from messages   where chat_id = p_chat and (to_id = p_me or from_id = p_me);
  delete from key_offers where chat_id = p_chat and to_id = p_me;
  if coalesce(array_length(m, 1), 0) < 2 then
    -- discussion à deux (ou groupe réduit à une personne) : tout disparaît chez l'autre
    foreach o in array m loop
      insert into notices (to_id, chat_id, kind) values (o, p_chat, 'del');
    end loop;
    delete from chats where id = p_chat;
  else
    -- groupe : la personne part, ses messages sont retirés chez les autres
    update chats set members = m where id = p_chat;
    foreach o in array m loop
      insert into notices (to_id, chat_id, kind, who) values (o, p_chat, 'purge', p_me);
    end loop;
  end if;
end $$;

create function public.leave_chat(p_chat text) returns void
language sql security definer set search_path = public as
$$ select public._leave(p_chat, public.me()) $$;

-- vider une discussion pour tout le monde
create function public.clear_chat(p_chat text) returns void
language plpgsql security definer set search_path = public as $$
declare m text[]; o text; v text := public.me();
begin
  select members into m from chats where id = p_chat;
  if m is null or v is null or not (v = any(m)) then return; end if;
  delete from messages where chat_id = p_chat;
  foreach o in array m loop
    if o <> v then
      insert into notices (to_id, chat_id, kind) values (o, p_chat, 'clear');
    end if;
  end loop;
end $$;

-- supprimer son compte
create function public.delete_account() returns void
language plpgsql security definer set search_path = public, auth as $$
declare v text := public.me(); c text;
begin
  if v is null then return; end if;
  for c in select id from chats where v = any(members) loop
    perform public._leave(c, v);
  end loop;
  delete from messages where from_id = v or to_id = v;
  delete from notices  where to_id = v;
  delete from auth.users where id = auth.uid();
end $$;

revoke all on function public._leave(text, text) from public, anon, authenticated;
revoke all on function public.leave_chat(text)   from public, anon;
revoke all on function public.clear_chat(text)   from public, anon;
revoke all on function public.delete_account()   from public, anon;
grant execute on function public.leave_chat(text)   to authenticated;
grant execute on function public.clear_chat(text)   to authenticated;
grant execute on function public.delete_account()   to authenticated;

alter publication supabase_realtime add table messages, key_offers, chats, notices;
