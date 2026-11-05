-- =====================================================================
-- Mantenimiento Opticalia · Contraseñas de primer uso y recuperación
-- Ejecutar UNA vez en Supabase → SQL Editor → New query → Run.
-- Es seguro volver a ejecutarlo.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- 1. Contraseña de primer uso -----------------------------------------
alter table public.perfiles add column if not exists debe_cambiar boolean not null default true;
-- Las contraseñas actuales quedan como "de primer uso" para ambos usuarios:
update public.perfiles set debe_cambiar = true;

create or replace function public.fn_es_biomedico() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.perfiles where user_id = auth.uid() and rol = 'biomedico');
$$;

-- Cambia la contraseña del usuario que tiene la sesión abierta.
-- Biomédicos: siempre. Opticalia: solo cuando debe cambiarla (primer ingreso).
create or replace function public.cambiar_mi_clave(nueva text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare p public.perfiles;
begin
  if auth.uid() is null then raise exception 'Debes iniciar sesión.'; end if;
  select * into p from public.perfiles where user_id = auth.uid();
  if p is null then raise exception 'Usuario sin perfil.'; end if;
  if p.rol <> 'biomedico' and not p.debe_cambiar then
    raise exception 'Solo el usuario Biomédicos puede cambiar la contraseña desde la aplicación.';
  end if;
  if length(coalesce(nueva,'')) < 8 then raise exception 'La contraseña debe tener al menos 8 caracteres.'; end if;
  update auth.users set encrypted_password = crypt(nueva, gen_salt('bf')), updated_at = now() where id = auth.uid();
  update public.perfiles set debe_cambiar = false where user_id = auth.uid();
end $$;

-- 2. Solicitudes de recuperación (Opticalia → aprobación de Biomédicos)
create table if not exists public.solicitudes_clave(
  id uuid primary key default gen_random_uuid(),
  usuario text not null default 'opticalia',
  nota text,
  estado text not null default 'pendiente' check (estado in ('pendiente','aprobada','rechazada','reemplazada')),
  creado_en timestamptz not null default now(),
  resuelto_en timestamptz,
  resuelto_por uuid
);
-- La contraseña propuesta se guarda cifrada en una tabla que nadie puede leer desde la app.
create table if not exists public.solicitudes_clave_hash(
  solicitud_id uuid primary key references public.solicitudes_clave(id) on delete cascade,
  clave_hash text not null
);
alter table public.solicitudes_clave enable row level security;
alter table public.solicitudes_clave_hash enable row level security;
drop policy if exists "biomedico lee solicitudes" on public.solicitudes_clave;
create policy "biomedico lee solicitudes" on public.solicitudes_clave
  for select to authenticated using (public.fn_es_biomedico());

-- Opticalia (sin sesión) pide recuperar la contraseña y propone la nueva.
create or replace function public.solicitar_recuperacion(nueva text, nota text default null) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare nid uuid;
begin
  if length(coalesce(nueva,'')) < 8 then raise exception 'La contraseña debe tener al menos 8 caracteres.'; end if;
  if (select count(*) from public.solicitudes_clave where creado_en > now() - interval '1 day') >= 10 then
    raise exception 'Se alcanzó el límite de solicitudes por hoy. Comunícate con Biomédicos.';
  end if;
  update public.solicitudes_clave set estado = 'reemplazada', resuelto_en = now()
    where usuario = 'opticalia' and estado = 'pendiente';
  delete from public.solicitudes_clave_hash h using public.solicitudes_clave s
    where h.solicitud_id = s.id and s.estado <> 'pendiente';
  insert into public.solicitudes_clave(usuario, nota) values ('opticalia', left(nota, 300)) returning id into nid;
  insert into public.solicitudes_clave_hash(solicitud_id, clave_hash) values (nid, crypt(nueva, gen_salt('bf')));
  return nid;
end $$;

-- Consulta del estado de una solicitud (pantalla de ingreso).
create or replace function public.estado_solicitud(sid uuid) returns text
language sql stable security definer set search_path = public as $$
  select estado from public.solicitudes_clave where id = sid;
$$;

-- Biomédicos aprueba o rechaza.
create or replace function public.resolver_solicitud(sid uuid, aprobar boolean) returns void
language plpgsql security definer set search_path = public as $$
declare s public.solicitudes_clave; h text; uid uuid;
begin
  if not public.fn_es_biomedico() then raise exception 'Solo el usuario Biomédicos puede aprobar solicitudes.'; end if;
  select * into s from public.solicitudes_clave where id = sid for update;
  if s is null or s.estado <> 'pendiente' then raise exception 'La solicitud ya no está pendiente.'; end if;
  if aprobar then
    select clave_hash into h from public.solicitudes_clave_hash where solicitud_id = sid;
    select user_id into uid from public.perfiles where rol = 'opticalia' limit 1;
    if h is null or uid is null then raise exception 'No se encontró el usuario Opticalia.'; end if;
    update auth.users set encrypted_password = h, updated_at = now() where id = uid;
    update public.perfiles set debe_cambiar = false where user_id = uid;
  end if;
  update public.solicitudes_clave set estado = case when aprobar then 'aprobada' else 'rechazada' end,
    resuelto_en = now(), resuelto_por = auth.uid() where id = sid;
  delete from public.solicitudes_clave_hash where solicitud_id = sid;
end $$;

-- 3. Permisos -----------------------------------------------------------
revoke all on function public.cambiar_mi_clave(text) from public, anon;
revoke all on function public.resolver_solicitud(uuid, boolean) from public, anon;
grant execute on function public.cambiar_mi_clave(text) to authenticated;
grant execute on function public.resolver_solicitud(uuid, boolean) to authenticated;
grant execute on function public.solicitar_recuperacion(text, text) to anon, authenticated;
grant execute on function public.estado_solicitud(uuid) to anon, authenticated;
grant execute on function public.fn_es_biomedico() to authenticated;

-- 4. Notificación en tiempo real para Biomédicos ------------------------
do $$ begin
  alter publication supabase_realtime add table public.solicitudes_clave;
exception when duplicate_object then null; end $$;
