-- =====================================================================
-- Mantenimiento Opticalia · INSTALACIÓN COMPLETA en un proyecto Supabase nuevo
--
-- ANTES de ejecutarlo crea los dos usuarios en Authentication → Users → Add user
-- (marca "Auto Confirm User"):
--     biomedicos@opticalia.local   · contraseña de primer uso que tú elijas
--     opticalia@opticalia.local    · contraseña de primer uso que tú elijas
-- Luego: SQL Editor → New query → pega todo este archivo → Run.
-- Es seguro volver a ejecutarlo.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- 1. Tablas -------------------------------------------------------------
create table if not exists public.perfiles(
  user_id uuid primary key references auth.users(id) on delete cascade,
  rol text not null check (rol in ('biomedico','opticalia')),
  nombre text not null,
  debe_cambiar boolean not null default true
);

create table if not exists public.equipos(
  id uuid primary key default gen_random_uuid(),
  n integer not null unique,
  equipo text not null,
  tipo text not null default 'generico',
  marca text not null default 'NO REGISTRA',
  modelo text not null default 'NO REGISTRA',
  serie text not null default 'NO REGISTRA',
  ubicacion text not null default 'NO REGISTRA',
  codigo text default '-',
  creado_en timestamptz not null default now(),
  actualizado_en timestamptz not null default now()
);
do $$ begin
  alter table public.equipos add constraint equipos_n_key unique (n);
exception when duplicate_table or duplicate_object then null; end $$;

create table if not exists public.config(
  id integer primary key default 1 check (id = 1),
  datos jsonb not null default '{}'::jsonb,
  actualizado_en timestamptz not null default now()
);

create table if not exists public.protocolos(
  id uuid primary key default gen_random_uuid(),
  equipo_id uuid not null references public.equipos(id) on delete cascade,
  equipo_snapshot jsonb,
  num_mtto text,
  fecha date,
  datos jsonb not null default '{}'::jsonb,
  estado text not null default 'borrador' check (estado in ('borrador','pendiente','aprobado')),
  recibe_nombre text,
  recibe_cargo text,
  firma_recibe text,
  aprobado_en timestamptz,
  creado_en timestamptz not null default now(),
  actualizado_en timestamptz not null default now()
);

create table if not exists public.hojas_vida(
  equipo_id uuid primary key references public.equipos(id) on delete cascade,
  datos jsonb not null default '{}'::jsonb,
  creado_en timestamptz not null default now(),
  actualizado_en timestamptz not null default now()
);

create table if not exists public.reportes_cargados(
  id uuid primary key default gen_random_uuid(),
  equipo_id uuid not null references public.equipos(id) on delete cascade,
  ruta text not null unique,
  nombre_archivo text,
  tamano bigint,
  fecha date,
  num_mtto text,
  tipo text,
  descripcion text,
  creado_en timestamptz not null default now()
);

create table if not exists public.documentos(
  id uuid primary key default gen_random_uuid(),
  categoria text not null,
  titulo text not null,
  descripcion text,
  ruta text not null unique,
  nombre_archivo text,
  tamano bigint,
  creado_en timestamptz not null default now()
);

create table if not exists public.documentos_semillas(
  clave text primary key,
  creado_en timestamptz not null default now()
);

-- 2. Fechas automáticas ---------------------------------------------------
create or replace function public.fn_tocar() returns trigger language plpgsql as $$
begin
  new.actualizado_en := now();
  if tg_table_name = 'protocolos' then
    if new.estado = 'aprobado' and (tg_op = 'INSERT' or old.estado is distinct from 'aprobado') then new.aprobado_en := now();
    elsif new.estado <> 'aprobado' then new.aprobado_en := null; end if;
  end if;
  return new;
end $$;
do $$ declare t text; begin
  foreach t in array array['equipos','config','protocolos','hojas_vida'] loop
    execute format('drop trigger if exists tocar on public.%I', t);
    execute format('create trigger tocar before insert or update on public.%I for each row execute function public.fn_tocar()', t);
  end loop;
end $$;

-- 3. Roles ------------------------------------------------------------------
create or replace function public.fn_es_biomedico() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.perfiles where user_id = auth.uid() and rol = 'biomedico');
$$;
grant execute on function public.fn_es_biomedico() to authenticated;

-- 4. Seguridad por filas (RLS) -----------------------------------------------
-- Ambos usuarios leen todo. Biomédicos escribe todo. Opticalia solo firma/aprueba protocolos.
do $$ declare t text; p record; begin
  foreach t in array array['perfiles','equipos','config','protocolos','hojas_vida','reportes_cargados','documentos','documentos_semillas'] loop
    execute format('alter table public.%I enable row level security', t);
    for p in select policyname from pg_policies where schemaname='public' and tablename=t loop
      execute format('drop policy %I on public.%I', p.policyname, t);
    end loop;
  end loop;
  foreach t in array array['equipos','config','protocolos','hojas_vida','reportes_cargados','documentos','documentos_semillas'] loop
    execute format('create policy leer on public.%I for select to authenticated using (true)', t);
    execute format('create policy bio_escribe on public.%I for all to authenticated using (public.fn_es_biomedico()) with check (public.fn_es_biomedico())', t);
  end loop;
end $$;
create policy leer_propio on public.perfiles for select to authenticated using (user_id = auth.uid() or public.fn_es_biomedico());
create policy opticalia_firma on public.protocolos for update to authenticated
  using (exists(select 1 from public.perfiles where user_id = auth.uid() and rol = 'opticalia') and estado in ('pendiente','aprobado'))
  with check (exists(select 1 from public.perfiles where user_id = auth.uid() and rol = 'opticalia'));

-- 5. Archivos (Storage) ---------------------------------------------------------
insert into storage.buckets (id, name, public) values ('reportes','reportes',false), ('documentos','documentos',false)
  on conflict (id) do nothing;
drop policy if exists "opt leer archivos" on storage.objects;
drop policy if exists "opt bio sube archivos" on storage.objects;
drop policy if exists "opt bio cambia archivos" on storage.objects;
drop policy if exists "opt bio borra archivos" on storage.objects;
create policy "opt leer archivos" on storage.objects for select to authenticated using (bucket_id in ('reportes','documentos'));
create policy "opt bio sube archivos" on storage.objects for insert to authenticated with check (bucket_id in ('reportes','documentos') and public.fn_es_biomedico());
create policy "opt bio cambia archivos" on storage.objects for update to authenticated using (bucket_id in ('reportes','documentos') and public.fn_es_biomedico());
create policy "opt bio borra archivos" on storage.objects for delete to authenticated using (bucket_id in ('reportes','documentos') and public.fn_es_biomedico());

-- 6. Tiempo real ------------------------------------------------------------------
do $$ declare t text; begin
  foreach t in array array['equipos','config','protocolos','hojas_vida','reportes_cargados','documentos'] loop
    begin execute format('alter publication supabase_realtime add table public.%I', t);
    exception when duplicate_object then null; end;
  end loop;
end $$;

-- 7. Usuarios: enlaza las cuentas creadas en Authentication con su rol ---------------
insert into public.perfiles(user_id, rol, nombre, debe_cambiar)
  select id, 'biomedico', 'Biomédicos', true from auth.users where email = 'biomedicos@opticalia.local'
  on conflict (user_id) do update set rol = excluded.rol;
insert into public.perfiles(user_id, rol, nombre, debe_cambiar)
  select id, 'opticalia', 'Opticalia', true from auth.users where email = 'opticalia@opticalia.local'
  on conflict (user_id) do update set rol = excluded.rol;
do $$ begin
  if (select count(*) from public.perfiles) < 2 then
    raise warning 'Falta crear uno de los usuarios en Authentication → Users. Créalo y vuelve a ejecutar este script.';
  end if;
end $$;

-- 8. Datos iniciales: configuración e inventario (tomado de los reportes 2025) ----------
insert into public.config(id, datos) values (1, '{}'::jsonb) on conflict (id) do nothing;
insert into public.equipos(id, n, equipo, tipo, marca, modelo, serie, ubicacion, codigo) values
  ('24f1c2f9-b11c-454b-a661-003830a0c79d', 1, 'AUTOQUERATOMETRO', 'autoref', 'VIEW-LIGTH', 'RK-11', 'K1PGB2I', 'CONSULTORIO #1', '-'),
  ('2967670c-7e2e-42d4-8efd-3f79525522fe', 2, 'AUTOQUERATOMETRO', 'tonometro', 'NIDEK', 'NT530', '230376', 'CONSULTORIO #1', '-'),
  ('cabec8cc-615b-4144-965c-15ba904045d7', 3, 'LAMPARA DE HENDIDURA', 'lampara', 'OPHTHALMIC SLIT LAMP', 'LS-4', '21201043025', 'CONSULTORIO #1', '-'),
  ('9220b9a2-77a2-4d59-8d24-e572fc60ab72', 4, 'FOROPTER', 'foroptero', 'ADLER', 'AMR 5000', 'AMR20M09N19', 'CONSULTORIO #1', '-'),
  ('22e9b0cf-e366-400d-b42b-fe18d3bf5806', 5, 'UNIDAD OFTALMOLOGICA', 'unidad', 'ADLER', 'NO REGISTRA', 'NO REGISTRA', 'CONSULTORIO #1', '-'),
  ('eb72cae9-d33b-469c-a4bb-49a1058c7f31', 6, 'LENSOMETRO DIGITAL', 'lensometro', 'VIEW TECH', 'NO REGISTRA', '1905740560', 'CONSULTORIO #2', '-'),
  ('aa3e40ca-a82e-4f00-ac58-7fc9a4297676', 7, 'UNIDAD OFTALMOLOGICA', 'unidad', 'VIEW-LIGTH', 'MOZZART', '2VS1607172', 'CONSULTORIO #3', '-'),
  ('3cee9223-da25-45c5-a55a-4535bc373516', 8, 'FOROPTER', 'foroptero', 'ANDRU', 'NO REGISTRA', '20207205200', 'CONSULTORIO #3', '-'),
  ('11479ea5-e925-406b-afbe-29ee20086df1', 9, 'AUTOQUERATOMETRO', 'autoref', 'NINGBO', 'FKR-710', 'K71182105516', 'CONSULTORIO #3', '-'),
  ('4123d47a-3c77-4361-bc43-529c4d554e4a', 10, 'LAMPARA DE HENDIDURA', 'lampara', 'SLIT LAMP', 'NO REGISTRA', '160908122', 'CONSULTORIO #3', '-'),
  ('74f34809-726e-43c7-bbe5-605f89663fc5', 11, 'ESTUCHE DIAGNOSTICO', 'estuche', 'WELCH ALLYN', 'NO REGISTRA', 'NO REGISTRA', 'CONSULTORIO #3', '-'),
  ('c802c3d2-8291-4b9c-916d-0b099e633e13', 12, 'KIT DE DIAGNOSTICO', 'pared', 'WELCH ALLYN', 'GS-777', 'NO REGISTRA', 'CONSULTORIO #3', '-'),
  ('12e506ef-e8a9-421b-8920-b369241c0f61', 13, 'MAQUINA RANURADORA', 'ranuradora', 'ANDRU', '800', '21070320724', 'LABORATORIO', '-'),
  ('56ac1a10-c8f8-46b7-889e-f5fcc12cea4e', 14, 'BISELADORA AUTOMATICA', 'biseladora', 'JINGONG', 'SJG-800', '2208051', 'LABORATORIO', '-'),
  ('4371db9d-d8cd-4869-b5e1-7d160f284ef0', 15, 'SCANNER', 'trazador', 'JINGONG', 'AUTO LENS SCAN', 'NO REGISTRA', 'LABORATORIO', '-'),
  ('62eb67e1-e2f7-4517-9b43-2d545a4e9633', 16, 'CORTADORA', 'bismanual', 'HAND EDGER', 'NO REGISTRA', 'NO REGISTRA', 'LABORATORIO', '-'),
  ('0f32d0c0-07cd-4f8d-986b-1a4f77c1c502', 17, 'PROBADOR FOTOCROMATICO', 'fotocromatico', 'ANDRU', 'LG-828', '18121410123', 'LABORATORIO', '-'),
  ('e1897e33-c2f6-444b-871e-6f99ebb9bece', 18, 'CALENTADOR DE MONTURAS', 'calentador', 'RITABIITY', 'NO REGISTRA', 'NO REGISTRA', 'LABORATORIO', '-'),
  ('70959452-2fac-4697-96f7-ab0b9fec648b', 19, 'PULIDORA AUTOMATICA', 'pulidora', 'NO REGISTRA', 'LY-900', 'NO REGISTRA', 'LABORATORIO', '-'),
  ('fd629d39-8345-4339-af3c-099b789340bb', 20, 'PERFORADORA DE LENTES', 'perforadora', 'NO REGISTRA', 'CP-24B', 'NO REGISTRA', 'LABORATORIO', '-'),
  ('0c0b9edf-9f12-47b2-b824-6dc93ad10de0', 21, 'SCANER BIOMETRICO', 'biometro', 'ALCON', 'OCUSCAN RXP', '0902352301X', 'CONSULTORIO #3', '-')
on conflict do nothing;

-- 9. Contraseñas de primer uso y recuperación ------------------------------------
alter table public.perfiles add column if not exists debe_cambiar boolean not null default true;

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
