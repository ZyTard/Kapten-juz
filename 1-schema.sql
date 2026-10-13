-- =====================================================================
-- Stok Buah Kapten Juz : skema database, aturan keamanan, dan data awal
-- Cara pakai: Supabase Dashboard > SQL Editor > New query > tempel semua > Run
-- PENTING: buat dulu akun manager di Authentication > Users (lihat panduan),
--          baru jalankan skrip ini. Aman dijalankan ulang.
-- =====================================================================

-- ---------- 1. Tabel ----------

create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  email       text not null,
  full_name   text not null check (length(trim(full_name)) > 0),
  role        text not null check (role in ('manager','admin','produksi','kasir')),
  active      boolean not null default true,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.fruits (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (length(trim(name)) > 0),
  hidden      boolean not null default false,
  created_by  uuid default auth.uid(),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create unique index if not exists fruits_name_uq on public.fruits (lower(trim(name)));

create table if not exists public.entries (
  id          uuid primary key,
  entry_date  date not null,
  type        text not null check (type in ('masuk','produksi','eceran','waste','koreksi')),
  fruit_id    uuid not null references public.fruits(id) on delete restrict,
  kg          numeric(12,2) not null,
  price       numeric(14,2) check (price is null or price >= 0),
  origin      text,
  menu        text,
  category    text check (category is null or category in ('busuk','rusak','kupas','jatuh','lainnya')),
  stage       text check (stage is null or stage in ('gudang','produksi','eceran')),
  note        text,
  created_by  uuid not null default auth.uid() references public.profiles(id) on delete restrict,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  deleted_at  timestamptz,
  deleted_by  uuid references public.profiles(id) on delete restrict,
  constraint entries_kg_valid    check ((type = 'koreksi' and kg <> 0) or (type <> 'koreksi' and kg > 0)),
  constraint entries_waste_valid check (type <> 'waste' or (category is not null and stage is not null))
);
create index if not exists entries_updated_idx on public.entries (updated_at);
create index if not exists entries_date_idx    on public.entries (entry_date);

create table if not exists public.settings (
  id           int primary key default 1 check (id = 1),
  waste_target numeric(5,2) check (waste_target is null or waste_target >= 0),
  updated_at   timestamptz not null default now()
);
insert into public.settings (id) values (1) on conflict (id) do nothing;

-- ---------- 2. Fungsi bantu ----------

-- Peran akun yang sedang login (null kalau akun nonaktif atau belum terdaftar)
create or replace function public.my_role()
returns text language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid() and active
$$;
revoke all on function public.my_role() from public, anon;
grant execute on function public.my_role() to authenticated;

-- Aturan siapa boleh membuat jenis catatan apa. Ubah di sini kalau pembagian tugas berubah.
create or replace function public.can_write_type(r text, t text)
returns boolean language sql immutable as $$
  select case r
    when 'manager'  then true
    when 'admin'    then true
    when 'produksi' then t in ('produksi','waste')
    when 'kasir'    then t in ('eceran','waste')
    else false
  end
$$;
grant execute on function public.can_write_type(text, text) to authenticated;

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end $$;

-- Catatan tidak bisa diedit, hanya bisa ditandai terhapus (riwayat tetap utuh)
create or replace function public.entries_guard()
returns trigger language plpgsql as $$
begin
  if (to_jsonb(new) - 'deleted_at' - 'deleted_by' - 'updated_at')
     is distinct from (to_jsonb(old) - 'deleted_at' - 'deleted_by' - 'updated_at') then
    raise exception 'Catatan tidak bisa diubah. Hapus lalu catat ulang.';
  end if;
  new.updated_at = now();
  if new.deleted_at is not null and old.deleted_at is null then
    new.deleted_by = auth.uid();
  elsif new.deleted_at is null then
    new.deleted_by = null;
  end if;
  return new;
end $$;

drop trigger if exists fruits_touch   on public.fruits;
create trigger fruits_touch   before update on public.fruits   for each row execute function public.touch_updated_at();
drop trigger if exists profiles_touch on public.profiles;
create trigger profiles_touch before update on public.profiles for each row execute function public.touch_updated_at();
drop trigger if exists settings_touch on public.settings;
create trigger settings_touch before update on public.settings for each row execute function public.touch_updated_at();
drop trigger if exists entries_guard_t on public.entries;
create trigger entries_guard_t before update on public.entries for each row execute function public.entries_guard();

-- ---------- 3. Row Level Security ----------

alter table public.profiles enable row level security;
alter table public.fruits   enable row level security;
alter table public.entries  enable row level security;
alter table public.settings enable row level security;

-- profiles: staf aktif melihat semua staf. Perubahan hanya lewat fungsi staff-admin.
drop policy if exists profiles_read on public.profiles;
create policy profiles_read on public.profiles for select to authenticated
  using (id = auth.uid() or public.my_role() is not null);

-- fruits
drop policy if exists fruits_read   on public.fruits;
drop policy if exists fruits_insert on public.fruits;
drop policy if exists fruits_update on public.fruits;
drop policy if exists fruits_delete on public.fruits;
create policy fruits_read   on public.fruits for select to authenticated using (public.my_role() is not null);
create policy fruits_insert on public.fruits for insert to authenticated with check (public.my_role() is not null);
create policy fruits_update on public.fruits for update to authenticated
  using (public.my_role() in ('manager','admin')) with check (public.my_role() in ('manager','admin'));
create policy fruits_delete on public.fruits for delete to authenticated using (public.my_role() = 'manager');

-- entries
drop policy if exists entries_read   on public.entries;
drop policy if exists entries_insert on public.entries;
drop policy if exists entries_delete on public.entries;
create policy entries_read on public.entries for select to authenticated using (public.my_role() is not null);
create policy entries_insert on public.entries for insert to authenticated
  with check (
    created_by = auth.uid()
    and deleted_at is null
    and public.can_write_type(public.my_role(), type)
  );
-- "Hapus" = menandai deleted_at. Manager boleh semua; staf lain hanya catatannya sendiri dalam 24 jam.
create policy entries_delete on public.entries for update to authenticated
  using (
    public.my_role() = 'manager'
    or (public.my_role() is not null and created_by = auth.uid() and created_at > now() - interval '1 day')
  )
  with check (
    public.my_role() = 'manager'
    or (public.my_role() is not null and created_by = auth.uid() and created_at > now() - interval '1 day')
  );

-- settings
drop policy if exists settings_read   on public.settings;
drop policy if exists settings_update on public.settings;
create policy settings_read   on public.settings for select to authenticated using (public.my_role() is not null);
create policy settings_update on public.settings for update to authenticated
  using (public.my_role() = 'manager') with check (public.my_role() = 'manager');

-- ---------- 4. Hak akses tabel (dibatasi sampai level kolom) ----------

revoke all on public.profiles, public.fruits, public.entries, public.settings from anon, authenticated;
grant usage on schema public to authenticated;

grant select on public.profiles to authenticated;

grant select on public.fruits to authenticated;
grant insert (id, name) on public.fruits to authenticated;
grant update (name, hidden) on public.fruits to authenticated;
grant delete on public.fruits to authenticated;

grant select on public.entries to authenticated;
grant insert (id, entry_date, type, fruit_id, kg, price, origin, menu, category, stage, note, created_by)
  on public.entries to authenticated;
grant update (deleted_at) on public.entries to authenticated;

grant select on public.settings to authenticated;
grant update (waste_target) on public.settings to authenticated;

-- ---------- 5. Data awal ----------

-- Daftar buah awal (bisa diubah kapan saja dari aplikasi)
insert into public.fruits (name) values
  ('Alpukat'),('Mangga'),('Nangka'),('Pisang'),('Nanas'),
  ('Jeruk'),('Melon'),('Semangka'),('Pepaya'),('Stroberi')
on conflict do nothing;

-- Akun manager pertama (harus sudah dibuat di Authentication > Users)
insert into public.profiles (id, email, full_name, role, active)
select id, email, 'Manager', 'manager', true
from auth.users
where lower(email) = 'cakybalqis@gmail.com'
on conflict (id) do update set role = 'manager', active = true;

-- Hasil: harus muncul 1 baris dengan peran manager
select email, full_name, role, active from public.profiles;
