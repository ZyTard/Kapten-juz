// =====================================================================
// Edge Function: staff-admin
// Dipakai halaman "Staf" di aplikasi untuk menambah akun, mengubah peran,
// reset kata sandi, menonaktifkan, dan menghapus akun staf.
// Hanya akun dengan peran manager yang aktif yang boleh memanggilnya.
// Cara pasang: Supabase Dashboard > Edge Functions > Deploy a new function
//              > Via Editor > nama: staff-admin > tempel kode ini > Deploy.
// =====================================================================
import { createClient } from 'npm:@supabase/supabase-js@2';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-client-info',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

const ROLES = ['manager', 'admin', 'produksi', 'kasir'];

// Kunci rahasia dibaca dari environment Supabase (tidak pernah ada di aplikasi)
function secretKey(): string {
  try {
    const k = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') ?? '{}');
    if (k.default) return k.default;
  } catch (_) { /* pakai kunci lama di bawah */ }
  return Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';
}

const admin = createClient(Deno.env.get('SUPABASE_URL')!, secretKey(), {
  auth: { persistSession: false, autoRefreshToken: false },
});

async function otherActiveManagerExists(excludeId: string): Promise<boolean> {
  const { count } = await admin
    .from('profiles')
    .select('id', { count: 'exact', head: true })
    .eq('role', 'manager')
    .eq('active', true)
    .neq('id', excludeId);
  return (count ?? 0) > 0;
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  if (req.method !== 'POST') return json({ error: 'Metode tidak didukung.' }, 405);

  // 1. Pastikan pemanggil login dan berperan manager aktif
  const token = (req.headers.get('Authorization') ?? '').replace(/^Bearer\s+/i, '');
  if (!token) return json({ error: 'Belum login.' }, 401);
  const { data: auth, error: authErr } = await admin.auth.getUser(token);
  if (authErr || !auth?.user) return json({ error: 'Sesi tidak valid. Silakan login ulang.' }, 401);

  const { data: me } = await admin.from('profiles').select('id, role, active').eq('id', auth.user.id).maybeSingle();
  if (!me || !me.active || me.role !== 'manager') {
    return json({ error: 'Hanya manager yang boleh mengelola staf.' }, 403);
  }

  let b: any;
  try { b = await req.json(); } catch (_) { return json({ error: 'Permintaan tidak valid.' }, 400); }

  try {
    switch (b.action) {
      case 'create': {
        const email = String(b.email ?? '').trim().toLowerCase();
        const fullName = String(b.full_name ?? '').trim();
        const password = String(b.password ?? '');
        const role = String(b.role ?? '');
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Format email tidak valid.' }, 400);
        if (!fullName) return json({ error: 'Nama lengkap wajib diisi.' }, 400);
        if (password.length < 8) return json({ error: 'Kata sandi minimal 8 karakter.' }, 400);
        if (!ROLES.includes(role)) return json({ error: 'Peran tidak dikenal.' }, 400);

        const { data: created, error: cErr } = await admin.auth.admin.createUser({
          email, password, email_confirm: true, user_metadata: { full_name: fullName },
        });
        if (cErr || !created?.user) {
          const msg = /already|registered|exists/i.test(cErr?.message ?? '')
            ? 'Email ini sudah terdaftar.' : (cErr?.message ?? 'Gagal membuat akun.');
          return json({ error: msg }, 400);
        }
        const { error: pErr } = await admin.from('profiles').insert({
          id: created.user.id, email, full_name: fullName, role, active: true,
        });
        if (pErr) {
          await admin.auth.admin.deleteUser(created.user.id);
          return json({ error: 'Gagal menyimpan profil: ' + pErr.message }, 500);
        }
        return json({ ok: true, id: created.user.id });
      }

      case 'update': {
        const id = String(b.id ?? '');
        const { data: t } = await admin.from('profiles').select('id, role').eq('id', id).maybeSingle();
        if (!t) return json({ error: 'Staf tidak ditemukan.' }, 404);
        const patch: Record<string, unknown> = {};
        if (b.full_name !== undefined) {
          const n = String(b.full_name).trim();
          if (!n) return json({ error: 'Nama lengkap wajib diisi.' }, 400);
          patch.full_name = n;
        }
        if (b.role !== undefined && b.role !== t.role) {
          if (!ROLES.includes(b.role)) return json({ error: 'Peran tidak dikenal.' }, 400);
          if (id === me.id) return json({ error: 'Kamu tidak bisa mengubah perananmu sendiri.' }, 400);
          if (t.role === 'manager' && !(await otherActiveManagerExists(id))) {
            return json({ error: 'Harus ada minimal satu manager aktif.' }, 400);
          }
          patch.role = b.role;
        }
        if (!Object.keys(patch).length) return json({ ok: true });
        const { error } = await admin.from('profiles').update(patch).eq('id', id);
        if (error) return json({ error: error.message }, 500);
        return json({ ok: true });
      }

      case 'set_active': {
        const id = String(b.id ?? '');
        const active = !!b.active;
        const { data: t } = await admin.from('profiles').select('id, role').eq('id', id).maybeSingle();
        if (!t) return json({ error: 'Staf tidak ditemukan.' }, 404);
        if (!active) {
          if (id === me.id) return json({ error: 'Kamu tidak bisa menonaktifkan akunmu sendiri.' }, 400);
          if (t.role === 'manager' && !(await otherActiveManagerExists(id))) {
            return json({ error: 'Harus ada minimal satu manager aktif.' }, 400);
          }
        }
        await admin.auth.admin.updateUserById(id, { ban_duration: active ? 'none' : '876000h' });
        const { error } = await admin.from('profiles').update({ active }).eq('id', id);
        if (error) return json({ error: error.message }, 500);
        return json({ ok: true });
      }

      case 'reset_password': {
        const id = String(b.id ?? '');
        const password = String(b.password ?? '');
        if (password.length < 8) return json({ error: 'Kata sandi minimal 8 karakter.' }, 400);
        const { error } = await admin.auth.admin.updateUserById(id, { password });
        if (error) return json({ error: error.message }, 400);
        return json({ ok: true });
      }

      case 'delete': {
        const id = String(b.id ?? '');
        if (id === me.id) return json({ error: 'Kamu tidak bisa menghapus akunmu sendiri.' }, 400);
        const { data: t } = await admin.from('profiles').select('id, role').eq('id', id).maybeSingle();
        if (!t) return json({ error: 'Staf tidak ditemukan.' }, 404);
        if (t.role === 'manager' && !(await otherActiveManagerExists(id))) {
          return json({ error: 'Harus ada minimal satu manager aktif.' }, 400);
        }
        const { count } = await admin.from('entries').select('id', { count: 'exact', head: true }).eq('created_by', id);
        if ((count ?? 0) > 0) {
          return json({ error: 'Staf ini sudah punya catatan. Nonaktifkan saja agar riwayat tetap utuh.' }, 409);
        }
        const { error } = await admin.auth.admin.deleteUser(id);
        if (error) return json({ error: error.message }, 500);
        return json({ ok: true });
      }

      default:
        return json({ error: 'Aksi tidak dikenal.' }, 400);
    }
  } catch (e) {
    return json({ error: String((e as Error)?.message ?? e) }, 500);
  }
});
