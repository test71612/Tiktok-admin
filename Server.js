/* ============================================================
   XDreemB52 — لوحة الحضور
   خادم آمن: الباسوردات والمفاتيح الحساسة كلها هنا، لا تصل المتصفح أبداً
   ============================================================ */

const express = require('express');
const crypto  = require('crypto');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ---------- متغيرات البيئة (تُضبط من Render → Environment) ---------- */
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const SESSION_SECRET       = process.env.SESSION_SECRET;
const BOOTSTRAP_MASTER     = process.env.MASTER_PASSWORD;

for (const [k, v] of Object.entries({ SUPABASE_URL, SUPABASE_SERVICE_KEY, SESSION_SECRET })) {
  if (!v) { console.error(`✖ متغير البيئة ${k} مفقود. أضفه في Render → Environment.`); process.exit(1); }
}

const TOKEN_TTL_MS  = 8 * 60 * 60 * 1000;   // مدة الجلسة: 8 ساعات
const MAX_ATTEMPTS  = 6;                     // محاولات دخول لكل IP
const WINDOW_MS     = 10 * 60 * 1000;        // خلال 10 دقائق

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '6mb' }));

/* ---------- رؤوس أمان أساسية ---------- */
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

/* ============================================================
   تشفير الباسوردات (scrypt + ملح عشوائي) ومقارنة آمنة زمنياً
   ============================================================ */
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key  = crypto.scryptSync(String(plain), salt, 64).toString('hex');
  return `scrypt$${salt}$${key}`;
}

function verifyPassword(plain, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const [scheme, salt, key] = stored.split('$');
  if (scheme !== 'scrypt' || !salt || !key) return false;
  const candidate = crypto.scryptSync(String(plain), salt, 64).toString('hex');
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(key, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* ============================================================
   توكن الجلسة: حمولة موقّعة بـ HMAC — لا يمكن تزويرها بدون السر
   ============================================================ */
function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function readToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig || '');
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const user   = readToken(header.replace(/^Bearer\s+/i, ''));
  if (!user) return res.status(401).json({ error: 'انتهت الجلسة، سجّل الدخول من جديد' });
  req.user = user;
  next();
}

function requireMaster(req, res, next) {
  if (!req.user?.master) return res.status(403).json({ error: 'هذا الإجراء للأدمن فقط' });
  next();
}

/* ============================================================
   حماية من التخمين: تحديد المحاولات لكل IP + تأخير عند الفشل
   ============================================================ */
const attempts = new Map();

function throttle(ip) {
  const now = Date.now();
  const rec = attempts.get(ip);
  if (!rec || now > rec.resetAt) { attempts.set(ip, { count: 0, resetAt: now + WINDOW_MS }); return { blocked: false }; }
  if (rec.count >= MAX_ATTEMPTS) return { blocked: true, waitMin: Math.ceil((rec.resetAt - now) / 60000) };
  return { blocked: false };
}

function noteFailure(ip) {
  const rec = attempts.get(ip) || { count: 0, resetAt: Date.now() + WINDOW_MS };
  rec.count += 1;
  attempts.set(ip, rec);
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of attempts) if (now > rec.resetAt) attempts.delete(ip);
}, 5 * 60 * 1000).unref();

/* ============================================================
   الوصول إلى Supabase بمفتاح الخدمة (يتجاوز RLS) — من الخادم فقط
   ============================================================ */
async function sb(pathname, options = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${pathname}`, {
    ...options,
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const text = await res.json().catch(() => null);
  if (!res.ok) throw new Error(text?.message || `Supabase ${res.status}`);
  return text;
}

/* جدول app_auth يحمل: master_hash + قائمة المستخدمين {name, hash} */
async function loadAuth() {
  const rows = await sb('app_auth?id=eq.1&select=master_hash,users');
  const row  = rows?.[0];
  if (row) return { master_hash: row.master_hash || null, users: row.users || [] };

  // أول تشغيل: ننشئ السجل من الباسورد الموجود في متغيرات البيئة
  const seed = { id: 1, master_hash: BOOTSTRAP_MASTER ? hashPassword(BOOTSTRAP_MASTER) : null, users: [] };
  await sb('app_auth', { method: 'POST', headers: { Prefer: 'resolution=merge-duplicates' }, body: JSON.stringify(seed) });
  return { master_hash: seed.master_hash, users: [] };
}

async function saveAuth(auth) {
  await sb('app_auth', {
    method: 'POST',
    headers: { Prefer: 'resolution=merge-duplicates' },
    body: JSON.stringify({ id: 1, master_hash: auth.master_hash, users: auth.users }),
  });
}

/* ============================================================
   تسجيل الدخول
   ============================================================ */
app.post('/api/login', async (req, res) => {
  const ip = req.ip || 'unknown';
  const gate = throttle(ip);
  if (gate.blocked) {
    return res.status(429).json({ error: `محاولات كثيرة. انتظر ${gate.waitMin} دقيقة ثم أعد المحاولة.` });
  }

  const password = String(req.body?.password || '').trim();
  if (!password) return res.status(400).json({ error: 'أدخل كلمة المرور' });

  try {
    const auth = await loadAuth();
    let identity = null;

    if (auth.master_hash && verifyPassword(password, auth.master_hash)) {
      identity = { name: 'الماستر', master: true };
    } else {
      const hit = (auth.users || []).find(u => verifyPassword(password, u.hash));
      if (hit) identity = { name: hit.name, master: false };
    }

    if (!identity) {
      noteFailure(ip);
      await new Promise(r => setTimeout(r, 600));      // يبطئ التخمين الآلي
      return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
    }

    attempts.delete(ip);
    const token = signToken({ ...identity, exp: Date.now() + TOKEN_TTL_MS });
    res.json({ token, name: identity.name, master: identity.master });
  } catch (err) {
    console.error('login:', err.message);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.get('/api/session', requireAuth, (req, res) => {
  res.json({ name: req.user.name, master: !!req.user.master });
});

/* ============================================================
   حفظ الجدول — يمر عبر الخادم فقط، والمتصفح لا يملك صلاحية كتابة
   ============================================================ */
app.post('/api/save', requireAuth, async (req, res) => {
  const incoming = req.body?.state;
  if (!incoming || typeof incoming !== 'object' || !Array.isArray(incoming.names)) {
    return res.status(400).json({ error: 'بيانات غير صالحة' });
  }

  // تنظيف: لا نسمح بتسريب أي بيانات اعتماد داخل جدول الحضور
  delete incoming.masterPassword;
  delete incoming.adminUsers;

  try {
    await sb('attendance', {
      method: 'POST',
      headers: { Prefer: 'resolution=merge-duplicates' },
      body: JSON.stringify({ id: 1, data: incoming }),
    });
    res.json({ ok: true, by: req.user.name });
  } catch (err) {
    console.error('save:', err.message);
    res.status(500).json({ error: 'تعذّر الحفظ' });
  }
});

/* ============================================================
   إدارة المستخدمين — للماستر فقط، والباسوردات تُخزَّن مشفّرة
   ============================================================ */
app.get('/api/users', requireAuth, requireMaster, async (req, res) => {
  try {
    const auth = await loadAuth();
    res.json({ users: (auth.users || []).map(u => ({ name: u.name })) });   // بدون أي باسورد
  } catch { res.status(500).json({ error: 'تعذّر جلب المستخدمين' }); }
});

app.post('/api/users', requireAuth, requireMaster, async (req, res) => {
  const name     = String(req.body?.name || '').trim();
  const password = String(req.body?.password || '').trim();
  if (!name || !password)      return res.status(400).json({ error: 'أدخل الاسم والباسورد' });
  if (password.length < 8)     return res.status(400).json({ error: 'الباسورد لازم 8 خانات على الأقل' });

  try {
    const auth = await loadAuth();
    if ((auth.users || []).some(u => u.name === name))             return res.status(409).json({ error: 'الاسم مستخدم بالفعل' });
    if (auth.master_hash && verifyPassword(password, auth.master_hash)) return res.status(409).json({ error: 'هذا الباسورد محجوز للماستر' });
    if ((auth.users || []).some(u => verifyPassword(password, u.hash))) return res.status(409).json({ error: 'هذا الباسورد مستخدم بالفعل' });

    auth.users = [...(auth.users || []), { name, hash: hashPassword(password) }];
    await saveAuth(auth);
    res.json({ ok: true, users: auth.users.map(u => ({ name: u.name })) });
  } catch { res.status(500).json({ error: 'تعذّرت الإضافة' }); }
});

app.delete('/api/users/:name', requireAuth, requireMaster, async (req, res) => {
  try {
    const auth = await loadAuth();
    auth.users = (auth.users || []).filter(u => u.name !== req.params.name);
    await saveAuth(auth);
    res.json({ ok: true, users: auth.users.map(u => ({ name: u.name })) });
  } catch { res.status(500).json({ error: 'تعذّر الحذف' }); }
});

app.post('/api/master-password', requireAuth, requireMaster, async (req, res) => {
  const next = String(req.body?.password || '').trim();
  if (next.length < 10) return res.status(400).json({ error: 'باسورد الماستر لازم 10 خانات على الأقل' });
  try {
    const auth = await loadAuth();
    if ((auth.users || []).some(u => verifyPassword(next, u.hash))) {
      return res.status(409).json({ error: 'هذا الباسورد مستخدم لمستخدم آخر' });
    }
    auth.master_hash = hashPassword(next);
    await saveAuth(auth);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'تعذّر التغيير' }); }
});

/* ============================================================
   عدّاد الزوار — انتقل للخادم حتى نغلق الكتابة نهائياً على المتصفح
   ============================================================ */
app.post('/api/visit', async (req, res) => {
  const visitorId = String(req.body?.visitorId || '').slice(0, 60);
  if (!visitorId) return res.status(400).json({ error: 'معرّف ناقص' });
  try {
    const rows = await sb('visitors?id=eq.1&select=count,visitor_ids');
    const row  = rows?.[0];
    if (!row) {
      await sb('visitors', { method: 'POST', headers: { Prefer: 'resolution=merge-duplicates' }, body: JSON.stringify({ id: 1, count: 1, visitor_ids: [visitorId] }) });
      return res.json({ count: 1 });
    }
    const ids = row.visitor_ids || [];
    if (ids.includes(visitorId)) return res.json({ count: row.count || 0 });
    const count = (row.count || 0) + 1;
    await sb('visitors', { method: 'POST', headers: { Prefer: 'resolution=merge-duplicates' }, body: JSON.stringify({ id: 1, count, visitor_ids: [...ids, visitorId] }) });
    res.json({ count });
  } catch { res.status(500).json({ error: 'تعذّر التحديث' }); }
});

/* ---------- الملفات الثابتة ---------- */
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '5m', etag: true }));
app.get('/healthz', (req, res) => res.type('text').send('ok'));
app.use((req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`✔ يعمل على المنفذ ${PORT}`));
