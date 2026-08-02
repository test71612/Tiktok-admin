-- ============================================================
--  XDreemB52 — إعداد قاعدة البيانات والحماية
--  شغّل هذا الملف مرة واحدة في: Supabase → SQL Editor → New query
-- ============================================================

-- 1) جدول بيانات الاعتماد (الباسوردات مشفّرة، ولا يقرأها المتصفح أبداً)
create table if not exists public.app_auth (
  id          int primary key,
  master_hash text,
  users       jsonb not null default '[]'::jsonb
);

-- 2) تفعيل الحماية على مستوى الصف
alter table public.attendance enable row level security;
alter table public.visitors   enable row level security;
alter table public.app_auth   enable row level security;

-- 3) القراءة العامة مسموحة (عشان الجدول يظهر للزوار والتحديث اللحظي يشتغل)
drop policy if exists "anon read attendance" on public.attendance;
create policy "anon read attendance" on public.attendance for select using (true);

drop policy if exists "anon read visitors" on public.visitors;
create policy "anon read visitors" on public.visitors for select using (true);

-- 4) لا توجد أي سياسة كتابة → المتصفح لا يقدر يكتب إطلاقاً.
--    الخادم يكتب بمفتاح service_role الذي يتجاوز RLS.
--    وجدول app_auth بلا أي سياسة → غير مقروء نهائياً من المتصفح.

-- 5) تفعيل التحديث اللحظي على جدول الحضور
alter publication supabase_realtime add table public.attendance;

-- 6) تنظيف: احذف الباسوردات القديمة المخزّنة كنص صريح داخل بيانات الجدول
update public.attendance
set data = (data - 'masterPassword') - 'adminUsers'
where id = 1;
