-- Execute uma vez no SQL Editor do Supabase.
create table if not exists public.store_payments (
  id uuid primary key default gen_random_uuid(),
  store_id uuid not null references public.stores(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  mp_payment_id text not null unique,
  amount numeric(10,2) not null default 49.90,
  status text not null default 'pending',
  qr_code text,
  qr_code_base64 text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.store_payments enable row level security;
drop policy if exists "Users can read own store payments" on public.store_payments;
create policy "Users can read own store payments" on public.store_payments
  for select to authenticated using (auth.uid() = user_id);
-- Sem INSERT/UPDATE/DELETE para usuários: somente o backend Render escreve.
