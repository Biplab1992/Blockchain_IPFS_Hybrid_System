create extension if not exists pgcrypto;

create table if not exists public.certificates (
  cert_id text primary key,
  issuer text,
  title text,
  institution_name text,
  metadata_cid text,
  file_cid text,
  file_hash text,
  version int,
  replaces_cert_id text null,
  revoked boolean not null default false,
  issue_tx text,
  revoke_tx text null,
  block_number bigint,
  revoke_block_number bigint null,
  issued_at bigint,
  revoked_at bigint null,
  updated_at timestamptz not null default now()
);

alter table public.certificates add column if not exists title text;
alter table public.certificates add column if not exists institution_name text;
alter table public.certificates add column if not exists issue_tx text;
alter table public.certificates add column if not exists revoke_tx text null;
alter table public.certificates add column if not exists block_number bigint;
alter table public.certificates add column if not exists revoke_block_number bigint null;
alter table public.certificates add column if not exists issued_at bigint;
alter table public.certificates add column if not exists revoked_at bigint null;

create index if not exists certificates_issuer_idx on public.certificates (issuer);
create index if not exists certificates_block_number_idx on public.certificates (block_number desc);
create index if not exists certificates_replaces_idx on public.certificates (replaces_cert_id);

create table if not exists public.indexer_state (
  id text primary key,
  last_block bigint not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.issuer_status (
  issuer text primary key,
  is_authorized boolean not null,
  last_tx_hash text,
  last_block_number bigint,
  last_changed_at bigint,
  changed_by text null,
  updated_at timestamptz not null default now()
);

create index if not exists issuer_status_authorized_idx on public.issuer_status (is_authorized);
create index if not exists issuer_status_last_block_idx on public.issuer_status (last_block_number desc);

create table if not exists public.issuer_events (
  tx_hash text not null,
  log_index int not null,
  block_number bigint not null,
  issuer text not null,
  allowed boolean not null,
  changed_by text null,
  changed_at bigint null,
  created_at timestamptz not null default now(),
  primary key (tx_hash, log_index)
);

create index if not exists issuer_events_issuer_idx on public.issuer_events (issuer);
create index if not exists issuer_events_block_idx on public.issuer_events (block_number desc);

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  password_hash text not null,
  role text not null check (role in ('MOE_ADMIN','INSTITUTION_ADMIN','INDIVIDUAL')),
  email_verified boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.institutions (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  status text not null check (status in ('PENDING','ACTIVE','SUSPENDED')),
  admin_email text not null,
  issuer_wallet text not null,
  created_at timestamptz not null default now()
);

alter table public.institutions add column if not exists authorization_request_status text null;
alter table public.institutions add column if not exists authorization_request_note text null;
alter table public.institutions add column if not exists authorization_requested_at timestamptz null;
alter table public.institutions add column if not exists authorization_request_resolved_at timestamptz null;

create table if not exists public.institution_users (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  institution_id uuid not null references public.institutions(id) on delete cascade,
  is_primary_admin boolean not null default false,
  created_at timestamptz not null default now(),
  unique (user_id, institution_id)
);

create table if not exists public.invitations (
  id uuid primary key default gen_random_uuid(),
  institution_id uuid not null references public.institutions(id) on delete cascade,
  email text not null,
  token_hash text not null,
  expires_at timestamptz not null,
  used_at timestamptz null,
  created_at timestamptz not null default now()
);

create table if not exists public.wallet_bindings (
  id uuid primary key default gen_random_uuid(),
  institution_id uuid not null references public.institutions(id) on delete cascade,
  wallet_address text not null,
  verified boolean not null default false,
  verified_at timestamptz null,
  created_at timestamptz not null default now(),
  unique (institution_id, wallet_address)
);

create table if not exists public.refresh_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  token_hash text not null,
  expires_at timestamptz not null,
  revoked_at timestamptz null,
  created_at timestamptz not null default now()
);

create table if not exists public.password_reset_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  token_hash text not null,
  expires_at timestamptz not null,
  used_at timestamptz null,
  created_at timestamptz not null default now()
);

create table if not exists public.authorization_requests (
  id uuid primary key default gen_random_uuid(),
  institution_id uuid not null references public.institutions(id) on delete cascade,
  requester_user_id uuid null references public.users(id) on delete set null,
  issuer_wallet text not null,
  status text not null check (status in ('PENDING','APPROVED','REJECTED','CANCELLED')),
  note text null,
  resolved_by_user_id uuid null references public.users(id) on delete set null,
  resolved_at timestamptz null,
  created_at timestamptz not null default now()
);

create table if not exists public.audit_logs (
  id bigint generated by default as identity primary key,
  actor_user_id uuid null references public.users(id) on delete set null,
  actor_wallet text null,
  action text not null,
  entity_type text not null,
  entity_id text null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists users_email_idx on public.users (email);
create index if not exists institutions_status_idx on public.institutions (status);
create index if not exists invitations_token_hash_idx on public.invitations (token_hash);
create index if not exists wallet_bindings_inst_idx on public.wallet_bindings (institution_id);
create index if not exists refresh_tokens_user_idx on public.refresh_tokens (user_id);
create index if not exists refresh_tokens_hash_idx on public.refresh_tokens (token_hash);
create index if not exists password_reset_tokens_user_idx on public.password_reset_tokens (user_id);
create index if not exists password_reset_tokens_hash_idx on public.password_reset_tokens (token_hash);
create index if not exists authorization_requests_institution_idx on public.authorization_requests (institution_id);
create index if not exists authorization_requests_status_idx on public.authorization_requests (status);
create index if not exists audit_logs_actor_idx on public.audit_logs (actor_user_id);
create index if not exists audit_logs_action_idx on public.audit_logs (action);

alter table public.users enable row level security;
alter table public.institutions enable row level security;
alter table public.institution_users enable row level security;
alter table public.invitations enable row level security;
alter table public.wallet_bindings enable row level security;
alter table public.refresh_tokens enable row level security;
alter table public.password_reset_tokens enable row level security;
alter table public.authorization_requests enable row level security;
alter table public.audit_logs enable row level security;

do $$
begin
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='users' and policyname='users_service_role_all') then
    create policy users_service_role_all on public.users for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
  end if;
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='institutions' and policyname='institutions_service_role_all') then
    create policy institutions_service_role_all on public.institutions for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
  end if;
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='institution_users' and policyname='institution_users_service_role_all') then
    create policy institution_users_service_role_all on public.institution_users for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
  end if;
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='invitations' and policyname='invitations_service_role_all') then
    create policy invitations_service_role_all on public.invitations for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
  end if;
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='wallet_bindings' and policyname='wallet_bindings_service_role_all') then
    create policy wallet_bindings_service_role_all on public.wallet_bindings for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
  end if;
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='refresh_tokens' and policyname='refresh_tokens_service_role_all') then
    create policy refresh_tokens_service_role_all on public.refresh_tokens for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
  end if;
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='password_reset_tokens' and policyname='password_reset_tokens_service_role_all') then
    create policy password_reset_tokens_service_role_all on public.password_reset_tokens for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
  end if;
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='authorization_requests' and policyname='authorization_requests_service_role_all') then
    create policy authorization_requests_service_role_all on public.authorization_requests for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
  end if;
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='audit_logs' and policyname='audit_logs_service_role_all') then
    create policy audit_logs_service_role_all on public.audit_logs for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
  end if;
end
$$;
