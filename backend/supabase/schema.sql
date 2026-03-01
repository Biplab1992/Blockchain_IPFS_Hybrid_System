create table if not exists public.certificates (
  cert_id text primary key,
  issuer text,
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
