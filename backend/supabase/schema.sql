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
