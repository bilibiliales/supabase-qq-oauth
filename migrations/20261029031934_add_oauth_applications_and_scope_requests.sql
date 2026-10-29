create table if not exists public.oauth_applications (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(btrim(name)) between 1 and 100),
  apikey text not null unique check (apikey ~ '^[a-f0-9]{64}$'),
  enabled boolean not null default true,
  notify_hosts text[] not null default '{}',
  return_hosts text[] not null default '{}',
  return_schemes text[] not null default array['https', 'http'],
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (cardinality(notify_hosts) <= 100 and array_position(notify_hosts, null::text) is null),
  check (cardinality(return_hosts) <= 100 and array_position(return_hosts, null::text) is null),
  check (cardinality(return_schemes) between 1 and 20 and array_position(return_schemes, null::text) is null)
);

comment on table public.oauth_applications is
  'Registered client applications for the shared QQ OAuth service. API keys are bearer secrets and must never be exposed to client-side code.';
comment on column public.oauth_applications.apikey is
  'Plaintext application API key, 64 lowercase hexadecimal characters. Readable only by trusted server-side service-role code.';
comment on column public.oauth_applications.notify_hosts is
  'Exact allowed hostnames for asynchronous notification URLs.';
comment on column public.oauth_applications.return_hosts is
  'Exact allowed hostnames for HTTP(S) return URLs.';
comment on column public.oauth_applications.return_schemes is
  'Allowed URL schemes including registered custom deep-link schemes.';

alter table public.qq_oauth_requests
  add column if not exists app_id uuid references public.oauth_applications(id);

-- Historical migration added app_id NOT NULL after migration of legacy data.
-- The production project had no request rows at migration time. On a fresh replay
-- the table is empty, so enforcing NOT NULL is safe.
alter table public.qq_oauth_requests alter column app_id set not null;

alter table public.qq_oauth_requests
  drop constraint if exists qq_oauth_requests_completed_requires_identity;
alter table public.qq_oauth_requests
  add constraint qq_oauth_requests_completed_requires_identity
  check (status <> 'completed' or openid_hmac is not null);

create index if not exists qq_oauth_requests_app_id_created_at_idx
  on public.qq_oauth_requests (app_id, created_at desc);
create index if not exists qq_oauth_requests_expires_at_idx
  on public.qq_oauth_requests (expires_at);

alter table public.oauth_applications enable row level security;
revoke all on table public.oauth_applications from anon, authenticated;
grant all on table public.oauth_applications to service_role;
revoke all on table public.qq_oauth_requests from anon, authenticated;
grant all on table public.qq_oauth_requests to service_role;
