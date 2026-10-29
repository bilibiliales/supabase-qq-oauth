-- Historical baseline migration. Later migrations scope requests to an app and
-- remove the legacy appkey_hash column; preserve this history for migration replay.
create table if not exists public.qq_oauth_requests (
  state text primary key check (state ~ '^[a-f0-9]{32}$'),
  appkey_hash text not null,
  notify_url text not null,
  return_url text not null,
  status text not null default 'pending'
    check (status in ('pending', 'processing', 'completed', 'failed')),
  openid_hmac text check (openid_hmac is null or openid_hmac ~ '^[a-f0-9]{64}$'),
  nickname text,
  avatar text,
  error_code text,
  notify_status text not null default 'not_sent'
    check (notify_status in ('not_sent', 'sent', 'failed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '15 minutes'),
  completed_at timestamptz
);

comment on table public.qq_oauth_requests is
  'QQ OAuth state records. Raw QQ openid and access tokens must never be stored.';
alter table public.qq_oauth_requests enable row level security;
revoke all on table public.qq_oauth_requests from anon, authenticated;
grant all on table public.qq_oauth_requests to service_role;
