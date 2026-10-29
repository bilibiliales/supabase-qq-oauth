alter table public.qq_oauth_requests
  drop column if exists appkey_hash;

alter table public.qq_oauth_requests
  drop constraint if exists qq_oauth_requests_notify_status_check;
alter table public.qq_oauth_requests
  add constraint qq_oauth_requests_notify_status_check
  check (notify_status in ('not_sent', 'sending', 'sent', 'failed'));
