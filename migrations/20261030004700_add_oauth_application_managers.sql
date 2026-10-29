-- Manage API-key-related capabilities through dedicated Auth users, not profiles.role.
-- Provision manager rows only from trusted SQL/service-role code.

create table if not exists public.oauth_application_managers (
  user_id uuid primary key references auth.users(id) on delete cascade,
  enabled boolean not null default true,
  can_rotate_apikey boolean not null default false,
  can_manage_allowlist boolean not null default false,
  can_toggle_enabled boolean not null default false,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id) on delete set null,
  constraint oauth_application_managers_at_least_one_permission
    check (can_rotate_apikey or can_manage_allowlist or can_toggle_enabled)
);

comment on table public.oauth_application_managers is
  'Explicit per-user permissions for managing registered OAuth applications. Rows are provisioned by trusted operators, not by end users.';
comment on column public.oauth_application_managers.enabled is
  'Master switch for this manager account; false disables all API-application management capabilities.';
comment on column public.oauth_application_managers.can_rotate_apikey is
  'Allows rotating an application API key without exposing the existing key.';
comment on column public.oauth_application_managers.can_manage_allowlist is
  'Allows updating notification hosts, return hosts, and return URL schemes.';
comment on column public.oauth_application_managers.can_toggle_enabled is
  'Allows enabling or disabling registered OAuth applications.';

alter table public.oauth_application_managers enable row level security;

revoke all on table public.oauth_application_managers from anon, authenticated;
grant select on table public.oauth_application_managers to authenticated;
grant all on table public.oauth_application_managers to service_role;

drop policy if exists "Managers can read their own permission record"
  on public.oauth_application_managers;
create policy "Managers can read their own permission record"
  on public.oauth_application_managers
  for select
  to authenticated
  using (user_id = (select auth.uid()));

-- No authenticated INSERT/UPDATE/DELETE policies are intentionally defined.
-- Assign or revoke managers using trusted SQL/service-role access only.

create or replace function public.rotate_oauth_application_apikey(
  p_app_id uuid,
  p_new_apikey text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  if p_new_apikey is null or p_new_apikey !~ '^[a-f0-9]{64}$' then
    raise exception 'API key must be exactly 64 lowercase hexadecimal characters'
      using errcode = '22023';
  end if;

  if not exists (
    select 1
    from public.oauth_application_managers m
    where m.user_id = (select auth.uid())
      and m.enabled
      and m.can_rotate_apikey
  ) then
    raise exception 'Missing API-key rotation permission' using errcode = '42501';
  end if;

  update public.oauth_applications
  set apikey = p_new_apikey,
      updated_at = now()
  where id = p_app_id;

  if not found then
    raise exception 'OAuth application not found' using errcode = 'P0002';
  end if;
end;
$$;

create or replace function public.update_oauth_application_allowlist(
  p_app_id uuid,
  p_notify_hosts text[],
  p_return_hosts text[],
  p_return_schemes text[]
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  if not exists (
    select 1
    from public.oauth_application_managers m
    where m.user_id = (select auth.uid())
      and m.enabled
      and m.can_manage_allowlist
  ) then
    raise exception 'Missing allowlist management permission' using errcode = '42501';
  end if;

  if p_notify_hosts is null
     or p_return_hosts is null
     or p_return_schemes is null
     or cardinality(p_notify_hosts) > 100
     or cardinality(p_return_hosts) > 100
     or cardinality(p_return_schemes) not between 1 and 20
     or array_position(p_notify_hosts, null::text) is not null
     or array_position(p_return_hosts, null::text) is not null
     or array_position(p_return_schemes, null::text) is not null then
    raise exception 'Invalid allowlist: check array sizes and null entries'
      using errcode = '22023';
  end if;

  update public.oauth_applications
  set notify_hosts = p_notify_hosts,
      return_hosts = p_return_hosts,
      return_schemes = p_return_schemes,
      updated_at = now()
  where id = p_app_id;

  if not found then
    raise exception 'OAuth application not found' using errcode = 'P0002';
  end if;
end;
$$;

create or replace function public.set_oauth_application_enabled(
  p_app_id uuid,
  p_enabled boolean
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  if not exists (
    select 1
    from public.oauth_application_managers m
    where m.user_id = (select auth.uid())
      and m.enabled
      and m.can_toggle_enabled
  ) then
    raise exception 'Missing application enable/disable permission' using errcode = '42501';
  end if;

  if p_enabled is null then
    raise exception 'p_enabled must not be null' using errcode = '22023';
  end if;

  update public.oauth_applications
  set enabled = p_enabled,
      updated_at = now()
  where id = p_app_id;

  if not found then
    raise exception 'OAuth application not found' using errcode = 'P0002';
  end if;
end;
$$;

-- SECURITY DEFINER RPCs are executable only by authenticated users; each function
-- performs its own auth.uid() and capability check before changing any row.
revoke all on function public.rotate_oauth_application_apikey(uuid, text) from public, anon;
revoke all on function public.update_oauth_application_allowlist(uuid, text[], text[], text[]) from public, anon;
revoke all on function public.set_oauth_application_enabled(uuid, boolean) from public, anon;

grant execute on function public.rotate_oauth_application_apikey(uuid, text) to authenticated;
grant execute on function public.update_oauth_application_allowlist(uuid, text[], text[], text[]) to authenticated;
grant execute on function public.set_oauth_application_enabled(uuid, boolean) to authenticated;
