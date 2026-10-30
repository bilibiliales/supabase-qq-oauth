-- Grant management of an OAuth application to explicitly assigned Auth users.
-- A manager can read and update the entire oauth_applications row (including its
-- API key). Manager assignments are provisioned only by trusted SQL/service-role code.

create table if not exists public.oauth_application_managers (
  app_id uuid not null
    references public.oauth_applications(id) on delete cascade,
  user_id uuid not null
    references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id) on delete set null,
  primary key (app_id, user_id)
);

comment on table public.oauth_application_managers is
  'Maps Auth users to OAuth applications they are allowed to manage. Each row grants full row-level management access to the corresponding oauth_applications row.';

alter table public.oauth_application_managers enable row level security;

revoke all on table public.oauth_application_managers from anon, authenticated;
grant select on table public.oauth_application_managers to authenticated;
grant all on table public.oauth_application_managers to service_role;

drop policy if exists "Managers can read their own assignments"
  on public.oauth_application_managers;
create policy "Managers can read their own assignments"
  on public.oauth_application_managers
  for select
  to authenticated
  using (user_id = (select auth.uid()));

-- Do not allow users to grant themselves access or alter manager assignments.
-- Assignments are maintained by trusted SQL/service-role operations.

alter table public.oauth_applications enable row level security;

revoke all on table public.oauth_applications from anon, authenticated;
grant select, update on table public.oauth_applications to authenticated;
grant all on table public.oauth_applications to service_role;

drop policy if exists "Assigned managers can view OAuth applications"
  on public.oauth_applications;
create policy "Assigned managers can view OAuth applications"
  on public.oauth_applications
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.oauth_application_managers m
      where m.app_id = oauth_applications.id
        and m.user_id = (select auth.uid())
    )
  );

drop policy if exists "Assigned managers can update OAuth applications"
  on public.oauth_applications;
create policy "Assigned managers can update OAuth applications"
  on public.oauth_applications
  for update
  to authenticated
  using (
    exists (
      select 1
      from public.oauth_application_managers m
      where m.app_id = oauth_applications.id
        and m.user_id = (select auth.uid())
    )
  )
  with check (
    exists (
      select 1
      from public.oauth_application_managers m
      where m.app_id = oauth_applications.id
        and m.user_id = (select auth.uid())
    )
  );

-- No SECURITY DEFINER functions are required. INSERT/DELETE of applications
-- and all manager assignments remain restricted to trusted service-role access.
-- Authenticated managers can SELECT and UPDATE only application rows assigned
-- to their auth.uid(); all columns of those rows are manageable, including apikey.
