-- Context Relay Task 17: authenticated, session-bound account deletion lifecycle.
-- The Edge caller supplies only a workspace selector. Account and session
-- authority are derived from verified JWT claims and revalidated after the
-- account serialization lock.

do $$
begin
  if not exists (
    select 1
    from pg_catalog.pg_roles
    where rolname = 'context_relay_rls_owner'
  ) then
    raise exception using errcode = '42704', message = 'context_relay_rls_owner is missing';
  end if;

  if exists (
    select 1
    from pg_catalog.pg_roles as owner_role
    where owner_role.rolname = 'context_relay_rls_owner'
      and (
        owner_role.rolcanlogin
        or owner_role.rolinherit
        or owner_role.rolsuper
        or owner_role.rolbypassrls
        or owner_role.rolcreatedb
        or owner_role.rolcreaterole
        or owner_role.rolreplication
      )
  ) then
    raise exception using errcode = '42501', message = 'context_relay_rls_owner has unsafe attributes';
  end if;
end
$$;

grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;
grant usage, create on schema context_relay_private to session_user;
reset role;

-- The managed auth schema cannot grant USAGE to the runtime owner. This
-- non-exposed migration-owned bridge returns one boolean, holds the exact
-- session row against concurrent deletion, and grants no Auth table access.
create function context_relay_private.lock_live_account_lifecycle_auth_session(
  p_auth_user_id uuid,
  p_session_id uuid
)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  perform 1
  from auth.sessions as session
  where session.id = p_session_id
    and session.user_id = p_auth_user_id
    and (session.not_after is null or session.not_after > pg_catalog.clock_timestamp())
  for share;
  return found;
end;
$$;

revoke all on function context_relay_private.lock_live_account_lifecycle_auth_session(uuid, uuid)
from public, anon, authenticated, service_role, context_relay_rls_owner;
grant execute on function context_relay_private.lock_live_account_lifecycle_auth_session(uuid, uuid)
to context_relay_rls_owner;

set local role context_relay_rls_owner;
revoke all on schema context_relay_private from session_user;

create table context_relay_private.account_lifecycle_rate_limits (
  account_id uuid primary key references public.accounts (id) on delete cascade,
  window_started_at timestamptz not null,
  request_count integer not null check (request_count > 0)
);
alter table context_relay_private.account_lifecycle_rate_limits
owner to context_relay_rls_owner;
alter table context_relay_private.account_lifecycle_rate_limits enable row level security;
revoke all on table context_relay_private.account_lifecycle_rate_limits
from public, anon, authenticated, service_role;

create table context_relay_private.account_lifecycle_receipts (
  account_id uuid not null references public.accounts (id) on delete cascade,
  request_id bytea not null check (pg_catalog.octet_length(request_id) = 32),
  auth_user_id uuid not null,
  session_id uuid not null,
  workspace_id uuid not null,
  action text not null check (action in ('begin_deletion', 'cancel_deletion')),
  projection jsonb not null check (pg_catalog.jsonb_typeof(projection) = 'object'),
  primary key (account_id, request_id)
);
alter table context_relay_private.account_lifecycle_receipts owner to context_relay_rls_owner;
alter table context_relay_private.account_lifecycle_receipts enable row level security;
revoke all on table context_relay_private.account_lifecycle_receipts
from public, anon, authenticated, service_role;

create function context_relay_private.find_account_lifecycle_receipt(
  p_account_id uuid, p_auth_user_id uuid, p_session_id uuid, p_workspace_id uuid,
  p_request_id bytea, p_action text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  receipt_row context_relay_private.account_lifecycle_receipts%rowtype;
begin
  if p_request_id is null or pg_catalog.octet_length(p_request_id) <> 32 then
    raise exception using errcode = '22023', message = 'invalid_request';
  end if;
  select receipt.* into receipt_row
  from context_relay_private.account_lifecycle_receipts as receipt
  where receipt.account_id = p_account_id and receipt.request_id = p_request_id;
  if not found then return null; end if;
  if receipt_row.auth_user_id <> p_auth_user_id
     or receipt_row.session_id <> p_session_id
     or receipt_row.workspace_id <> p_workspace_id
     or receipt_row.action <> p_action then
    raise exception using errcode = '55000', message = 'conflict';
  end if;
  return receipt_row.projection;
end;
$$;

create function context_relay_private.store_account_lifecycle_receipt(
  p_account_id uuid, p_auth_user_id uuid, p_session_id uuid, p_workspace_id uuid,
  p_request_id bytea, p_action text, p_projection jsonb
)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  -- Never evict receipts while the account exists: an old retry must not acquire
  -- new authority. Bound storage and fail closed if this pre-release cap is hit.
  if (select pg_catalog.count(*) from context_relay_private.account_lifecycle_receipts
      where account_id = p_account_id) >= 10000 then
    raise exception using errcode = '55000', message = 'conflict';
  end if;
  insert into context_relay_private.account_lifecycle_receipts (
    account_id, request_id, auth_user_id, session_id, workspace_id, action, projection
  ) values (
    p_account_id, p_request_id, p_auth_user_id, p_session_id, p_workspace_id, p_action, p_projection
  );
end;
$$;

create function context_relay_private.consume_account_lifecycle_request(p_account_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  request_time timestamptz := pg_catalog.clock_timestamp();
  current_request_count integer;
begin
  insert into context_relay_private.account_lifecycle_rate_limits as budget (
    account_id, window_started_at, request_count
  ) values (p_account_id, request_time, 1)
  on conflict (account_id) do update
  set window_started_at = case
        when budget.window_started_at + interval '60 seconds' <= request_time
          then request_time else budget.window_started_at end,
      request_count = case
        when budget.window_started_at + interval '60 seconds' <= request_time
          then 1 else budget.request_count + 1 end
  returning request_count into current_request_count;

  if current_request_count > 30 then
    raise exception using errcode = 'P0001', message = 'rate_limited';
  end if;
end;
$$;

create function context_relay_private.require_fresh_account_lifecycle_auth(
  p_credential_authenticated_at_seconds bigint
)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  current_seconds bigint := pg_catalog.floor(extract(epoch from pg_catalog.clock_timestamp()))::bigint;
begin
  if p_credential_authenticated_at_seconds is null
     or p_credential_authenticated_at_seconds < current_seconds - 300
     or p_credential_authenticated_at_seconds > current_seconds then
    raise exception using errcode = '28000', message = 'fresh_auth_required';
  end if;
end;
$$;

create function context_relay_private.locked_account_lifecycle_context(
  p_auth_user_id uuid,
  p_session_id uuid,
  p_workspace_id uuid
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  initial_account_id uuid;
  initial_device_id uuid;
  refreshed_account_id uuid;
  refreshed_device_id uuid;
begin
  if p_auth_user_id is null or p_session_id is null or p_workspace_id is null then
    raise exception using errcode = '22023', message = 'auth_required';
  end if;

  select binding.account_id, binding.device_id
  into strict initial_account_id, initial_device_id
  from public.device_bindings as binding
  join public.accounts as account
    on account.id = binding.account_id
   and account.owner_user_id = p_auth_user_id
  join public.device_certificates as certificate
    on certificate.account_id = binding.account_id
   and certificate.workspace_id = p_workspace_id
   and certificate.device_id = binding.device_id
   and certificate.control_epoch = account.control_epoch
  where binding.auth_user_id = p_auth_user_id
    and binding.session_id = p_session_id
    and binding.state = 'active'::context_relay_private.device_binding_state
    and binding.revoked_at is null
    and (binding.expires_at is null or binding.expires_at > pg_catalog.now())
    and account.deletion_state in (
      'active'::context_relay_private.account_deletion_state,
      'pending_delete'::context_relay_private.account_deletion_state
    );

  perform 1
  from public.accounts as account
  where account.id = initial_account_id
  for update;
  if not found then
    raise exception using errcode = '28000', message = 'revoked';
  end if;

  select binding.account_id, binding.device_id
  into strict refreshed_account_id, refreshed_device_id
  from public.device_bindings as binding
  join public.accounts as account
    on account.id = binding.account_id
   and account.owner_user_id = p_auth_user_id
  join public.device_certificates as certificate
    on certificate.account_id = binding.account_id
   and certificate.workspace_id = p_workspace_id
   and certificate.device_id = binding.device_id
   and certificate.control_epoch = account.control_epoch
  where binding.auth_user_id = p_auth_user_id
    and binding.session_id = p_session_id
    and binding.state = 'active'::context_relay_private.device_binding_state
    and binding.revoked_at is null
    and (binding.expires_at is null or binding.expires_at > pg_catalog.now())
    and account.deletion_state in (
      'active'::context_relay_private.account_deletion_state,
      'pending_delete'::context_relay_private.account_deletion_state
    );

  if refreshed_account_id <> initial_account_id or refreshed_device_id <> initial_device_id then
    raise exception using errcode = '28000', message = 'revoked';
  end if;

  if not context_relay_private.lock_live_account_lifecycle_auth_session(
    p_auth_user_id, p_session_id
  ) then
    raise exception using errcode = '28000', message = 'revoked';
  end if;
  perform context_relay_private.consume_account_lifecycle_request(refreshed_account_id);

  return pg_catalog.jsonb_build_object(
    'accountId', refreshed_account_id::text,
    'workspaceId', p_workspace_id::text,
    'deviceId', refreshed_device_id::text
  );
exception
  when no_data_found or too_many_rows then
    raise exception using errcode = '28000', message = 'revoked';
end;
$$;

create function context_relay_private.account_deletion_projection(p_account_id uuid)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  account_row public.accounts%rowtype;
  request_row public.deletion_requests%rowtype;
  has_request boolean;
begin
  select account.*
  into strict account_row
  from public.accounts as account
  where account.id = p_account_id;

  select request.*
  into request_row
  from public.deletion_requests as request
  where request.account_id = p_account_id;
  has_request := found;

  if account_row.deletion_state = 'active'::context_relay_private.account_deletion_state then
    if account_row.deletion_requested_at is not null
       or account_row.deletion_scheduled_for is not null
       or (
         has_request
         and (
           request_row.state <> 'active'::context_relay_private.account_deletion_state
           or request_row.cancelled_at is null
           or request_row.purged_at is not null
         )
       ) then
      raise exception using errcode = '55000', message = 'conflict';
    end if;
    return pg_catalog.jsonb_build_object(
      'state', 'active',
      'requestedAtMs', null,
      'purgeDeadlineMs', null
    );
  end if;

  if account_row.deletion_state = 'pending_delete'::context_relay_private.account_deletion_state then
    if not has_request
       or request_row.state <> 'pending_delete'::context_relay_private.account_deletion_state
       or request_row.cancelled_at is not null
       or request_row.purged_at is not null
       or account_row.deletion_requested_at <> request_row.requested_at
       or account_row.deletion_scheduled_for <> request_row.grace_deadline
       or request_row.grace_deadline <> request_row.requested_at + interval '7 days' then
      raise exception using errcode = '55000', message = 'conflict';
    end if;
    return pg_catalog.jsonb_build_object(
      'state', 'pending_delete',
      'requestedAtMs',
        pg_catalog.floor(extract(epoch from request_row.requested_at) * 1000)::bigint::text,
      'purgeDeadlineMs',
        pg_catalog.floor(extract(epoch from request_row.grace_deadline) * 1000)::bigint::text
    );
  end if;

  if account_row.deletion_state = 'purged'::context_relay_private.account_deletion_state
     and account_row.deletion_requested_at is not null
     and account_row.deletion_scheduled_for is not null
     and has_request
     and request_row.state = 'purged'::context_relay_private.account_deletion_state
     and request_row.purged_at is not null
     and request_row.cancelled_at is null then
    return pg_catalog.jsonb_build_object(
      'state', 'purged',
      'requestedAtMs', null,
      'purgeDeadlineMs', null
    );
  end if;

  raise exception using errcode = '55000', message = 'conflict';
exception
  when no_data_found or too_many_rows then
    raise exception using errcode = '28000', message = 'revoked';
end;
$$;

create function public.service_account_deletion_status_for_session(
  p_auth_user_id uuid,
  p_session_id uuid,
  p_workspace_id uuid
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  lifecycle_context jsonb;
begin
  lifecycle_context := context_relay_private.locked_account_lifecycle_context(
    p_auth_user_id,
    p_session_id,
    p_workspace_id
  );
  return context_relay_private.account_deletion_projection(
    (lifecycle_context ->> 'accountId')::uuid
  );
end;
$$;

create function public.service_begin_account_deletion_for_session(
  p_auth_user_id uuid,
  p_session_id uuid,
  p_workspace_id uuid,
  p_credential_authenticated_at_seconds bigint,
  p_request_id bytea
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  lifecycle_context jsonb;
  account_id uuid;
  receipt jsonb;
begin
  lifecycle_context := context_relay_private.locked_account_lifecycle_context(
    p_auth_user_id,
    p_session_id,
    p_workspace_id
  );
  account_id := (lifecycle_context ->> 'accountId')::uuid;
  perform context_relay_private.require_fresh_account_lifecycle_auth(
    p_credential_authenticated_at_seconds
  );
  receipt := context_relay_private.find_account_lifecycle_receipt(
    account_id, p_auth_user_id, p_session_id, p_workspace_id, p_request_id, 'begin_deletion'
  );
  if receipt is not null then
    return receipt;
  end if;
  perform public.service_begin_account_deletion(account_id);
  receipt := context_relay_private.account_deletion_projection(account_id);
  perform context_relay_private.store_account_lifecycle_receipt(
    account_id, p_auth_user_id, p_session_id, p_workspace_id, p_request_id, 'begin_deletion', receipt
  );
  return receipt;
exception
  when sqlstate '55000' then
    raise exception using errcode = '55000', message = 'conflict';
end;
$$;

create function public.service_cancel_account_deletion_for_session(
  p_auth_user_id uuid,
  p_session_id uuid,
  p_workspace_id uuid,
  p_credential_authenticated_at_seconds bigint,
  p_request_id bytea
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  lifecycle_context jsonb;
  account_id uuid;
  receipt jsonb;
begin
  lifecycle_context := context_relay_private.locked_account_lifecycle_context(
    p_auth_user_id,
    p_session_id,
    p_workspace_id
  );
  account_id := (lifecycle_context ->> 'accountId')::uuid;
  perform context_relay_private.require_fresh_account_lifecycle_auth(
    p_credential_authenticated_at_seconds
  );
  receipt := context_relay_private.find_account_lifecycle_receipt(
    account_id, p_auth_user_id, p_session_id, p_workspace_id, p_request_id, 'cancel_deletion'
  );
  if receipt is not null then
    return receipt;
  end if;
  perform public.service_cancel_account_deletion(account_id);
  receipt := context_relay_private.account_deletion_projection(account_id);
  perform context_relay_private.store_account_lifecycle_receipt(
    account_id, p_auth_user_id, p_session_id, p_workspace_id, p_request_id, 'cancel_deletion', receipt
  );
  return receipt;
exception
  when sqlstate '55000' then
    raise exception using errcode = '55000', message = 'conflict';
end;
$$;

alter function context_relay_private.locked_account_lifecycle_context(uuid, uuid, uuid)
owner to context_relay_rls_owner;
alter function context_relay_private.account_deletion_projection(uuid)
owner to context_relay_rls_owner;
alter function public.service_account_deletion_status_for_session(uuid, uuid, uuid)
owner to context_relay_rls_owner;
alter function public.service_begin_account_deletion_for_session(uuid, uuid, uuid, bigint, bytea)
owner to context_relay_rls_owner;
alter function public.service_cancel_account_deletion_for_session(uuid, uuid, uuid, bigint, bytea)
owner to context_relay_rls_owner;

revoke all on function context_relay_private.locked_account_lifecycle_context(uuid, uuid, uuid)
from public, anon, authenticated, service_role;
revoke all on function context_relay_private.account_deletion_projection(uuid)
from public, anon, authenticated, service_role;
revoke all on function context_relay_private.consume_account_lifecycle_request(uuid)
from public, anon, authenticated, service_role;
revoke all on function context_relay_private.require_fresh_account_lifecycle_auth(bigint)
from public, anon, authenticated, service_role;
revoke all on function context_relay_private.find_account_lifecycle_receipt(uuid, uuid, uuid, uuid, bytea, text)
from public, anon, authenticated, service_role;
revoke all on function context_relay_private.store_account_lifecycle_receipt(uuid, uuid, uuid, uuid, bytea, text, jsonb)
from public, anon, authenticated, service_role;
revoke all on function public.service_account_deletion_status_for_session(uuid, uuid, uuid)
from public, anon, authenticated, service_role;
revoke all on function public.service_begin_account_deletion_for_session(uuid, uuid, uuid, bigint, bytea)
from public, anon, authenticated, service_role;
revoke all on function public.service_cancel_account_deletion_for_session(uuid, uuid, uuid, bigint, bytea)
from public, anon, authenticated, service_role;

-- Retire the pre-Edge account-ID entrypoints from the service role. The new
-- wrappers derive the account only from the verified session binding.
revoke all on function public.service_begin_account_deletion(uuid)
from public, anon, authenticated, service_role;
revoke all on function public.service_cancel_account_deletion(uuid)
from public, anon, authenticated, service_role;

grant execute on function public.service_account_deletion_status_for_session(uuid, uuid, uuid)
to service_role;
grant execute on function public.service_begin_account_deletion_for_session(uuid, uuid, uuid, bigint, bytea)
to service_role;
grant execute on function public.service_cancel_account_deletion_for_session(uuid, uuid, uuid, bigint, bytea)
to service_role;

reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
