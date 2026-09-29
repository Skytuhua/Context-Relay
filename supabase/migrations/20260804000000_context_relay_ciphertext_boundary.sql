do $$
begin
  if not exists (select 1 from pg_catalog.pg_roles where rolname = 'context_relay_rls_owner') then
    create role context_relay_rls_owner nologin noinherit;
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
    raise exception using
      errcode = '42501',
      message = 'context_relay_rls_owner has unsafe attributes';
  end if;
end
$$;

-- PostgreSQL 17 gives a non-superuser CREATEROLE caller ADMIN-only membership
-- in a role it creates. Add SET only while assigning ownership, then revoke
-- that grant at the end of the transaction.
grant context_relay_rls_owner to current_user with inherit false, set true;

create schema if not exists context_relay_private;
alter schema context_relay_private owner to context_relay_rls_owner;
set local role context_relay_rls_owner;
revoke all on schema context_relay_private from public, anon, authenticated, service_role;
grant usage on schema context_relay_private to authenticated, service_role;
grant usage, create on schema context_relay_private to session_user;
reset role;
grant create on schema public to context_relay_rls_owner;

-- Hosted Supabase owns the auth schema with a managed role that cannot grant
-- schema USAGE to custom roles. This non-exposed bridge reads only the two
-- request claims needed by the dedicated identity helpers.
create function context_relay_private.request_auth_context()
returns table (
  auth_user_id uuid,
  session_id text
)
language sql
stable
security definer
set search_path = ''
as $auth_context$
  select auth.uid(), auth.jwt() ->> 'session_id'
$auth_context$;

revoke all on function context_relay_private.request_auth_context()
from public, anon, authenticated, service_role, context_relay_rls_owner;
grant execute on function context_relay_private.request_auth_context()
to context_relay_rls_owner;

create type context_relay_private.device_binding_state as enum (
  'pending',
  'active',
  'revoked'
);

create type context_relay_private.account_deletion_state as enum (
  'active',
  'pending_delete',
  'purged'
);

create type context_relay_private.pairing_request_state as enum (
  'pending',
  'approved',
  'rejected',
  'expired',
  'cancelled'
);

create type context_relay_private.upload_reservation_state as enum (
  'reserved',
  'finalized',
  'expired',
  'cancelled'
);

alter type context_relay_private.device_binding_state owner to context_relay_rls_owner;
alter type context_relay_private.account_deletion_state owner to context_relay_rls_owner;
alter type context_relay_private.pairing_request_state owner to context_relay_rls_owner;
alter type context_relay_private.upload_reservation_state owner to context_relay_rls_owner;

create function context_relay_private.valid_ciphertext_part_sizes(part_sizes jsonb)
returns boolean
language plpgsql
immutable
strict
security invoker
parallel safe
set search_path = ''
as $$
declare
  part_value jsonb;
  part_number numeric;
begin
  if pg_catalog.jsonb_typeof(part_sizes) <> 'array' then
    return false;
  end if;

  if pg_catalog.jsonb_array_length(part_sizes) = 0
     or pg_catalog.jsonb_array_length(part_sizes) > 16 then
    return false;
  end if;

  for part_value in
    select element.value
    from pg_catalog.jsonb_array_elements(part_sizes) as element(value)
  loop
    if pg_catalog.jsonb_typeof(part_value) <> 'number' then
      return false;
    end if;

    part_number := (part_value #>> '{}')::numeric;
    if part_number <> pg_catalog.trunc(part_number)
       or not (part_number > 0 and part_number <= 33554432) then
      return false;
    end if;
  end loop;

  return true;
end;
$$;

alter function context_relay_private.valid_ciphertext_part_sizes(jsonb) owner to context_relay_rls_owner;
revoke all on function context_relay_private.valid_ciphertext_part_sizes(jsonb)
from public, anon, authenticated, service_role;

create function context_relay_private.ciphertext_part_sizes_total(part_sizes jsonb)
returns bigint
language plpgsql
immutable
strict
security invoker
parallel safe
set search_path = ''
as $$
declare
  total_bytes bigint := 0;
  part_value jsonb;
begin
  if not context_relay_private.valid_ciphertext_part_sizes(part_sizes) then
    return null;
  end if;

  for part_value in
    select element.value
    from pg_catalog.jsonb_array_elements(part_sizes) as element(value)
  loop
    total_bytes := total_bytes + (part_value #>> '{}')::bigint;
  end loop;

  return total_bytes;
end;
$$;

alter function context_relay_private.ciphertext_part_sizes_total(jsonb) owner to context_relay_rls_owner;
revoke all on function context_relay_private.ciphertext_part_sizes_total(jsonb)
from public, anon, authenticated, service_role;

create function context_relay_private.valid_sync_causal_frontier(frontier jsonb)
returns boolean
language plpgsql
immutable
strict
security invoker
parallel safe
set search_path = ''
as $$
declare
  entry jsonb;
  device_id_text text;
  previous_device_id text;
  sequence_text text;
begin
  if pg_catalog.jsonb_typeof(frontier) <> 'array' then
    return false;
  end if;

  if pg_catalog.jsonb_array_length(frontier) > 10000 then
    return false;
  end if;

  for entry in
    select element.value
    from pg_catalog.jsonb_array_elements(frontier) as element(value)
  loop
    if pg_catalog.jsonb_typeof(entry) <> 'object' then
      return false;
    end if;

    if not (entry ? 'deviceId' and entry ? 'sequence')
       or (select pg_catalog.count(*) from pg_catalog.jsonb_object_keys(entry)) <> 2
       or pg_catalog.jsonb_typeof(entry -> 'deviceId') <> 'string'
       or (entry ->> 'deviceId') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       or pg_catalog.jsonb_typeof(entry -> 'sequence') <> 'string' then
      return false;
    end if;

    device_id_text := entry ->> 'deviceId';
    if previous_device_id is not null
       and device_id_text::pg_catalog.uuid <= previous_device_id::pg_catalog.uuid then
      return false;
    end if;
    previous_device_id := device_id_text;

    sequence_text := entry ->> 'sequence';
    if sequence_text !~ '^(0|[1-9][0-9]{0,19})$' then
      return false;
    end if;

    if sequence_text::numeric > 18446744073709551615 then
      return false;
    end if;
  end loop;

  return true;
end;
$$;

create function context_relay_private.valid_sync_blob_refs(blob_refs jsonb)
returns boolean
language plpgsql
immutable
strict
security invoker
parallel safe
set search_path = ''
as $$
declare
  entry jsonb;
  ciphertext_bytes_text text;
  storage_id_text text;
begin
  if pg_catalog.jsonb_typeof(blob_refs) <> 'array' then
    return false;
  end if;

  if pg_catalog.jsonb_array_length(blob_refs) > 10000 then
    return false;
  end if;

  for entry in
    select element.value
    from pg_catalog.jsonb_array_elements(blob_refs) as element(value)
  loop
    if pg_catalog.jsonb_typeof(entry) <> 'object' then
      return false;
    end if;

    if not (entry ? 'digest' and entry ? 'ciphertextBytes' and entry ? 'storageId')
       or (select pg_catalog.count(*) from pg_catalog.jsonb_object_keys(entry)) <> 3
       or pg_catalog.jsonb_typeof(entry -> 'digest') <> 'string'
       or (entry ->> 'digest') !~ '^[0-9a-f]{64}$'
       or pg_catalog.jsonb_typeof(entry -> 'ciphertextBytes') <> 'string'
       or pg_catalog.jsonb_typeof(entry -> 'storageId') <> 'string' then
      return false;
    end if;

    ciphertext_bytes_text := entry ->> 'ciphertextBytes';
    storage_id_text := entry ->> 'storageId';
    if ciphertext_bytes_text !~ '^[1-9][0-9]{0,19}$' then
      return false;
    end if;

    if ciphertext_bytes_text::numeric > 524288000
       or pg_catalog.btrim(
         storage_id_text,
         U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000'
       ) = ''
       or pg_catalog.octet_length(storage_id_text) > 512 then
      return false;
    end if;
  end loop;

  return true;
end;
$$;

create function context_relay_private.valid_hybrid_logical_clock(clock jsonb)
returns boolean
language plpgsql
immutable
strict
security invoker
parallel safe
set search_path = ''
as $$
declare
  physical_ms_text text;
  logical_text text;
begin
  if pg_catalog.jsonb_typeof(clock) <> 'object' then
    return false;
  end if;

  if not (clock ? 'physicalMs' and clock ? 'logical' and clock ? 'node')
     or (select pg_catalog.count(*) from pg_catalog.jsonb_object_keys(clock)) <> 3
     or pg_catalog.jsonb_typeof(clock -> 'physicalMs') <> 'string'
     or pg_catalog.jsonb_typeof(clock -> 'logical') <> 'number'
     or pg_catalog.jsonb_typeof(clock -> 'node') <> 'string'
     or (clock ->> 'node') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
    return false;
  end if;

  physical_ms_text := clock ->> 'physicalMs';
  if physical_ms_text !~ '^(0|[1-9][0-9]{0,19})$' then
    return false;
  end if;

  logical_text := clock ->> 'logical';
  if logical_text !~ '^(0|[1-9][0-9]*)$' then
    return false;
  end if;

  return physical_ms_text::numeric <= 18446744073709551615
    and logical_text::numeric <= 4294967295;
end;
$$;

alter function context_relay_private.valid_sync_causal_frontier(jsonb) owner to context_relay_rls_owner;
alter function context_relay_private.valid_sync_blob_refs(jsonb) owner to context_relay_rls_owner;
alter function context_relay_private.valid_hybrid_logical_clock(jsonb) owner to context_relay_rls_owner;

revoke all on function
  context_relay_private.valid_sync_causal_frontier(jsonb),
  context_relay_private.valid_sync_blob_refs(jsonb),
  context_relay_private.valid_hybrid_logical_clock(jsonb)
from public, anon, authenticated, service_role;

create table public.accounts (
  id uuid primary key,
  owner_user_id uuid not null,
  deletion_state context_relay_private.account_deletion_state not null default 'active',
  deletion_requested_at timestamptz,
  deletion_scheduled_for timestamptz,
  control_epoch bigint not null default 0,
  key_epoch bigint not null default 0,
  quota_limit_bytes bigint not null default 524288000,
  used_bytes bigint not null default 0,
  reserved_bytes bigint not null default 0,
  created_at timestamptz not null default pg_catalog.now(),
  updated_at timestamptz not null default pg_catalog.now(),
  constraint accounts_owner_user_id_key unique (owner_user_id),
  constraint accounts_id_owner_user_id_key unique (id, owner_user_id),
  constraint accounts_owner_user_id_fkey foreign key (owner_user_id) references auth.users (id) on delete restrict,
  constraint accounts_control_epoch_nonnegative_check check (control_epoch >= 0),
  constraint accounts_key_epoch_nonnegative_check check (key_epoch >= 0),
  constraint accounts_quota_limit_check check (quota_limit_bytes = 524288000),
  constraint accounts_used_bytes_nonnegative_check check (used_bytes >= 0),
  constraint accounts_reserved_bytes_nonnegative_check check (reserved_bytes >= 0),
  constraint accounts_quota_balance_check check (used_bytes + reserved_bytes <= quota_limit_bytes),
  constraint accounts_deletion_timestamps_check check (
    (deletion_state = 'active' and deletion_requested_at is null and deletion_scheduled_for is null)
    or (deletion_state = 'pending_delete' and deletion_requested_at is not null and deletion_scheduled_for is not null)
    or deletion_state = 'purged'
  )
);

create index accounts_deletion_state_idx on public.accounts (deletion_state);

create table public.device_bindings (
  id uuid primary key default pg_catalog.gen_random_uuid(),
  account_id uuid not null,
  auth_user_id uuid not null,
  session_id uuid not null,
  device_id uuid not null,
  state context_relay_private.device_binding_state not null default 'pending',
  expires_at timestamptz,
  revoked_at timestamptz,
  revocation_reason text,
  cutoff_device_sequence bigint,
  cutoff_hash bytea,
  cutoff_signature bytea,
  created_at timestamptz not null default pg_catalog.now(),
  updated_at timestamptz not null default pg_catalog.now(),
  constraint device_bindings_session_id_key unique (session_id),
  constraint device_bindings_account_device_binding_key unique (account_id, device_id, id),
  constraint device_bindings_account_owner_fkey foreign key (account_id, auth_user_id) references public.accounts (id, owner_user_id) on delete cascade,
  constraint device_bindings_cutoff_sequence_check check (cutoff_device_sequence is null or cutoff_device_sequence >= 0),
  constraint device_bindings_cutoff_hash_width_check check (cutoff_hash is null or pg_catalog.octet_length(cutoff_hash) = 32),
  constraint device_bindings_cutoff_signature_width_check check (cutoff_signature is null or pg_catalog.octet_length(cutoff_signature) = 64),
  constraint device_bindings_signed_cutoff_check check (
    (revoked_at is null and cutoff_device_sequence is null and cutoff_hash is null and cutoff_signature is null)
    or (revoked_at is not null and cutoff_device_sequence is not null and cutoff_hash is not null and cutoff_signature is not null)
  ),
  constraint device_bindings_revocation_state_check check ((state = 'revoked') = (revoked_at is not null))
);

create unique index device_bindings_one_live_per_device_idx
  on public.device_bindings (account_id, device_id)
  where state in ('pending', 'active');
create index device_bindings_account_owner_idx on public.device_bindings (account_id, auth_user_id);
create index device_bindings_auth_session_idx on public.device_bindings (auth_user_id, session_id);
create index device_bindings_state_idx on public.device_bindings (state);
create index device_bindings_expiry_idx on public.device_bindings (expires_at);
create index device_bindings_revoked_at_idx on public.device_bindings (revoked_at);

create table public.device_certificates (
  id uuid primary key,
  account_id uuid not null,
  workspace_id uuid not null,
  control_epoch bigint not null,
  request_nonce bytea not null,
  device_id uuid not null,
  issuer_kind text not null,
  issuer_device_id uuid,
  issuer_recovery_public_key bytea,
  issuer_signing_public_key bytea not null,
  device_signing_public_key bytea not null,
  device_wrapping_public_key bytea not null,
  signature bytea not null,
  created_at timestamptz not null default pg_catalog.now(),
  constraint device_certificates_account_workspace_device_key unique (account_id, workspace_id, device_id),
  constraint device_certificates_account_workspace_device_certificate_key unique (account_id, workspace_id, device_id, id),
  constraint device_certificates_account_fkey foreign key (account_id) references public.accounts (id) on delete cascade,
  constraint device_certificates_issuer_device_fkey foreign key (account_id, workspace_id, issuer_device_id) references public.device_certificates (account_id, workspace_id, device_id),
  constraint device_certificates_control_epoch_check check (control_epoch >= 0),
  constraint device_certificates_request_nonce_width_check check (pg_catalog.octet_length(request_nonce) = 32),
  constraint device_certificates_issuer_kind_check check (issuer_kind in ('device', 'recovery_root')),
  constraint device_certificates_issuer_source_check check (
    (issuer_kind = 'device' and issuer_device_id is not null and issuer_recovery_public_key is null)
    or (issuer_kind = 'recovery_root' and issuer_device_id is null and issuer_recovery_public_key is not null)
  ),
  constraint device_certificates_recovery_key_width_check check (issuer_recovery_public_key is null or pg_catalog.octet_length(issuer_recovery_public_key) = 32),
  constraint device_certificates_issuer_signing_key_width_check check (pg_catalog.octet_length(issuer_signing_public_key) = 32),
  constraint device_certificates_device_signing_key_width_check check (pg_catalog.octet_length(device_signing_public_key) = 32),
  constraint device_certificates_device_wrapping_key_width_check check (pg_catalog.octet_length(device_wrapping_public_key) = 32),
  constraint device_certificates_signature_width_check check (pg_catalog.octet_length(signature) = 64)
);

create index device_certificates_issuer_device_idx on public.device_certificates (account_id, workspace_id, issuer_device_id);

create table public.sync_operations (
  id uuid primary key,
  account_id uuid not null,
  workspace_id uuid not null,
  project_id uuid,
  record_id uuid not null,
  record_kind text not null,
  mutation_kind text not null,
  device_id uuid not null,
  device_certificate_id uuid not null,
  schema_version integer not null,
  device_sequence numeric not null,
  causal_frontier jsonb not null,
  control_epoch bigint not null,
  key_epoch bigint not null,
  previous_device_hash bytea not null,
  nonce bytea not null,
  ciphertext bytea not null,
  ciphertext_hash bytea not null,
  blob_refs jsonb not null default '[]'::jsonb,
  created_hlc jsonb not null,
  signature bytea not null,
  received_at timestamptz not null default pg_catalog.now(),
  constraint sync_operations_account_workspace_operation_key unique (account_id, workspace_id, id),
  constraint sync_operations_account_device_sequence_key unique (account_id, device_id, device_sequence),
  constraint sync_operations_device_certificate_fkey foreign key (account_id, workspace_id, device_id, device_certificate_id) references public.device_certificates (account_id, workspace_id, device_id, id),
  constraint sync_operations_uuid_v7_check check (
    id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and account_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and workspace_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and (project_id is null or project_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
    and record_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and device_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  constraint sync_operations_schema_version_check check (schema_version = 1),
  constraint sync_operations_record_kind_check check (record_kind in ('memory', 'memory_candidate', 'task', 'secret_ref', 'instruction', 'component', 'project')),
  constraint sync_operations_mutation_kind_check check (mutation_kind in ('upsert', 'tombstone')),
  constraint sync_operations_device_sequence_check check (
    device_sequence = pg_catalog.trunc(device_sequence)
    and device_sequence between 0 and 18446744073709551615
  ),
  constraint sync_operations_control_epoch_check check (control_epoch between 0 and 4294967295),
  constraint sync_operations_key_epoch_check check (key_epoch between 0 and 4294967295),
  constraint sync_operations_causal_frontier_check check (context_relay_private.valid_sync_causal_frontier(causal_frontier)),
  constraint sync_operations_previous_hash_width_check check (pg_catalog.octet_length(previous_device_hash) = 32),
  constraint sync_operations_nonce_width_check check (pg_catalog.octet_length(nonce) = 24),
  constraint sync_operations_ciphertext_size_check check (pg_catalog.octet_length(ciphertext) <= 4194304),
  constraint sync_operations_ciphertext_hash_width_check check (pg_catalog.octet_length(ciphertext_hash) = 32),
  constraint sync_operations_blob_refs_check check (context_relay_private.valid_sync_blob_refs(blob_refs)),
  constraint sync_operations_hlc_check check (context_relay_private.valid_hybrid_logical_clock(created_hlc)),
  constraint sync_operations_signature_width_check check (pg_catalog.octet_length(signature) = 64)
);

create index sync_operations_device_certificate_idx on public.sync_operations (account_id, workspace_id, device_id, device_certificate_id);
create index sync_operations_account_workspace_received_idx on public.sync_operations (account_id, workspace_id, received_at, id);

create function context_relay_private.charge_sync_operation_bytes()
returns trigger
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  account_state context_relay_private.account_deletion_state;
  account_used_bytes bigint;
  account_reserved_bytes bigint;
  account_quota_limit_bytes bigint;
  operation_ciphertext_bytes bigint;
begin
  operation_ciphertext_bytes := pg_catalog.octet_length(new.ciphertext);

  select
    account.deletion_state,
    account.used_bytes,
    account.reserved_bytes,
    account.quota_limit_bytes
  into
    account_state,
    account_used_bytes,
    account_reserved_bytes,
    account_quota_limit_bytes
  from public.accounts as account
  where account.id = new.account_id
  for update;

  if not found then
    raise exception using
      errcode = 'P0002',
      message = 'operation account not found';
  end if;

  if account_state <> 'active'::context_relay_private.account_deletion_state then
    raise exception using
      errcode = '55000',
      message = 'account state does not permit operation append';
  end if;

  if account_used_bytes + account_reserved_bytes + operation_ciphertext_bytes
       > account_quota_limit_bytes then
    raise exception using
      errcode = '23514',
      message = 'operation ciphertext exceeds account quota';
  end if;

  update public.accounts as account
  set used_bytes = account.used_bytes + operation_ciphertext_bytes,
      updated_at = pg_catalog.statement_timestamp()
  where account.id = new.account_id;

  return new;
end;
$$;

alter function context_relay_private.charge_sync_operation_bytes() owner to context_relay_rls_owner;
revoke all on function context_relay_private.charge_sync_operation_bytes()
from public, anon, authenticated, service_role;

create trigger sync_operations_charge_quota_before_insert
before insert on public.sync_operations
for each row
execute function context_relay_private.charge_sync_operation_bytes();

create table public.sync_checkpoints (
  id uuid primary key,
  account_id uuid not null,
  workspace_id uuid not null,
  creator_device_id uuid not null,
  device_certificate_id uuid not null,
  schema_version integer not null,
  previous_checkpoint_hash bytea not null,
  causal_frontier jsonb not null,
  state_hash bytea not null,
  key_epoch bigint not null,
  created_hlc jsonb not null,
  signature bytea not null,
  received_at timestamptz not null default pg_catalog.now(),
  constraint sync_checkpoints_account_workspace_checkpoint_key unique (account_id, workspace_id, id),
  constraint sync_checkpoints_device_certificate_fkey foreign key (account_id, workspace_id, creator_device_id, device_certificate_id) references public.device_certificates (account_id, workspace_id, device_id, id),
  constraint sync_checkpoints_routing_uuid_v7_check check (
    account_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and workspace_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and creator_device_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  constraint sync_checkpoints_schema_version_check check (schema_version = 1),
  constraint sync_checkpoints_previous_hash_width_check check (pg_catalog.octet_length(previous_checkpoint_hash) = 32),
  constraint sync_checkpoints_causal_frontier_check check (context_relay_private.valid_sync_causal_frontier(causal_frontier)),
  constraint sync_checkpoints_state_hash_width_check check (pg_catalog.octet_length(state_hash) = 32),
  constraint sync_checkpoints_key_epoch_check check (key_epoch between 0 and 4294967295),
  constraint sync_checkpoints_hlc_check check (context_relay_private.valid_hybrid_logical_clock(created_hlc)),
  constraint sync_checkpoints_signature_width_check check (pg_catalog.octet_length(signature) = 64)
);

create index sync_checkpoints_device_certificate_idx on public.sync_checkpoints (account_id, workspace_id, creator_device_id, device_certificate_id);
create index sync_checkpoints_account_workspace_received_idx on public.sync_checkpoints (account_id, workspace_id, received_at, id);
create index sync_checkpoints_creator_received_idx on public.sync_checkpoints (account_id, workspace_id, creator_device_id, received_at, id);
create index sync_checkpoints_causal_frontier_idx on public.sync_checkpoints using gin (causal_frontier jsonb_path_ops);

create table public.blob_manifests (
  id uuid primary key default pg_catalog.gen_random_uuid(),
  account_id uuid not null,
  workspace_id uuid not null,
  storage_id uuid not null,
  ciphertext_digest bytea not null,
  total_ciphertext_bytes bigint not null,
  ciphertext_part_sizes jsonb not null,
  part_count integer not null,
  creator_device_id uuid not null,
  device_certificate_id uuid not null,
  finalized_at timestamptz not null,
  created_at timestamptz not null default pg_catalog.now(),
  updated_at timestamptz not null default pg_catalog.now(),
  constraint blob_manifests_account_workspace_storage_key unique (account_id, workspace_id, storage_id),
  constraint blob_manifests_storage_id_key unique (storage_id),
  constraint blob_manifests_device_certificate_fkey foreign key (account_id, workspace_id, creator_device_id, device_certificate_id) references public.device_certificates (account_id, workspace_id, device_id, id),
  constraint blob_manifests_digest_width_check check (pg_catalog.octet_length(ciphertext_digest) = 32),
  constraint blob_manifests_total_size_check check (total_ciphertext_bytes > 0 and total_ciphertext_bytes <= 524288000),
  constraint blob_manifests_part_count_check check (part_count between 1 and 16),
  constraint blob_manifests_total_matches_parts_check check (
    total_ciphertext_bytes = context_relay_private.ciphertext_part_sizes_total(ciphertext_part_sizes)
  ),
  constraint blob_manifests_parts_array_check check (
    case
      when context_relay_private.valid_ciphertext_part_sizes(ciphertext_part_sizes)
      then pg_catalog.jsonb_array_length(ciphertext_part_sizes) = part_count
      else false
    end
  )
);

create index blob_manifests_device_certificate_idx on public.blob_manifests (account_id, workspace_id, creator_device_id, device_certificate_id);
create index blob_manifests_account_storage_idx on public.blob_manifests (account_id, storage_id);

create table public.pairing_requests (
  id uuid primary key,
  account_id uuid not null,
  workspace_id uuid not null,
  request_payload bytea not null,
  request_digest bytea not null,
  requester_signing_public_key bytea not null,
  requester_wrapping_public_key bytea not null,
  code_digest bytea not null,
  state context_relay_private.pairing_request_state not null default 'pending',
  expires_at timestamptz not null,
  decision_device_id uuid,
  decision_certificate_id uuid,
  decision_metadata jsonb,
  decided_at timestamptz,
  created_at timestamptz not null default pg_catalog.now(),
  updated_at timestamptz not null default pg_catalog.now(),
  constraint pairing_requests_account_workspace_request_key unique (account_id, workspace_id, id),
  constraint pairing_requests_account_fkey foreign key (account_id) references public.accounts (id) on delete cascade,
  constraint pairing_requests_decision_certificate_fkey foreign key (account_id, workspace_id, decision_device_id, decision_certificate_id) references public.device_certificates (account_id, workspace_id, device_id, id),
  constraint pairing_requests_request_digest_width_check check (pg_catalog.octet_length(request_digest) = 32),
  constraint pairing_requests_requester_signing_key_width_check check (pg_catalog.octet_length(requester_signing_public_key) = 32),
  constraint pairing_requests_requester_wrapping_key_width_check check (pg_catalog.octet_length(requester_wrapping_public_key) = 32),
  constraint pairing_requests_code_digest_width_check check (pg_catalog.octet_length(code_digest) = 32),
  constraint pairing_requests_decision_fields_check check ((decision_device_id is null) = (decision_certificate_id is null))
);

create index pairing_requests_decision_certificate_idx on public.pairing_requests (account_id, workspace_id, decision_device_id, decision_certificate_id);

create table public.recovery_roots (
  id uuid primary key,
  account_id uuid not null,
  signing_public_key bytea not null,
  wrapping_public_key bytea not null,
  encrypted_recovery_metadata bytea not null,
  revoked_at timestamptz,
  created_at timestamptz not null default pg_catalog.now(),
  updated_at timestamptz not null default pg_catalog.now(),
  constraint recovery_roots_account_root_key unique (account_id, id),
  constraint recovery_roots_account_fkey foreign key (account_id) references public.accounts (id) on delete cascade,
  constraint recovery_roots_signing_key_width_check check (pg_catalog.octet_length(signing_public_key) = 32),
  constraint recovery_roots_wrapping_key_width_check check (pg_catalog.octet_length(wrapping_public_key) = 32)
);

create table public.github_installations (
  id uuid primary key default pg_catalog.gen_random_uuid(),
  account_id uuid not null,
  installation_id bigint not null,
  encrypted_token_reference jsonb not null,
  created_at timestamptz not null default pg_catalog.now(),
  updated_at timestamptz not null default pg_catalog.now(),
  constraint github_installations_installation_id_key unique (installation_id),
  constraint github_installations_account_installation_key unique (account_id, installation_id),
  constraint github_installations_account_fkey foreign key (account_id) references public.accounts (id) on delete cascade,
  constraint github_installations_installation_id_check check (installation_id > 0),
  constraint github_installations_token_reference_check check (pg_catalog.jsonb_typeof(encrypted_token_reference) = 'object')
);

create table public.deletion_requests (
  id uuid primary key default pg_catalog.gen_random_uuid(),
  account_id uuid not null,
  state context_relay_private.account_deletion_state not null default 'pending_delete',
  requested_at timestamptz not null default pg_catalog.now(),
  grace_deadline timestamptz not null,
  cancelled_at timestamptz,
  purged_at timestamptz,
  transition_evidence jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default pg_catalog.now(),
  updated_at timestamptz not null default pg_catalog.now(),
  constraint deletion_requests_account_id_key unique (account_id),
  constraint deletion_requests_account_fkey foreign key (account_id) references public.accounts (id) on delete cascade,
  constraint deletion_requests_seven_day_deadline_check check (grace_deadline = requested_at + interval '7 days'),
  constraint deletion_requests_transition_evidence_check check (pg_catalog.jsonb_typeof(transition_evidence) = 'object'),
  constraint deletion_requests_terminal_timestamps_check check (not (cancelled_at is not null and purged_at is not null))
);

create table context_relay_private.blob_upload_reservations (
  id uuid primary key default pg_catalog.gen_random_uuid(),
  account_id uuid not null,
  workspace_id uuid not null,
  storage_id uuid not null,
  ciphertext_digest bytea not null,
  expected_total_bytes bigint not null,
  expected_part_sizes jsonb not null,
  part_count integer not null,
  state context_relay_private.upload_reservation_state not null default 'reserved',
  creator_device_id uuid not null,
  device_certificate_id uuid not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default pg_catalog.now(),
  updated_at timestamptz not null default pg_catalog.now(),
  constraint blob_upload_reservations_account_workspace_storage_key unique (account_id, workspace_id, storage_id),
  constraint blob_upload_reservations_storage_id_key unique (storage_id),
  constraint blob_upload_reservations_device_certificate_fkey foreign key (account_id, workspace_id, creator_device_id, device_certificate_id) references public.device_certificates (account_id, workspace_id, device_id, id),
  constraint blob_upload_reservations_digest_width_check check (pg_catalog.octet_length(ciphertext_digest) = 32),
  constraint blob_upload_reservations_total_size_check check (expected_total_bytes > 0 and expected_total_bytes <= 524288000),
  constraint blob_upload_reservations_part_count_check check (part_count between 1 and 16),
  constraint blob_upload_reservations_total_matches_parts_check check (
    expected_total_bytes = context_relay_private.ciphertext_part_sizes_total(expected_part_sizes)
  ),
  constraint blob_upload_reservations_parts_array_check check (
    case
      when context_relay_private.valid_ciphertext_part_sizes(expected_part_sizes)
      then pg_catalog.jsonb_array_length(expected_part_sizes) = part_count
      else false
    end
  )
);

create index blob_upload_reservations_device_certificate_idx
  on context_relay_private.blob_upload_reservations (account_id, workspace_id, creator_device_id, device_certificate_id);

alter table public.accounts owner to context_relay_rls_owner;
alter table public.device_bindings owner to context_relay_rls_owner;
alter table public.device_certificates owner to context_relay_rls_owner;
alter table public.sync_operations owner to context_relay_rls_owner;
alter table public.sync_checkpoints owner to context_relay_rls_owner;
alter table public.blob_manifests owner to context_relay_rls_owner;
alter table public.pairing_requests owner to context_relay_rls_owner;
alter table public.recovery_roots owner to context_relay_rls_owner;
alter table public.github_installations owner to context_relay_rls_owner;
alter table public.deletion_requests owner to context_relay_rls_owner;
alter table context_relay_private.blob_upload_reservations owner to context_relay_rls_owner;

set local role context_relay_rls_owner;
alter table public.accounts enable row level security;
alter table public.device_bindings enable row level security;
alter table public.device_certificates enable row level security;
alter table public.sync_operations enable row level security;
alter table public.sync_checkpoints enable row level security;
alter table public.blob_manifests enable row level security;
alter table public.pairing_requests enable row level security;
alter table public.recovery_roots enable row level security;
alter table public.github_installations enable row level security;
alter table public.deletion_requests enable row level security;
alter table context_relay_private.blob_upload_reservations enable row level security;

alter default privileges for role context_relay_rls_owner in schema public
  revoke all on tables from public, anon, authenticated, service_role;
alter default privileges for role context_relay_rls_owner in schema context_relay_private
  revoke all on tables from public, anon, authenticated, service_role;
alter default privileges for role context_relay_rls_owner in schema public
  revoke execute on functions from public, anon, authenticated, service_role;
alter default privileges for role context_relay_rls_owner in schema context_relay_private
  revoke execute on functions from public, anon, authenticated, service_role;

revoke all on table
  public.accounts,
  public.device_bindings,
  public.device_certificates,
  public.sync_operations,
  public.sync_checkpoints,
  public.blob_manifests,
  public.pairing_requests,
  public.recovery_roots,
  public.github_installations,
  public.deletion_requests,
  context_relay_private.blob_upload_reservations
from public, anon, authenticated, service_role;

create function context_relay_private.current_session_id()
returns uuid
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  raw_session_id text;
begin
  select auth_context.session_id
  into raw_session_id
  from context_relay_private.request_auth_context() as auth_context;

  return raw_session_id::uuid;
exception
  when invalid_text_representation then
    return null;
end;
$$;

create function context_relay_private.current_read_account_id()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select binding.account_id
  from public.device_bindings as binding
  join public.accounts as account
    on account.id = binding.account_id
   and account.owner_user_id = binding.auth_user_id
  cross join context_relay_private.request_auth_context() as auth_context
  where binding.auth_user_id = auth_context.auth_user_id
    and binding.session_id = context_relay_private.current_session_id()
    and binding.state = 'active'::context_relay_private.device_binding_state
    and binding.revoked_at is null
    and (binding.expires_at is null or binding.expires_at > pg_catalog.now())
    and account.deletion_state in (
      'active'::context_relay_private.account_deletion_state,
      'pending_delete'::context_relay_private.account_deletion_state
    )
$$;

create function context_relay_private.current_write_account_id()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select binding.account_id
  from public.device_bindings as binding
  join public.accounts as account
    on account.id = binding.account_id
   and account.owner_user_id = binding.auth_user_id
  cross join context_relay_private.request_auth_context() as auth_context
  where binding.auth_user_id = auth_context.auth_user_id
    and binding.session_id = context_relay_private.current_session_id()
    and binding.state = 'active'::context_relay_private.device_binding_state
    and binding.revoked_at is null
    and (binding.expires_at is null or binding.expires_at > pg_catalog.now())
    and account.deletion_state = 'active'::context_relay_private.account_deletion_state
$$;

create function context_relay_private.current_read_device_id()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select binding.device_id
  from public.device_bindings as binding
  join public.accounts as account
    on account.id = binding.account_id
   and account.owner_user_id = binding.auth_user_id
  cross join context_relay_private.request_auth_context() as auth_context
  where binding.auth_user_id = auth_context.auth_user_id
    and binding.session_id = context_relay_private.current_session_id()
    and binding.state = 'active'::context_relay_private.device_binding_state
    and binding.revoked_at is null
    and (binding.expires_at is null or binding.expires_at > pg_catalog.now())
    and account.deletion_state in (
      'active'::context_relay_private.account_deletion_state,
      'pending_delete'::context_relay_private.account_deletion_state
    )
$$;

create function context_relay_private.current_write_device_id()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select binding.device_id
  from public.device_bindings as binding
  join public.accounts as account
    on account.id = binding.account_id
   and account.owner_user_id = binding.auth_user_id
  cross join context_relay_private.request_auth_context() as auth_context
  where binding.auth_user_id = auth_context.auth_user_id
    and binding.session_id = context_relay_private.current_session_id()
    and binding.state = 'active'::context_relay_private.device_binding_state
    and binding.revoked_at is null
    and (binding.expires_at is null or binding.expires_at > pg_catalog.now())
    and account.deletion_state = 'active'::context_relay_private.account_deletion_state
$$;

alter function context_relay_private.current_session_id() owner to context_relay_rls_owner;
alter function context_relay_private.current_read_account_id() owner to context_relay_rls_owner;
alter function context_relay_private.current_write_account_id() owner to context_relay_rls_owner;
alter function context_relay_private.current_read_device_id() owner to context_relay_rls_owner;
alter function context_relay_private.current_write_device_id() owner to context_relay_rls_owner;

revoke all on function
  context_relay_private.current_session_id(),
  context_relay_private.current_read_account_id(),
  context_relay_private.current_write_account_id(),
  context_relay_private.current_read_device_id(),
  context_relay_private.current_write_device_id()
from public, anon, authenticated, service_role;

grant execute on function
  context_relay_private.current_read_account_id(),
  context_relay_private.current_write_account_id(),
  context_relay_private.current_read_device_id(),
  context_relay_private.current_write_device_id()
to authenticated;

grant select on table
  public.accounts,
  public.device_bindings,
  public.device_certificates,
  public.sync_operations,
  public.sync_checkpoints,
  public.blob_manifests
to authenticated;

create policy accounts_authenticated_read
on public.accounts
for select
to authenticated
using (id = (select context_relay_private.current_read_account_id()));

create policy device_bindings_authenticated_read
on public.device_bindings
for select
to authenticated
using (account_id = (select context_relay_private.current_read_account_id()));

create policy device_certificates_authenticated_read
on public.device_certificates
for select
to authenticated
using (account_id = (select context_relay_private.current_read_account_id()));

create policy sync_operations_authenticated_read
on public.sync_operations
for select
to authenticated
using (account_id = (select context_relay_private.current_read_account_id()));

create policy sync_checkpoints_authenticated_read
on public.sync_checkpoints
for select
to authenticated
using (account_id = (select context_relay_private.current_read_account_id()));

create policy blob_manifests_authenticated_read
on public.blob_manifests
for select
to authenticated
using (
  account_id = (select context_relay_private.current_read_account_id())
  and finalized_at is not null
);

create function public.service_revoke_device_binding(
  p_account_id uuid,
  p_device_id uuid,
  p_cutoff_sequence bigint,
  p_cutoff_hash bytea,
  p_cutoff_signature bytea
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  account_state context_relay_private.account_deletion_state;
  replay_binding_id uuid;
  history_binding_id uuid;
  max_prior_cutoff_sequence bigint;
  active_binding_id uuid;
  transition_time timestamptz := pg_catalog.statement_timestamp();
begin
  if p_account_id is null
     or p_device_id is null
     or p_cutoff_sequence is null
     or p_cutoff_hash is null
     or p_cutoff_signature is null then
    raise exception using
      errcode = '22004',
      message = 'revocation arguments must be non-null';
  end if;

  if p_cutoff_sequence < 0
     or pg_catalog.octet_length(p_cutoff_hash) <> 32
     or pg_catalog.octet_length(p_cutoff_signature) <> 64 then
    raise exception using
      errcode = '22023',
      message = 'invalid signed revocation cutoff';
  end if;

  select account.deletion_state
  into account_state
  from public.accounts as account
  where account.id = p_account_id
  for update;

  if not found then
    raise exception using
      errcode = 'P0002',
      message = 'account not found';
  end if;

  if account_state not in (
    'active'::context_relay_private.account_deletion_state,
    'pending_delete'::context_relay_private.account_deletion_state
  ) then
    raise exception using
      errcode = '55000',
      message = 'account state does not permit device revocation';
  end if;

  select binding.id
  into replay_binding_id
  from public.device_bindings as binding
  where binding.account_id = p_account_id
    and binding.device_id = p_device_id
    and binding.state = 'revoked'::context_relay_private.device_binding_state
    and binding.cutoff_device_sequence = p_cutoff_sequence
    and binding.cutoff_hash = p_cutoff_hash
    and binding.cutoff_signature = p_cutoff_signature
  order by binding.id
  limit 1
  for update;

  if found then
    return;
  end if;

  select
    binding.id,
    binding.cutoff_device_sequence
  into
    history_binding_id,
    max_prior_cutoff_sequence
  from public.device_bindings as binding
  where binding.account_id = p_account_id
    and binding.device_id = p_device_id
    and binding.state = 'revoked'::context_relay_private.device_binding_state
  order by binding.cutoff_device_sequence desc, binding.revoked_at desc, binding.id desc
  limit 1
  for update;

  if found and p_cutoff_sequence <= max_prior_cutoff_sequence then
    raise exception using
      errcode = '55000',
      message = 'revocation cutoff is stale or conflicts with history';
  end if;

  select binding.id
  into active_binding_id
  from public.device_bindings as binding
  where binding.account_id = p_account_id
    and binding.device_id = p_device_id
    and binding.state = 'active'::context_relay_private.device_binding_state
    and binding.revoked_at is null
    and (binding.expires_at is null or binding.expires_at > transition_time)
  order by binding.id
  for update;

  if not found then
    raise exception using
      errcode = '55000',
      message = 'live unexpired active device binding not found';
  end if;

  update public.device_bindings as binding
  set state = 'revoked'::context_relay_private.device_binding_state,
      revoked_at = transition_time,
      revocation_reason = 'service_revocation',
      cutoff_device_sequence = p_cutoff_sequence,
      cutoff_hash = p_cutoff_hash,
      cutoff_signature = p_cutoff_signature,
      updated_at = transition_time
  where binding.id = active_binding_id;

  update public.accounts as account
  set control_epoch = account.control_epoch + 1,
      key_epoch = account.key_epoch + 1,
      updated_at = transition_time
  where account.id = p_account_id;
end;
$$;

create function public.service_begin_account_deletion(p_account_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  account_state context_relay_private.account_deletion_state;
  request_row public.deletion_requests%rowtype;
  transition_time timestamptz := pg_catalog.statement_timestamp();
begin
  if p_account_id is null then
    raise exception using
      errcode = '22004',
      message = 'account ID must be non-null';
  end if;

  select account.deletion_state
  into account_state
  from public.accounts as account
  where account.id = p_account_id
  for update;

  if not found then
    raise exception using
      errcode = 'P0002',
      message = 'account not found';
  end if;

  select request.*
  into request_row
  from public.deletion_requests as request
  where request.account_id = p_account_id
  for update;

  if account_state = 'pending_delete'::context_relay_private.account_deletion_state then
    if not found
       or request_row.state <> 'pending_delete'::context_relay_private.account_deletion_state
       or request_row.cancelled_at is not null
       or request_row.purged_at is not null
       or not exists (
         select 1
         from public.accounts as account
         where account.id = p_account_id
           and account.deletion_requested_at = request_row.requested_at
           and account.deletion_scheduled_for = request_row.grace_deadline
       ) then
      raise exception using
        errcode = '55000',
        message = 'conflicting pending deletion state';
    end if;

    return request_row.id;
  end if;

  if account_state <> 'active'::context_relay_private.account_deletion_state then
    raise exception using
      errcode = '55000',
      message = 'account deletion state is terminal';
  end if;

  if found then
    if request_row.state <> 'active'::context_relay_private.account_deletion_state
       or request_row.cancelled_at is null
       or request_row.purged_at is not null then
      raise exception using
        errcode = '55000',
        message = 'deletion lifecycle record is terminal or inconsistent';
    end if;

    update public.deletion_requests as request
    set state = 'pending_delete'::context_relay_private.account_deletion_state,
        requested_at = transition_time,
        grace_deadline = transition_time + interval '7 days',
        cancelled_at = null,
        purged_at = null,
        updated_at = transition_time
    where request.id = request_row.id
    returning request.* into request_row;
  else
    insert into public.deletion_requests (
      account_id,
      state,
      requested_at,
      grace_deadline,
      cancelled_at,
      purged_at,
      created_at,
      updated_at
    ) values (
      p_account_id,
      'pending_delete'::context_relay_private.account_deletion_state,
      transition_time,
      transition_time + interval '7 days',
      null,
      null,
      transition_time,
      transition_time
    )
    returning * into request_row;
  end if;

  update public.accounts as account
  set deletion_state = 'pending_delete'::context_relay_private.account_deletion_state,
      deletion_requested_at = transition_time,
      deletion_scheduled_for = transition_time + interval '7 days',
      updated_at = transition_time
  where account.id = p_account_id;

  return request_row.id;
end;
$$;

create function public.service_cancel_account_deletion(p_account_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  account_row public.accounts%rowtype;
  request_row public.deletion_requests%rowtype;
  transition_time timestamptz := pg_catalog.statement_timestamp();
begin
  if p_account_id is null then
    raise exception using
      errcode = '22004',
      message = 'account ID must be non-null';
  end if;

  select account.*
  into account_row
  from public.accounts as account
  where account.id = p_account_id
  for update;

  if not found then
    raise exception using
      errcode = 'P0002',
      message = 'account not found';
  end if;

  select request.*
  into request_row
  from public.deletion_requests as request
  where request.account_id = p_account_id
  for update;

  if not found then
    raise exception using
      errcode = '55000',
      message = 'pending deletion request not found';
  end if;

  if account_row.deletion_state = 'pending_delete'::context_relay_private.account_deletion_state then
    if request_row.state <> 'pending_delete'::context_relay_private.account_deletion_state
       or request_row.cancelled_at is not null
       or request_row.purged_at is not null
       or account_row.deletion_requested_at <> request_row.requested_at
       or account_row.deletion_scheduled_for <> request_row.grace_deadline
       or request_row.grace_deadline <= transition_time then
      raise exception using
        errcode = '55000',
        message = 'deletion request is expired, terminal, or inconsistent';
    end if;

    update public.deletion_requests as request
    set state = 'active'::context_relay_private.account_deletion_state,
        cancelled_at = transition_time,
        updated_at = transition_time
    where request.id = request_row.id;

    update public.accounts as account
    set deletion_state = 'active'::context_relay_private.account_deletion_state,
        deletion_requested_at = null,
        deletion_scheduled_for = null,
        updated_at = transition_time
    where account.id = p_account_id;

    return;
  end if;

  if account_row.deletion_state = 'active'::context_relay_private.account_deletion_state
     and account_row.deletion_requested_at is null
     and account_row.deletion_scheduled_for is null
     and request_row.state = 'active'::context_relay_private.account_deletion_state
     and request_row.cancelled_at is not null
     and request_row.purged_at is null
     and request_row.grace_deadline > transition_time then
    return;
  end if;

  raise exception using
    errcode = '55000',
    message = 'account deletion cannot be cancelled from its current state';
end;
$$;

alter function public.service_revoke_device_binding(uuid, uuid, bigint, bytea, bytea) owner to context_relay_rls_owner;
alter function public.service_begin_account_deletion(uuid) owner to context_relay_rls_owner;
alter function public.service_cancel_account_deletion(uuid) owner to context_relay_rls_owner;

revoke all on function public.service_revoke_device_binding(uuid, uuid, bigint, bytea, bytea)
from public, anon, authenticated, service_role;
revoke all on function public.service_begin_account_deletion(uuid)
from public, anon, authenticated, service_role;
revoke all on function public.service_cancel_account_deletion(uuid)
from public, anon, authenticated, service_role;

grant execute on function public.service_revoke_device_binding(uuid, uuid, bigint, bytea, bytea)
to service_role;
grant execute on function public.service_begin_account_deletion(uuid)
to service_role;
grant execute on function public.service_cancel_account_deletion(uuid)
to service_role;

create function public.service_reserve_blob_upload(
  p_account_id uuid,
  p_device_id uuid,
  p_storage_id uuid,
  p_ciphertext_sha256 bytea,
  p_part_sizes bigint[],
  p_expires_at timestamptz
)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  account_row public.accounts%rowtype;
  certificate_count bigint;
  certificate_id uuid;
  certificate_workspace_id uuid;
  part_size bigint;
  requested_total_bytes bigint := 0;
  transition_time timestamptz := pg_catalog.statement_timestamp();
begin
  if p_account_id is null
     or p_device_id is null
     or p_storage_id is null
     or p_ciphertext_sha256 is null
     or p_part_sizes is null
     or p_expires_at is null then
    raise exception using
      errcode = '22004',
      message = 'blob reservation arguments must be non-null';
  end if;

  if pg_catalog.octet_length(p_ciphertext_sha256) <> 32 then
    raise exception using
      errcode = '22023',
      message = 'ciphertext digest must be exactly 32 bytes';
  end if;

  if pg_catalog.array_ndims(p_part_sizes) <> 1
     or pg_catalog.cardinality(p_part_sizes) not between 1 and 16 then
    raise exception using
      errcode = '22023',
      message = 'ciphertext upload must contain one through sixteen parts';
  end if;

  foreach part_size in array p_part_sizes
  loop
    if part_size is null or part_size <= 0 or part_size > 33554432 then
      raise exception using
        errcode = '22023',
        message = 'ciphertext part size is outside the permitted range';
    end if;
    requested_total_bytes := requested_total_bytes + part_size;
  end loop;

  if requested_total_bytes > 524288000 then
    raise exception using
      errcode = '22023',
      message = 'ciphertext upload exceeds the logical blob limit';
  end if;

  if p_expires_at <= transition_time then
    raise exception using
      errcode = '22023',
      message = 'blob reservation expiry must be in the future';
  end if;

  select account.*
  into account_row
  from public.accounts as account
  where account.id = p_account_id
  for update;

  if not found then
    raise exception using
      errcode = 'P0002',
      message = 'blob reservation account not found';
  end if;

  if account_row.deletion_state <> 'active'::context_relay_private.account_deletion_state then
    raise exception using
      errcode = '55000',
      message = 'account state does not permit blob reservation';
  end if;

  if account_row.used_bytes < 0
     or account_row.reserved_bytes < 0
     or account_row.used_bytes + account_row.reserved_bytes > account_row.quota_limit_bytes then
    raise exception using
      errcode = '23514',
      message = 'account quota counters are inconsistent';
  end if;

  select pg_catalog.count(*)
  into certificate_count
  from public.device_certificates as certificate
  where certificate.account_id = p_account_id
    and certificate.device_id = p_device_id
    and exists (
      select 1
      from public.device_bindings as binding
      where binding.account_id = p_account_id
        and binding.device_id = p_device_id
        and binding.state = 'active'::context_relay_private.device_binding_state
        and binding.revoked_at is null
        and (binding.expires_at is null or binding.expires_at > transition_time)
    );

  if certificate_count <> 1 then
    raise exception using
      errcode = '55000',
      message = 'missing or ambiguous device certificate for blob reservation';
  end if;

  select certificate.id, certificate.workspace_id
  into certificate_id, certificate_workspace_id
  from public.device_certificates as certificate
  where certificate.account_id = p_account_id
    and certificate.device_id = p_device_id;

  if exists (
       select 1
       from context_relay_private.blob_upload_reservations as reservation
       where reservation.storage_id = p_storage_id
     )
     or exists (
       select 1
       from public.blob_manifests as manifest
       where manifest.storage_id = p_storage_id
     ) then
    raise exception using
      errcode = '23505',
      message = 'blob storage ID already exists';
  end if;

  if requested_total_bytes
       > account_row.quota_limit_bytes - account_row.used_bytes - account_row.reserved_bytes then
    raise exception using
      errcode = '23514',
      message = 'blob reservation exceeds remaining account quota';
  end if;

  insert into context_relay_private.blob_upload_reservations (
    account_id, workspace_id, storage_id, ciphertext_digest,
    expected_total_bytes, expected_part_sizes, part_count, state,
    creator_device_id, device_certificate_id, expires_at, created_at, updated_at
  ) values (
    p_account_id, certificate_workspace_id, p_storage_id, p_ciphertext_sha256,
    requested_total_bytes, pg_catalog.to_jsonb(p_part_sizes), pg_catalog.cardinality(p_part_sizes),
    'reserved'::context_relay_private.upload_reservation_state,
    p_device_id, certificate_id, p_expires_at, transition_time, transition_time
  );

  update public.accounts as account
  set reserved_bytes = account.reserved_bytes + requested_total_bytes,
      updated_at = transition_time
  where account.id = p_account_id;
end;
$$;

alter function public.service_reserve_blob_upload(uuid, uuid, uuid, bytea, bigint[], timestamptz)
owner to context_relay_rls_owner;
revoke all on function public.service_reserve_blob_upload(uuid, uuid, uuid, bytea, bigint[], timestamptz)
from public, anon, authenticated, service_role;

create function public.service_finalize_blob_upload(p_storage_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  account_id_for_lock uuid;
  account_row public.accounts%rowtype;
  reservation_row context_relay_private.blob_upload_reservations%rowtype;
  manifest_row public.blob_manifests%rowtype;
  actual_object_count bigint;
  object_set_invalid boolean;
  transition_time timestamptz := pg_catalog.statement_timestamp();
begin
  if p_storage_id is null then
    raise exception using errcode = '22004', message = 'blob storage ID must be non-null';
  end if;

  select reservation.account_id into account_id_for_lock
  from context_relay_private.blob_upload_reservations as reservation
  where reservation.storage_id = p_storage_id;
  if not found then
    raise exception using errcode = 'P0002', message = 'blob upload reservation not found';
  end if;

  -- Stable transition order: lock the account row first, then the upload reservation.
  select account.* into account_row
  from public.accounts as account
  where account.id = account_id_for_lock
  for update;
  if not found then
    raise exception using errcode = 'P0002', message = 'blob reservation account not found';
  end if;

  select reservation.* into reservation_row
  from context_relay_private.blob_upload_reservations as reservation
  where reservation.storage_id = p_storage_id
    and reservation.account_id = account_id_for_lock
  for update;
  if not found then
    raise exception using errcode = '55000', message = 'blob upload reservation changed during finalization';
  end if;

  if reservation_row.state = 'finalized'::context_relay_private.upload_reservation_state then
    select manifest.* into manifest_row
    from public.blob_manifests as manifest
    where manifest.storage_id = p_storage_id;
    if not found
       or manifest_row.account_id is distinct from reservation_row.account_id
       or manifest_row.workspace_id is distinct from reservation_row.workspace_id
       or manifest_row.ciphertext_digest is distinct from reservation_row.ciphertext_digest
       or manifest_row.total_ciphertext_bytes is distinct from reservation_row.expected_total_bytes
       or manifest_row.ciphertext_part_sizes is distinct from reservation_row.expected_part_sizes
       or manifest_row.part_count is distinct from reservation_row.part_count
       or manifest_row.creator_device_id is distinct from reservation_row.creator_device_id
       or manifest_row.device_certificate_id is distinct from reservation_row.device_certificate_id then
      raise exception using errcode = '55000', message = 'finalized blob manifest conflicts with its reservation';
    end if;
    return;
  end if;

  if reservation_row.state <> 'reserved'::context_relay_private.upload_reservation_state then
    raise exception using errcode = '55000', message = 'blob upload reservation is already terminal';
  end if;
  if reservation_row.expires_at <= transition_time then
    raise exception using errcode = '55000', message = 'expired blob upload reservation cannot finalize';
  end if;
  if account_row.deletion_state <> 'active'::context_relay_private.account_deletion_state then
    raise exception using errcode = '55000', message = 'account state does not permit blob finalization';
  end if;
  if not exists (
    select 1
    from public.device_bindings as binding
    where binding.account_id = reservation_row.account_id
      and binding.device_id = reservation_row.creator_device_id
      and binding.state = 'active'::context_relay_private.device_binding_state
      and binding.revoked_at is null
      and (binding.expires_at is null or binding.expires_at > transition_time)
  ) then
    raise exception using errcode = '55000', message = 'active creator device binding required for blob finalization';
  end if;
  if account_row.reserved_bytes < reservation_row.expected_total_bytes
     or account_row.used_bytes < 0
     or account_row.used_bytes + account_row.reserved_bytes > account_row.quota_limit_bytes then
    raise exception using errcode = '23514', message = 'blob reservation quota counters are inconsistent';
  end if;
  if exists (select 1 from public.blob_manifests as manifest where manifest.storage_id = p_storage_id) then
    raise exception using errcode = '23505', message = 'blob manifest already exists for reserved upload';
  end if;

  with expected as (
    select reservation_row.account_id::text || '/' || reservation_row.storage_id::text || '/'
      || pg_catalog.lpad(part.part_index::text, 8, '0') || '.bin' as object_name,
      (reservation_row.expected_part_sizes ->> part.part_index)::bigint as expected_size
    from pg_catalog.generate_series(0, reservation_row.part_count - 1) as part(part_index)
  ), actual as (
    select object.name as object_name, object.metadata,
      pg_catalog.jsonb_typeof(object.metadata -> 'size') = 'number' as size_is_number
    from storage.objects as object
    where object.bucket_id = 'ciphertext'
      and object.name like reservation_row.account_id::text || '/'
        || reservation_row.storage_id::text || '/%'
  ), compared as (
    select expected.expected_size, actual.metadata, actual.size_is_number
    from expected full join actual using (object_name)
  )
  select (select pg_catalog.count(*) from actual),
    exists (select 1 from compared
      where expected_size is null
         or metadata is null
         or case
           when size_is_number then
             (metadata ->> 'size')::numeric <> pg_catalog.trunc((metadata ->> 'size')::numeric)
             or (metadata ->> 'size')::numeric <> expected_size::numeric
           else true
         end)
  into actual_object_count, object_set_invalid;

  if actual_object_count <> reservation_row.part_count or object_set_invalid then
    raise exception using errcode = '55000', message = 'Storage object set does not exactly match blob reservation';
  end if;

  insert into public.blob_manifests (
    account_id, workspace_id, storage_id, ciphertext_digest, total_ciphertext_bytes,
    ciphertext_part_sizes, part_count, creator_device_id, device_certificate_id,
    finalized_at, created_at, updated_at
  ) values (
    reservation_row.account_id, reservation_row.workspace_id, reservation_row.storage_id,
    reservation_row.ciphertext_digest, reservation_row.expected_total_bytes,
    reservation_row.expected_part_sizes, reservation_row.part_count,
    reservation_row.creator_device_id, reservation_row.device_certificate_id,
    transition_time, transition_time, transition_time
  );
  update public.accounts as account
  set reserved_bytes = account.reserved_bytes - reservation_row.expected_total_bytes,
      used_bytes = account.used_bytes + reservation_row.expected_total_bytes,
      updated_at = transition_time
  where account.id = reservation_row.account_id;
  update context_relay_private.blob_upload_reservations as reservation
  set state = 'finalized'::context_relay_private.upload_reservation_state,
      updated_at = transition_time
  where reservation.id = reservation_row.id;
end;
$$;

alter function public.service_finalize_blob_upload(uuid) owner to context_relay_rls_owner;
revoke all on function public.service_finalize_blob_upload(uuid)
from public, anon, authenticated, service_role;

create function public.service_release_blob_upload(
  p_storage_id uuid,
  p_terminal_state context_relay_private.upload_reservation_state
)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  account_id_for_lock uuid;
  account_row public.accounts%rowtype;
  reservation_row context_relay_private.blob_upload_reservations%rowtype;
  transition_time timestamptz := pg_catalog.statement_timestamp();
begin
  if p_storage_id is null or p_terminal_state is null then
    raise exception using errcode = '22004', message = 'blob release arguments must be non-null';
  end if;
  if p_terminal_state not in (
    'expired'::context_relay_private.upload_reservation_state,
    'cancelled'::context_relay_private.upload_reservation_state
  ) then
    raise exception using errcode = '22023', message = 'blob release terminal state must be expired or cancelled';
  end if;

  select reservation.account_id into account_id_for_lock
  from context_relay_private.blob_upload_reservations as reservation
  where reservation.storage_id = p_storage_id;
  if not found then
    raise exception using errcode = 'P0002', message = 'blob upload reservation not found';
  end if;

  -- Stable transition order: lock the account row first, then the upload reservation.
  select account.* into account_row
  from public.accounts as account
  where account.id = account_id_for_lock
  for update;
  if not found then
    raise exception using errcode = 'P0002', message = 'blob reservation account not found';
  end if;

  select reservation.* into reservation_row
  from context_relay_private.blob_upload_reservations as reservation
  where reservation.storage_id = p_storage_id
    and reservation.account_id = account_id_for_lock
  for update;
  if not found then
    raise exception using errcode = '55000', message = 'blob upload reservation changed during release';
  end if;

  if reservation_row.state = p_terminal_state then
    return;
  end if;
  if reservation_row.state <> 'reserved'::context_relay_private.upload_reservation_state then
    raise exception using errcode = '55000', message = 'blob upload reservation has a different terminal state';
  end if;
  if p_terminal_state = 'expired'::context_relay_private.upload_reservation_state
     and reservation_row.expires_at > transition_time then
    raise exception using errcode = '55000', message = 'unexpired blob upload reservation cannot be expired';
  end if;
  if account_row.reserved_bytes < reservation_row.expected_total_bytes
     or account_row.reserved_bytes < 0
     or account_row.used_bytes + account_row.reserved_bytes > account_row.quota_limit_bytes then
    raise exception using errcode = '23514', message = 'blob release quota counters are inconsistent';
  end if;

  update public.accounts as account
  set reserved_bytes = account.reserved_bytes - reservation_row.expected_total_bytes,
      updated_at = transition_time
  where account.id = reservation_row.account_id;
  update context_relay_private.blob_upload_reservations as reservation
  set state = p_terminal_state,
      updated_at = transition_time
  where reservation.id = reservation_row.id;
end;
$$;

alter function public.service_release_blob_upload(uuid, context_relay_private.upload_reservation_state)
owner to context_relay_rls_owner;
revoke all on function public.service_release_blob_upload(uuid, context_relay_private.upload_reservation_state)
from public, anon, authenticated, service_role;

create function context_relay_private.can_upload_ciphertext_object(
  p_bucket_id text,
  p_name text,
  p_metadata jsonb
)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  path_account_id uuid;
  path_storage_id uuid;
  path_part_index integer;
  metadata_size numeric;
  write_account_id uuid;
  write_device_id uuid;
begin
  if p_bucket_id is distinct from 'ciphertext'
     or p_name is null
     or p_name !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9]{8}\.bin$' then
    return false;
  end if;
  if p_metadata is null
     or pg_catalog.jsonb_typeof(p_metadata -> 'size') is null
     or pg_catalog.jsonb_typeof(p_metadata -> 'size') <> 'number' then
    return false;
  end if;

  metadata_size := (p_metadata ->> 'size')::numeric;
  if metadata_size <> pg_catalog.trunc(metadata_size)
     or metadata_size <= 0 or metadata_size > 33554432 then
    return false;
  end if;

  path_account_id := pg_catalog.split_part(p_name, '/', 1)::uuid;
  path_storage_id := pg_catalog.split_part(p_name, '/', 2)::uuid;
  path_part_index := pg_catalog.split_part(pg_catalog.split_part(p_name, '/', 3), '.', 1)::integer;
  write_account_id := context_relay_private.current_write_account_id();
  write_device_id := context_relay_private.current_write_device_id();
  if write_account_id is null or write_device_id is null or path_account_id <> write_account_id then
    return false;
  end if;

  return exists (
    select 1
    from context_relay_private.blob_upload_reservations as reservation
    where reservation.account_id = write_account_id
      and reservation.storage_id = path_storage_id
      and reservation.creator_device_id = write_device_id
      and reservation.state = 'reserved'::context_relay_private.upload_reservation_state
      and reservation.expires_at > pg_catalog.statement_timestamp()
      and path_part_index between 0 and reservation.part_count - 1
      and p_name = reservation.account_id::text || '/' || reservation.storage_id::text || '/'
        || pg_catalog.lpad(path_part_index::text, 8, '0') || '.bin'
      and pg_catalog.jsonb_typeof(p_metadata -> 'size') = 'number'
      and metadata_size = (reservation.expected_part_sizes ->> path_part_index)::numeric
  );
exception
  when invalid_text_representation or numeric_value_out_of_range then return false;
end;
$$;

alter function context_relay_private.can_upload_ciphertext_object(text, text, jsonb)
owner to context_relay_rls_owner;
revoke all on function context_relay_private.can_upload_ciphertext_object(text, text, jsonb)
from public, anon, authenticated, service_role;

create function context_relay_private.can_read_ciphertext_object(
  p_bucket_id text,
  p_name text
)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  path_account_id uuid;
  path_storage_id uuid;
  path_part_index integer;
  read_account_id uuid;
begin
  if p_bucket_id is distinct from 'ciphertext'
     or p_name is null
     or p_name !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9]{8}\.bin$' then
    return false;
  end if;

  path_account_id := pg_catalog.split_part(p_name, '/', 1)::uuid;
  path_storage_id := pg_catalog.split_part(p_name, '/', 2)::uuid;
  path_part_index := pg_catalog.split_part(pg_catalog.split_part(p_name, '/', 3), '.', 1)::integer;
  read_account_id := context_relay_private.current_read_account_id();
  if read_account_id is null or path_account_id <> read_account_id then
    return false;
  end if;

  return exists (
    select 1
    from public.blob_manifests as manifest
    where manifest.account_id = read_account_id
      and manifest.storage_id = path_storage_id
      and path_part_index between 0 and manifest.part_count - 1
      and p_name = manifest.account_id::text || '/' || manifest.storage_id::text || '/'
        || pg_catalog.lpad(path_part_index::text, 8, '0') || '.bin'
  );
exception
  when invalid_text_representation or numeric_value_out_of_range then return false;
end;
$$;

alter function context_relay_private.can_read_ciphertext_object(text, text)
owner to context_relay_rls_owner;
revoke all on function context_relay_private.can_read_ciphertext_object(text, text)
from public, anon, authenticated, service_role;

grant execute on function public.service_reserve_blob_upload(uuid, uuid, uuid, bytea, bigint[], timestamptz)
to service_role;
grant execute on function public.service_finalize_blob_upload(uuid)
to service_role;
grant execute on function public.service_release_blob_upload(uuid, context_relay_private.upload_reservation_state)
to service_role;
grant execute on function context_relay_private.can_upload_ciphertext_object(text, text, jsonb)
to authenticated;
grant execute on function context_relay_private.can_read_ciphertext_object(text, text)
to authenticated;

reset role;
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('ciphertext', 'ciphertext', false, 33554432, null)
on conflict (id) do update
set name = excluded.name,
    public = excluded.public,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

grant usage on schema storage to context_relay_rls_owner;
grant select on table storage.objects to context_relay_rls_owner;

create policy ciphertext_objects_authenticated_insert
on storage.objects
for insert
to authenticated
with check (context_relay_private.can_upload_ciphertext_object(bucket_id, name, metadata));

create policy ciphertext_objects_authenticated_select
on storage.objects
for select
to authenticated
using (
  context_relay_private.can_read_ciphertext_object(bucket_id, name)
  or (
    storage.allow_only_operation('storage.object.upload')
    and context_relay_private.can_upload_ciphertext_object(bucket_id, name, metadata)
  )
);

create policy ciphertext_objects_rls_owner_select
on storage.objects
for select
to context_relay_rls_owner
using (bucket_id = 'ciphertext');

create policy context_relay_authenticated_sync_hint_read
on realtime.messages
for select
to authenticated
using (
  extension = 'broadcast'
  and (select realtime.topic()) = 'account:'
    || (select context_relay_private.current_read_account_id())::text
    || ':sync'
);

revoke create on schema public from context_relay_rls_owner;
set local role context_relay_rls_owner;
revoke all on schema context_relay_private from session_user;
reset role;
revoke context_relay_rls_owner from current_user granted by current_user;
