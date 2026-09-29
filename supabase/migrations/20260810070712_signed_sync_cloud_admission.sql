-- Context Relay Task 16: service-only admission for canonical signed ciphertext.
-- This migration is intentionally fail-closed if a pre-release deployment has
-- already accepted rows that cannot be reconstructed into exact canonical CBOR.

create extension if not exists pgcrypto with schema extensions;

do $$
begin
  if exists (select 1 from public.sync_operations)
     or exists (select 1 from public.sync_checkpoints) then
    raise exception using
      errcode = '55000',
      message = 'signed sync canonical hash migration requires empty pre-release logs';
  end if;
end;
$$;

do $$
begin
  if not exists (
    select 1
    from pg_catalog.pg_roles
    where rolname = 'context_relay_rls_owner'
  ) then
    raise exception using
      errcode = '42704',
      message = 'context_relay_rls_owner is missing';
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

grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
grant usage on schema realtime to context_relay_rls_owner;
grant execute on function realtime.send(jsonb, text, text, boolean)
to context_relay_rls_owner;
set local role context_relay_rls_owner;

alter table public.sync_operations
  add column canonical_sha256 bytea;
alter table public.sync_operations
  alter column canonical_sha256 set not null;
alter table public.sync_operations
  add constraint sync_operations_canonical_sha256_width_check
  check (pg_catalog.octet_length(canonical_sha256) = 32);

alter table public.sync_operations
  drop constraint sync_operations_account_device_sequence_key;
alter table public.sync_operations
  add constraint sync_operations_account_workspace_device_sequence_key
  unique (account_id, workspace_id, device_id, device_sequence);

alter table public.sync_checkpoints
  add column canonical_sha256 bytea;
alter table public.sync_checkpoints
  alter column canonical_sha256 set not null;
alter table public.sync_checkpoints
  add constraint sync_checkpoints_canonical_sha256_width_check
  check (pg_catalog.octet_length(canonical_sha256) = 32);
alter table public.sync_checkpoints
  add constraint sync_checkpoints_account_workspace_canonical_hash_key
  unique (account_id, workspace_id, canonical_sha256);
alter table public.sync_checkpoints
  alter column id set default pg_catalog.gen_random_uuid();
alter table public.sync_checkpoints
  drop constraint sync_checkpoints_schema_version_check;
alter table public.sync_checkpoints
  add constraint sync_checkpoints_schema_version_check
  check (schema_version = 2);
create index sync_checkpoints_account_workspace_received_hash_idx
  on public.sync_checkpoints (account_id, workspace_id, schema_version, received_at, canonical_sha256);
create index sync_checkpoints_account_workspace_previous_hash_idx
  on public.sync_checkpoints (account_id, workspace_id, previous_checkpoint_hash);

create function public.service_sync_identity_context(
  p_auth_user_id uuid,
  p_session_id uuid,
  p_workspace_id uuid,
  p_device_id uuid
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  binding_row public.device_bindings%rowtype;
  account_row public.accounts%rowtype;
  leaf_certificate public.device_certificates%rowtype;
  chain_rows jsonb;
  chain_count integer;
  terminal_issuer_kind text;
  terminal_recovery_key bytea;
  recovery_root_count integer;
  mismatched_link_count integer;
begin
  if p_auth_user_id is null
     or p_session_id is null
     or p_workspace_id is null
     or p_device_id is null then
    raise exception using errcode = '22023', message = 'auth_required';
  end if;

  select binding.*
  into strict binding_row
  from public.device_bindings as binding
  where binding.auth_user_id = p_auth_user_id
    and binding.session_id = p_session_id
    and binding.device_id = p_device_id
    and binding.state = 'active'::context_relay_private.device_binding_state
    and binding.revoked_at is null
    and (binding.expires_at is null or binding.expires_at > pg_catalog.now());

  select account.*
  into strict account_row
  from public.accounts as account
  where account.id = binding_row.account_id
    and account.owner_user_id = p_auth_user_id
    and account.deletion_state = 'active'::context_relay_private.account_deletion_state;

  select certificate.*
  into strict leaf_certificate
  from public.device_certificates as certificate
  where certificate.account_id = account_row.id
    and certificate.workspace_id = p_workspace_id
    and certificate.device_id = p_device_id
    and certificate.control_epoch = account_row.control_epoch;

  with recursive certificate_chain as (
    select certificate.*, 0 as depth
    from public.device_certificates as certificate
    where certificate.id = leaf_certificate.id

    union all

    select issuer.*, child.depth + 1
    from certificate_chain as child
    join public.device_certificates as issuer
      on child.issuer_kind = 'device'
     and issuer.account_id = child.account_id
     and issuer.workspace_id = child.workspace_id
     and issuer.device_id = child.issuer_device_id
    where child.depth < 63
  ), ordered_chain as (
    select chain.*
    from certificate_chain as chain
    order by chain.depth
  )
  select
    pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object(
        'certificateId', certificate.id::text,
        'accountId', certificate.account_id::text,
        'workspaceId', certificate.workspace_id::text,
        'controlEpoch', certificate.control_epoch,
        'requestNonce', pg_catalog.encode(certificate.request_nonce, 'hex'),
        'deviceId', certificate.device_id::text,
        'issuerKind', certificate.issuer_kind,
        'issuerDeviceId',
          case when certificate.issuer_device_id is null then null
               else certificate.issuer_device_id::text end,
        'issuerRecoveryPublicKey',
          case when certificate.issuer_recovery_public_key is null then null
               else pg_catalog.encode(certificate.issuer_recovery_public_key, 'hex') end,
        'issuerSigningPublicKey',
          pg_catalog.encode(certificate.issuer_signing_public_key, 'hex'),
        'deviceSigningPublicKey',
          pg_catalog.encode(certificate.device_signing_public_key, 'hex'),
        'deviceWrappingPublicKey',
          pg_catalog.encode(certificate.device_wrapping_public_key, 'hex'),
        'signature', pg_catalog.encode(certificate.signature, 'hex')
      )
      order by certificate.depth
    ),
    pg_catalog.count(*)::integer
  into chain_rows, chain_count
  from ordered_chain as certificate;

  if chain_count = 0 or chain_count > 64 then
    raise exception using errcode = '22023', message = 'certificate_chain_invalid';
  end if;

  with recursive certificate_chain as (
    select certificate.*, 0 as depth
    from public.device_certificates as certificate
    where certificate.id = leaf_certificate.id

    union all

    select issuer.*, child.depth + 1
    from certificate_chain as child
    join public.device_certificates as issuer
      on child.issuer_kind = 'device'
     and issuer.account_id = child.account_id
     and issuer.workspace_id = child.workspace_id
     and issuer.device_id = child.issuer_device_id
    where child.depth < 63
  )
  select chain.issuer_kind, chain.issuer_recovery_public_key
  into terminal_issuer_kind, terminal_recovery_key
  from certificate_chain as chain
  order by chain.depth desc
  limit 1;

  if terminal_issuer_kind <> 'recovery_root'
     or terminal_recovery_key is null then
    raise exception using errcode = '22023', message = 'certificate_chain_invalid';
  end if;

  with recursive certificate_chain as (
    select certificate.*, 0 as depth
    from public.device_certificates as certificate
    where certificate.id = leaf_certificate.id

    union all

    select issuer.*, child.depth + 1
    from certificate_chain as child
    join public.device_certificates as issuer
      on child.issuer_kind = 'device'
     and issuer.account_id = child.account_id
     and issuer.workspace_id = child.workspace_id
     and issuer.device_id = child.issuer_device_id
    where child.depth < 63
  )
  select pg_catalog.count(*)::integer
  into mismatched_link_count
  from certificate_chain as child
  join certificate_chain as issuer
    on issuer.depth = child.depth + 1
  where child.issuer_kind <> 'device'
     or child.issuer_device_id <> issuer.device_id
     or child.issuer_signing_public_key <> issuer.device_signing_public_key
     or child.account_id <> issuer.account_id
     or child.workspace_id <> issuer.workspace_id
     or child.control_epoch <> issuer.control_epoch;

  if mismatched_link_count <> 0 then
    raise exception using errcode = '22023', message = 'certificate_chain_invalid';
  end if;

  select pg_catalog.count(*)::integer
  into recovery_root_count
  from public.recovery_roots as recovery_root
  where recovery_root.account_id = account_row.id
    and recovery_root.signing_public_key = terminal_recovery_key
    and recovery_root.revoked_at is null;

  if recovery_root_count <> 1 then
    raise exception using errcode = '22023', message = 'certificate_chain_invalid';
  end if;

  return pg_catalog.jsonb_build_object(
    'accountId', account_row.id::text,
    'workspaceId', p_workspace_id::text,
    'deviceId', binding_row.device_id::text,
    'certificateId', leaf_certificate.id::text,
    'controlEpoch', account_row.control_epoch,
    'keyEpoch', account_row.key_epoch,
    'signingPublicKey', pg_catalog.encode(leaf_certificate.device_signing_public_key, 'hex'),
    'certificateChain', chain_rows,
    'recoverySigningPublicKey', pg_catalog.encode(terminal_recovery_key, 'hex')
  );
exception
  when no_data_found or too_many_rows then
    raise exception using errcode = '28000', message = 'revoked';
end;
$$;

alter function public.service_sync_identity_context(uuid, uuid, uuid, uuid)
owner to context_relay_rls_owner;
revoke all on function public.service_sync_identity_context(uuid, uuid, uuid, uuid)
from public, anon, authenticated, service_role;
grant execute on function public.service_sync_identity_context(uuid, uuid, uuid, uuid)
to service_role;

create function context_relay_private.locked_sync_identity_context(
  p_auth_user_id uuid,
  p_session_id uuid,
  p_workspace_id uuid,
  p_device_id uuid
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  identity_context jsonb;
  locked_account_id uuid;
begin
  identity_context := public.service_sync_identity_context(
    p_auth_user_id,
    p_session_id,
    p_workspace_id,
    p_device_id
  );
  locked_account_id := (identity_context ->> 'accountId')::uuid;

  perform 1
  from public.accounts as account
  where account.id = locked_account_id
  for update;
  if not found then
    raise exception using errcode = '28000', message = 'revoked';
  end if;

  identity_context := public.service_sync_identity_context(
    p_auth_user_id,
    p_session_id,
    p_workspace_id,
    p_device_id
  );
  if (identity_context ->> 'accountId')::uuid <> locked_account_id then
    raise exception using errcode = '28000', message = 'revoked';
  end if;
  return identity_context;
exception
  when no_data_found or too_many_rows then
    raise exception using errcode = '28000', message = 'revoked';
end;
$$;

alter function context_relay_private.locked_sync_identity_context(uuid, uuid, uuid, uuid)
owner to context_relay_rls_owner;
revoke all on function context_relay_private.locked_sync_identity_context(uuid, uuid, uuid, uuid)
from public, anon, authenticated, service_role;

create function public.service_sync_session_context(
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
  bound_device_id uuid;
begin
  select binding.device_id
  into strict bound_device_id
  from public.device_bindings as binding
  where binding.auth_user_id = p_auth_user_id
    and binding.session_id = p_session_id
    and binding.state = 'active'::context_relay_private.device_binding_state
    and binding.revoked_at is null
    and (binding.expires_at is null or binding.expires_at > pg_catalog.now());

  return public.service_sync_identity_context(
    p_auth_user_id,
    p_session_id,
    p_workspace_id,
    bound_device_id
  );
exception
  when no_data_found or too_many_rows then
    raise exception using errcode = '28000', message = 'revoked';
end;
$$;

alter function public.service_sync_session_context(uuid, uuid, uuid)
owner to context_relay_rls_owner;
revoke all on function public.service_sync_session_context(uuid, uuid, uuid)
from public, anon, authenticated, service_role;
grant execute on function public.service_sync_session_context(uuid, uuid, uuid)
to service_role;

create function public.service_reserve_blob_upload_for_session(
  p_auth_user_id uuid,
  p_session_id uuid,
  p_workspace_id uuid,
  p_storage_id uuid,
  p_ciphertext_sha256 bytea,
  p_part_sizes bigint[],
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  identity_context jsonb;
  context_account_id uuid;
  context_workspace_id uuid;
  context_device_id uuid;
  context_certificate_id uuid;
  account_row public.accounts%rowtype;
  part_size bigint;
  requested_total_bytes bigint := 0;
  transition_time timestamptz := pg_catalog.statement_timestamp();
  upload_paths jsonb;
  inserted_storage_id uuid;
begin
  if p_storage_id is null
     or p_ciphertext_sha256 is null
     or p_part_sizes is null
     or p_expires_at is null
     or pg_catalog.octet_length(p_ciphertext_sha256) <> 32
     or pg_catalog.array_ndims(p_part_sizes) <> 1
     or pg_catalog.cardinality(p_part_sizes) not between 1 and 16
     or p_expires_at <= transition_time then
    raise exception using errcode = '22023', message = 'invalid_request';
  end if;

  identity_context := public.service_sync_session_context(
    p_auth_user_id,
    p_session_id,
    p_workspace_id
  );
  identity_context := context_relay_private.locked_sync_identity_context(
    p_auth_user_id,
    p_session_id,
    p_workspace_id,
    (identity_context ->> 'deviceId')::uuid
  );
  context_account_id := (identity_context ->> 'accountId')::uuid;
  context_workspace_id := (identity_context ->> 'workspaceId')::uuid;
  context_device_id := (identity_context ->> 'deviceId')::uuid;
  context_certificate_id := (identity_context ->> 'certificateId')::uuid;

  foreach part_size in array p_part_sizes
  loop
    if part_size is null or part_size <= 0 or part_size > 33554432 then
      raise exception using errcode = '22023', message = 'invalid_request';
    end if;
    requested_total_bytes := requested_total_bytes + part_size;
  end loop;
  if requested_total_bytes > 524288000 then
    raise exception using errcode = '22023', message = 'invalid_request';
  end if;

  select account.*
  into strict account_row
  from public.accounts as account
  where account.id = context_account_id
    and account.owner_user_id = p_auth_user_id
    and account.deletion_state = 'active'::context_relay_private.account_deletion_state
  for update;

  if account_row.used_bytes < 0
     or account_row.reserved_bytes < 0
     or account_row.used_bytes + account_row.reserved_bytes > account_row.quota_limit_bytes then
    raise exception using errcode = '23514', message = 'quota_blocked';
  end if;
  if requested_total_bytes
       > account_row.quota_limit_bytes - account_row.used_bytes - account_row.reserved_bytes then
    raise exception using errcode = '23514', message = 'quota_blocked';
  end if;
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
    raise exception using errcode = '23505', message = 'blob_storage_conflict';
  end if;

  insert into context_relay_private.blob_upload_reservations (
    account_id,
    workspace_id,
    storage_id,
    ciphertext_digest,
    expected_total_bytes,
    expected_part_sizes,
    part_count,
    state,
    creator_device_id,
    device_certificate_id,
    expires_at,
    created_at,
    updated_at
  ) values (
    context_account_id,
    context_workspace_id,
    p_storage_id,
    p_ciphertext_sha256,
    requested_total_bytes,
    pg_catalog.to_jsonb(p_part_sizes),
    pg_catalog.cardinality(p_part_sizes),
    'reserved'::context_relay_private.upload_reservation_state,
    context_device_id,
    context_certificate_id,
    p_expires_at,
    transition_time,
    transition_time
  )
  on conflict (storage_id) do nothing
  returning storage_id into inserted_storage_id;

  if inserted_storage_id is null then
    raise exception using errcode = '23505', message = 'blob_storage_conflict';
  end if;

  update public.accounts as account
  set reserved_bytes = account.reserved_bytes + requested_total_bytes,
      updated_at = transition_time
  where account.id = context_account_id;

  select pg_catalog.jsonb_agg(
    context_account_id::text || '/' || p_storage_id::text || '/'
      || pg_catalog.lpad(part.part_index::text, 8, '0') || '.bin'
    order by part.part_index
  )
  into upload_paths
  from pg_catalog.generate_series(
    0,
    pg_catalog.cardinality(p_part_sizes) - 1
  ) as part(part_index);

  return pg_catalog.jsonb_build_object(
    'storageId', p_storage_id::text,
    'paths', upload_paths,
    'expiresAt', pg_catalog.to_char(
      p_expires_at at time zone 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
    )
  );
exception
  when no_data_found or too_many_rows then
    raise exception using errcode = '28000', message = 'revoked';
end;
$$;

alter function public.service_reserve_blob_upload_for_session(
  uuid, uuid, uuid, uuid, bytea, bigint[], timestamptz
) owner to context_relay_rls_owner;
revoke all on function public.service_reserve_blob_upload_for_session(
  uuid, uuid, uuid, uuid, bytea, bigint[], timestamptz
) from public, anon, authenticated, service_role;
grant execute on function public.service_reserve_blob_upload_for_session(
  uuid, uuid, uuid, uuid, bytea, bigint[], timestamptz
) to service_role;

create function public.service_finalize_blob_upload_for_session(
  p_auth_user_id uuid,
  p_session_id uuid,
  p_storage_id uuid
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  reservation_row context_relay_private.blob_upload_reservations%rowtype;
  identity_context jsonb;
begin
  select reservation.*
  into strict reservation_row
  from context_relay_private.blob_upload_reservations as reservation
  where reservation.storage_id = p_storage_id;

  identity_context := context_relay_private.locked_sync_identity_context(
    p_auth_user_id,
    p_session_id,
    reservation_row.workspace_id,
    reservation_row.creator_device_id
  );
  if (identity_context ->> 'accountId')::uuid <> reservation_row.account_id
     or (identity_context ->> 'deviceId')::uuid <> reservation_row.creator_device_id
     or (identity_context ->> 'certificateId')::uuid <> reservation_row.device_certificate_id then
    raise exception using errcode = '28000', message = 'revoked';
  end if;

  perform public.service_finalize_blob_upload(p_storage_id);
  return pg_catalog.jsonb_build_object(
    'storageId', p_storage_id::text,
    'state', 'finalized'
  );
exception
  when no_data_found or too_many_rows then
    raise exception using errcode = '28000', message = 'revoked';
end;
$$;

alter function public.service_finalize_blob_upload_for_session(uuid, uuid, uuid)
owner to context_relay_rls_owner;
revoke all on function public.service_finalize_blob_upload_for_session(uuid, uuid, uuid)
from public, anon, authenticated, service_role;
grant execute on function public.service_finalize_blob_upload_for_session(uuid, uuid, uuid)
to service_role;

create function public.service_release_blob_upload_for_session(
  p_auth_user_id uuid,
  p_session_id uuid,
  p_storage_id uuid
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  reservation_row context_relay_private.blob_upload_reservations%rowtype;
  identity_context jsonb;
begin
  select reservation.*
  into strict reservation_row
  from context_relay_private.blob_upload_reservations as reservation
  where reservation.storage_id = p_storage_id;

  identity_context := context_relay_private.locked_sync_identity_context(
    p_auth_user_id,
    p_session_id,
    reservation_row.workspace_id,
    reservation_row.creator_device_id
  );
  if (identity_context ->> 'accountId')::uuid <> reservation_row.account_id
     or (identity_context ->> 'deviceId')::uuid <> reservation_row.creator_device_id
     or (identity_context ->> 'certificateId')::uuid <> reservation_row.device_certificate_id then
    raise exception using errcode = '28000', message = 'revoked';
  end if;

  perform public.service_release_blob_upload(
    p_storage_id,
    'cancelled'::context_relay_private.upload_reservation_state
  );
  return pg_catalog.jsonb_build_object(
    'storageId', p_storage_id::text,
    'state', 'cancelled'
  );
exception
  when no_data_found or too_many_rows then
    raise exception using errcode = '28000', message = 'revoked';
end;
$$;

alter function public.service_release_blob_upload_for_session(uuid, uuid, uuid)
owner to context_relay_rls_owner;
revoke all on function public.service_release_blob_upload_for_session(uuid, uuid, uuid)
from public, anon, authenticated, service_role;
grant execute on function public.service_release_blob_upload_for_session(uuid, uuid, uuid)
to service_role;

create function public.service_append_sync_operations(
  p_auth_user_id uuid,
  p_session_id uuid,
  p_operations jsonb
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  identity_context jsonb;
  context_account_id uuid;
  context_workspace_id uuid;
  context_device_id uuid;
  context_certificate_id uuid;
  context_control_epoch bigint;
  context_key_epoch bigint;
  account_used_bytes bigint;
  account_reserved_bytes bigint;
  account_quota_limit_bytes bigint;
  operation jsonb;
  operation_keys text[];
  operation_id uuid;
  operation_account_id uuid;
  operation_workspace_id uuid;
  operation_project_id uuid;
  operation_record_id uuid;
  operation_device_id uuid;
  operation_sequence numeric;
  operation_control_epoch bigint;
  operation_key_epoch bigint;
  operation_previous_hash bytea;
  operation_nonce bytea;
  operation_ciphertext bytea;
  operation_ciphertext_hash bytea;
  operation_signature bytea;
  operation_canonical_sha256 bytea;
  existing_account_id uuid;
  existing_workspace_id uuid;
  existing_canonical_sha256 bytea;
  head_sequence numeric;
  head_canonical_sha256 bytea;
  inserted_id uuid;
  accepted_ids jsonb := '[]'::jsonb;
  duplicate_ids jsonb := '[]'::jsonb;
begin
  if pg_catalog.jsonb_typeof(p_operations) <> 'array'
     or not (pg_catalog.jsonb_array_length(p_operations) between 1 and 256) then
    raise exception using errcode = '22023', message = 'invalid_request';
  end if;

  operation := p_operations -> 0;
  if pg_catalog.jsonb_typeof(operation) <> 'object' then
    raise exception using errcode = '22023', message = 'invalid_request';
  end if;

  identity_context := context_relay_private.locked_sync_identity_context(
    p_auth_user_id,
    p_session_id,
    (operation ->> 'workspaceId')::uuid,
    (operation ->> 'deviceId')::uuid
  );
  context_account_id := (identity_context ->> 'accountId')::uuid;
  context_workspace_id := (identity_context ->> 'workspaceId')::uuid;
  context_device_id := (identity_context ->> 'deviceId')::uuid;
  context_certificate_id := (identity_context ->> 'certificateId')::uuid;
  context_control_epoch := (identity_context ->> 'controlEpoch')::bigint;
  context_key_epoch := (identity_context ->> 'keyEpoch')::bigint;

  select account.used_bytes, account.reserved_bytes, account.quota_limit_bytes
  into strict account_used_bytes, account_reserved_bytes, account_quota_limit_bytes
  from public.accounts as account
  where account.id = context_account_id
    and account.owner_user_id = p_auth_user_id
    and account.deletion_state = 'active'::context_relay_private.account_deletion_state
  for update;

  for operation in
    select element.value
    from pg_catalog.jsonb_array_elements(p_operations) as element(value)
  loop
    if pg_catalog.jsonb_typeof(operation) <> 'object' then
      raise exception using errcode = '22023', message = 'invalid_request';
    end if;

    select pg_catalog.array_agg(key_name order by key_name)
    into operation_keys
    from pg_catalog.jsonb_object_keys(operation) as keys(key_name);

    if operation_keys <> array[
      'accountId', 'blobRefs', 'canonicalSha256', 'causalFrontier',
      'ciphertextBase64', 'ciphertextHash', 'controlEpoch', 'createdHlc',
      'deviceId', 'deviceSequence', 'keyEpoch', 'mutationKind', 'nonce',
      'operationId', 'previousDeviceHash', 'projectId', 'recordId',
      'recordKind', 'schemaVersion', 'signature', 'workspaceId'
    ]::text[] then
      raise exception using errcode = '22023', message = 'invalid_request';
    end if;

    if pg_catalog.jsonb_typeof(operation -> 'operationId') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'accountId') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'workspaceId') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'recordId') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'recordKind') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'mutationKind') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'deviceId') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'schemaVersion') <> 'number'
       or pg_catalog.jsonb_typeof(operation -> 'deviceSequence') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'causalFrontier') <> 'array'
       or pg_catalog.jsonb_typeof(operation -> 'controlEpoch') <> 'number'
       or pg_catalog.jsonb_typeof(operation -> 'keyEpoch') <> 'number'
       or pg_catalog.jsonb_typeof(operation -> 'previousDeviceHash') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'nonce') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'ciphertextBase64') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'ciphertextHash') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'blobRefs') <> 'array'
       or pg_catalog.jsonb_typeof(operation -> 'createdHlc') <> 'object'
       or pg_catalog.jsonb_typeof(operation -> 'signature') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'canonicalSha256') <> 'string'
       or pg_catalog.jsonb_typeof(operation -> 'projectId') not in ('string', 'null') then
      raise exception using errcode = '22023', message = 'invalid_request';
    end if;

    operation_id := (operation ->> 'operationId')::uuid;
    operation_account_id := (operation ->> 'accountId')::uuid;
    operation_workspace_id := (operation ->> 'workspaceId')::uuid;
    operation_project_id := case
      when pg_catalog.jsonb_typeof(operation -> 'projectId') = 'null' then null
      else (operation ->> 'projectId')::uuid
    end;
    operation_record_id := (operation ->> 'recordId')::uuid;
    operation_device_id := (operation ->> 'deviceId')::uuid;
    operation_sequence := (operation ->> 'deviceSequence')::numeric;
    operation_control_epoch := (operation ->> 'controlEpoch')::bigint;
    operation_key_epoch := (operation ->> 'keyEpoch')::bigint;
    operation_previous_hash := pg_catalog.decode(operation ->> 'previousDeviceHash', 'hex');
    operation_nonce := pg_catalog.decode(operation ->> 'nonce', 'hex');
    operation_ciphertext := pg_catalog.decode(operation ->> 'ciphertextBase64', 'base64');
    operation_ciphertext_hash := pg_catalog.decode(operation ->> 'ciphertextHash', 'hex');
    operation_signature := pg_catalog.decode(operation ->> 'signature', 'hex');
    operation_canonical_sha256 := pg_catalog.decode(operation ->> 'canonicalSha256', 'hex');

    if operation_account_id <> context_account_id
       or operation_workspace_id <> context_workspace_id
       or operation_device_id <> context_device_id
       or operation_control_epoch <> context_control_epoch
       or operation_key_epoch <> context_key_epoch
       or (operation ->> 'schemaVersion')::integer <> 1
       or pg_catalog.octet_length(operation_previous_hash) <> 32
       or pg_catalog.octet_length(operation_nonce) <> 24
       or pg_catalog.octet_length(operation_ciphertext) > 4194304
       or pg_catalog.octet_length(operation_ciphertext_hash) <> 32
       or extensions.digest(operation_ciphertext, 'sha256') <> operation_ciphertext_hash
       or pg_catalog.octet_length(operation_signature) <> 64
       or pg_catalog.octet_length(operation_canonical_sha256) <> 32 then
      raise exception using errcode = '22023', message = 'invalid_envelope';
    end if;

    select existing.account_id, existing.workspace_id, existing.canonical_sha256
    into existing_account_id, existing_workspace_id, existing_canonical_sha256
    from public.sync_operations as existing
    where existing.id = operation_id;

    if found then
      if existing_account_id = context_account_id
         and existing_workspace_id = context_workspace_id
         and existing_canonical_sha256 = operation_canonical_sha256 then
        duplicate_ids := duplicate_ids || pg_catalog.jsonb_build_array(operation_id::text);
        continue;
      end if;
      raise exception using errcode = '23505', message = 'duplicate_operation_mismatch';
    end if;

    select head.device_sequence, head.canonical_sha256
    into head_sequence, head_canonical_sha256
    from public.sync_operations as head
    where head.account_id = context_account_id
      and head.workspace_id = context_workspace_id
      and head.device_id = context_device_id
    order by head.device_sequence desc
    limit 1;

    if found then
      if operation_sequence <> head_sequence + 1 then
        raise exception using errcode = '22000', message = 'device_sequence_gap';
      end if;
      if operation_previous_hash <> head_canonical_sha256 then
        raise exception using errcode = '22000', message = 'device_hash_mismatch';
      end if;
    else
      if operation_sequence <> 1 then
        raise exception using errcode = '22000', message = 'device_sequence_gap';
      end if;
      if operation_previous_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') then
        raise exception using errcode = '22000', message = 'device_hash_mismatch';
      end if;
    end if;

    if account_used_bytes + account_reserved_bytes
         + pg_catalog.octet_length(operation_ciphertext) > account_quota_limit_bytes then
      raise exception using errcode = '23514', message = 'quota_blocked';
    end if;

    inserted_id := null;
    insert into public.sync_operations (
      id,
      account_id,
      workspace_id,
      project_id,
      record_id,
      record_kind,
      mutation_kind,
      device_id,
      device_certificate_id,
      schema_version,
      device_sequence,
      causal_frontier,
      control_epoch,
      key_epoch,
      previous_device_hash,
      nonce,
      ciphertext,
      ciphertext_hash,
      blob_refs,
      created_hlc,
      signature,
      canonical_sha256,
      received_at
    ) values (
      operation_id,
      context_account_id,
      context_workspace_id,
      operation_project_id,
      operation_record_id,
      operation ->> 'recordKind',
      operation ->> 'mutationKind',
      context_device_id,
      context_certificate_id,
      1,
      operation_sequence,
      operation -> 'causalFrontier',
      context_control_epoch,
      context_key_epoch,
      operation_previous_hash,
      operation_nonce,
      operation_ciphertext,
      operation_ciphertext_hash,
      operation -> 'blobRefs',
      operation -> 'createdHlc',
      operation_signature,
      operation_canonical_sha256,
      pg_catalog.clock_timestamp()
    )
    on conflict (id) do nothing
    returning id into inserted_id;

    if inserted_id is null then
      select existing.account_id, existing.workspace_id, existing.canonical_sha256
      into existing_account_id, existing_workspace_id, existing_canonical_sha256
      from public.sync_operations as existing
      where existing.id = operation_id;
      if not found
         or existing_account_id <> context_account_id
         or existing_workspace_id <> context_workspace_id
         or existing_canonical_sha256 <> operation_canonical_sha256 then
        raise exception using errcode = '23505', message = 'duplicate_operation_mismatch';
      end if;
      duplicate_ids := duplicate_ids || pg_catalog.jsonb_build_array(operation_id::text);
    else
      accepted_ids := accepted_ids || pg_catalog.jsonb_build_array(operation_id::text);
      account_used_bytes := account_used_bytes + pg_catalog.octet_length(operation_ciphertext);
    end if;
  end loop;

  return pg_catalog.jsonb_build_object(
    'accepted', accepted_ids,
    'duplicates', duplicate_ids
  );
exception
  when no_data_found or too_many_rows then
    raise exception using errcode = '28000', message = 'revoked';
end;
$$;

alter function public.service_append_sync_operations(uuid, uuid, jsonb)
owner to context_relay_rls_owner;
revoke all on function public.service_append_sync_operations(uuid, uuid, jsonb)
from public, anon, authenticated, service_role;
grant execute on function public.service_append_sync_operations(uuid, uuid, jsonb)
to service_role;

create function public.service_append_sync_checkpoint(
  p_auth_user_id uuid,
  p_session_id uuid,
  p_checkpoint jsonb
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  checkpoint_keys text[];
  identity_context jsonb;
  context_account_id uuid;
  context_workspace_id uuid;
  context_device_id uuid;
  context_certificate_id uuid;
  context_key_epoch bigint;
  checkpoint_account_id uuid;
  checkpoint_workspace_id uuid;
  checkpoint_creator_device_id uuid;
  checkpoint_key_epoch bigint;
  checkpoint_previous_hash bytea;
  checkpoint_state_hash bytea;
  checkpoint_signature bytea;
  checkpoint_canonical_sha256 bytea;
  head_canonical_hashes bytea[];
  checkpoint_count integer;
  existing_checkpoint public.sync_checkpoints%rowtype;
begin
  if pg_catalog.jsonb_typeof(p_checkpoint) <> 'object' then
    raise exception using errcode = '22023', message = 'invalid_request';
  end if;

  select pg_catalog.array_agg(key_name order by key_name)
  into checkpoint_keys
  from pg_catalog.jsonb_object_keys(p_checkpoint) as keys(key_name);

  if checkpoint_keys <> array[
    'accountId', 'canonicalSha256', 'causalFrontier', 'createdHlc',
    'creatorDeviceId', 'keyEpoch', 'previousCheckpointHash',
    'schemaVersion', 'signature', 'stateHash', 'workspaceId'
  ]::text[] then
    raise exception using errcode = '22023', message = 'invalid_request';
  end if;

  if pg_catalog.jsonb_typeof(p_checkpoint -> 'accountId') <> 'string'
     or pg_catalog.jsonb_typeof(p_checkpoint -> 'workspaceId') <> 'string'
     or pg_catalog.jsonb_typeof(p_checkpoint -> 'schemaVersion') <> 'number'
     or pg_catalog.jsonb_typeof(p_checkpoint -> 'previousCheckpointHash') <> 'string'
     or pg_catalog.jsonb_typeof(p_checkpoint -> 'causalFrontier') <> 'array'
     or pg_catalog.jsonb_typeof(p_checkpoint -> 'stateHash') <> 'string'
     or pg_catalog.jsonb_typeof(p_checkpoint -> 'keyEpoch') <> 'number'
     or pg_catalog.jsonb_typeof(p_checkpoint -> 'creatorDeviceId') <> 'string'
     or pg_catalog.jsonb_typeof(p_checkpoint -> 'createdHlc') <> 'object'
     or pg_catalog.jsonb_typeof(p_checkpoint -> 'signature') <> 'string'
     or pg_catalog.jsonb_typeof(p_checkpoint -> 'canonicalSha256') <> 'string' then
    raise exception using errcode = '22023', message = 'invalid_request';
  end if;

  checkpoint_account_id := (p_checkpoint ->> 'accountId')::uuid;
  checkpoint_workspace_id := (p_checkpoint ->> 'workspaceId')::uuid;
  checkpoint_creator_device_id := (p_checkpoint ->> 'creatorDeviceId')::uuid;
  checkpoint_key_epoch := (p_checkpoint ->> 'keyEpoch')::bigint;
  checkpoint_previous_hash := pg_catalog.decode(
    p_checkpoint ->> 'previousCheckpointHash',
    'hex'
  );
  checkpoint_state_hash := pg_catalog.decode(p_checkpoint ->> 'stateHash', 'hex');
  checkpoint_signature := pg_catalog.decode(p_checkpoint ->> 'signature', 'hex');
  checkpoint_canonical_sha256 := pg_catalog.decode(
    p_checkpoint ->> 'canonicalSha256',
    'hex'
  );

  identity_context := context_relay_private.locked_sync_identity_context(
    p_auth_user_id,
    p_session_id,
    checkpoint_workspace_id,
    checkpoint_creator_device_id
  );
  context_account_id := (identity_context ->> 'accountId')::uuid;
  context_workspace_id := (identity_context ->> 'workspaceId')::uuid;
  context_device_id := (identity_context ->> 'deviceId')::uuid;
  context_certificate_id := (identity_context ->> 'certificateId')::uuid;
  context_key_epoch := (identity_context ->> 'keyEpoch')::bigint;

  if checkpoint_account_id <> context_account_id
     or checkpoint_workspace_id <> context_workspace_id
     or checkpoint_creator_device_id <> context_device_id
     or checkpoint_key_epoch <> context_key_epoch
     or (p_checkpoint ->> 'schemaVersion')::integer <> 2
     or not context_relay_private.valid_sync_causal_frontier(
       p_checkpoint -> 'causalFrontier'
     )
     or not context_relay_private.valid_hybrid_logical_clock(
       p_checkpoint -> 'createdHlc'
     )
     or pg_catalog.octet_length(checkpoint_previous_hash) <> 32
     or pg_catalog.octet_length(checkpoint_state_hash) <> 32
     or pg_catalog.octet_length(checkpoint_signature) <> 64
     or pg_catalog.octet_length(checkpoint_canonical_sha256) <> 32 then
    raise exception using errcode = '22023', message = 'invalid_envelope';
  end if;

  perform 1
  from public.accounts as account
  where account.id = context_account_id
    and account.owner_user_id = p_auth_user_id
    and account.deletion_state = 'active'::context_relay_private.account_deletion_state
  for update;
  if not found then
    raise exception using errcode = '28000', message = 'revoked';
  end if;

  select checkpoint.*
  into existing_checkpoint
  from public.sync_checkpoints as checkpoint
  where checkpoint.account_id = context_account_id
    and checkpoint.workspace_id = context_workspace_id
    and checkpoint.canonical_sha256 = checkpoint_canonical_sha256;

  if found then
    if existing_checkpoint.creator_device_id <> context_device_id
       or existing_checkpoint.device_certificate_id <> context_certificate_id
       or existing_checkpoint.schema_version <> 2
       or existing_checkpoint.previous_checkpoint_hash <> checkpoint_previous_hash
       or existing_checkpoint.causal_frontier <> p_checkpoint -> 'causalFrontier'
       or existing_checkpoint.state_hash <> checkpoint_state_hash
       or existing_checkpoint.key_epoch <> context_key_epoch
       or existing_checkpoint.created_hlc <> p_checkpoint -> 'createdHlc'
       or existing_checkpoint.signature <> checkpoint_signature then
      raise exception using errcode = '23505', message = 'duplicate_checkpoint_mismatch';
    end if;
    return pg_catalog.jsonb_build_object(
      'canonicalHash', pg_catalog.encode(checkpoint_canonical_sha256, 'hex'),
      'duplicate', true
    );
  end if;

  with scope_checkpoints as materialized (
    select checkpoint.canonical_sha256, checkpoint.previous_checkpoint_hash
    from public.sync_checkpoints as checkpoint
    where checkpoint.account_id = context_account_id
      and checkpoint.workspace_id = context_workspace_id
  ), chain_tips as (
    select candidate.canonical_sha256
    from scope_checkpoints as candidate
    where not exists (
      select 1
      from scope_checkpoints as child
      where child.previous_checkpoint_hash = candidate.canonical_sha256
    )
  )
  select
    (select pg_catalog.count(*)::integer from scope_checkpoints),
    pg_catalog.array_agg(chain_tip.canonical_sha256 order by chain_tip.canonical_sha256)
  into checkpoint_count, head_canonical_hashes
  from chain_tips as chain_tip;

  if checkpoint_count > 0
     and coalesce(pg_catalog.cardinality(head_canonical_hashes), 0) <> 1 then
    raise exception using errcode = '22000', message = 'checkpoint_chain_mismatch';
  end if;

  if checkpoint_count > 0 then
    if checkpoint_previous_hash <> head_canonical_hashes[1] then
      raise exception using errcode = '22000', message = 'checkpoint_chain_mismatch';
    end if;
  elsif checkpoint_previous_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') then
    raise exception using errcode = '22000', message = 'checkpoint_chain_mismatch';
  end if;

  insert into public.sync_checkpoints (
    account_id,
    workspace_id,
    creator_device_id,
    device_certificate_id,
    schema_version,
    previous_checkpoint_hash,
    causal_frontier,
    state_hash,
    key_epoch,
    created_hlc,
    signature,
    canonical_sha256,
    received_at
  ) values (
    context_account_id,
    context_workspace_id,
    context_device_id,
    context_certificate_id,
    2,
    checkpoint_previous_hash,
    p_checkpoint -> 'causalFrontier',
    checkpoint_state_hash,
    context_key_epoch,
    p_checkpoint -> 'createdHlc',
    checkpoint_signature,
    checkpoint_canonical_sha256,
    pg_catalog.clock_timestamp()
  );

  return pg_catalog.jsonb_build_object(
    'canonicalHash', pg_catalog.encode(checkpoint_canonical_sha256, 'hex'),
    'duplicate', false
  );
exception
  when no_data_found or too_many_rows then
    raise exception using errcode = '28000', message = 'revoked';
end;
$$;

alter function public.service_append_sync_checkpoint(uuid, uuid, jsonb)
owner to context_relay_rls_owner;
revoke all on function public.service_append_sync_checkpoint(uuid, uuid, jsonb)
from public, anon, authenticated, service_role;
grant execute on function public.service_append_sync_checkpoint(uuid, uuid, jsonb)
to service_role;

create function public.service_send_sync_hint(p_account_id uuid)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if not exists (
    select 1
    from public.accounts as account
    where account.id = p_account_id
      and account.deletion_state in (
        'active'::context_relay_private.account_deletion_state,
        'pending_delete'::context_relay_private.account_deletion_state
      )
  ) then
    raise exception using errcode = '28000', message = 'revoked';
  end if;

  perform realtime.send(
    pg_catalog.jsonb_build_object('v', 1, 'kind', 'pull_now'),
    'pull_now',
    'account:' || p_account_id::text || ':sync',
    true
  );

  return pg_catalog.jsonb_build_object('sent', true);
end;
$$;

alter function public.service_send_sync_hint(uuid)
owner to context_relay_rls_owner;
revoke all on function public.service_send_sync_hint(uuid)
from public, anon, authenticated, service_role;
grant execute on function public.service_send_sync_hint(uuid)
to service_role;

reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
