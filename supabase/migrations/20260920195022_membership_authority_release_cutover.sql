-- Additive cutover: signed issuance epochs are immutable; current membership
-- and the current account/head epochs decide authority after rotation.
grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;

create or replace function context_relay_private.current_membership_certificate(p_certificate_id uuid)
returns boolean language sql stable security definer set search_path=''
as $$
  select exists (
    select 1 from public.device_certificates c
    join public.accounts a on a.id=c.account_id
    left join context_relay_private.membership_heads h on h.workspace_id=c.workspace_id
    where c.id=p_certificate_id
      and case when h.workspace_id is null then c.control_epoch=a.control_epoch
      else c.control_epoch between 1 and a.control_epoch
        and h.account_id=a.id and h.control_epoch=a.control_epoch and h.key_epoch=a.key_epoch
        and exists(select 1 from context_relay_private.membership_members m
          where m.workspace_id=c.workspace_id and m.device_id=c.device_id
            and m.certificate_id=c.id and m.active)
      end
  );
$$;
revoke all on function context_relay_private.current_membership_certificate(uuid) from public,anon,authenticated,service_role;

create or replace function public.service_sync_identity_context(
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

  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id) then
    raise exception using errcode='28000',message='revoked';
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
    and context_relay_private.current_membership_certificate(certificate.id);

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
     or issuer.control_epoch > child.control_epoch
     or issuer.control_epoch < 1;

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

create or replace function context_relay_private.locked_account_lifecycle_context(
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
   and context_relay_private.current_membership_certificate(certificate.id)
  where binding.auth_user_id = p_auth_user_id
    and binding.session_id = p_session_id
    and binding.state = 'active'::context_relay_private.device_binding_state
    and binding.revoked_at is null
    and (binding.expires_at is null or binding.expires_at > pg_catalog.clock_timestamp())
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

  if not context_relay_private.lock_live_account_lifecycle_auth_session(
    p_auth_user_id, p_session_id
  ) then
    raise exception using errcode = '28000', message = 'revoked';
  end if;

  -- Recheck binding authority after both the account and Auth session locks.
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
   and context_relay_private.current_membership_certificate(certificate.id)
  where binding.auth_user_id = p_auth_user_id
    and binding.session_id = p_session_id
    and binding.state = 'active'::context_relay_private.device_binding_state
    and binding.revoked_at is null
    and (binding.expires_at is null or binding.expires_at > pg_catalog.clock_timestamp())
    and account.deletion_state in (
      'active'::context_relay_private.account_deletion_state,
      'pending_delete'::context_relay_private.account_deletion_state
    );

  if refreshed_account_id <> initial_account_id or refreshed_device_id <> initial_device_id then
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

create or replace function public.service_commit_recovery_for_session(
  p_auth_user_id uuid,p_session_id uuid,p_restore_id uuid,p_enrollment_id uuid,p_root_id uuid,
  p_account_id uuid,p_workspace_id uuid,p_certificate_id uuid,p_device_id uuid,p_expected_generation bigint,
  p_record_sha256 bytea,p_canonical_claim bytea,p_request_nonce bytea,
  p_device_signing_key bytea,p_device_wrapping_key bytea,p_certificate_signature bytea
)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare
  account_row public.accounts%rowtype;
  root_row public.recovery_roots%rowtype;
  enrollment context_relay_private.enrollment_commits%rowtype;
  previous context_relay_private.recovery_commits%rowtype;
  result jsonb;
  candidate uuid;
  key_bytes bytea;
begin
  if p_auth_user_id is null or p_session_id is null or p_expected_generation is null
    or p_expected_generation < 0 or p_expected_generation >= 9223372036854775807
    or p_canonical_claim is null or pg_catalog.octet_length(p_canonical_claim) not between 1 and 32768
    or p_certificate_signature is null or pg_catalog.octet_length(p_certificate_signature) <> 64
  then raise exception using errcode='22023',message='invalid_recovery_request'; end if;
  foreach candidate in array array[p_restore_id,p_enrollment_id,p_root_id,p_account_id,p_workspace_id,p_certificate_id,p_device_id] loop
    if candidate is null or candidate::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    then raise exception using errcode='22023',message='invalid_recovery_request'; end if;
  end loop;
  foreach key_bytes in array array[p_record_sha256,p_request_nonce,p_device_signing_key,p_device_wrapping_key] loop
    if key_bytes is null or pg_catalog.octet_length(key_bytes) <> 32
    then raise exception using errcode='22023',message='invalid_recovery_request'; end if;
  end loop;
  if p_device_signing_key=p_device_wrapping_key
  then raise exception using errcode='22023',message='invalid_recovery_request'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='enrollment_session_denied'; end if;
  select * into account_row from public.accounts where id=p_account_id and owner_user_id=p_auth_user_id for update;
  if not found then raise exception using errcode='42501',message='recovery_denied'; end if;
  select * into enrollment from context_relay_private.enrollment_commits
    where account_id=p_account_id and auth_user_id=p_auth_user_id for share;
  if not found or enrollment.receipt->>'enrollmentId' <> p_enrollment_id::text
    or enrollment.receipt->>'recoveryRootId' <> p_root_id::text
    or enrollment.receipt->>'workspaceId' <> p_workspace_id::text
    or pg_catalog.sha256(enrollment.canonical_record) <> p_record_sha256
  then raise exception using errcode='40001',message='recovery_conflict'; end if;
  select * into root_row from public.recovery_roots where id=p_root_id and account_id=p_account_id for update;
  if not found then raise exception using errcode='42501',message='recovery_denied'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='enrollment_session_denied'; end if;
  select * into previous from context_relay_private.recovery_commits where restore_id=p_restore_id;
  if found then
    if previous.account_id<>p_account_id or previous.auth_user_id<>p_auth_user_id
      or previous.session_id<>p_session_id or previous.canonical_claim<>p_canonical_claim
    then raise exception using errcode='40001',message='recovery_conflict'; end if;
    -- A receipt acknowledges a past transaction and never reactivates its binding.
    return previous.receipt;
  end if;
  if account_row.deletion_state<>'active' or root_row.revoked_at is not null
  then raise exception using errcode='42501',message='recovery_denied'; end if;
  -- V1 has no signed membership event. Preserve receipt lookup only; new
  -- admissions must use V2 so a certificate can never bypass public history.
  raise exception using errcode='40001',message='recovery_conflict';
end;
$$;

reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
