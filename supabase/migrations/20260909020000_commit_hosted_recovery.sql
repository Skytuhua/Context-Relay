grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;

create table context_relay_private.recovery_commits (
  restore_id uuid primary key,
  account_id uuid not null references public.accounts(id) on delete cascade,
  auth_user_id uuid not null,
  session_id uuid not null,
  canonical_claim bytea not null check (pg_catalog.octet_length(canonical_claim) between 1 and 32768),
  receipt jsonb not null
);
alter table context_relay_private.recovery_commits enable row level security;
revoke all on table context_relay_private.recovery_commits from public,anon,authenticated,service_role;

-- Only the trusted Edge verifier may supply decoded claim fields. This transaction
-- enforces mutable authority after cryptographic verification, not in its place.
create function public.service_commit_recovery_for_session(
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
  if account_row.control_epoch<>1 or account_row.key_epoch<>1
    or root_row.recovery_generation<>p_expected_generation
    or p_certificate_id::text=enrollment.receipt->>'genesisCertificateId'
    or exists(select 1 from public.device_certificates where account_id=p_account_id and device_id=p_device_id)
    or exists(select 1 from public.device_bindings where session_id=p_session_id)
  then raise exception using errcode='40001',message='recovery_conflict'; end if;

  insert into public.device_certificates(id,account_id,workspace_id,control_epoch,request_nonce,device_id,
    issuer_kind,issuer_recovery_public_key,issuer_signing_public_key,device_signing_public_key,device_wrapping_public_key,signature)
    values(p_certificate_id,p_account_id,p_workspace_id,1,p_request_nonce,p_device_id,'recovery_root',
      root_row.signing_public_key,root_row.signing_public_key,p_device_signing_key,p_device_wrapping_key,p_certificate_signature);
  insert into public.device_bindings(account_id,auth_user_id,session_id,device_id,state)
    values(p_account_id,p_auth_user_id,p_session_id,p_device_id,'active');
  update public.recovery_roots set recovery_generation=p_expected_generation+1,updated_at=pg_catalog.clock_timestamp() where id=p_root_id;
  -- Unique/FK checks above may wait; expiry after a wait rolls back all writes.
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='enrollment_session_denied'; end if;
  result:=pg_catalog.jsonb_build_object('restoreId',p_restore_id,'enrollmentId',p_enrollment_id,'recoveryRootId',p_root_id,
    'accountId',p_account_id,'workspaceId',p_workspace_id,'certificateId',p_certificate_id,
    'canonicalRecordSha256',pg_catalog.encode(p_record_sha256,'hex'),
    'canonicalClaimSha256',pg_catalog.encode(pg_catalog.sha256(p_canonical_claim),'hex'),
    'acceptedGeneration',(p_expected_generation+1)::text,
    'acceptedAtMs',pg_catalog.floor(extract(epoch from pg_catalog.clock_timestamp())*1000)::text);
  insert into context_relay_private.recovery_commits(restore_id,account_id,auth_user_id,session_id,canonical_claim,receipt)
    values(p_restore_id,p_account_id,p_auth_user_id,p_session_id,p_canonical_claim,result);
  return result;
end;
$$;
revoke all on function public.service_commit_recovery_for_session(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,bytea,bytea,bytea,bytea,bytea)
from public,anon,authenticated,service_role;
grant execute on function public.service_commit_recovery_for_session(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,bytea,bytea,bytea,bytea,bytea) to service_role;

create function public.service_recovery_claim_for_session(p_auth_user_id uuid,p_session_id uuid,p_restore_id uuid)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare
  account_row public.accounts%rowtype;
  committed context_relay_private.recovery_commits%rowtype;
begin
  if p_auth_user_id is null or p_session_id is null or p_restore_id is null
  then raise exception using errcode='22023',message='invalid_recovery_request'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='enrollment_session_denied'; end if;
  select * into account_row from public.accounts where owner_user_id=p_auth_user_id for share;
  if found then
    select * into committed from context_relay_private.recovery_commits
      where account_id=account_row.id and auth_user_id=p_auth_user_id and session_id=p_session_id and restore_id=p_restore_id for share;
  end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='enrollment_session_denied'; end if;
  if committed.restore_id is null then return 'null'::jsonb; end if;
  return pg_catalog.jsonb_build_object('canonicalClaim',pg_catalog.encode(committed.canonical_claim,'hex'),'receipt',committed.receipt);
end;
$$;
revoke all on function public.service_recovery_claim_for_session(uuid,uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.service_recovery_claim_for_session(uuid,uuid,uuid) to service_role;
reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
