grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;

create table context_relay_private.enrollment_commits (
  auth_user_id uuid primary key,
  account_id uuid not null references public.accounts(id) on delete cascade,
  reservation_id uuid not null,
  session_id uuid not null,
  canonical_record bytea not null check (pg_catalog.octet_length(canonical_record) between 1 and 32768),
  receipt jsonb not null
);
alter table context_relay_private.enrollment_commits enable row level security;
revoke all on table context_relay_private.enrollment_commits from public, anon, authenticated, service_role;

-- Only the trusted Edge verifier may supply these decoded fields. This RPC
-- rechecks mutable authority; it does not replace canonical/signature validation.
create function public.service_commit_enrollment_for_session(
  p_auth_user_id uuid, p_session_id uuid, p_reservation_id uuid, p_nonce bytea,
  p_account_id uuid, p_workspace_id uuid, p_enrollment_id uuid, p_root_id uuid,
  p_certificate_id uuid, p_device_id uuid, p_request_nonce bytea,
  p_root_signing_key bytea, p_root_wrapping_key bytea,
  p_device_signing_key bytea, p_device_wrapping_key bytea, p_certificate_signature bytea,
  p_encrypted_metadata bytea, p_canonical_record bytea
)
returns jsonb
language plpgsql volatile security definer set search_path = ''
as $$
declare
  reservation context_relay_private.enrollment_reservations%rowtype;
  committed context_relay_private.enrollment_commits%rowtype;
  receipt jsonb;
  candidate uuid;
  key_bytes bytea;
begin
  if p_auth_user_id is null or p_session_id is null then
    raise exception using errcode = '22023', message = 'invalid_enrollment_request';
  end if;
  foreach candidate in array array[p_reservation_id,p_account_id,p_workspace_id,p_enrollment_id,p_root_id,p_certificate_id,p_device_id] loop
    if candidate is null or candidate::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    then raise exception using errcode = '22023', message = 'invalid_enrollment_request'; end if;
  end loop;
  foreach key_bytes in array array[p_nonce,p_request_nonce,p_root_signing_key,p_root_wrapping_key,p_device_signing_key,p_device_wrapping_key] loop
    if key_bytes is null or pg_catalog.octet_length(key_bytes) <> 32
    then raise exception using errcode = '22023', message = 'invalid_enrollment_request'; end if;
  end loop;
  if p_certificate_signature is null or pg_catalog.octet_length(p_certificate_signature) <> 64
    or p_canonical_record is null or pg_catalog.octet_length(p_canonical_record) not between 1 and 32768
    or p_encrypted_metadata is null or pg_catalog.octet_length(p_encrypted_metadata) not between 16 and 32768
    or p_root_signing_key = p_root_wrapping_key or p_device_signing_key = p_device_wrapping_key
  then raise exception using errcode = '22023', message = 'invalid_enrollment_request'; end if;

  select * into reservation from context_relay_private.enrollment_reservations
    where auth_user_id=p_auth_user_id for update;
  if not found or reservation.session_id <> p_session_id
    or reservation.reservation_id <> p_reservation_id or reservation.nonce <> p_nonce
    or reservation.account_id <> p_account_id or reservation.workspace_id <> p_workspace_id
  then raise exception using errcode = '42501', message = 'enrollment_reservation_denied'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode = '42501', message = 'enrollment_session_denied'; end if;

  select * into committed from context_relay_private.enrollment_commits where auth_user_id=p_auth_user_id;
  if found then
    if committed.session_id <> p_session_id or committed.reservation_id <> p_reservation_id
      or committed.canonical_record <> p_canonical_record
    then raise exception using errcode = '40001', message = 'enrollment_conflict'; end if;
    -- A receipt confirms a past transaction; it never reactivates a binding.
    return committed.receipt;
  end if;
  if reservation.expires_at <= pg_catalog.clock_timestamp()
  then raise exception using errcode = '42501', message = 'enrollment_reservation_expired'; end if;
  if exists(select 1 from public.accounts where owner_user_id=p_auth_user_id)
  then raise exception using errcode = '42501', message = 'enrollment_requires_pairing'; end if;

  insert into public.accounts(id,owner_user_id,control_epoch,key_epoch)
    values(p_account_id,p_auth_user_id,1,1);
  insert into public.recovery_roots(id,account_id,signing_public_key,wrapping_public_key,encrypted_recovery_metadata)
    values(p_root_id,p_account_id,p_root_signing_key,p_root_wrapping_key,p_encrypted_metadata);
  insert into public.device_certificates(id,account_id,workspace_id,control_epoch,request_nonce,device_id,
    issuer_kind,issuer_recovery_public_key,issuer_signing_public_key,device_signing_public_key,device_wrapping_public_key,signature)
    values(p_certificate_id,p_account_id,p_workspace_id,1,p_request_nonce,p_device_id,
      'recovery_root',p_root_signing_key,p_root_signing_key,p_device_signing_key,p_device_wrapping_key,p_certificate_signature);
  insert into public.device_bindings(account_id,auth_user_id,session_id,device_id,state)
    values(p_account_id,p_auth_user_id,p_session_id,p_device_id,'active');
  -- Inserts can themselves wait on uniqueness/FK checks. Recheck before receipt.
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode = '42501', message = 'enrollment_session_denied'; end if;
  if reservation.expires_at <= pg_catalog.clock_timestamp()
  then raise exception using errcode = '42501', message = 'enrollment_reservation_expired'; end if;
  receipt := pg_catalog.jsonb_build_object('enrollmentId',p_enrollment_id,'recoveryRootId',p_root_id,
    'accountId',p_account_id,'workspaceId',p_workspace_id,'genesisCertificateId',p_certificate_id,
    'canonicalRecordSha256',pg_catalog.encode(pg_catalog.sha256(p_canonical_record),'hex'),
    'registeredAtMs',pg_catalog.floor(extract(epoch from pg_catalog.clock_timestamp())*1000)::text);
  insert into context_relay_private.enrollment_commits(auth_user_id,account_id,reservation_id,session_id,canonical_record,receipt)
    values(p_auth_user_id,p_account_id,p_reservation_id,p_session_id,p_canonical_record,receipt);
  return receipt;
end;
$$;
revoke all on function public.service_commit_enrollment_for_session(uuid,uuid,uuid,bytea,uuid,uuid,uuid,uuid,uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea,bytea,bytea)
from public,anon,authenticated,service_role;
grant execute on function public.service_commit_enrollment_for_session(uuid,uuid,uuid,bytea,uuid,uuid,uuid,uuid,uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea,bytea,bytea)
to service_role;

reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
