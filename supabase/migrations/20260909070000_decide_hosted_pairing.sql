grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;
alter table context_relay_private.pairing_invites
  add column canonical_approved_payload bytea check (pg_catalog.octet_length(canonical_approved_payload) between 1 and 32768),
  add column decision_receipt jsonb;

-- Only the Edge verifier supplies decoded approval fields, after verifying the
-- stored request, server-selected issuer and original-session possession proof.
create function public.service_decide_pairing_request(
  p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_device_id uuid,p_pairing_id uuid,
  p_request_digest bytea,p_action text,p_control_epoch bigint,p_key_epoch bigint,
  p_approved_payload bytea,p_certificate_id uuid,p_child_device_id uuid,p_request_nonce bytea,p_signature bytea
) returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare
  selected_account_id uuid;
  invite context_relay_private.pairing_invites%rowtype;
  request public.pairing_requests%rowtype;
  issuer public.device_certificates%rowtype;
  candidate uuid;
  receipt jsonb;
  decision_time timestamptz;
begin
  if p_auth_user_id is null or p_session_id is null or p_action is null or p_action not in ('approve','reject')
    or p_request_digest is null or pg_catalog.octet_length(p_request_digest)<>32
    or p_control_epoch is null or p_control_epoch not between 1 and 4294967295
    or p_key_epoch is null or p_key_epoch not between 1 and 4294967295
  then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  foreach candidate in array array[p_workspace_id,p_device_id,p_pairing_id] loop
    if candidate is null or candidate::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  end loop;
  if p_action='approve' then
    foreach candidate in array array[p_certificate_id,p_child_device_id] loop
      if candidate is null or candidate::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
    end loop;
    if p_approved_payload is null or pg_catalog.octet_length(p_approved_payload) not between 1 and 32768
      or p_request_nonce is null or pg_catalog.octet_length(p_request_nonce)<>32
      or p_signature is null or pg_catalog.octet_length(p_signature)<>64
    then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  elsif p_approved_payload is not null or p_certificate_id is not null or p_child_device_id is not null
    or p_request_nonce is not null or p_signature is not null
  then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select * into invite from context_relay_private.pairing_invites
    where id=p_pairing_id and auth_user_id=p_auth_user_id and session_id=p_session_id
      and workspace_id=p_workspace_id and device_id=p_device_id;
  if not found then raise exception using errcode='42501',message='pairing_denied'; end if;
  -- New grants lock both Auth sessions before account/device locks. Past receipts
  -- do not require a still-live joining session and never reinstall its binding.
  if p_action='approve' and invite.decision_receipt is null
    and not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,invite.located_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select a.id into selected_account_id from public.accounts a where a.owner_user_id=p_auth_user_id for update;
  select * into invite from context_relay_private.pairing_invites
    where id=p_pairing_id and account_id=selected_account_id and auth_user_id=p_auth_user_id
      and session_id=p_session_id and workspace_id=p_workspace_id and device_id=p_device_id for update;
  if not found then raise exception using errcode='42501',message='pairing_denied'; end if;
  select * into request from public.pairing_requests where id=invite.id
    and account_id=invite.account_id and workspace_id=invite.workspace_id for update;
  if not found or request.request_digest<>p_request_digest
    or invite.control_epoch<>p_control_epoch or invite.key_epoch<>p_key_epoch
  then raise exception using errcode='40001',message='pairing_conflict'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  if invite.decision_receipt is not null then
    if (p_action='approve' and invite.state='approved' and invite.canonical_approved_payload=p_approved_payload)
      or (p_action='reject' and invite.state='rejected')
    then return invite.decision_receipt; end if;
    raise exception using errcode='40001',message='pairing_conflict';
  end if;
  perform public.service_control_pairing_invite(p_auth_user_id,p_session_id,p_workspace_id,p_device_id,p_pairing_id,'status');
  if invite.state='canceled' then raise exception using errcode='42501',message='pairing_canceled'; end if;
  if invite.state<>'pending' then raise exception using errcode='40001',message='pairing_conflict'; end if;
  if p_action='approve' then
    if p_child_device_id=p_device_id or p_certificate_id=invite.certificate_id
      or exists(select 1 from public.device_certificates where account_id=invite.account_id and device_id=p_child_device_id)
      or exists(select 1 from public.device_bindings where session_id=invite.located_session_id)
    then raise exception using errcode='40001',message='pairing_conflict'; end if;
    select * into strict issuer from public.device_certificates where id=invite.certificate_id;
    insert into public.device_certificates(id,account_id,workspace_id,control_epoch,request_nonce,device_id,
      issuer_kind,issuer_device_id,issuer_signing_public_key,device_signing_public_key,device_wrapping_public_key,signature)
    values(p_certificate_id,invite.account_id,invite.workspace_id,invite.control_epoch,p_request_nonce,p_child_device_id,
      'device',invite.device_id,issuer.device_signing_public_key,request.requester_signing_public_key,request.requester_wrapping_public_key,p_signature);
    insert into public.device_bindings(account_id,auth_user_id,session_id,device_id,state)
    values(invite.account_id,p_auth_user_id,invite.located_session_id,p_child_device_id,'active');
  end if;
  decision_time:=pg_catalog.clock_timestamp();
  receipt:=pg_catalog.jsonb_build_object('pairingId',invite.id,'requestDigest',pg_catalog.encode(p_request_digest,'hex'),
    'decision',case when p_action='approve' then 'approved' else 'rejected' end,
    'approvedPayloadDigest',case when p_action='approve' then pg_catalog.encode(pg_catalog.sha256(p_approved_payload),'hex') else null end,
    'decidedAt',pg_catalog.floor(extract(epoch from decision_time)*1000)::text);
  update public.pairing_requests set state=(case when p_action='approve' then 'approved' else 'rejected' end)::context_relay_private.pairing_request_state,
    decision_device_id=invite.device_id,decision_certificate_id=invite.certificate_id,
    decision_metadata=receipt,decided_at=decision_time,updated_at=pg_catalog.clock_timestamp()
    where id=invite.id and account_id=invite.account_id and workspace_id=invite.workspace_id;
  update context_relay_private.pairing_invites set state=case when p_action='approve' then 'approved' else 'rejected' end,
    canonical_approved_payload=p_approved_payload,decision_receipt=receipt where id=invite.id;
  -- Unique/FK checks may wait. Recheck time even though state is now terminal;
  -- any failure rolls back the certificate, binding, decision and receipt together.
  perform public.service_control_pairing_invite(p_auth_user_id,p_session_id,p_workspace_id,p_device_id,p_pairing_id,'status');
  if invite.expires_at<=pg_catalog.clock_timestamp()
    or (p_action='approve' and not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,invite.located_session_id))
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  return receipt;
end;
$$;
revoke all on function public.service_decide_pairing_request(uuid,uuid,uuid,uuid,uuid,bytea,text,bigint,bigint,bytea,uuid,uuid,bytea,bytea)
from public,anon,authenticated,service_role;
grant execute on function public.service_decide_pairing_request(uuid,uuid,uuid,uuid,uuid,bytea,text,bigint,bigint,bytea,uuid,uuid,bytea,bytea) to service_role;

create function public.service_pairing_result_for_session(p_auth_user_id uuid,p_session_id uuid,p_pairing_id uuid,p_request_digest bytea)
returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare
  selected_account_id uuid;
  invite context_relay_private.pairing_invites%rowtype;
begin
  if p_auth_user_id is null or p_session_id is null or p_pairing_id is null
    or p_request_digest is null or pg_catalog.octet_length(p_request_digest)<>32
  then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select a.id into selected_account_id from public.accounts a where a.owner_user_id=p_auth_user_id for share;
  select * into invite from context_relay_private.pairing_invites
    where id=p_pairing_id and account_id=selected_account_id and auth_user_id=p_auth_user_id
      and located_session_id=p_session_id for share;
  if not found then raise exception using errcode='42501',message='pairing_denied'; end if;
  perform 1 from public.pairing_requests where id=invite.id and account_id=invite.account_id
    and workspace_id=invite.workspace_id and request_digest=p_request_digest for share;
  if not found then raise exception using errcode='40001',message='pairing_conflict'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  if invite.state='pending' and invite.expires_at<=pg_catalog.clock_timestamp()
  then raise exception using errcode='42501',message='pairing_expired'; end if;
  if invite.state='approved' then
    return pg_catalog.jsonb_build_object('status','approved','canonicalApprovedPayload',
      pg_catalog.encode(invite.canonical_approved_payload,'hex'),'receipt',invite.decision_receipt);
  elsif invite.state='rejected' then
    return pg_catalog.jsonb_build_object('status','rejected','receipt',invite.decision_receipt);
  end if;
  return pg_catalog.jsonb_build_object('status',invite.state);
end;
$$;
revoke all on function public.service_pairing_result_for_session(uuid,uuid,uuid,bytea) from public,anon,authenticated,service_role;
grant execute on function public.service_pairing_result_for_session(uuid,uuid,uuid,bytea) to service_role;
reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
