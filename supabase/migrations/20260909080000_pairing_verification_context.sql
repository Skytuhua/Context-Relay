grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;

create function public.service_pairing_verification_context(
  p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_device_id uuid,p_pairing_id uuid
) returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare
  selected_account_id uuid;
  invite context_relay_private.pairing_invites%rowtype;
  request public.pairing_requests%rowtype;
  issuer public.device_certificates%rowtype;
  candidate uuid;
begin
  if p_auth_user_id is null or p_session_id is null
  then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  foreach candidate in array array[p_workspace_id,p_device_id,p_pairing_id] loop
    if candidate is null or candidate::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  end loop;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select a.id into selected_account_id from public.accounts a where a.owner_user_id=p_auth_user_id for update;
  select * into invite from context_relay_private.pairing_invites
    where id=p_pairing_id and account_id=selected_account_id and auth_user_id=p_auth_user_id
      and session_id=p_session_id and workspace_id=p_workspace_id and device_id=p_device_id for update;
  if not found or invite.control_epoch not between 1 and 4294967295 or invite.key_epoch not between 1 and 4294967295
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  -- New decisions require current authority. A committed decision keeps its
  -- historical verification context so exact receipt retries survive revocation.
  -- The commit RPC alone decides whether a new grant may install trust.
  if invite.decision_receipt is null then
    perform public.service_control_pairing_invite(p_auth_user_id,p_session_id,p_workspace_id,p_device_id,p_pairing_id,'status');
    if invite.state<>'pending' then raise exception using errcode='42501',message='pairing_canceled'; end if;
  end if;
  select * into request from public.pairing_requests where id=invite.id
    and account_id=invite.account_id and workspace_id=invite.workspace_id for share;
  if not found then raise exception using errcode='40001',message='pairing_conflict'; end if;
  select * into issuer from public.device_certificates where id=invite.certificate_id
    and account_id=invite.account_id and workspace_id=invite.workspace_id and device_id=invite.device_id
    and control_epoch=invite.control_epoch and issuer_kind='recovery_root' for share;
  if not found then raise exception using errcode='42501',message='pairing_denied'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  return pg_catalog.jsonb_build_object('canonicalRequest',pg_catalog.encode(request.request_payload,'hex'),
    'trusted',pg_catalog.jsonb_build_object('accountId',invite.account_id,'workspaceId',invite.workspace_id,
      'controlEpoch',invite.control_epoch,'keyEpoch',invite.key_epoch,'issuerDeviceId',invite.device_id,
      'issuerCertificateId',invite.certificate_id,'issuerSigningKey',pg_catalog.encode(issuer.device_signing_public_key,'hex'),
      'recoverySigningKey',pg_catalog.encode(issuer.issuer_recovery_public_key,'hex')));
end;
$$;
revoke all on function public.service_pairing_verification_context(uuid,uuid,uuid,uuid,uuid)
from public,anon,authenticated,service_role;
grant execute on function public.service_pairing_verification_context(uuid,uuid,uuid,uuid,uuid) to service_role;
reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
