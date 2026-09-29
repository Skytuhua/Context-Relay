grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;

-- Edge verifies the canonical request and session-bound possession proof first.
-- The privileged transaction stores exact bytes and grants no device authority.
create function public.service_submit_pairing_request(
  p_auth_user_id uuid,p_session_id uuid,p_pairing_id uuid,p_canonical_request bytea,
  p_signing_key bytea,p_wrapping_key bytea
) returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare
  selected_account_id uuid;
  invite context_relay_private.pairing_invites%rowtype;
  request public.pairing_requests%rowtype;
  digest bytea;
begin
  if p_auth_user_id is null or p_session_id is null or p_pairing_id is null
    or p_pairing_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    or p_canonical_request is null or pg_catalog.octet_length(p_canonical_request) not between 1 and 8192
    or p_signing_key is null or pg_catalog.octet_length(p_signing_key)<>32
    or p_wrapping_key is null or pg_catalog.octet_length(p_wrapping_key)<>32 or p_signing_key=p_wrapping_key
  then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  -- Acquire both Auth locks before account/device locks, matching lifecycle lock order.
  select * into invite from context_relay_private.pairing_invites
    where id=p_pairing_id and auth_user_id=p_auth_user_id and located_session_id=p_session_id;
  if not found then raise exception using errcode='42501',message='pairing_denied'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,invite.session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select a.id into selected_account_id from public.accounts a where a.owner_user_id=p_auth_user_id for update;
  select * into invite from context_relay_private.pairing_invites i
    where i.id=p_pairing_id and i.account_id=selected_account_id and i.located_session_id=p_session_id for update;
  if not found then raise exception using errcode='42501',message='pairing_denied'; end if;
  perform public.service_control_pairing_invite(p_auth_user_id,invite.session_id,
    invite.workspace_id,invite.device_id,invite.id,'status');
  digest:=pg_catalog.sha256(p_canonical_request);
  select * into request from public.pairing_requests where id=invite.id for update;
  if found then
    if request.account_id<>invite.account_id or request.workspace_id<>invite.workspace_id
      or request.request_payload<>p_canonical_request or request.request_digest<>digest
      or request.requester_signing_public_key<>p_signing_key or request.requester_wrapping_public_key<>p_wrapping_key
    then raise exception using errcode='40001',message='pairing_conflict'; end if;
  else
    if invite.state='canceled' then raise exception using errcode='42501',message='pairing_canceled'; end if;
    if invite.state<>'pending' then raise exception using errcode='40001',message='pairing_conflict'; end if;
    insert into public.pairing_requests(id,account_id,workspace_id,request_payload,request_digest,
      requester_signing_public_key,requester_wrapping_public_key,code_digest,expires_at,created_at,updated_at)
    values(invite.id,invite.account_id,invite.workspace_id,p_canonical_request,digest,
      p_signing_key,p_wrapping_key,invite.code_digest,invite.expires_at,pg_catalog.clock_timestamp(),pg_catalog.clock_timestamp())
    returning * into request;
  end if;
  -- A competing unique/FK check can wait after the first authority snapshot.
  perform public.service_control_pairing_invite(p_auth_user_id,invite.session_id,
    invite.workspace_id,invite.device_id,invite.id,'status');
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  return pg_catalog.jsonb_build_object('pairingId',invite.id,'requestDigest',pg_catalog.encode(digest,'hex'),
    'requestedAt',pg_catalog.floor(extract(epoch from request.created_at)*1000)::text);
end;
$$;
revoke all on function public.service_submit_pairing_request(uuid,uuid,uuid,bytea,bytea,bytea)
from public,anon,authenticated,service_role;
grant execute on function public.service_submit_pairing_request(uuid,uuid,uuid,bytea,bytea,bytea) to service_role;

create function public.service_pairing_request_for_approver(
  p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_device_id uuid,p_pairing_id uuid
) returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare
  status jsonb;
  request public.pairing_requests%rowtype;
begin
  status:=public.service_control_pairing_invite(p_auth_user_id,p_session_id,p_workspace_id,p_device_id,p_pairing_id,'status');
  if status->>'state'='canceled' then raise exception using errcode='42501',message='pairing_canceled'; end if;
  select r.* into request from public.pairing_requests r
    join context_relay_private.pairing_invites i on i.id=r.id
      and i.account_id=r.account_id and i.workspace_id=r.workspace_id
    where r.id=p_pairing_id;
  if not found then return 'null'::jsonb; end if;
  return pg_catalog.jsonb_build_object('pairingId',request.id,'accountId',request.account_id,
    'workspaceId',request.workspace_id,'canonicalRequest',pg_catalog.encode(request.request_payload,'hex'),
    'requestDigest',pg_catalog.encode(request.request_digest,'hex'),
    'requestedAt',pg_catalog.floor(extract(epoch from request.created_at)*1000)::text);
end;
$$;
revoke all on function public.service_pairing_request_for_approver(uuid,uuid,uuid,uuid,uuid)
from public,anon,authenticated,service_role;
grant execute on function public.service_pairing_request_for_approver(uuid,uuid,uuid,uuid,uuid) to service_role;
create or replace function public.service_control_pairing_invite(
  p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_device_id uuid,p_pairing_id uuid,p_action text
) returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare
  account_row public.accounts%rowtype;
  invite context_relay_private.pairing_invites%rowtype;
  binding_row public.device_bindings%rowtype;
  certificate_row public.device_certificates%rowtype;
  candidate uuid;
  checked_at timestamptz;
begin
  if p_auth_user_id is null or p_session_id is null or p_action is null or p_action not in ('status','cancel')
  then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  foreach candidate in array array[p_workspace_id,p_device_id,p_pairing_id] loop
    if candidate is null or candidate::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  end loop;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select * into account_row from public.accounts where owner_user_id=p_auth_user_id for update;
  if not found or account_row.deletion_state<>'active'
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select * into invite from context_relay_private.pairing_invites
    where id=p_pairing_id and account_id=account_row.id and workspace_id=p_workspace_id
      and device_id=p_device_id and auth_user_id=p_auth_user_id and session_id=p_session_id for update;
  if not found or invite.control_epoch<>account_row.control_epoch or invite.key_epoch<>account_row.key_epoch
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select * into binding_row from public.device_bindings
    where account_id=invite.account_id and session_id=p_session_id
      and auth_user_id=p_auth_user_id and device_id=p_device_id for update;
  if not found or binding_row.state<>'active' or binding_row.revoked_at is not null
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select * into certificate_row from public.device_certificates
    where id=invite.certificate_id and account_id=invite.account_id
      and workspace_id=p_workspace_id and device_id=p_device_id and control_epoch=invite.control_epoch for share;
  if not found or certificate_row.issuer_kind<>'recovery_root'
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  perform 1 from public.recovery_roots where account_id=invite.account_id
    and signing_public_key=certificate_row.issuer_recovery_public_key and revoked_at is null for share;
  if not found then raise exception using errcode='42501',message='pairing_denied'; end if;
  perform 1 from public.pairing_requests where id=invite.id
    and account_id=invite.account_id and workspace_id=invite.workspace_id for update;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  checked_at:=pg_catalog.clock_timestamp();
  if binding_row.expires_at is not null and binding_row.expires_at<=checked_at
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  -- Terminal decisions survive the original invite lifetime, as in the native provider.
  if invite.state='pending' and invite.expires_at<=checked_at
  then raise exception using errcode='42501',message='pairing_expired'; end if;
  if p_action='cancel' then
    if invite.state='approved' then raise exception using errcode='40001',message='pairing_conflict'; end if;
    if invite.state='rejected' then raise exception using errcode='40001',message='pairing_rejected'; end if;
    update public.pairing_requests set state='cancelled',updated_at=pg_catalog.clock_timestamp()
      where id=invite.id and account_id=invite.account_id and workspace_id=invite.workspace_id;
    update context_relay_private.pairing_invites set state='canceled' where id=invite.id returning * into invite;
  end if;
  return pg_catalog.jsonb_build_object('pairingId',invite.id,'state',invite.state,
    'createdAt',pg_catalog.floor(extract(epoch from invite.created_at)*1000)::text,
    'expiresAt',pg_catalog.floor(extract(epoch from invite.expires_at)*1000)::text);
end;
$$;
revoke all on function public.service_control_pairing_invite(uuid,uuid,uuid,uuid,uuid,text)
from public,anon,authenticated,service_role;
grant execute on function public.service_control_pairing_invite(uuid,uuid,uuid,uuid,uuid,text) to service_role;

reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
