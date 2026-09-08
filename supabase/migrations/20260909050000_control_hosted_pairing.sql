grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;
alter table context_relay_private.pairing_invites add column state text not null default 'pending'
  check (state in ('pending','canceled','approved','rejected'));

create function public.service_control_pairing_invite(
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
create or replace function public.service_resolve_pairing_code(
  p_auth_user_id uuid,p_session_id uuid,p_code_digest bytea
) returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare
  account_row public.accounts%rowtype;
  invite context_relay_private.pairing_invites%rowtype;
  binding_row public.device_bindings%rowtype;
  certificate_row public.device_certificates%rowtype;
  failures integer;
  live_issuer boolean := false;
  checked_at timestamptz;
begin
  if p_auth_user_id is null or p_session_id is null or p_code_digest is null
    or pg_catalog.octet_length(p_code_digest)<>32
  then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  -- The unique insert and lookup-row lock serialize guesses, including the first one.
  insert into context_relay_private.pairing_lookup_sessions(session_id) values(p_session_id)
    on conflict do nothing;
  select failed_attempts into failures from context_relay_private.pairing_lookup_sessions
    where session_id=p_session_id for update;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  if failures>=5 then return pg_catalog.jsonb_build_object('status','exhausted'); end if;
  select * into account_row from public.accounts where owner_user_id=p_auth_user_id for update;
  select * into invite from context_relay_private.pairing_invites
    where account_id=account_row.id and code_digest=p_code_digest for update;
  if found and account_row.deletion_state='active'
    and invite.control_epoch=account_row.control_epoch and invite.key_epoch=account_row.key_epoch then
    select * into binding_row from public.device_bindings
      where account_id=invite.account_id and session_id=invite.session_id
        and auth_user_id=p_auth_user_id and device_id=invite.device_id for update;
    if found and binding_row.state='active' and binding_row.revoked_at is null then
      select * into certificate_row from public.device_certificates
        where id=invite.certificate_id and account_id=invite.account_id
          and workspace_id=invite.workspace_id and device_id=invite.device_id
          and control_epoch=invite.control_epoch for share;
      if found and certificate_row.issuer_kind='recovery_root' then
        perform 1 from public.recovery_roots where account_id=invite.account_id
          and signing_public_key=certificate_row.issuer_recovery_public_key and revoked_at is null for share;
        live_issuer:=found;
      end if;
    end if;
  end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  checked_at:=pg_catalog.clock_timestamp();
  if not live_issuer or (binding_row.expires_at is not null and binding_row.expires_at<=checked_at) then
    update context_relay_private.pairing_lookup_sessions set failed_attempts=failed_attempts+1
      where session_id=p_session_id returning failed_attempts into failures;
    -- Return failures: an exception would roll back the attempt counter.
    return pg_catalog.jsonb_build_object('status',case when failures=5 then 'exhausted' else 'invalid' end);
  end if;
  if invite.state='canceled' then return pg_catalog.jsonb_build_object('status','canceled'); end if;
  if invite.state='rejected' then return pg_catalog.jsonb_build_object('status','rejected'); end if;
  if invite.state='approved' then return pg_catalog.jsonb_build_object('status','conflict'); end if;
  if invite.expires_at<=checked_at then return pg_catalog.jsonb_build_object('status','expired'); end if;
  if invite.located_session_id is not null and invite.located_session_id<>p_session_id
  then return pg_catalog.jsonb_build_object('status','invalid'); end if;
  update context_relay_private.pairing_invites set located_session_id=p_session_id where id=invite.id;
  return pg_catalog.jsonb_build_object('status','located','pairingId',invite.id);
end;
$$;
revoke all on function public.service_resolve_pairing_code(uuid,uuid,bytea) from public,anon,authenticated,service_role;
grant execute on function public.service_resolve_pairing_code(uuid,uuid,bytea) to service_role;

reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
