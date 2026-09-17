grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;
grant usage, create on schema context_relay_private to session_user;
reset role;
create table context_relay_private.pairing_lookup_sessions (
  session_id uuid primary key references auth.sessions(id) on delete cascade,
  failed_attempts integer not null default 0 check (failed_attempts between 0 and 5)
);
alter table context_relay_private.pairing_lookup_sessions owner to context_relay_rls_owner;
set local role context_relay_rls_owner;
revoke all on schema context_relay_private from session_user;
alter table context_relay_private.pairing_lookup_sessions enable row level security;
revoke all on context_relay_private.pairing_lookup_sessions from public,anon,authenticated,service_role;
-- Retain the original locator session even after logout; another session cannot adopt it.
alter table context_relay_private.pairing_invites add column located_session_id uuid;

create function public.service_resolve_pairing_code(
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
