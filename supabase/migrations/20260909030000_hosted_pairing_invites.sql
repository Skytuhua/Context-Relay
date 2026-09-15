grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;

create table context_relay_private.pairing_invites (
  id uuid primary key,
  account_id uuid not null references public.accounts(id) on delete cascade,
  workspace_id uuid not null,
  auth_user_id uuid not null,
  session_id uuid not null,
  device_id uuid not null,
  certificate_id uuid not null,
  control_epoch bigint not null check (control_epoch > 0),
  key_epoch bigint not null check (key_epoch > 0),
  code_digest bytea not null unique check (pg_catalog.octet_length(code_digest)=32),
  created_at timestamptz not null,
  expires_at timestamptz not null,
  constraint pairing_invite_lifetime check (expires_at=created_at+interval '10 minutes'),
  foreign key (account_id,workspace_id,device_id,certificate_id)
    references public.device_certificates(account_id,workspace_id,device_id,id)
);
create index pairing_invites_account_time on context_relay_private.pairing_invites(account_id,created_at);
alter table context_relay_private.pairing_invites enable row level security;
revoke all on context_relay_private.pairing_invites from public,anon,authenticated,service_role;

-- Edge generates the UUIDv7 and code, and supplies only the peppered code digest.
-- Creating an invite installs no trust. The raw code is never stored here.
create function public.service_create_pairing_invite(
  p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_device_id uuid,
  p_pairing_id uuid,p_code_digest bytea
) returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare
  account_row public.accounts%rowtype;
  binding_row public.device_bindings%rowtype;
  certificate_row public.device_certificates%rowtype;
  invite context_relay_private.pairing_invites%rowtype;
  candidate uuid;
  checked_at timestamptz;
begin
  if p_auth_user_id is null or p_session_id is null or p_code_digest is null
    or pg_catalog.octet_length(p_code_digest)<>32
  then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  foreach candidate in array array[p_workspace_id,p_device_id,p_pairing_id] loop
    if candidate is null or candidate::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    then raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  end loop;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select * into account_row from public.accounts where owner_user_id=p_auth_user_id for update;
  if not found or account_row.deletion_state<>'active' or account_row.control_epoch<1 or account_row.key_epoch<1
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select * into binding_row from public.device_bindings
    where account_id=account_row.id and auth_user_id=p_auth_user_id and session_id=p_session_id
      and device_id=p_device_id for update;
  if not found or binding_row.state<>'active' or binding_row.revoked_at is not null
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select * into certificate_row from public.device_certificates
    where account_id=account_row.id and workspace_id=p_workspace_id and device_id=p_device_id
      and control_epoch=account_row.control_epoch for share;
  if not found or certificate_row.issuer_kind<>'recovery_root'
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  perform 1 from public.recovery_roots where account_id=account_row.id
    and signing_public_key=certificate_row.issuer_recovery_public_key and revoked_at is null for share;
  if not found then raise exception using errcode='42501',message='pairing_denied'; end if;
  -- Account locking serializes creation limits; check time and Auth after waits.
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  checked_at:=pg_catalog.clock_timestamp();
  if binding_row.expires_at is not null and binding_row.expires_at<=checked_at
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  select * into invite from context_relay_private.pairing_invites where id=p_pairing_id;
  if found then
    if invite.account_id<>account_row.id or invite.workspace_id<>p_workspace_id
      or invite.auth_user_id<>p_auth_user_id or invite.session_id<>p_session_id
      or invite.device_id<>p_device_id or invite.certificate_id<>certificate_row.id
      or invite.control_epoch<>account_row.control_epoch or invite.key_epoch<>account_row.key_epoch
      or invite.code_digest<>p_code_digest
    then raise exception using errcode='40001',message='pairing_conflict'; end if;
    if invite.expires_at<=checked_at then raise exception using errcode='42501',message='pairing_expired'; end if;
  else
    if (select count(*) from context_relay_private.pairing_invites
      where account_id=account_row.id and created_at>checked_at-interval '1 hour')>=6
    then raise exception using errcode='54000',message='pairing_rate_limited'; end if;
    insert into context_relay_private.pairing_invites values
      (p_pairing_id,account_row.id,p_workspace_id,p_auth_user_id,p_session_id,p_device_id,
       certificate_row.id,account_row.control_epoch,account_row.key_epoch,p_code_digest,
       checked_at,checked_at+interval '10 minutes') returning * into invite;
  end if;
  -- Unique/FK checks can also wait. A stale session must roll back the insert.
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
    or (binding_row.expires_at is not null and binding_row.expires_at<=pg_catalog.clock_timestamp())
    or invite.expires_at<=pg_catalog.clock_timestamp()
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  return pg_catalog.jsonb_build_object('pairingId',invite.id,
    'createdAt',pg_catalog.floor(extract(epoch from invite.created_at)*1000)::text,
    'expiresAt',pg_catalog.floor(extract(epoch from invite.expires_at)*1000)::text);
end;
$$;
revoke all on function public.service_create_pairing_invite(uuid,uuid,uuid,uuid,uuid,bytea)
from public,anon,authenticated,service_role;
grant execute on function public.service_create_pairing_invite(uuid,uuid,uuid,uuid,uuid,bytea) to service_role;
reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
