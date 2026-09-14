-- Public history is immutable server CAS state, never a native acceptance signal.
grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;

create table context_relay_private.membership_heads (
  workspace_id uuid primary key,
  account_id uuid not null references public.accounts(id) on delete cascade,
  enrollment_sha256 bytea not null check(octet_length(enrollment_sha256)=32),
  genesis_sha256 bytea not null check(octet_length(genesis_sha256)=32),
  state_sha256 bytea not null check(octet_length(state_sha256)=32),
  control_epoch bigint not null check(control_epoch between 1 and 4294967295),
  key_epoch bigint not null check(key_epoch between 1 and 4294967295)
);
create table context_relay_private.membership_members (
  workspace_id uuid not null references context_relay_private.membership_heads(workspace_id) on delete cascade,
  device_id uuid not null,
  certificate_id uuid not null unique references public.device_certificates(id) deferrable initially deferred,
  canonical_certificate bytea not null check(octet_length(canonical_certificate) between 1 and 1024),
  admission_sha256 bytea not null check(octet_length(admission_sha256)=32),
  active boolean not null,
  primary key(workspace_id,device_id)
);
create table context_relay_private.membership_events (
  event_id uuid primary key,
  workspace_id uuid not null references context_relay_private.membership_heads(workspace_id) on delete cascade,
  parent_sha256 bytea not null check(octet_length(parent_sha256)=32),
  successor_sha256 bytea not null check(octet_length(successor_sha256)=32),
  canonical_object bytea not null check(octet_length(canonical_object) between 1 and 16777216),
  unique(workspace_id,parent_sha256),
  unique(workspace_id,successor_sha256)
);
alter table context_relay_private.membership_heads enable row level security;
alter table context_relay_private.membership_members enable row level security;
alter table context_relay_private.membership_events enable row level security;
revoke all on table context_relay_private.membership_heads,context_relay_private.membership_members,
  context_relay_private.membership_events from public,anon,authenticated,service_role;
alter table context_relay_private.pairing_invites add column membership_signature bytea
  check(membership_signature is null or octet_length(membership_signature)=64);

-- Exact canonical V1 extraction, not a general CBOR parser or signature verifier.
-- Edge verifies root/certificate/possession before the existing enrollment RPC.
create function context_relay_private.initialize_committed_membership(p_auth_user_id uuid)
returns context_relay_private.membership_heads language plpgsql volatile security definer set search_path=''
as $$
<<anchor>>
declare
  committed context_relay_private.enrollment_commits%rowtype;
  account_row public.accounts%rowtype;
  head context_relay_private.membership_heads%rowtype;
  record bytea; cert bytea; pin bytea; genesis bytea;
  account_id uuid; workspace_id uuid; device_id uuid; certificate_id uuid; root_id uuid;
begin
  select * into account_row from public.accounts where owner_user_id=p_auth_user_id for update;
  if not found or account_row.deletion_state<>'active' then
    raise exception using errcode='42501',message='pairing_denied'; end if;
  select * into committed from context_relay_private.enrollment_commits ec
    where ec.auth_user_id=p_auth_user_id and ec.account_id=account_row.id for share;
  if not found then raise exception using errcode='40001',message='pairing_conflict'; end if;
  record:=committed.canonical_record;
  if octet_length(record) not between 500 and 32768
    or substring(record from 1 for 5)<>decode('ae00010150','hex')
    or substring(record from 22 for 2)<>decode('0250','hex')
    or substring(record from 40 for 2)<>decode('0350','hex')
    or substring(record from 58 for 2)<>decode('0450','hex')
    or substring(record from 76 for 3)<>decode('055820','hex')
    or substring(record from 111 for 3)<>decode('065820','hex')
    or substring(record from 146 for 2)<>decode('0750','hex')
    or get_byte(record,163)<>8 or get_byte(record,432)<>9 then
    raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  cert:=substring(record from 165 for 268);
  if substring(cert from 1 for 8)<>decode('a900a20000015820','hex')
    or substring(cert from 41 for 2)<>decode('0150','hex')
    or substring(cert from 59 for 2)<>decode('0250','hex')
    or substring(cert from 77 for 5)<>decode('0301045820','hex')
    or substring(cert from 114 for 2)<>decode('0550','hex')
    or substring(cert from 132 for 3)<>decode('065820','hex')
    or substring(cert from 167 for 3)<>decode('075820','hex')
    or substring(cert from 202 for 3)<>decode('085840','hex')
    or substring(cert from 9 for 32)<>substring(record from 79 for 32)
    or substring(cert from 43 for 16)<>substring(record from 42 for 16)
    or substring(cert from 61 for 16)<>substring(record from 60 for 16) then
    raise exception using errcode='22023',message='invalid_pairing_request'; end if;
  account_id:=encode(substring(record from 42 for 16),'hex')::uuid;
  workspace_id:=encode(substring(record from 60 for 16),'hex')::uuid;
  certificate_id:=encode(substring(record from 148 for 16),'hex')::uuid;
  device_id:=encode(substring(cert from 116 for 16),'hex')::uuid;
  root_id:=encode(substring(record from 24 for 16),'hex')::uuid;
  pin:=pg_catalog.sha256(record);
  if account_id<>account_row.id or jsonb_typeof(committed.receipt) is distinct from 'object'
    or (committed.receipt->>'registeredAtMs') is null or (committed.receipt->>'registeredAtMs') !~ '^(0|[1-9][0-9]*)$'
    or committed.receipt->>'accountId' is distinct from account_id::text
    or committed.receipt->>'workspaceId' is distinct from workspace_id::text
    or committed.receipt->>'genesisCertificateId' is distinct from certificate_id::text
    or committed.receipt->>'recoveryRootId' is distinct from root_id::text
    or committed.receipt->>'enrollmentId' is distinct from encode(substring(record from 6 for 16),'hex')::uuid::text
    or committed.receipt->>'canonicalRecordSha256' is distinct from encode(pin,'hex')
    or exists(select 1 from unnest(array[account_id,workspace_id,certificate_id,device_id,root_id]) as x(id)
      where x.id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') then
    raise exception using errcode='40001',message='pairing_conflict'; end if;
  genesis:=pg_catalog.sha256(convert_to('context-relay/revocation-anchor/v1','UTF8')||decode('00','hex')||pin||decode('00000001','hex')||pg_catalog.uuid_send(device_id)||pg_catalog.sha256(cert));
  select * into head from context_relay_private.membership_heads h where h.workspace_id=anchor.workspace_id for update;
  if found then
    if head.account_id<>account_id or head.enrollment_sha256<>pin or head.genesis_sha256<>genesis
      or not exists(select 1 from context_relay_private.membership_members m where m.workspace_id=head.workspace_id
        and m.device_id=anchor.device_id and m.certificate_id=anchor.certificate_id
        and m.canonical_certificate=cert and m.admission_sha256=genesis) then
      raise exception using errcode='40001',message='pairing_conflict'; end if;
    return head; -- Preserve a descendant head and all revoked-member facts.
  end if;
  if account_row.control_epoch<>1 or account_row.key_epoch<>1
    or (select count(*) from public.device_certificates c where c.account_id=account_row.id)<>1
    or not exists(select 1 from public.recovery_roots r where r.id=root_id and r.account_id=account_row.id
      and r.signing_public_key=substring(record from 79 for 32) and r.wrapping_public_key=substring(record from 114 for 32)
      and r.revoked_at is null)
    or not exists(select 1 from public.device_certificates c where c.id=anchor.certificate_id and c.account_id=account_row.id
      and c.workspace_id=anchor.workspace_id and c.device_id=anchor.device_id
      and c.control_epoch=1 and c.issuer_kind='recovery_root' and c.issuer_recovery_public_key=substring(cert from 9 for 32)
      and c.request_nonce=substring(cert from 82 for 32) and c.device_signing_public_key=substring(cert from 135 for 32)
      and c.device_wrapping_public_key=substring(cert from 170 for 32) and c.signature=substring(cert from 205 for 64)) then
    raise exception using errcode='40001',message='pairing_conflict'; end if;
  insert into context_relay_private.membership_heads values(workspace_id,account_id,pin,genesis,genesis,1,1) returning * into head;
  insert into context_relay_private.membership_members values(workspace_id,device_id,certificate_id,cert,genesis,true);
  return head;
end;
$$;
revoke all on function context_relay_private.initialize_committed_membership(uuid) from public,anon,authenticated,service_role;

create function context_relay_private.initialize_enrollment_membership_trigger()
returns trigger language plpgsql volatile security definer set search_path=''
as $$
begin
  perform context_relay_private.initialize_committed_membership(new.auth_user_id);
  if not context_relay_private.lock_live_account_lifecycle_auth_session(new.auth_user_id,new.session_id) then
    raise exception using errcode='42501',message='enrollment_session_denied'; end if;
  return new;
end;
$$;
revoke all on function context_relay_private.initialize_enrollment_membership_trigger() from public,anon,authenticated,service_role;
create trigger initialize_enrollment_membership after insert on context_relay_private.enrollment_commits
  for each row execute function context_relay_private.initialize_enrollment_membership_trigger();

-- The Edge re-verifies the stored root-signed record before requesting this
-- idempotent initialization; the RPC independently binds its exact pin and scope.
create function public.service_initialize_committed_membership(
  p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_enrollment_sha256 bytea
) returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare h context_relay_private.membership_heads%rowtype;
begin
  if p_workspace_id is null or p_workspace_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    or p_enrollment_sha256 is null or octet_length(p_enrollment_sha256)<>32
  then raise exception using errcode='22023',message='invalid_pairing_request';end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied';end if;
  h:=context_relay_private.initialize_committed_membership(p_auth_user_id);
  if h.workspace_id<>p_workspace_id or h.enrollment_sha256<>p_enrollment_sha256
  then raise exception using errcode='40001',message='pairing_conflict';end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied';end if;
  return jsonb_build_object('stateSha256',encode(h.state_sha256,'hex'),'controlEpoch',h.control_epoch,'keyEpoch',h.key_epoch);
end;
$$;
revoke all on function public.service_initialize_committed_membership(uuid,uuid,uuid,bytea) from public,anon,authenticated,service_role;
grant execute on function public.service_initialize_committed_membership(uuid,uuid,uuid,bytea) to service_role;

-- Shared current authorization only. Accepted canonical history supplies member
-- identity; provider bindings restrict its live session and never add a member.
create function context_relay_private.lock_current_membership_member(
  p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_device_id uuid
) returns context_relay_private.membership_members language plpgsql volatile security definer set search_path=''
as $$
declare
  a public.accounts%rowtype;
  h context_relay_private.membership_heads%rowtype;
  m context_relay_private.membership_members%rowtype;
  b public.device_bindings%rowtype;
  candidate uuid;
begin
  foreach candidate in array array[p_workspace_id,p_device_id] loop
    if candidate is null or candidate::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    then raise exception using errcode='22023',message='invalid_pairing_request';end if;
  end loop;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied';end if;
  select * into a from public.accounts where owner_user_id=p_auth_user_id for update;
  if not found or a.deletion_state<>'active'
  then raise exception using errcode='42501',message='pairing_denied';end if;
  select * into h from context_relay_private.membership_heads where workspace_id=p_workspace_id and account_id=a.id for update;
  if not found or h.control_epoch<>a.control_epoch or h.key_epoch<>a.key_epoch
  then raise exception using errcode='42501',message='pairing_denied';end if;
  select * into m from context_relay_private.membership_members where workspace_id=p_workspace_id and device_id=p_device_id for share;
  if not found or not m.active then raise exception using errcode='42501',message='pairing_denied';end if;
  select * into b from public.device_bindings where account_id=a.id and auth_user_id=p_auth_user_id
    and session_id=p_session_id and device_id=p_device_id for update;
  if not found or b.state<>'active' or b.revoked_at is not null
  then raise exception using errcode='42501',message='pairing_denied';end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
    or (b.expires_at is not null and b.expires_at<=clock_timestamp())
  then raise exception using errcode='42501',message='pairing_denied';end if;
  return m;
end;
$$;
revoke all on function context_relay_private.lock_current_membership_member(uuid,uuid,uuid,uuid) from public,anon,authenticated,service_role;

create function public.service_membership_endpoint(p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_device_id uuid)
returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare h context_relay_private.membership_heads%rowtype;
begin
  perform context_relay_private.lock_current_membership_member(p_auth_user_id,p_session_id,p_workspace_id,p_device_id);
  select * into strict h from context_relay_private.membership_heads where workspace_id=p_workspace_id;
  return jsonb_build_object('stateSha256',encode(h.state_sha256,'hex'),'controlEpoch',h.control_epoch,'keyEpoch',h.key_epoch);
end;
$$;
revoke all on function public.service_membership_endpoint(uuid,uuid,uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.service_membership_endpoint(uuid,uuid,uuid,uuid) to service_role;

-- Pairing now authorizes the current canonical membership, including admitted issuers.
create or replace function public.service_create_pairing_invite(
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
  select * into certificate_row from public.device_certificates where id=
    (context_relay_private.lock_current_membership_member(p_auth_user_id,p_session_id,p_workspace_id,p_device_id)).certificate_id;
  if not found then raise exception using errcode='42501',message='pairing_denied';end if;
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
    -- Keep the entire creation-limit window and every committed decision.
    -- Account locking serializes this cleanup with all pairing mutations.
    with expired as (
      delete from context_relay_private.pairing_invites
      where account_id=account_row.id and created_at<=checked_at-interval '1 hour'
        and expires_at<=checked_at and state in ('pending','canceled') and decision_receipt is null
      returning id,account_id,workspace_id
    )
    delete from public.pairing_requests r using expired e
      where r.id=e.id and r.account_id=e.account_id and r.workspace_id=e.workspace_id
        and r.state in ('pending','cancelled') and r.decision_metadata is null;
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
  if (context_relay_private.lock_current_membership_member(p_auth_user_id,p_session_id,p_workspace_id,p_device_id)).certificate_id<>invite.certificate_id
  then raise exception using errcode='42501',message='pairing_denied';end if;
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
  select * into invite from context_relay_private.pairing_invites
    where auth_user_id=p_auth_user_id and code_digest=p_code_digest;
  if found then
    live_issuer:=context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,invite.session_id);
  end if;
  select * into account_row from public.accounts where owner_user_id=p_auth_user_id for update;
  select * into invite from context_relay_private.pairing_invites
    where account_id=account_row.id and code_digest=p_code_digest for update;
  if found and live_issuer and account_row.deletion_state='active'
    and invite.control_epoch=account_row.control_epoch and invite.key_epoch=account_row.key_epoch then
    begin
      live_issuer:=(context_relay_private.lock_current_membership_member(p_auth_user_id,invite.session_id,invite.workspace_id,invite.device_id)).certificate_id=invite.certificate_id;
    exception when insufficient_privilege then live_issuer:=false;end;
  else live_issuer:=false;
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

create or replace function public.service_decide_pairing_request(
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
  if exists(select 1 from context_relay_private.membership_heads where workspace_id=p_workspace_id) then
    raise exception using errcode='40001',message='pairing_conflict';end if;
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

create or replace function public.service_decide_pairing_request_v2(
  p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_device_id uuid,p_pairing_id uuid,
  p_request_digest bytea,p_action text,p_control_epoch bigint,p_key_epoch bigint,
  p_approved_payload bytea,p_certificate_id uuid,p_child_device_id uuid,p_request_nonce bytea,p_signature bytea,
  p_previous_state_sha256 bytea,p_enrollment_sha256 bytea,p_membership_signature bytea,p_canonical_certificate bytea
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
  h context_relay_private.membership_heads%rowtype;
  member context_relay_private.membership_members%rowtype;
  statement bytea; successor bytea; object bytea;
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
  if p_previous_state_sha256 is null or octet_length(p_previous_state_sha256)<>32
    or p_enrollment_sha256 is null or octet_length(p_enrollment_sha256)<>32
    or (p_action='approve' and (p_membership_signature is null or octet_length(p_membership_signature)<>64
      or p_canonical_certificate is null or octet_length(p_canonical_certificate) not between 1 and 1024))
    or (p_action='reject' and (p_membership_signature is not null or p_canonical_certificate is not null))
  then raise exception using errcode='22023',message='invalid_pairing_request';end if;
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
  member:=context_relay_private.lock_current_membership_member(p_auth_user_id,p_session_id,p_workspace_id,p_device_id);
  if member.certificate_id<>invite.certificate_id then raise exception using errcode='42501',message='pairing_denied';end if;
  select * into strict h from context_relay_private.membership_heads where workspace_id=p_workspace_id;
  if h.enrollment_sha256<>p_enrollment_sha256 then raise exception using errcode='40001',message='pairing_conflict';end if;
  if invite.decision_receipt is not null then
    if (p_action='approve' and invite.state='approved' and invite.canonical_approved_payload=p_approved_payload
      and invite.membership_signature=p_membership_signature
      and exists(select 1 from context_relay_private.membership_events e where e.event_id=invite.id
        and e.workspace_id=p_workspace_id and e.parent_sha256=p_previous_state_sha256)
      and exists(select 1 from context_relay_private.membership_members m where m.workspace_id=p_workspace_id
        and m.device_id=p_child_device_id and m.certificate_id=p_certificate_id and m.canonical_certificate=p_canonical_certificate))
      or (p_action='reject' and invite.state='rejected')
    then return invite.decision_receipt; end if;
    raise exception using errcode='40001',message='pairing_conflict';
  end if;
  if h.state_sha256<>p_previous_state_sha256 or h.control_epoch<>p_control_epoch or h.key_epoch<>p_key_epoch
  then raise exception using errcode='40001',message='pairing_conflict';end if;
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
  if p_action='approve' then
    statement:=convert_to('context-relay/device-membership-add/v1','UTF8')||decode('000001','hex')||uuid_send(invite.id)
      ||uuid_send(invite.account_id)||uuid_send(invite.workspace_id)||p_previous_state_sha256
      ||decode(lpad(to_hex(p_control_epoch),8,'0'),'hex')||decode(lpad(to_hex(p_key_epoch),8,'0'),'hex')
      ||uuid_send(invite.device_id)||uuid_send(p_certificate_id)||sha256(p_canonical_certificate)||sha256(p_approved_payload);
    successor:=sha256(convert_to('context-relay/membership-control-state/v1','UTF8')||decode('00','hex')||statement||p_membership_signature);
    object:=convert_to('context-relay/public-membership-event/v1','UTF8')||decode('0001','hex')
      ||int4send(octet_length(statement))||statement||int4send(64)||p_membership_signature
      ||int4send(octet_length(request.request_payload))||request.request_payload
      ||int4send(octet_length(p_approved_payload))||p_approved_payload;
    insert into context_relay_private.membership_events values(invite.id,invite.workspace_id,p_previous_state_sha256,successor,object);
    insert into context_relay_private.membership_members values(invite.workspace_id,p_child_device_id,p_certificate_id,p_canonical_certificate,successor,true);
    update context_relay_private.membership_heads set state_sha256=successor where workspace_id=p_workspace_id and state_sha256=p_previous_state_sha256;
    if not found then raise exception using errcode='40001',message='pairing_conflict';end if;
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
    canonical_approved_payload=p_approved_payload,membership_signature=p_membership_signature,decision_receipt=receipt where id=invite.id;
  -- Unique/FK checks may wait. Recheck time even though state is now terminal;
  -- any failure rolls back the certificate, binding, decision and receipt together.
  perform public.service_control_pairing_invite(p_auth_user_id,p_session_id,p_workspace_id,p_device_id,p_pairing_id,'status');
  if invite.expires_at<=pg_catalog.clock_timestamp()
    or (p_action='approve' and not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,invite.located_session_id))
  then raise exception using errcode='42501',message='pairing_denied'; end if;
  return receipt;
end;
$$;
revoke all on function public.service_decide_pairing_request_v2(uuid,uuid,uuid,uuid,uuid,bytea,text,bigint,bigint,bytea,uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea) from public,anon,authenticated,service_role;
grant execute on function public.service_decide_pairing_request_v2(uuid,uuid,uuid,uuid,uuid,bytea,text,bigint,bigint,bytea,uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea) to service_role;

-- Verification context is selected from exact canonical membership. An exact
-- committed approval retry verifies its original parent but still needs a live
-- current issuer and the original invite epochs.
create or replace function public.service_pairing_verification_context(
  p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_device_id uuid,p_pairing_id uuid
) returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare
  invite context_relay_private.pairing_invites%rowtype;
  request public.pairing_requests%rowtype;
  m context_relay_private.membership_members%rowtype;
  h context_relay_private.membership_heads%rowtype;
  issuer public.device_certificates%rowtype;
  parent bytea;
begin
  perform public.service_control_pairing_invite(p_auth_user_id,p_session_id,p_workspace_id,p_device_id,p_pairing_id,'status');
  m:=context_relay_private.lock_current_membership_member(p_auth_user_id,p_session_id,p_workspace_id,p_device_id);
  select * into strict h from context_relay_private.membership_heads where workspace_id=p_workspace_id;
  select * into strict invite from context_relay_private.pairing_invites where id=p_pairing_id;
  select * into request from public.pairing_requests where id=invite.id and account_id=h.account_id and workspace_id=h.workspace_id for share;
  if not found then raise exception using errcode='40001',message='pairing_conflict';end if;
  select * into strict issuer from public.device_certificates where id=m.certificate_id;
  parent:=h.state_sha256;
  if invite.state='approved' then
    select parent_sha256 into parent from context_relay_private.membership_events where event_id=invite.id and workspace_id=h.workspace_id;
    if not found or invite.membership_signature is null then raise exception using errcode='40001',message='pairing_conflict';end if;
  end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied';end if;
  return jsonb_build_object('canonicalRequest',encode(request.request_payload,'hex'),'trusted',jsonb_build_object(
    'accountId',h.account_id,'workspaceId',h.workspace_id,'controlEpoch',h.control_epoch,'keyEpoch',h.key_epoch,
    'issuerDeviceId',m.device_id,'issuerCertificateId',m.certificate_id,'issuerSigningKey',encode(issuer.device_signing_public_key,'hex'),
    'issuerCertificate',encode(m.canonical_certificate,'hex'),'stateSha256',encode(parent,'hex'),'enrollmentSha256',encode(h.enrollment_sha256,'hex')));
end;
$$;

create function context_relay_private.lock_pairing_membership_recipient(
  p_auth_user_id uuid,p_session_id uuid,p_pairing_id uuid,p_request_digest bytea
) returns context_relay_private.membership_members language plpgsql volatile security definer set search_path=''
as $$
declare
  selected_account_id uuid;
  invite context_relay_private.pairing_invites%rowtype;
  request public.pairing_requests%rowtype;
  binding public.device_bindings%rowtype;
  m context_relay_private.membership_members%rowtype;
begin
  if p_pairing_id is null or p_pairing_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    or p_request_digest is null or octet_length(p_request_digest)<>32
  then raise exception using errcode='22023',message='invalid_pairing_request';end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='pairing_denied';end if;
  select a.id into selected_account_id from public.accounts a where a.owner_user_id=p_auth_user_id for update;
  select * into invite from context_relay_private.pairing_invites i where i.id=p_pairing_id and i.account_id=selected_account_id
    and i.auth_user_id=p_auth_user_id and i.located_session_id=p_session_id for share;
  if not found or invite.state<>'approved' or invite.membership_signature is null
  then raise exception using errcode='42501',message='pairing_denied';end if;
  select * into request from public.pairing_requests r where r.id=invite.id and r.account_id=invite.account_id
    and r.workspace_id=invite.workspace_id and r.request_digest=p_request_digest for share;
  if not found then raise exception using errcode='40001',message='pairing_conflict';end if;
  select * into binding from public.device_bindings b where b.account_id=invite.account_id
    and b.auth_user_id=p_auth_user_id and b.session_id=p_session_id;
  if not found then raise exception using errcode='42501',message='pairing_denied';end if;
  m:=context_relay_private.lock_current_membership_member(p_auth_user_id,p_session_id,invite.workspace_id,binding.device_id);
  if not exists(select 1 from public.device_certificates c where c.id=m.certificate_id and c.account_id=invite.account_id
    and c.workspace_id=invite.workspace_id and c.device_id=m.device_id
    and c.device_signing_public_key=request.requester_signing_public_key and c.device_wrapping_public_key=request.requester_wrapping_public_key)
  then raise exception using errcode='42501',message='pairing_denied';end if;
  return m;
end;
$$;
revoke all on function context_relay_private.lock_pairing_membership_recipient(uuid,uuid,uuid,bytea) from public,anon,authenticated,service_role;

create function public.service_pairing_membership_object(
  p_auth_user_id uuid,p_session_id uuid,p_pairing_id uuid,p_request_digest bytea,p_kind text,p_address bytea
) returns text language plpgsql volatile security definer set search_path=''
as $$
declare
  m context_relay_private.membership_members%rowtype;
  h context_relay_private.membership_heads%rowtype;
  object bytea;
begin
  if p_kind is null or p_kind not in ('membership_enrollment','membership_event')
    or p_address is null or octet_length(p_address)<>32
  then raise exception using errcode='22023',message='invalid_pairing_request';end if;
  m:=context_relay_private.lock_pairing_membership_recipient(p_auth_user_id,p_session_id,p_pairing_id,p_request_digest);
  select * into strict h from context_relay_private.membership_heads where workspace_id=m.workspace_id;
  if p_kind='membership_enrollment' and p_address=h.enrollment_sha256 then
    select ec.canonical_record into object from context_relay_private.enrollment_commits ec
      where ec.auth_user_id=p_auth_user_id and ec.account_id=h.account_id;
  elsif p_kind='membership_event' then
    -- Bound reads to ancestors of this recipient's immutable admission C. Later
    -- server heads never select a native D, and absent evidence stays repairable.
    with recursive lineage(address,depth) as (
      select m.admission_sha256,0
      union all
      select e.parent_sha256,l.depth+1 from lineage l join context_relay_private.membership_events e
        on e.workspace_id=m.workspace_id and e.successor_sha256=l.address where l.depth<4096
    ) select e.canonical_object into object from context_relay_private.membership_events e
      where e.workspace_id=m.workspace_id and e.successor_sha256=p_address
        and exists(select 1 from lineage l where l.address=p_address);
  end if;
  perform context_relay_private.lock_pairing_membership_recipient(p_auth_user_id,p_session_id,p_pairing_id,p_request_digest);
  return encode(object,'hex');
end;
$$;
revoke all on function public.service_pairing_membership_object(uuid,uuid,uuid,bytea,text,bytea) from public,anon,authenticated,service_role;
grant execute on function public.service_pairing_membership_object(uuid,uuid,uuid,bytea,text,bytea) to service_role;

create or replace function public.service_pairing_result_for_session(p_auth_user_id uuid,p_session_id uuid,p_pairing_id uuid,p_request_digest bytea)
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
    perform context_relay_private.lock_pairing_membership_recipient(p_auth_user_id,p_session_id,p_pairing_id,p_request_digest);
    return pg_catalog.jsonb_build_object('status','approved','canonicalApprovedPayload',
      pg_catalog.encode(invite.canonical_approved_payload,'hex'),'receipt',invite.decision_receipt,'membershipSignature',encode(invite.membership_signature,'hex'));
  elsif invite.state='rejected' then
    return pg_catalog.jsonb_build_object('status','rejected','receipt',invite.decision_receipt);
  end if;
  return pg_catalog.jsonb_build_object('status',invite.state);
end;
$$;
revoke all on function public.service_pairing_result_for_session(uuid,uuid,uuid,bytea) from public,anon,authenticated,service_role;
grant execute on function public.service_pairing_result_for_session(uuid,uuid,uuid,bytea) to service_role;
-- V2 root recovery shares the exact public membership CAS.
create function public.service_commit_recovery_v2_for_session(
  p_auth_user_id uuid,p_session_id uuid,p_restore_id uuid,p_enrollment_id uuid,p_root_id uuid,
  p_account_id uuid,p_workspace_id uuid,p_certificate_id uuid,p_device_id uuid,p_expected_generation bigint,
  p_record_sha256 bytea,p_canonical_claim bytea,p_request_nonce bytea,
  p_device_signing_key bytea,p_device_wrapping_key bytea,p_certificate_signature bytea,
  p_control_epoch bigint,p_key_epoch bigint,p_parent_sha256 bytea,p_canonical_certificate bytea,p_root_signature bytea
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
  head context_relay_private.membership_heads%rowtype;
  member context_relay_private.membership_members%rowtype;
  successor bytea;
  object bytea;
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
  if p_control_epoch is null or p_control_epoch not between 1 and 4294967295
    or p_key_epoch is null or p_key_epoch not between 1 and 4294967295
    or p_parent_sha256 is null or octet_length(p_parent_sha256)<>32 or p_parent_sha256=decode(repeat('00',32),'hex')
    or p_canonical_certificate is null or octet_length(p_canonical_certificate) not between 1 and 1024
    or p_root_signature is null or octet_length(p_root_signature)<>64
    or substring(p_canonical_claim from 1 for 3)<>decode('b00002','hex')
    or substring(p_canonical_claim from octet_length(p_canonical_claim)-63 for 64)<>p_root_signature
  then raise exception using errcode='22023',message='invalid_recovery_request';end if;
  successor:=sha256(convert_to('context-relay/recovery-membership-add/v1','UTF8')||decode('00','hex')||p_canonical_claim);
  object:=convert_to('context-relay/public-membership-event/v1','UTF8')||decode('0002','hex')||int4send(0)||int4send(64)||p_root_signature||int4send(0)||int4send(octet_length(p_canonical_claim))||p_canonical_claim;
  if p_device_signing_key=p_device_wrapping_key
  then raise exception using errcode='22023',message='invalid_recovery_request'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='enrollment_session_denied'; end if;
  select * into account_row from public.accounts where id=p_account_id and owner_user_id=p_auth_user_id for update;
  if not found or account_row.deletion_state<>'active' then raise exception using errcode='42501',message='recovery_denied'; end if;
  select * into head from context_relay_private.membership_heads where account_id=p_account_id and workspace_id=p_workspace_id for update;
  if not found or head.enrollment_sha256<>p_record_sha256
    or head.control_epoch<>account_row.control_epoch or head.key_epoch<>account_row.key_epoch
  then raise exception using errcode='40001',message='recovery_conflict';end if;
  select * into enrollment from context_relay_private.enrollment_commits
    where account_id=p_account_id and auth_user_id=p_auth_user_id for share;
  if not found or enrollment.receipt->>'enrollmentId' <> p_enrollment_id::text
    or enrollment.receipt->>'recoveryRootId' <> p_root_id::text
    or enrollment.receipt->>'workspaceId' <> p_workspace_id::text
    or pg_catalog.sha256(enrollment.canonical_record) <> p_record_sha256
  then raise exception using errcode='40001',message='recovery_conflict'; end if;
  select * into root_row from public.recovery_roots where id=p_root_id and account_id=p_account_id for update;
  if not found or root_row.revoked_at is not null then raise exception using errcode='42501',message='recovery_denied'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='enrollment_session_denied'; end if;
  select * into previous from context_relay_private.recovery_commits where restore_id=p_restore_id;
  if found then
    if previous.account_id<>p_account_id or previous.auth_user_id<>p_auth_user_id
      or previous.session_id<>p_session_id or previous.canonical_claim<>p_canonical_claim
    then raise exception using errcode='40001',message='recovery_conflict'; end if;
    -- Exact retries acknowledge history only while the original recipient is
    -- still current. No binding or head is recreated from the receipt.
    begin
      member:=context_relay_private.lock_current_membership_member(p_auth_user_id,p_session_id,p_workspace_id,p_device_id);
    exception when insufficient_privilege then raise exception using errcode='42501',message='recovery_denied';end;
    if member.certificate_id<>p_certificate_id or member.canonical_certificate<>p_canonical_certificate
      or member.admission_sha256<>successor
      or not exists(select 1 from context_relay_private.membership_events e where e.event_id=p_restore_id
        and e.workspace_id=p_workspace_id and e.parent_sha256=p_parent_sha256 and e.successor_sha256=successor and e.canonical_object=object)
    then raise exception using errcode='40001',message='recovery_conflict';end if;
    return previous.receipt;
  end if;
  if account_row.deletion_state<>'active' or root_row.revoked_at is not null
  then raise exception using errcode='42501',message='recovery_denied'; end if;
  if account_row.control_epoch<>p_control_epoch or account_row.key_epoch<>p_key_epoch
    or head.state_sha256<>p_parent_sha256
    or root_row.recovery_generation<>p_expected_generation
  then raise exception using errcode='40001',message='recovery_publication_rejected'; end if;
  if p_certificate_id::text=enrollment.receipt->>'genesisCertificateId'
    or exists(select 1 from public.device_certificates where account_id=p_account_id and device_id=p_device_id)
    or exists(select 1 from public.device_bindings where session_id=p_session_id)
  then raise exception using errcode='40001',message='recovery_conflict'; end if;

  insert into public.device_certificates(id,account_id,workspace_id,control_epoch,request_nonce,device_id,
    issuer_kind,issuer_recovery_public_key,issuer_signing_public_key,device_signing_public_key,device_wrapping_public_key,signature)
    values(p_certificate_id,p_account_id,p_workspace_id,p_control_epoch,p_request_nonce,p_device_id,'recovery_root',
      root_row.signing_public_key,root_row.signing_public_key,p_device_signing_key,p_device_wrapping_key,p_certificate_signature);
  insert into public.device_bindings(account_id,auth_user_id,session_id,device_id,state)
    values(p_account_id,p_auth_user_id,p_session_id,p_device_id,'active');
  insert into context_relay_private.membership_members(workspace_id,device_id,certificate_id,canonical_certificate,admission_sha256,active)
    values(p_workspace_id,p_device_id,p_certificate_id,p_canonical_certificate,successor,true);
  insert into context_relay_private.membership_events(event_id,workspace_id,parent_sha256,successor_sha256,canonical_object)
    values(p_restore_id,p_workspace_id,p_parent_sha256,successor,object);
  update context_relay_private.membership_heads set state_sha256=successor where workspace_id=p_workspace_id;
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
revoke all on function public.service_commit_recovery_v2_for_session(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,bytea,bytea,bytea,bytea,bytea,bigint,bigint,bytea,bytea,bytea)
from public,anon,authenticated,service_role;
grant execute on function public.service_commit_recovery_v2_for_session(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,bytea,bytea,bytea,bytea,bytea,bigint,bigint,bytea,bytea,bytea) to service_role;

create function context_relay_private.lock_recovery_membership(
  p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_record_sha256 bytea
) returns context_relay_private.membership_heads language plpgsql volatile security definer set search_path=''
as $$
declare
  a public.accounts%rowtype;
  h context_relay_private.membership_heads%rowtype;
  e context_relay_private.enrollment_commits%rowtype;
  r public.recovery_roots%rowtype;
begin
  if p_workspace_id is null or p_workspace_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    or p_record_sha256 is null or octet_length(p_record_sha256)<>32
  then raise exception using errcode='22023',message='invalid_recovery_request';end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='enrollment_session_denied';end if;
  select * into a from public.accounts where owner_user_id=p_auth_user_id for update;
  if not found or a.deletion_state<>'active' then raise exception using errcode='42501',message='recovery_denied';end if;
  select * into h from context_relay_private.membership_heads where account_id=a.id and workspace_id=p_workspace_id for share;
  if not found or h.enrollment_sha256<>p_record_sha256 or h.control_epoch<>a.control_epoch or h.key_epoch<>a.key_epoch
  then raise exception using errcode='40001',message='recovery_conflict';end if;
  select * into e from context_relay_private.enrollment_commits where account_id=a.id and auth_user_id=p_auth_user_id for share;
  if not found or sha256(e.canonical_record)<>p_record_sha256 or e.receipt->>'workspaceId'<>p_workspace_id::text
  then raise exception using errcode='40001',message='recovery_conflict';end if;
  select * into r from public.recovery_roots where account_id=a.id and id=(e.receipt->>'recoveryRootId')::uuid for share;
  if not found or r.revoked_at is not null then raise exception using errcode='42501',message='recovery_denied';end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='enrollment_session_denied';end if;
  return h;
end;
$$;
revoke all on function context_relay_private.lock_recovery_membership(uuid,uuid,uuid,bytea) from public,anon,authenticated,service_role;

-- A live account owner may inventory public history without a surviving device.
-- Only the native phrase and exact signed lineage authenticate recovery authority.
create function public.service_recovery_membership_endpoint(p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_record_sha256 bytea)
returns jsonb language plpgsql volatile security definer set search_path=''
as $$
declare h context_relay_private.membership_heads%rowtype;
begin
  h:=context_relay_private.lock_recovery_membership(p_auth_user_id,p_session_id,p_workspace_id,p_record_sha256);
  return jsonb_build_object('stateSha256',encode(h.state_sha256,'hex'),'controlEpoch',h.control_epoch,'keyEpoch',h.key_epoch);
end;
$$;
revoke all on function public.service_recovery_membership_endpoint(uuid,uuid,uuid,bytea) from public,anon,authenticated,service_role;
grant execute on function public.service_recovery_membership_endpoint(uuid,uuid,uuid,bytea) to service_role;

create function public.service_recovery_membership_event(p_auth_user_id uuid,p_session_id uuid,p_workspace_id uuid,p_record_sha256 bytea,p_successor_sha256 bytea)
returns text language plpgsql volatile security definer set search_path=''
as $$
declare
  h context_relay_private.membership_heads%rowtype;
  object bytea;
begin
  if p_successor_sha256 is null or octet_length(p_successor_sha256)<>32
  then raise exception using errcode='22023',message='invalid_recovery_request';end if;
  h:=context_relay_private.lock_recovery_membership(p_auth_user_id,p_session_id,p_workspace_id,p_record_sha256);
  with recursive ancestors(hash,depth) as (
    select h.state_sha256,0
    union all
    select e.parent_sha256,a.depth+1 from ancestors a join context_relay_private.membership_events e
      on e.workspace_id=p_workspace_id and e.successor_sha256=a.hash where a.depth<4096
  ) select e.canonical_object into object from context_relay_private.membership_events e
    where e.workspace_id=p_workspace_id and e.successor_sha256=p_successor_sha256
      and exists(select 1 from ancestors a where a.hash=e.successor_sha256);
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501',message='enrollment_session_denied';end if;
  return encode(object,'hex');
end;
$$;
revoke all on function public.service_recovery_membership_event(uuid,uuid,uuid,bytea,bytea) from public,anon,authenticated,service_role;
grant execute on function public.service_recovery_membership_event(uuid,uuid,uuid,bytea,bytea) to service_role;
reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
