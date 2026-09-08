grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;

alter table public.recovery_roots add column recovery_generation bigint not null default 0
  check (recovery_generation >= 0);

-- A fresh owner's session may read the encrypted recovery record. This grants
-- no device binding: restoring trust still requires a verified root-signed claim.
create function public.service_recovery_snapshot_for_session(p_auth_user_id uuid, p_session_id uuid)
returns jsonb
language plpgsql volatile security definer set search_path = ''
as $$
declare
  account_row public.accounts%rowtype;
  root_row public.recovery_roots%rowtype;
  committed context_relay_private.enrollment_commits%rowtype;
begin
  if p_auth_user_id is null or p_session_id is null
  then raise exception using errcode = '22023', message = 'invalid_enrollment_request'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode = '42501', message = 'enrollment_session_denied'; end if;

  select * into account_row from public.accounts where owner_user_id=p_auth_user_id for share;
  if found and account_row.deletion_state='active' then
    select * into committed from context_relay_private.enrollment_commits
      where auth_user_id=p_auth_user_id and account_id=account_row.id for share;
    if found then
      select * into root_row from public.recovery_roots
        where account_id=account_row.id and id=(committed.receipt->>'recoveryRootId')::uuid
        for share;
    end if;
  end if;
  -- Account/root locks can wait beyond session expiry; check again before data leaves.
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode = '42501', message = 'enrollment_session_denied'; end if;
  if root_row.id is null or root_row.revoked_at is not null then return 'null'::jsonb; end if;
  return pg_catalog.jsonb_build_object('accountId',account_row.id,
    'workspaceId',committed.receipt->>'workspaceId',
    'canonicalRecord',pg_catalog.encode(committed.canonical_record,'hex'),
    'canonicalRecordSha256',committed.receipt->>'canonicalRecordSha256',
    'registeredAtMs',committed.receipt->>'registeredAtMs',
    'recoveryGeneration',root_row.recovery_generation::text);
end;
$$;
revoke all on function public.service_recovery_snapshot_for_session(uuid,uuid)
from public,anon,authenticated,service_role;
grant execute on function public.service_recovery_snapshot_for_session(uuid,uuid) to service_role;

reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
