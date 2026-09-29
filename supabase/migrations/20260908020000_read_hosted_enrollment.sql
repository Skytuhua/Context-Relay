grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;

-- No client table access: derive the reservation from the verified Auth identity.
-- A committed receipt survives challenge expiry for response-loss recovery.
create function public.service_enrollment_status_for_session(
  p_auth_user_id uuid, p_session_id uuid, p_reservation_id uuid
)
returns jsonb
language plpgsql volatile security definer set search_path = ''
as $$
declare
  reservation context_relay_private.enrollment_reservations%rowtype;
  committed context_relay_private.enrollment_commits%rowtype;
begin
  if p_auth_user_id is null or p_session_id is null or p_reservation_id is null
  then raise exception using errcode = '22023', message = 'invalid_enrollment_request'; end if;
  select * into reservation from context_relay_private.enrollment_reservations
    where auth_user_id=p_auth_user_id for share;
  if not found or reservation.session_id <> p_session_id or reservation.reservation_id <> p_reservation_id
  then raise exception using errcode = '42501', message = 'enrollment_reservation_denied'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode = '42501', message = 'enrollment_session_denied'; end if;
  select * into committed from context_relay_private.enrollment_commits
    where auth_user_id=p_auth_user_id and session_id=p_session_id and reservation_id=p_reservation_id;
  if not found and reservation.expires_at <= pg_catalog.clock_timestamp()
  then raise exception using errcode = '42501', message = 'enrollment_reservation_expired'; end if;
  return pg_catalog.jsonb_build_object('reservationId',reservation.reservation_id,
    'accountId',reservation.account_id,'workspaceId',reservation.workspace_id,
    'nonce',pg_catalog.encode(reservation.nonce,'hex'),
    'expiresAt',pg_catalog.floor(extract(epoch from reservation.expires_at)*1000)::text,
    'receipt',committed.receipt);
end;
$$;
revoke all on function public.service_enrollment_status_for_session(uuid,uuid,uuid)
from public,anon,authenticated,service_role;
grant execute on function public.service_enrollment_status_for_session(uuid,uuid,uuid) to service_role;

reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
