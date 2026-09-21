-- Renewal rotates an expired challenge while retaining its original scope and operation.
-- It cannot change or reactivate a committed enrollment.
grant context_relay_rls_owner to current_user with inherit false, set true;
grant create on schema public to context_relay_rls_owner;
set local role context_relay_rls_owner;

create function public.service_renew_enrollment_for_session(
  p_auth_user_id uuid, p_session_id uuid, p_reservation_id uuid, p_nonce bytea
)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare
  reservation context_relay_private.enrollment_reservations%rowtype;
  checked_at timestamptz;
begin
  if p_auth_user_id is null or p_session_id is null or p_reservation_id is null
    or p_nonce is null or pg_catalog.octet_length(p_nonce) <> 32
  then raise exception using errcode='22023', message='invalid_enrollment_request'; end if;
  select * into reservation from context_relay_private.enrollment_reservations
    where auth_user_id=p_auth_user_id for update;
  if not found or reservation.session_id <> p_session_id or reservation.reservation_id <> p_reservation_id
  then raise exception using errcode='42501', message='enrollment_reservation_denied'; end if;
  if not context_relay_private.lock_live_account_lifecycle_auth_session(p_auth_user_id,p_session_id)
  then raise exception using errcode='42501', message='enrollment_session_denied'; end if;
  checked_at := pg_catalog.clock_timestamp();
  if not exists (select 1 from context_relay_private.enrollment_commits
    where auth_user_id=p_auth_user_id and session_id=p_session_id and reservation_id=p_reservation_id)
    and reservation.expires_at <= checked_at then
    if exists (select 1 from public.accounts where owner_user_id=p_auth_user_id)
    then raise exception using errcode='42501', message='enrollment_requires_pairing'; end if;
    if reservation.window_started_at + interval '1 hour' <= checked_at then
      reservation.window_started_at := checked_at;
      reservation.request_count := 0;
    end if;
    if reservation.request_count >= 6
    then raise exception using errcode='54000', message='enrollment_rate_limited'; end if;
    if reservation.nonce = p_nonce
    then raise exception using errcode='22023', message='invalid_enrollment_request'; end if;
    update context_relay_private.enrollment_reservations set nonce=p_nonce,
      expires_at=checked_at+interval '10 minutes',
      window_started_at=reservation.window_started_at, request_count=reservation.request_count+1
      where auth_user_id=p_auth_user_id;
  end if;
  -- Live and committed retries return the same challenge, including after a lost response.
  return public.service_enrollment_status_for_session(p_auth_user_id,p_session_id,p_reservation_id) - 'receipt';
end;
$$;
revoke all on function public.service_renew_enrollment_for_session(uuid,uuid,uuid,bytea)
from public,anon,authenticated,service_role;
grant execute on function public.service_renew_enrollment_for_session(uuid,uuid,uuid,bytea) to service_role;
reset role;
revoke create on schema public from context_relay_rls_owner;
revoke context_relay_rls_owner from current_user;
