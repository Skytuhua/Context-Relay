begin;
set local search_path = public, extensions;
select plan(10);
select ok(not has_function_privilege('authenticated', 'public.service_reserve_enrollment_for_session(uuid,uuid,uuid,uuid,uuid,bytea)', 'execute'), 'client cannot reserve directly');
select ok(not has_table_privilege('service_role', 'context_relay_private.enrollment_reservations', 'select'), 'service cannot read reservation table');
grant context_relay_rls_owner to current_user with inherit true, set true;
insert into auth.users(id) values ('10000000-0000-4000-8000-000000000011');
insert into auth.sessions(id,user_id) values
('10000000-0000-4000-8000-000000000012','10000000-0000-4000-8000-000000000011');
create function pg_temp.reserve_enrollment(operation text default '018f22e2-79b0-7cc8-98c4-dc0c0c073901') returns jsonb
language sql as $$
select public.service_reserve_enrollment_for_session(
 '10000000-0000-4000-8000-000000000011', '10000000-0000-4000-8000-000000000012', operation::uuid,
 '018f22e2-79b0-7cc8-98c4-dc0c0c073902','018f22e2-79b0-7cc8-98c4-dc0c0c073903',decode(repeat('42',32),'hex'));
$$;
set local role service_role;
select is(pg_temp.reserve_enrollment()->>'accountId','018f22e2-79b0-7cc8-98c4-dc0c0c073902','reserve returns assigned scope');
select is(pg_temp.reserve_enrollment(),pg_temp.reserve_enrollment(),'retry returns exact challenge and expiry');
select throws_ok($$select pg_temp.reserve_enrollment('018f22e2-79b0-7cc8-98c4-dc0c0c073904')$$,'40001','enrollment_in_progress','competing operation denied');
reset role;
select is((select count(*)::integer from public.accounts where owner_user_id='10000000-0000-4000-8000-000000000011'),0,'reservation creates no account');
update context_relay_private.enrollment_reservations set expires_at=clock_timestamp()-interval '1 second';
set local role service_role;
select throws_ok($$select pg_temp.reserve_enrollment()$$,'42501','enrollment_reservation_expired','expired operation cannot resurrect');
select is(pg_temp.reserve_enrollment('018f22e2-79b0-7cc8-98c4-dc0c0c073904')->>'reservationId','018f22e2-79b0-7cc8-98c4-dc0c0c073904','fresh operation replaces expired reservation');
reset role;
update context_relay_private.enrollment_reservations set expires_at=clock_timestamp()-interval '1 second',request_count=6;
set local role service_role;
select throws_ok($$select pg_temp.reserve_enrollment()$$,'54000','enrollment_rate_limited','new reservation is rate limited');
reset role;
update auth.sessions set not_after=clock_timestamp()-interval '1 second' where id='10000000-0000-4000-8000-000000000012';
set local role service_role;
select throws_ok($$select pg_temp.reserve_enrollment()$$,'42501','enrollment_session_denied','expired session denied');
reset role;
select * from finish();
rollback;
