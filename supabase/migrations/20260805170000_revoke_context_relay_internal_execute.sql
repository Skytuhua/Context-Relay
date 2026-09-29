do $$
begin
  if not exists (
    select 1
    from pg_catalog.pg_roles
    where rolname = 'context_relay_rls_owner'
  ) then
    raise exception using
      errcode = '42704',
      message = 'context_relay_rls_owner is missing';
  end if;

  if exists (
    select 1
    from pg_catalog.pg_roles as owner_role
    where owner_role.rolname = 'context_relay_rls_owner'
      and (
        owner_role.rolcanlogin
        or owner_role.rolinherit
        or owner_role.rolsuper
        or owner_role.rolbypassrls
        or owner_role.rolcreatedb
        or owner_role.rolcreaterole
        or owner_role.rolreplication
      )
  ) then
    raise exception using
      errcode = '42501',
      message = 'context_relay_rls_owner has unsafe attributes';
  end if;
end
$$;

-- The foundation migration transferred these functions before revoking their
-- default privileges. Hosted PostgreSQL requires switching to the new owner for
-- the revocation to take effect.
grant context_relay_rls_owner to current_user with inherit false, set true;
set local role context_relay_rls_owner;

revoke all on function
  context_relay_private.valid_ciphertext_part_sizes(jsonb),
  context_relay_private.ciphertext_part_sizes_total(jsonb),
  context_relay_private.valid_sync_causal_frontier(jsonb),
  context_relay_private.valid_sync_blob_refs(jsonb),
  context_relay_private.valid_hybrid_logical_clock(jsonb),
  context_relay_private.charge_sync_operation_bytes()
from public, anon, authenticated, service_role;

reset role;
revoke context_relay_rls_owner from current_user;
