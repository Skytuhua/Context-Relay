begin;

create extension if not exists pgtap with schema extensions;
set local search_path = public, extensions;

select plan(502);

select has_schema('context_relay_private', 'private Context Relay schema exists');

select has_type('context_relay_private', enum_name, format('%s enum exists', enum_name))
from (values
  ('device_binding_state'),
  ('account_deletion_state'),
  ('pairing_request_state'),
  ('upload_reservation_state')
) as enums(enum_name);

select has_table(schema_name, relation_name, format('%s.%s exists', schema_name, relation_name))
from (values
  ('public', 'accounts'),
  ('public', 'device_bindings'),
  ('public', 'device_certificates'),
  ('public', 'sync_operations'),
  ('public', 'sync_checkpoints'),
  ('public', 'blob_manifests'),
  ('public', 'pairing_requests'),
  ('public', 'recovery_roots'),
  ('public', 'github_installations'),
  ('public', 'deletion_requests'),
  ('context_relay_private', 'blob_upload_reservations')
) as relations(schema_name, relation_name);

select has_pk(schema_name, relation_name, format('%s.%s has a primary key', schema_name, relation_name))
from (values
  ('public', 'accounts'),
  ('public', 'device_bindings'),
  ('public', 'device_certificates'),
  ('public', 'sync_operations'),
  ('public', 'sync_checkpoints'),
  ('public', 'blob_manifests'),
  ('public', 'pairing_requests'),
  ('public', 'recovery_roots'),
  ('public', 'github_installations'),
  ('public', 'deletion_requests'),
  ('context_relay_private', 'blob_upload_reservations')
) as relations(schema_name, relation_name);

select has_fk(schema_name, relation_name, format('%s.%s has foreign keys', schema_name, relation_name))
from (values
  ('public', 'accounts'),
  ('public', 'device_bindings'),
  ('public', 'device_certificates'),
  ('public', 'sync_operations'),
  ('public', 'sync_checkpoints'),
  ('public', 'blob_manifests'),
  ('public', 'pairing_requests'),
  ('public', 'recovery_roots'),
  ('public', 'github_installations'),
  ('public', 'deletion_requests'),
  ('context_relay_private', 'blob_upload_reservations')
) as relations(schema_name, relation_name);

select ok(
  (select count(*) >= 8
   from pg_catalog.pg_constraint
   where conname in (
     'accounts_id_owner_user_id_key',
     'device_bindings_session_id_key',
     'device_bindings_account_device_binding_key',
     'device_certificates_account_workspace_device_certificate_key',
     'sync_operations_account_device_sequence_key',
     'sync_checkpoints_account_workspace_checkpoint_key',
     'blob_manifests_account_workspace_storage_key',
     'blob_upload_reservations_account_workspace_storage_key'
   )),
  'compound and identity unique constraints exist'
);

select ok(
  (select pg_catalog.replace(pg_catalog.pg_get_expr(ad.adbin, ad.adrelid), '::bigint', '') in ('524288000', '(524288000)')
   from pg_catalog.pg_attrdef ad
   join pg_catalog.pg_attribute a on a.attrelid = ad.adrelid and a.attnum = ad.adnum
   where ad.adrelid = 'public.accounts'::regclass and a.attname = 'quota_limit_bytes'),
  'account quota defaults to exactly 524288000 bytes'
);

select ok(
  exists (select 1 from pg_catalog.pg_constraint where conrelid = 'public.accounts'::regclass and pg_catalog.pg_get_constraintdef(oid) like '%524288000%'),
  'account quota invariant fixes the 500 MiB limit'
);
select ok(
  exists (select 1 from pg_catalog.pg_constraint where conrelid = 'public.sync_operations'::regclass and pg_catalog.pg_get_constraintdef(oid) like '%4194304%'),
  'operation ciphertext is capped at 4194304 bytes'
);
select ok(
  (select pg_catalog.count(*) = 2
     and pg_catalog.bool_and(
       pg_catalog.pg_get_constraintdef(constraint_row.oid)
         like '%context_relay_private.valid_ciphertext_part_sizes%'
     )
   from pg_catalog.pg_constraint as constraint_row
   where (constraint_row.conrelid, constraint_row.conname) in (
     ('public.blob_manifests'::regclass, 'blob_manifests_parts_array_check'),
     ('context_relay_private.blob_upload_reservations'::regclass, 'blob_upload_reservations_parts_array_check')
   ))
  and (select pg_catalog.pg_get_functiondef(function_row.oid) like '%part_number <= 33554432%'
       from pg_catalog.pg_proc as function_row
       join pg_catalog.pg_namespace as function_namespace on function_namespace.oid = function_row.pronamespace
       where function_namespace.nspname = 'context_relay_private'
         and function_row.proname = 'valid_ciphertext_part_sizes'
         and function_row.pronargs = 1),
  'blob parts are capped at 33554432 bytes'
);
select ok(
  exists (select 1 from pg_catalog.pg_constraint where conrelid = 'public.deletion_requests'::regclass and pg_catalog.pg_get_constraintdef(oid) like '%7 days%'),
  'deletion deadline is exactly seven days after request'
);
select ok(
  exists (select 1 from pg_catalog.pg_constraint where conrelid = 'public.device_bindings'::regclass and pg_catalog.pg_get_constraintdef(oid) like '%cutoff_device_sequence%' and pg_catalog.pg_get_constraintdef(oid) like '%cutoff_hash%' and pg_catalog.pg_get_constraintdef(oid) like '%cutoff_signature%'),
  'signed revocation cutoff fields are all present or all absent'
);
select ok(
  (select count(*) >= 12 from pg_catalog.pg_constraint where pg_catalog.pg_get_constraintdef(oid) ~ 'octet_length.*(24|32|64)'),
  'cryptographic byte fields have fixed-width checks'
);

select ok(c.relrowsecurity, format('%s.%s has RLS enabled', n.nspname, c.relname))
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where (n.nspname, c.relname) in (
  ('public', 'accounts'),
  ('public', 'device_bindings'),
  ('public', 'device_certificates'),
  ('public', 'sync_operations'),
  ('public', 'sync_checkpoints'),
  ('public', 'blob_manifests'),
  ('public', 'pairing_requests'),
  ('public', 'recovery_roots'),
  ('public', 'github_installations'),
  ('public', 'deletion_requests'),
  ('context_relay_private', 'blob_upload_reservations')
)
order by n.nspname, c.relname;

select ok(
  not exists (
    select 1
    from pg_catalog.pg_constraint con
    where con.contype = 'f'
      and con.connamespace in ('public'::regnamespace, 'context_relay_private'::regnamespace)
      and con.conrelid in (
        'public.accounts'::regclass,
        'public.device_bindings'::regclass,
        'public.device_certificates'::regclass,
        'public.sync_operations'::regclass,
        'public.sync_checkpoints'::regclass,
        'public.blob_manifests'::regclass,
        'public.pairing_requests'::regclass,
        'public.recovery_roots'::regclass,
        'public.github_installations'::regclass,
        'public.deletion_requests'::regclass,
        'context_relay_private.blob_upload_reservations'::regclass
      )
      and not exists (
        select 1
        from pg_catalog.pg_index idx
        where idx.indrelid = con.conrelid
          and idx.indisvalid
          and (pg_catalog.string_to_array(idx.indkey::text, ' ')::smallint[])[1:pg_catalog.cardinality(con.conkey)] = con.conkey
      )
  ),
  'every foreign key has a supporting btree index'
);

select has_index('public', 'device_bindings', index_name, format('%s exists for identity hot path', index_name))
from (values
  ('device_bindings_auth_session_idx'),
  ('device_bindings_one_live_per_device_idx'),
  ('device_bindings_state_idx'),
  ('device_bindings_expiry_idx')
) as indexes(index_name);

select has_function('context_relay_private', helper_name, array[]::text[], format('%s() exists', helper_name))
from (values
  ('current_session_id'),
  ('current_read_account_id'),
  ('current_write_account_id'),
  ('current_read_device_id'),
  ('current_write_device_id')
) as helpers(helper_name);

select is(
  (select count(*)::integer
   from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'context_relay_private' and p.proname like 'current\_%\_id'),
  5,
  'the private schema exposes exactly five current identity helpers'
);

select ok(
  (select pg_catalog.bool_and(
     p.pronargs = 0
     and p.provolatile = 's'
     and p.prosecdef
     and p.proowner = 'context_relay_rls_owner'::regrole
     and p.proconfig = array['search_path=""']::text[]
     and pg_catalog.pg_get_functiondef(p.oid) !~* '\mexecute\M'
   )
   from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'context_relay_private' and p.proname like 'current\_%\_id'),
  'identity helpers are stable zero-argument hardened definers without dynamic SQL'
);

select ok(
  (select p.pronargs = 0
     and p.provolatile = 's'
     and p.prosecdef
     and p.proowner <> 'context_relay_rls_owner'::regrole
     and p.proconfig = array['search_path=""']::text[]
     and p.proretset
     and pg_catalog.pg_get_function_result(p.oid) = 'TABLE(auth_user_id uuid, session_id text)'
   from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'context_relay_private'
     and p.proname = 'request_auth_context')
  and pg_catalog.has_function_privilege('context_relay_rls_owner', 'context_relay_private.request_auth_context()', 'execute')
  and not pg_catalog.has_function_privilege('anon', 'context_relay_private.request_auth_context()', 'execute')
  and not pg_catalog.has_function_privilege('authenticated', 'context_relay_private.request_auth_context()', 'execute')
  and not pg_catalog.has_function_privilege('service_role', 'context_relay_private.request_auth_context()', 'execute')
  and not exists (
    select 1
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    cross join lateral pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) privilege
    where n.nspname = 'context_relay_private'
      and p.proname = 'request_auth_context'
      and privilege.grantee = 0
      and pg_catalog.lower(privilege.privilege_type) = 'execute'
  ),
  'hosted Auth bridge exposes only minimal request identity to the dedicated owner'
);

select has_function(
  'context_relay_private',
  'valid_ciphertext_part_sizes',
  array['jsonb']::text[],
  'the shared ciphertext part-size validator exists'
);

select ok(
  (select p.pronargs = 1
     and p.provolatile = 'i'
     and p.proisstrict
     and not p.prosecdef
     and p.proowner = 'context_relay_rls_owner'::regrole
     and p.proconfig = array['search_path=""']::text[]
   from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'context_relay_private'
     and p.proname = 'valid_ciphertext_part_sizes'),
  'part-size validator is an immutable strict invoker owned with an empty search path'
);

select ok(
  (select not r.rolcanlogin
     and not r.rolinherit
     and not r.rolsuper
     and not r.rolbypassrls
     and not r.rolcreatedb
     and not r.rolcreaterole
     and not r.rolreplication
     and not pg_catalog.has_schema_privilege(r.rolname, 'public', 'CREATE')
   from pg_catalog.pg_roles r
   where r.rolname = 'context_relay_rls_owner'),
  'Context Relay owner has no login, inheritance, superuser, bypass, creation, or replication attributes'
);

select ok(
  not exists (
    select 1
    from pg_catalog.pg_auth_members membership
    where membership.member = 'context_relay_rls_owner'::regrole
       or (
         membership.roleid = 'context_relay_rls_owner'::regrole
         and (membership.inherit_option or membership.set_option)
       )
  ),
  'Context Relay owner has no runtime-capability role memberships'
);

select ok(
  (select pg_catalog.bool_and(c.relowner = 'context_relay_rls_owner'::regrole)
   from pg_catalog.pg_class c
   join pg_catalog.pg_namespace n on n.oid = c.relnamespace
   where (n.nspname = 'public' and c.relname in ('accounts', 'device_bindings', 'device_certificates', 'sync_operations', 'sync_checkpoints', 'blob_manifests', 'pairing_requests', 'recovery_roots', 'github_installations', 'deletion_requests'))
      or (n.nspname = 'context_relay_private' and c.relname = 'blob_upload_reservations')),
  'the dedicated NOLOGIN role owns every Context Relay relation'
);

select ok(
  pg_catalog.replace(coalesce(pg_catalog.current_setting('pgrst.db_schemas', true), 'public,graphql_public'), ' ', '') !~ '(^|,)context_relay_private(,|$)',
  'private schema is absent from PostgREST API schemas'
);

select ok(
  not exists (select 1 from pg_catalog.pg_publication_tables where pubname = 'supabase_realtime' and schemaname in ('public', 'context_relay_private') and tablename in ('accounts', 'device_bindings', 'device_certificates', 'sync_operations', 'sync_checkpoints', 'blob_manifests', 'pairing_requests', 'recovery_roots', 'github_installations', 'deletion_requests', 'blob_upload_reservations')),
  'no Context Relay relation is in the Realtime publication'
);

select is(
  (select count(*)
   from pg_catalog.pg_policy policy
   where policy.polrelid = pg_catalog.to_regclass('realtime.messages')
     and policy.polname = 'context_relay_authenticated_sync_hint_read'
     and policy.polcmd = 'r'
     and policy.polpermissive
     and policy.polroles = array['authenticated'::regrole::oid]::oid[]),
  1::bigint,
  'Realtime has exactly one named permissive SELECT policy for authenticated receivers'
);

select ok(
  (select pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) ~* E'extension\\s*=\\s*[^ ]*broadcast'
      and pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) ~* E'SELECT\\s+realtime\\.topic\\(\\)'
      and pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) like '%account:%'
      and pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) ~* E'SELECT\\s+context_relay_private\\.current_read_account_id\\(\\)'
      and pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) like '%:sync%'
      and pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) !~* 'presence'
   from pg_catalog.pg_policy policy
   where policy.polrelid = pg_catalog.to_regclass('realtime.messages')
     and policy.polname = 'context_relay_authenticated_sync_hint_read'),
  'Realtime receive policy requires Broadcast and the scalar exact account sync topic'
);

select ok(
  not exists (
    select 1
    from pg_catalog.pg_policy policy
    where policy.polrelid = pg_catalog.to_regclass('realtime.messages')
      and policy.polcmd = 'a'
      and 'authenticated'::regrole::oid = any(policy.polroles)
  ),
  'authenticated has no Realtime INSERT policy for client Broadcast sends'
);

select is(
  (select count(*)
   from pg_catalog.pg_policy policy
   where policy.polrelid = pg_catalog.to_regclass('realtime.messages')),
  1::bigint,
  'Realtime has no anonymous, presence, or additional Context Relay policy surface'
);

select has_function('context_relay_private', validator_name, array['jsonb']::text[], format('%s(jsonb) exists', validator_name))
from (values
  ('valid_sync_causal_frontier'),
  ('valid_sync_blob_refs'),
  ('valid_hybrid_logical_clock')
) as validators(validator_name);

select has_function(
  'context_relay_private',
  'charge_sync_operation_bytes',
  array[]::text[],
  'operation quota trigger function exists'
);

select ok(
  (select pg_catalog.bool_and(
     p.provolatile = 'i'
     and p.proisstrict
     and not p.prosecdef
     and p.proowner = 'context_relay_rls_owner'::regrole
     and p.proconfig = array['search_path=""']::text[]
   )
   from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'context_relay_private'
     and p.proname in ('valid_sync_causal_frontier', 'valid_sync_blob_refs', 'valid_hybrid_logical_clock')),
  'sync JSON validators are immutable strict invokers owned with empty search paths'
);

select has_trigger(
  'public',
  'sync_operations',
  'sync_operations_charge_quota_before_insert',
  'operation quota trigger is attached to sync_operations'
);

select ok(
  (select p.provolatile = 'v'
     and p.prosecdef
     and p.proowner = 'context_relay_rls_owner'::regrole
     and p.proconfig = array['search_path=""']::text[]
     and pg_catalog.pg_get_functiondef(p.oid) !~* '\mexecute\M'
   from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'context_relay_private'
     and p.proname = 'charge_sync_operation_bytes'),
  'operation quota trigger is a hardened volatile definer owned by the relation owner'
);

select has_index('public', relation_name, index_name, format('%s exists', index_name))
from (values
  ('sync_operations', 'sync_operations_account_workspace_received_idx'),
  ('sync_checkpoints', 'sync_checkpoints_account_workspace_received_idx'),
  ('sync_checkpoints', 'sync_checkpoints_creator_received_idx'),
  ('sync_checkpoints', 'sync_checkpoints_causal_frontier_idx'),
  ('blob_manifests', 'blob_manifests_account_storage_idx')
) as indexes(relation_name, index_name);

select ok(
  not exists (
    select 1
    from (values
      ('public.accounts'),
      ('public.device_bindings'),
      ('public.device_certificates'),
      ('public.sync_operations'),
      ('public.sync_checkpoints'),
      ('public.blob_manifests'),
      ('public.pairing_requests'),
      ('public.recovery_roots'),
      ('public.github_installations'),
      ('public.deletion_requests'),
      ('context_relay_private.blob_upload_reservations')
    ) as relations(qualified_name)
    cross join (values ('select'), ('insert'), ('update'), ('delete'), ('truncate'), ('references'), ('trigger'), ('maintain')) as privileges(privilege_name)
    where pg_catalog.has_table_privilege(roles.role_name, relations.qualified_name, privileges.privilege_name)
  ),
  format('%s has no direct privileges on any Context Relay relation', roles.role_name)
)
from (values ('anon'), ('service_role')) as roles(role_name);

select ok(
  not exists (
    select 1
    from (values
      ('public.accounts', true),
      ('public.device_bindings', true),
      ('public.device_certificates', true),
      ('public.sync_operations', true),
      ('public.sync_checkpoints', true),
      ('public.blob_manifests', true),
      ('public.pairing_requests', false),
      ('public.recovery_roots', false),
      ('public.github_installations', false),
      ('public.deletion_requests', false),
      ('context_relay_private.blob_upload_reservations', false)
    ) as relations(qualified_name, may_select)
    cross join (values ('select'), ('insert'), ('update'), ('delete'), ('truncate'), ('references'), ('trigger'), ('maintain')) as privileges(privilege_name)
    where pg_catalog.has_table_privilege('authenticated', relations.qualified_name, privileges.privilege_name)
      is distinct from (relations.may_select and privileges.privilege_name = 'select')
  ),
  'authenticated has SELECT only on the exact six read relations'
);

select ok(
  not pg_catalog.has_schema_privilege('anon', 'context_relay_private', 'usage')
  and pg_catalog.has_schema_privilege('authenticated', 'context_relay_private', 'usage')
  and pg_catalog.has_schema_privilege('service_role', 'context_relay_private', 'usage'),
  'authenticated and service_role receive private-schema usage for exact helper and enum calls'
);

select ok(
  not exists (
    select 1
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    cross join lateral pg_catalog.aclexplode(coalesce(c.relacl, pg_catalog.acldefault('r', c.relowner))) privilege
    where ((n.nspname = 'public' and c.relname in ('accounts', 'device_bindings', 'device_certificates', 'sync_operations', 'sync_checkpoints', 'blob_manifests', 'pairing_requests', 'recovery_roots', 'github_installations', 'deletion_requests'))
       or (n.nspname = 'context_relay_private' and c.relname = 'blob_upload_reservations'))
      and privilege.grantee = 0
      and pg_catalog.lower(privilege.privilege_type) in ('select', 'insert', 'update', 'delete', 'truncate', 'references', 'trigger', 'maintain')
  ),
  'PUBLIC has no direct privileges on any Context Relay relation'
);

select ok(
  pg_catalog.has_function_privilege('authenticated', 'context_relay_private.current_read_account_id()', 'execute')
  and pg_catalog.has_function_privilege('authenticated', 'context_relay_private.current_write_account_id()', 'execute')
  and pg_catalog.has_function_privilege('authenticated', 'context_relay_private.current_read_device_id()', 'execute')
  and pg_catalog.has_function_privilege('authenticated', 'context_relay_private.current_write_device_id()', 'execute')
  and not pg_catalog.has_function_privilege('authenticated', 'context_relay_private.current_session_id()', 'execute'),
  'authenticated has exactly the four policy-helper executions'
);

select ok(
  not exists (
    select 1
    from (values
      ('context_relay_private.current_session_id()'),
      ('context_relay_private.current_read_account_id()'),
      ('context_relay_private.current_write_account_id()'),
      ('context_relay_private.current_read_device_id()'),
      ('context_relay_private.current_write_device_id()')
    ) as helpers(signature)
    where pg_catalog.has_function_privilege(roles.role_name, helpers.signature, 'execute')
  ),
  format('%s cannot execute any identity helper', roles.role_name)
)
from (values ('anon'), ('service_role')) as roles(role_name);

select ok(
  not exists (
    select 1
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    cross join lateral pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) privilege
    where n.nspname = 'context_relay_private'
      and p.proname in ('current_session_id', 'current_read_account_id', 'current_write_account_id', 'current_read_device_id', 'current_write_device_id')
      and privilege.grantee = 0
      and pg_catalog.lower(privilege.privilege_type) = 'execute'
  ),
  'PUBLIC cannot execute any identity helper'
);

select ok(
  (select pg_catalog.count(*) = 6
     and pg_catalog.bool_and(
       pg_catalog.has_function_privilege('context_relay_rls_owner', function_row.oid, 'execute')
       and not pg_catalog.has_function_privilege('anon', function_row.oid, 'execute')
       and not pg_catalog.has_function_privilege('authenticated', function_row.oid, 'execute')
       and not pg_catalog.has_function_privilege('service_role', function_row.oid, 'execute')
       and not exists (
         select 1
         from pg_catalog.aclexplode(coalesce(
           function_row.proacl,
           pg_catalog.acldefault('f', function_row.proowner)
         )) as privilege
         where privilege.grantee = 0
           and pg_catalog.lower(privilege.privilege_type) = 'execute'
       )
     )
   from pg_catalog.pg_proc as function_row
   join pg_catalog.pg_namespace as function_namespace on function_namespace.oid = function_row.pronamespace
   where function_namespace.nspname = 'context_relay_private'
     and function_row.proname in (
       'valid_ciphertext_part_sizes',
       'ciphertext_part_sizes_total',
       'valid_sync_causal_frontier',
       'valid_sync_blob_refs',
       'valid_hybrid_logical_clock',
       'charge_sync_operation_bytes'
     )),
  'only the relation owner can execute the six internal validators and trigger helpers'
);

select has_function('public', 'service_revoke_device_binding', array['uuid', 'uuid', 'bigint', 'bytea', 'bytea']::text[], 'service revocation wrapper exists with the exact signature');
select has_function('public', 'service_begin_account_deletion', array['uuid']::text[], 'service deletion-begin wrapper exists with the exact signature');
select has_function('public', 'service_cancel_account_deletion', array['uuid']::text[], 'service deletion-cancel wrapper exists with the exact signature');

select ok(
  (select pg_catalog.bool_and(
     p.prosecdef
     and p.proowner = 'context_relay_rls_owner'::regrole
     and p.proconfig = array['search_path=""']::text[]
     and pg_catalog.pg_get_functiondef(p.oid) !~* '\mexecute\M'
   )
   from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'public'
     and p.proname in ('service_revoke_device_binding', 'service_begin_account_deletion', 'service_cancel_account_deletion')),
  'service lifecycle wrappers are hardened definers owned by the non-login role without dynamic SQL'
);

select ok(
  not exists (
    select 1
    from (values
      ('public.service_revoke_device_binding(uuid,uuid,bigint,bytea,bytea)'),
      ('public.service_begin_account_deletion(uuid)'),
      ('public.service_cancel_account_deletion(uuid)')
    ) as wrappers(signature)
    cross join (values ('anon'), ('authenticated')) as callers(role_name)
    where pg_catalog.has_function_privilege(callers.role_name, wrappers.signature, 'execute')
  )
  and not exists (
    select 1
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    cross join lateral pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) privilege
    where n.nspname = 'public'
      and p.proname in ('service_revoke_device_binding', 'service_begin_account_deletion', 'service_cancel_account_deletion')
      and privilege.grantee = 0
      and pg_catalog.lower(privilege.privilege_type) = 'execute'
  )
  and pg_catalog.has_function_privilege('service_role', 'public.service_revoke_device_binding(uuid,uuid,bigint,bytea,bytea)', 'execute')
  and pg_catalog.has_function_privilege('service_role', 'public.service_begin_account_deletion(uuid)', 'execute')
  and pg_catalog.has_function_privilege('service_role', 'public.service_cancel_account_deletion(uuid)', 'execute'),
  'only service_role can execute public lifecycle wrappers'
);

select has_column(
  'context_relay_private',
  'blob_upload_reservations',
  'ciphertext_digest',
  'upload reservations persist the exact 32-byte ciphertext digest'
);

select ok(
  exists (
    select 1 from pg_catalog.pg_constraint
    where conrelid = 'context_relay_private.blob_upload_reservations'::regclass
      and conname = 'blob_upload_reservations_storage_id_key'
      and contype = 'u'
  )
  and exists (
    select 1 from pg_catalog.pg_constraint
    where conrelid = 'public.blob_manifests'::regclass
      and conname = 'blob_manifests_storage_id_key'
      and contype = 'u'
  ),
  'storage IDs are globally unambiguous within reservations and manifests'
);

select ok(
  exists (
    select 1 from pg_catalog.pg_constraint
    where conrelid = 'context_relay_private.blob_upload_reservations'::regclass
      and conname = 'blob_upload_reservations_digest_width_check'
      and pg_catalog.pg_get_constraintdef(oid) like '%octet_length(ciphertext_digest)%32%'
  )
  and (select pg_catalog.count(*) = 2
         and pg_catalog.bool_and(
           pg_catalog.pg_get_constraintdef(constraint_row.oid) ~* E'part_count\\s*>=\\s*1'
           and pg_catalog.pg_get_constraintdef(constraint_row.oid) ~* E'part_count\\s*<=\\s*16'
         )
       from pg_catalog.pg_constraint as constraint_row
       where (constraint_row.conrelid, constraint_row.conname) in (
         ('public.blob_manifests'::regclass, 'blob_manifests_part_count_check'),
         ('context_relay_private.blob_upload_reservations'::regclass, 'blob_upload_reservations_part_count_check')
       )),
  'reservation digests and the exact one-through-sixteen part bound are constrained'
);

select has_function(
  'public',
  'service_reserve_blob_upload',
  array['uuid', 'uuid', 'uuid', 'bytea', 'bigint[]', 'timestamp with time zone']::text[],
  'blob reservation wrapper has the exact public signature'
);
select has_function(
  'public',
  'service_finalize_blob_upload',
  array['uuid']::text[],
  'blob finalization wrapper has the exact public signature'
);
select has_function(
  'public',
  'service_release_blob_upload',
  array['uuid', 'context_relay_private.upload_reservation_state']::text[],
  'blob release wrapper has the exact public signature'
);
select has_function(
  'context_relay_private',
  'can_upload_ciphertext_object',
  array['text', 'text', 'jsonb']::text[],
  'ciphertext upload policy predicate has only candidate-row arguments'
);
select has_function(
  'context_relay_private',
  'can_read_ciphertext_object',
  array['text', 'text']::text[],
  'ciphertext read policy predicate has only candidate-row arguments'
);

select ok(
  (select pg_catalog.count(*) = 2
     and pg_catalog.bool_and(
       p.provolatile = 's'
       and p.prosecdef
       and p.proowner = 'context_relay_rls_owner'::regrole
       and p.proconfig = array['search_path=""']::text[]
       and pg_catalog.pg_get_functiondef(p.oid) !~* '\mexecute\M'
     )
   from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'context_relay_private'
     and p.proname in ('can_upload_ciphertext_object', 'can_read_ciphertext_object')),
  'Storage predicates are stable hardened definers owned by the non-login role'
);

select ok(
  (select pg_catalog.count(*) = 3
     and pg_catalog.bool_and(
       p.provolatile = 'v'
       and p.prosecdef
       and p.proowner = 'context_relay_rls_owner'::regrole
       and p.proconfig = array['search_path=""']::text[]
       and pg_catalog.pg_get_functiondef(p.oid) !~* '\mexecute\M'
     )
   from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'public'
     and p.proname in (
       'service_reserve_blob_upload',
       'service_finalize_blob_upload',
       'service_release_blob_upload'
     )),
  'blob service wrappers are volatile hardened definers owned by the non-login role'
);

select results_eq(
  $$
    select id::text, name::text, public, file_size_limit
    from storage.buckets
    where id = 'ciphertext'
  $$,
  $$values ('ciphertext'::text, 'ciphertext'::text, false, 33554432::bigint)$$,
  'ciphertext bucket is private and capped at exactly 33554432 bytes per object'
);

select results_eq(
  $$
    select policy.polname::text collate "C", policy.polcmd::text collate "C", role_name.rolname::text collate "C"
    from pg_catalog.pg_policy policy
    join pg_catalog.pg_class relation on relation.oid = policy.polrelid
    join pg_catalog.pg_namespace namespace on namespace.oid = relation.relnamespace
    cross join lateral pg_catalog.unnest(policy.polroles) policy_role(role_oid)
    join pg_catalog.pg_roles role_name on role_name.oid = policy_role.role_oid
    where namespace.nspname = 'storage'
      and relation.relname = 'objects'
      and policy.polname like 'ciphertext_objects_%'
    order by policy.polname
  $$,
  $$values
    ('ciphertext_objects_authenticated_insert'::text collate "C", 'a'::text collate "C", 'authenticated'::text collate "C"),
    ('ciphertext_objects_authenticated_select'::text collate "C", 'r'::text collate "C", 'authenticated'::text collate "C"),
    ('ciphertext_objects_rls_owner_select'::text collate "C", 'r'::text collate "C", 'context_relay_rls_owner'::text collate "C")
  $$,
  'Storage has only the two authenticated object policies plus narrow owner metadata read'
);

select ok(
  exists (
    select 1
    from pg_catalog.pg_policy policy
    join pg_catalog.pg_class relation on relation.oid = policy.polrelid
    join pg_catalog.pg_namespace namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'storage'
      and relation.relname = 'objects'
      and policy.polname = 'ciphertext_objects_authenticated_select'
      and pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) like '%can_read_ciphertext_object%'
      and pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) like '%allow_only_operation%storage.object.upload%'
      and pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) like '%can_upload_ciphertext_object%'
  ),
  'reserved-object SELECT is scoped to Storage upload RETURNING while finalized reads remain available'
);

select ok(
  not exists (
    select 1
    from pg_catalog.pg_policy policy
    join pg_catalog.pg_class relation on relation.oid = policy.polrelid
    join pg_catalog.pg_namespace namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'storage'
      and relation.relname = 'objects'
      and policy.polroles @> array['authenticated'::regrole::oid]
      and policy.polcmd in ('w', 'd')
  ),
  'authenticated has no Storage UPDATE or DELETE policy'
);

select ok(
  (select pg_catalog.count(*) = 5
     and pg_catalog.bool_and(
       (privilege.grantee = 'service_role'::regrole::oid
        and n.nspname = 'public'
        and p.proname in (
          'service_reserve_blob_upload',
          'service_finalize_blob_upload',
          'service_release_blob_upload'
        ))
       or (privilege.grantee = 'authenticated'::regrole::oid
           and n.nspname = 'context_relay_private'
           and p.proname in (
             'can_upload_ciphertext_object',
             'can_read_ciphertext_object'
           ))
     )
   from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   cross join lateral pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) privilege
   where ((n.nspname = 'public' and p.proname in (
            'service_reserve_blob_upload',
            'service_finalize_blob_upload',
            'service_release_blob_upload'
          ))
       or (n.nspname = 'context_relay_private' and p.proname in (
            'can_upload_ciphertext_object',
            'can_read_ciphertext_object'
          )))
     and pg_catalog.lower(privilege.privilege_type) = 'execute'
     and privilege.grantee <> p.proowner),
  'blob wrappers and predicates have only their exact non-owner execution grants'
);

select results_eq(
  $$
    select relation.relname::text, count(*)::bigint
    from pg_catalog.pg_policy policy
    join pg_catalog.pg_class relation on relation.oid = policy.polrelid
    join pg_catalog.pg_namespace namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'public'
      and relation.relname in ('accounts', 'device_bindings', 'device_certificates', 'sync_operations', 'sync_checkpoints', 'blob_manifests')
      and policy.polcmd = 'r'
      and policy.polroles = array['authenticated'::regrole::oid]
    group by relation.relname
    order by relation.relname
  $$,
  $$values
    ('accounts'::text, 1::bigint),
    ('blob_manifests'::text, 1::bigint),
    ('device_bindings'::text, 1::bigint),
    ('device_certificates'::text, 1::bigint),
    ('sync_checkpoints'::text, 1::bigint),
    ('sync_operations'::text, 1::bigint)
  $$,
  'each exact read relation has one authenticated SELECT policy'
);

select ok(
  not exists (
    select 1
    from pg_catalog.pg_policy policy
    join pg_catalog.pg_class relation on relation.oid = policy.polrelid
    join pg_catalog.pg_namespace namespace on namespace.oid = relation.relnamespace
    where ((namespace.nspname = 'public' and relation.relname in ('pairing_requests', 'recovery_roots', 'github_installations', 'deletion_requests'))
       or (namespace.nspname = 'context_relay_private' and relation.relname = 'blob_upload_reservations'))
  ),
  'private-by-grant and reservation relations have no client policies'
);

insert into auth.users (id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, created_at, updated_at, raw_app_meta_data, raw_user_meta_data)
values
  ('10000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'a@example.test', '', now(), now(), now(), '{}'::jsonb, '{}'::jsonb),
  ('10000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'b@example.test', '', now(), now(), now(), '{}'::jsonb, '{}'::jsonb),
  ('10000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'quota@example.test', '', now(), now(), now(), '{}'::jsonb, '{}'::jsonb),
  ('10000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'd@example.test', '', now(), now(), now(), '{}'::jsonb, '{}'::jsonb),
  ('10000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'storage@example.test', '', now(), now(), now(), '{}'::jsonb, '{}'::jsonb);

insert into public.accounts (id, owner_user_id, deletion_state, deletion_requested_at, deletion_scheduled_for)
values
  ('20000000-0000-7000-8000-000000000001', '10000000-0000-0000-0000-000000000001', 'active', null, null),
  ('20000000-0000-7000-8000-000000000002', '10000000-0000-0000-0000-000000000002', 'active', null, null),
  ('20000000-0000-7000-8000-000000000003', '10000000-0000-0000-0000-000000000003', 'active', null, null),
  ('20000000-0000-7000-8000-000000000004', '10000000-0000-0000-0000-000000000004', 'active', null, null),
  ('20000000-0000-7000-8000-000000000005', '10000000-0000-0000-0000-000000000005', 'active', null, null);

insert into public.device_bindings (id, account_id, auth_user_id, session_id, device_id, state, expires_at, revoked_at, cutoff_device_sequence, cutoff_hash, cutoff_signature)
values
  ('30000000-0000-0000-0000-000000000001', '20000000-0000-7000-8000-000000000001', '10000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000001', '50000000-0000-7000-8000-000000000001', 'active', now() + interval '1 day', null, null, null, null),
  ('30000000-0000-0000-0000-000000000002', '20000000-0000-7000-8000-000000000001', '10000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000002', '50000000-0000-7000-8000-000000000002', 'pending', now() + interval '1 day', null, null, null, null),
  ('30000000-0000-0000-0000-000000000003', '20000000-0000-7000-8000-000000000001', '10000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000003', '50000000-0000-7000-8000-000000000003', 'revoked', now() + interval '1 day', now(), 7, decode(repeat('ab', 32), 'hex'), decode(repeat('cd', 64), 'hex')),
  ('30000000-0000-0000-0000-000000000004', '20000000-0000-7000-8000-000000000001', '10000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000004', '50000000-0000-7000-8000-000000000004', 'active', now() - interval '1 second', null, null, null, null),
  ('30000000-0000-0000-0000-000000000005', '20000000-0000-7000-8000-000000000002', '10000000-0000-0000-0000-000000000002', '40000000-0000-0000-0000-000000000005', '50000000-0000-7000-8000-000000000005', 'active', null, null, null, null, null),
  ('30000000-0000-0000-0000-000000000006', '20000000-0000-7000-8000-000000000004', '10000000-0000-0000-0000-000000000004', '40000000-0000-0000-0000-000000000006', '50000000-0000-7000-8000-000000000006', 'active', null, null, null, null, null),
  ('30000000-0000-0000-0000-000000000007', '20000000-0000-7000-8000-000000000002', '10000000-0000-0000-0000-000000000002', '40000000-0000-0000-0000-000000000007', '50000000-0000-7000-8000-000000000005', 'revoked', null, now(), 7, decode(repeat('a1', 32), 'hex'), decode(repeat('a2', 64), 'hex')),
  ('30000000-0000-0000-0000-000000000051', '20000000-0000-7000-8000-000000000005', '10000000-0000-0000-0000-000000000005', '40000000-0000-0000-0000-000000000051', '50000000-0000-7000-8000-000000000051', 'active', now() + interval '1 day', null, null, null, null),
  ('30000000-0000-0000-0000-000000000052', '20000000-0000-7000-8000-000000000005', '10000000-0000-0000-0000-000000000005', '40000000-0000-0000-0000-000000000052', '50000000-0000-7000-8000-000000000052', 'pending', now() + interval '1 day', null, null, null, null),
  ('30000000-0000-0000-0000-000000000053', '20000000-0000-7000-8000-000000000005', '10000000-0000-0000-0000-000000000005', '40000000-0000-0000-0000-000000000053', '50000000-0000-7000-8000-000000000053', 'revoked', now() + interval '1 day', now(), 1, decode(repeat('d1', 32), 'hex'), decode(repeat('d2', 64), 'hex')),
  ('30000000-0000-0000-0000-000000000054', '20000000-0000-7000-8000-000000000005', '10000000-0000-0000-0000-000000000005', '40000000-0000-0000-0000-000000000054', '50000000-0000-7000-8000-000000000054', 'active', now() - interval '1 second', null, null, null, null),
  ('30000000-0000-0000-0000-000000000055', '20000000-0000-7000-8000-000000000005', '10000000-0000-0000-0000-000000000005', '40000000-0000-0000-0000-000000000055', '50000000-0000-7000-8000-000000000055', 'active', now() + interval '1 day', null, null, null, null);

insert into public.device_certificates (
  id,
  account_id,
  workspace_id,
  control_epoch,
  request_nonce,
  device_id,
  issuer_kind,
  issuer_recovery_public_key,
  issuer_signing_public_key,
  device_signing_public_key,
  device_wrapping_public_key,
  signature
)
values
  (
    '60000000-0000-7000-8000-000000000001',
    '20000000-0000-7000-8000-000000000001',
    '70000000-0000-7000-8000-000000000001',
    0,
    decode(repeat('01', 32), 'hex'),
    '50000000-0000-7000-8000-000000000001',
    'recovery_root',
    decode(repeat('02', 32), 'hex'),
    decode(repeat('03', 32), 'hex'),
    decode(repeat('04', 32), 'hex'),
    decode(repeat('05', 32), 'hex'),
    decode(repeat('06', 64), 'hex')
  ),
  (
    '60000000-0000-7000-8000-000000000002',
    '20000000-0000-7000-8000-000000000002',
    '70000000-0000-7000-8000-000000000002',
    0,
    decode(repeat('11', 32), 'hex'),
    '50000000-0000-7000-8000-000000000005',
    'recovery_root',
    decode(repeat('12', 32), 'hex'),
    decode(repeat('13', 32), 'hex'),
    decode(repeat('14', 32), 'hex'),
    decode(repeat('15', 32), 'hex'),
    decode(repeat('16', 64), 'hex')
  ),
  (
    '60000000-0000-7000-8000-000000000003',
    '20000000-0000-7000-8000-000000000003',
    '70000000-0000-7000-8000-000000000003',
    0,
    decode(repeat('17', 32), 'hex'),
    '50000000-0000-7000-8000-000000000003',
    'recovery_root',
    decode(repeat('18', 32), 'hex'),
    decode(repeat('19', 32), 'hex'),
    decode(repeat('1a', 32), 'hex'),
    decode(repeat('1b', 32), 'hex'),
    decode(repeat('1c', 64), 'hex')
  ),
  (
    '60000000-0000-7000-8000-000000000004',
    '20000000-0000-7000-8000-000000000004',
    '70000000-0000-7000-8000-000000000004',
    0,
    decode(repeat('21', 32), 'hex'),
    '50000000-0000-7000-8000-000000000006',
    'recovery_root',
    decode(repeat('22', 32), 'hex'),
    decode(repeat('23', 32), 'hex'),
    decode(repeat('24', 32), 'hex'),
    decode(repeat('25', 32), 'hex'),
    decode(repeat('26', 64), 'hex')
  ),
  (
    '60000000-0000-7000-8000-000000000051',
    '20000000-0000-7000-8000-000000000005',
    '70000000-0000-7000-8000-000000000051',
    0,
    decode(repeat('27', 32), 'hex'),
    '50000000-0000-7000-8000-000000000051',
    'recovery_root',
    decode(repeat('28', 32), 'hex'),
    decode(repeat('29', 32), 'hex'),
    decode(repeat('2a', 32), 'hex'),
    decode(repeat('2b', 32), 'hex'),
    decode(repeat('2c', 64), 'hex')
  );

\ir fixtures/sync_envelopes.sql

select throws_ok(
  pg_catalog.format(
    $test$insert into public.blob_manifests (id, account_id, workspace_id, storage_id, ciphertext_digest, total_ciphertext_bytes, ciphertext_part_sizes, part_count, creator_device_id, device_certificate_id, finalized_at) values ('80000000-0000-7000-8000-000000000001', '20000000-0000-7000-8000-000000000001', '70000000-0000-7000-8000-000000000001', '81000000-0000-7000-8000-000000000001', decode(repeat('07', 32), 'hex'), 1, %L::jsonb, 1, '50000000-0000-7000-8000-000000000001', '60000000-0000-7000-8000-000000000001', now())$test$,
    invalid.json_text
  ),
  '23514',
  'new row for relation "blob_manifests" violates check constraint "blob_manifests_parts_array_check"',
  format('blob manifest rejects a %s part-size element', invalid.description)
)
from (values
  ('["1"]', 'string'),
  ('[{}]', 'object'),
  ('[1.5]', 'fractional number'),
  ('[0]', 'zero'),
  ('[33554433]', 'number above 33554432')
) as invalid(json_text, description);

select throws_ok(
  pg_catalog.format(
    $test$insert into context_relay_private.blob_upload_reservations (id, account_id, workspace_id, storage_id, ciphertext_digest, expected_total_bytes, expected_part_sizes, part_count, creator_device_id, device_certificate_id, expires_at) values ('82000000-0000-7000-8000-000000000001', '20000000-0000-7000-8000-000000000001', '70000000-0000-7000-8000-000000000001', '83000000-0000-7000-8000-000000000001', decode(repeat('0b', 32), 'hex'), 1, %L::jsonb, 1, '50000000-0000-7000-8000-000000000001', '60000000-0000-7000-8000-000000000001', now() + interval '1 day')$test$,
    invalid.json_text
  ),
  '23514',
  'new row for relation "blob_upload_reservations" violates check constraint "blob_upload_reservations_parts_array_check"',
  format('blob reservation rejects a %s part-size element', invalid.description)
)
from (values
  ('["1"]', 'string'),
  ('[{}]', 'object'),
  ('[1.5]', 'fractional number'),
  ('[0]', 'zero'),
  ('[33554433]', 'number above 33554432')
) as invalid(json_text, description);

set local role context_relay_rls_owner;

insert into public.blob_manifests (
  id, account_id, workspace_id, storage_id, ciphertext_digest,
  total_ciphertext_bytes, ciphertext_part_sizes, part_count,
  creator_device_id, device_certificate_id, finalized_at
) values (
  '84000000-0000-7000-8000-000000000001',
  '20000000-0000-7000-8000-000000000001',
  '70000000-0000-7000-8000-000000000001',
  '85000000-0000-7000-8000-000000000001',
  decode(repeat('08', 32), 'hex'),
  33554433,
  '[1, 33554432]'::jsonb,
  2,
  '50000000-0000-7000-8000-000000000001',
  '60000000-0000-7000-8000-000000000001',
  now()
);

insert into public.blob_manifests (
  id, account_id, workspace_id, storage_id, ciphertext_digest,
  total_ciphertext_bytes, ciphertext_part_sizes, part_count,
  creator_device_id, device_certificate_id, finalized_at
)
values
  ('84000000-0000-7000-8000-000000000002', '20000000-0000-7000-8000-000000000002', '70000000-0000-7000-8000-000000000002', '85000000-0000-7000-8000-000000000002', decode(repeat('71', 32), 'hex'), 1, '[1]', 1, '50000000-0000-7000-8000-000000000005', '60000000-0000-7000-8000-000000000002', now()),
  ('84000000-0000-7000-8000-000000000003', '20000000-0000-7000-8000-000000000003', '70000000-0000-7000-8000-000000000003', '85000000-0000-7000-8000-000000000003', decode(repeat('73', 32), 'hex'), 100, '[100]', 1, '50000000-0000-7000-8000-000000000003', '60000000-0000-7000-8000-000000000003', now()),
  ('84000000-0000-7000-8000-000000000004', '20000000-0000-7000-8000-000000000004', '70000000-0000-7000-8000-000000000004', '85000000-0000-7000-8000-000000000004', decode(repeat('72', 32), 'hex'), 1, '[1]', 1, '50000000-0000-7000-8000-000000000006', '60000000-0000-7000-8000-000000000004', now());

insert into context_relay_private.blob_upload_reservations (
  id, account_id, workspace_id, storage_id, expected_total_bytes,
  ciphertext_digest, expected_part_sizes, part_count, creator_device_id,
  device_certificate_id, expires_at
) values
(
  '86000000-0000-7000-8000-000000000001',
  '20000000-0000-7000-8000-000000000001',
  '70000000-0000-7000-8000-000000000001',
  '87000000-0000-7000-8000-000000000001',
  33554433,
  decode(repeat('09', 32), 'hex'),
  '[1, 33554432]'::jsonb,
  2,
  '50000000-0000-7000-8000-000000000001',
  '60000000-0000-7000-8000-000000000001',
  now() + interval '1 day'
),
(
  '86000000-0000-7000-8000-000000000003',
  '20000000-0000-7000-8000-000000000003',
  '70000000-0000-7000-8000-000000000003',
  '87000000-0000-7000-8000-000000000003',
  50,
  decode(repeat('0a', 32), 'hex'),
  '[50]'::jsonb,
  1,
  '50000000-0000-7000-8000-000000000003',
  '60000000-0000-7000-8000-000000000003',
  now() + interval '1 day'
);

update public.accounts
set used_bytes = used_bytes + case id
      when '20000000-0000-7000-8000-000000000001'::uuid then 33554433
      when '20000000-0000-7000-8000-000000000002'::uuid then 1
      when '20000000-0000-7000-8000-000000000003'::uuid then 100
      when '20000000-0000-7000-8000-000000000004'::uuid then 1
    end,
    reserved_bytes = reserved_bytes + case id
      when '20000000-0000-7000-8000-000000000001'::uuid then 33554433
      when '20000000-0000-7000-8000-000000000003'::uuid then 50
      else 0
    end
where id in (
  '20000000-0000-7000-8000-000000000001',
  '20000000-0000-7000-8000-000000000002',
  '20000000-0000-7000-8000-000000000003',
  '20000000-0000-7000-8000-000000000004'
);

reset role;

select ok(
  exists (
    select 1
    from public.blob_manifests
    where id = '84000000-0000-7000-8000-000000000001'
      and ciphertext_part_sizes = '[1, 33554432]'::jsonb
  ),
  'relation owner inserted a manifest with minimum and maximum valid part sizes'
);

select ok(
  exists (
    select 1
    from context_relay_private.blob_upload_reservations
    where id = '86000000-0000-7000-8000-000000000001'
      and expected_part_sizes = '[1, 33554432]'::jsonb
  ),
  'relation owner inserted a reservation with minimum and maximum valid part sizes'
);

select results_eq(
  $$select id, used_bytes, reserved_bytes from public.accounts order by id$$,
  $$values
    ('20000000-0000-7000-8000-000000000001'::uuid, 33554434::bigint, 33554433::bigint),
    ('20000000-0000-7000-8000-000000000002'::uuid, 2::bigint, 0::bigint),
    ('20000000-0000-7000-8000-000000000003'::uuid, 100::bigint, 50::bigint),
    ('20000000-0000-7000-8000-000000000004'::uuid, 2::bigint, 0::bigint),
    ('20000000-0000-7000-8000-000000000005'::uuid, 0::bigint, 0::bigint)
  $$,
  'fixture counters include finalized blob bytes, reservations, and each retained inline ciphertext exactly once'
);

update public.accounts
set used_bytes = 100,
    reserved_bytes = 0,
    updated_at = pg_catalog.statement_timestamp()
where id = '20000000-0000-7000-8000-000000000005';

select pg_catalog.set_config(
  'context_relay_test.storage_validation_counters',
  (select used_bytes::text || ':' || reserved_bytes::text
   from public.accounts
   where id = '20000000-0000-7000-8000-000000000005'),
  true
);

set local role service_role;

select throws_ok(command.sql, format('blob reservation rejects %s', command.description))
from (values
  ($$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-000000000001', decode(repeat('01', 31), 'hex'), array[1::bigint], now() + interval '1 hour')$$, 'a digest other than 32 bytes'),
  ($$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-000000000002', decode(repeat('02', 32), 'hex'), array[]::bigint[], now() + interval '1 hour')$$, 'an empty part list'),
  ($$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-000000000003', decode(repeat('03', 32), 'hex'), array[0::bigint], now() + interval '1 hour')$$, 'a zero-sized part'),
  ($$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-000000000004', decode(repeat('04', 32), 'hex'), array[-1::bigint], now() + interval '1 hour')$$, 'a negative-sized part'),
  ($$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-000000000005', decode(repeat('05', 32), 'hex'), array[33554433::bigint], now() + interval '1 hour')$$, 'a part above 33554432 bytes'),
  ($$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-000000000006', decode(repeat('06', 32), 'hex'), pg_catalog.array_fill(1::bigint, array[17]), now() + interval '1 hour')$$, 'more than sixteen parts'),
  ($$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-000000000007', decode(repeat('07', 32), 'hex'), pg_catalog.array_fill(33554432::bigint, array[16]), now() + interval '1 hour')$$, 'a logical total above 524288000 bytes'),
  ($$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-000000000008', decode(repeat('08', 32), 'hex'), array[1::bigint], now())$$, 'a non-future expiry'),
  ($$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000052', 'a0000000-0000-7000-8000-000000000009', decode(repeat('09', 32), 'hex'), array[1::bigint], now() + interval '1 hour')$$, 'a pending device'),
  ($$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000053', 'a0000000-0000-7000-8000-00000000000a', decode(repeat('0a', 32), 'hex'), array[1::bigint], now() + interval '1 hour')$$, 'a revoked device'),
  ($$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000054', 'a0000000-0000-7000-8000-00000000000b', decode(repeat('0b', 32), 'hex'), array[1::bigint], now() + interval '1 hour')$$, 'an expired device')
) as command(sql, description);

reset role;

select results_eq(
  $$select used_bytes, reserved_bytes from public.accounts where id = '20000000-0000-7000-8000-000000000005'$$,
  $$select split_part(value, ':', 1)::bigint, split_part(value, ':', 2)::bigint
    from (values (pg_catalog.current_setting('context_relay_test.storage_validation_counters'))) as expected(value)$$,
  'every invalid reservation leaves used and reserved counters unchanged'
);

update public.accounts
set deletion_state = 'pending_delete',
    deletion_requested_at = pg_catalog.statement_timestamp(),
    deletion_scheduled_for = pg_catalog.statement_timestamp() + interval '7 days'
where id = '20000000-0000-7000-8000-000000000005';

set local role service_role;
select throws_ok(
  $$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-00000000000c', decode(repeat('0c', 32), 'hex'), array[1::bigint], now() + interval '1 hour')$$,
  'blob reservation rejects a pending-delete account'
);
reset role;

update public.accounts
set deletion_state = 'active',
    deletion_requested_at = null,
    deletion_scheduled_for = null
where id = '20000000-0000-7000-8000-000000000005';

set local role service_role;
select lives_ok(
  $$select public.service_reserve_blob_upload(
    '20000000-0000-7000-8000-000000000005',
    '50000000-0000-7000-8000-000000000051',
    'a0000000-0000-7000-8000-00000000000d',
    decode(repeat('0d', 32), 'hex'),
    pg_catalog.array_fill(33554432::bigint, array[15]) || array[20971420::bigint],
    now() + interval '1 hour'
  )$$,
  'reservation may consume the exact remaining account quota byte'
);
reset role;

select results_eq(
  $$select used_bytes, reserved_bytes, quota_limit_bytes from public.accounts where id = '20000000-0000-7000-8000-000000000005'$$,
  $$values (100::bigint, 524287900::bigint, 524288000::bigint)$$,
  'reservation increments only reserved bytes and reaches the exact quota boundary'
);

set local role service_role;
select throws_ok(
  $$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-00000000000e', decode(repeat('0e', 32), 'hex'), array[1::bigint], now() + interval '1 hour')$$,
  'reservation rejects one byte beyond the exact remaining quota'
);
reset role;

select results_eq(
  $$select used_bytes, reserved_bytes, used_bytes + reserved_bytes <= quota_limit_bytes from public.accounts where id = '20000000-0000-7000-8000-000000000005'$$,
  $$values (100::bigint, 524287900::bigint, true)$$,
  'over-reservation failure preserves the exact account quota invariant'
);

set local role service_role;
select lives_ok(
  $$select public.service_release_blob_upload('a0000000-0000-7000-8000-00000000000d', 'cancelled')$$,
  'cancelling the exact-boundary reservation refunds its bytes'
);
select lives_ok(
  $$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-00000000000f', decode(repeat('0f', 32), 'hex'), array[7::bigint], now() + interval '1 hour')$$,
  'a small valid reservation succeeds after the boundary refund'
);
select throws_ok(
  $$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-00000000000f', decode(repeat('0f', 32), 'hex'), array[7::bigint], now() + interval '1 hour')$$,
  'duplicate reservation storage IDs fail rather than replaying'
);
reset role;

select results_eq(
  $$select used_bytes, reserved_bytes from public.accounts where id = '20000000-0000-7000-8000-000000000005'$$,
  $$values (100::bigint, 7::bigint)$$,
  'duplicate storage ID failure cannot double-charge reserved bytes'
);

set local role service_role;
select lives_ok(
  $$select public.service_release_blob_upload('a0000000-0000-7000-8000-00000000000f', 'cancelled')$$,
  'duplicate-ID fixture reservation can be cancelled exactly once'
);
reset role;

insert into public.device_certificates (
  id, account_id, workspace_id, control_epoch, request_nonce, device_id,
  issuer_kind, issuer_recovery_public_key, issuer_signing_public_key,
  device_signing_public_key, device_wrapping_public_key, signature
) values (
  '60000000-0000-7000-8000-000000000052',
  '20000000-0000-7000-8000-000000000005',
  '70000000-0000-7000-8000-000000000052',
  0,
  decode(repeat('41', 32), 'hex'),
  '50000000-0000-7000-8000-000000000051',
  'recovery_root',
  decode(repeat('42', 32), 'hex'),
  decode(repeat('43', 32), 'hex'),
  decode(repeat('44', 32), 'hex'),
  decode(repeat('45', 32), 'hex'),
  decode(repeat('46', 64), 'hex')
);

set local role service_role;
select throws_ok(
  $$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000005', '50000000-0000-7000-8000-000000000051', 'a0000000-0000-7000-8000-000000000010', decode(repeat('10', 32), 'hex'), array[1::bigint], now() + interval '1 hour')$$,
  'reservation rejects an ambiguous device certificate instead of choosing a workspace'
);
reset role;

delete from public.device_certificates
where id = '60000000-0000-7000-8000-000000000052';

select results_eq(
  $$select used_bytes, reserved_bytes from public.accounts where id = '20000000-0000-7000-8000-000000000005'$$,
  $$values (100::bigint, 0::bigint)$$,
  'certificate ambiguity and cleanup preserve quota counters'
);

set local role service_role;
select lives_ok(
  $$
    select public.service_reserve_blob_upload(
      '20000000-0000-7000-8000-000000000005',
      '50000000-0000-7000-8000-000000000051',
      reservation.storage_id,
      decode(repeat(reservation.digest_byte, 32), 'hex'),
      reservation.part_sizes,
      now() + interval '1 hour'
    )
    from (values
      ('a1000000-0000-7000-8000-000000000001'::uuid, '11'::text, array[4::bigint]),
      ('a1000000-0000-7000-8000-000000000002'::uuid, '12'::text, array[3::bigint, 5::bigint]),
      ('a1000000-0000-7000-8000-000000000003'::uuid, '13'::text, array[3::bigint, 5::bigint]),
      ('a1000000-0000-7000-8000-000000000004'::uuid, '14'::text, array[3::bigint]),
      ('a1000000-0000-7000-8000-000000000005'::uuid, '15'::text, array[3::bigint]),
      ('a1000000-0000-7000-8000-000000000006'::uuid, '16'::text, array[3::bigint]),
      ('a1000000-0000-7000-8000-000000000007'::uuid, '17'::text, array[3::bigint]),
      ('a1000000-0000-7000-8000-000000000008'::uuid, '18'::text, array[3::bigint]),
      ('a1000000-0000-7000-8000-000000000009'::uuid, '19'::text, array[6::bigint]),
      ('a1000000-0000-7000-8000-00000000000a'::uuid, '1a'::text, array[6::bigint]),
      ('a1000000-0000-7000-8000-00000000000e'::uuid, '1e'::text, array[3::bigint])
    ) as reservation(storage_id, digest_byte, part_sizes)
  $$,
  'service creates focused reservations for policy and terminal-state tests'
);
reset role;

\ir fixtures/storage_objects.sql

select is(
  (select count(*) from storage.objects where bucket_id = 'ciphertext'),
  12::bigint,
  'database-owner fixture seeds only realistic ciphertext object metadata'
);

set local role authenticated;
select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000005","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000055"}', true);
select is(
  context_relay_private.can_upload_ciphertext_object(
    'ciphertext',
    '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000009/00000000.bin',
    '{"size":6}'::jsonb
  ),
  false,
  'a second active device cannot upload against the first device reservation'
);
do $$
begin
  insert into storage.objects (id, bucket_id, name, owner_id, metadata) values (
    'b2000000-0000-7000-8000-000000000008',
    'ciphertext',
    '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000009/00000000.bin',
    '10000000-0000-0000-0000-000000000005',
    '{"size":6}'::jsonb
  );
exception
  when insufficient_privilege then null;
end
$$;
reset role;

select is(
  (select count(*) from storage.objects where id = 'b2000000-0000-7000-8000-000000000008'),
  0::bigint,
  'the actual INSERT policy leaves no object for a second device using the first device reservation'
);

set local role authenticated;
select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000005","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000051"}', true);

select is(
  context_relay_private.can_upload_ciphertext_object(
    'ciphertext',
    '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin',
    '{"size":4,"mimetype":"application/octet-stream"}'::jsonb
  ),
  true,
  'active owner may upload zero-based reserved part 00000000 at the exact numeric size'
);

select is(
  context_relay_private.can_upload_ciphertext_object(candidate.bucket_id, candidate.name, candidate.metadata),
  false,
  format('upload predicate rejects %s', candidate.description)
)
from (values
  ('other', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin', '{"size":4}'::jsonb, 'a non-ciphertext bucket'),
  ('ciphertext', '20000000-0000-7000-8000-000000000004/a1000000-0000-7000-8000-000000000001/00000000.bin', '{"size":4}'::jsonb, 'another account path'),
  ('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000001.bin', '{"size":4}'::jsonb, 'an extra part index'),
  ('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/../00000000.bin', '{"size":4}'::jsonb, 'a traversal-shaped four-component name'),
  ('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin', '{"size":5}'::jsonb, 'the wrong numeric size'),
  ('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin', '{"size":4.5}'::jsonb, 'a fractional numeric metadata size'),
  ('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin', '{"size":"4"}'::jsonb, 'a string metadata size'),
  ('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin', '{}'::jsonb, 'missing metadata size'),
  ('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin', '{"size":-4}'::jsonb, 'a negative metadata size'),
  ('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin/extra', '{"size":4}'::jsonb, 'a suffix-expanded object name')
) as candidate(bucket_id, name, metadata, description);

select lives_ok(
  $$insert into storage.objects (id, bucket_id, name, owner_id, metadata) values (
    'b2000000-0000-7000-8000-000000000001',
    'ciphertext',
    '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin',
    '10000000-0000-0000-0000-000000000005',
    '{"eTag":"policy-upload","size":4,"mimetype":"application/octet-stream","contentLength":4,"httpStatusCode":200}'::jsonb
  )$$,
  'authenticated INSERT policy accepts one exact reserved object'
);

select is(
  (select count(*) from storage.objects where name = '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin'),
  0::bigint,
  'an uploaded but unfinalized reserved object is unreadable to the client'
);

select throws_ok(command.sql, format('authenticated Storage policy rejects %s', command.description))
from (values
  ($$insert into storage.objects (id, bucket_id, name, owner_id, metadata) values ('b2000000-0000-7000-8000-000000000002', 'ciphertext', '20000000-0000-7000-8000-000000000004/a1000000-0000-7000-8000-000000000001/00000000.bin', '10000000-0000-0000-0000-000000000005', '{"size":4}'::jsonb)$$, 'a cross-account path'),
  ($$insert into storage.objects (id, bucket_id, name, owner_id, metadata) values ('b2000000-0000-7000-8000-000000000003', 'ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000001.bin', '10000000-0000-0000-0000-000000000005', '{"size":4}'::jsonb)$$, 'an extra part index'),
  ($$insert into storage.objects (id, bucket_id, name, owner_id, metadata) values ('b2000000-0000-7000-8000-000000000004', 'ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/../00000000.bin', '10000000-0000-0000-0000-000000000005', '{"size":4}'::jsonb)$$, 'a traversal-shaped name'),
  ($$insert into storage.objects (id, bucket_id, name, owner_id, metadata) values ('b2000000-0000-7000-8000-000000000005', 'ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin.extra', '10000000-0000-0000-0000-000000000005', '{"size":4}'::jsonb)$$, 'a noncanonical suffix')
) as command(sql, description);

select throws_ok(
  $$insert into storage.objects (id, bucket_id, name, owner_id, metadata) values (
    'b2000000-0000-7000-8000-000000000006',
    'ciphertext',
    '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000001/00000000.bin',
    '10000000-0000-0000-0000-000000000005',
    '{"size":4}'::jsonb
  ) on conflict (bucket_id, name) do update set metadata = excluded.metadata$$,
  'authenticated cannot duplicate or upsert a ciphertext part'
);
reset role;

set local role service_role;
select lives_ok(
  $$select public.service_release_blob_upload('a1000000-0000-7000-8000-000000000001', 'cancelled')$$,
  'incomplete policy upload reservation releases reserved bytes once'
);
reset role;

set local role service_role;
select throws_ok(
  pg_catalog.format(
    'select public.service_finalize_blob_upload(%L::uuid)',
    invalid.storage_id
  ),
  format('finalization rejects %s', invalid.description)
)
from (values
  ('a1000000-0000-7000-8000-000000000003', 'a missing object'),
  ('a1000000-0000-7000-8000-000000000004', 'an extra object'),
  ('a1000000-0000-7000-8000-000000000005', 'a wrong path encoding'),
  ('a1000000-0000-7000-8000-000000000006', 'a wrong zero-based part index'),
  ('a1000000-0000-7000-8000-000000000007', 'a wrong numeric metadata size'),
  ('a1000000-0000-7000-8000-000000000008', 'duplicate logical-index path encodings'),
  ('a1000000-0000-7000-8000-00000000000e', 'a nonnumeric metadata size')
) as invalid(storage_id, description);
reset role;

select results_eq(
  $$
    select storage_id, state::text
    from context_relay_private.blob_upload_reservations
    where storage_id in (
      'a1000000-0000-7000-8000-000000000003',
      'a1000000-0000-7000-8000-000000000004',
      'a1000000-0000-7000-8000-000000000005',
      'a1000000-0000-7000-8000-000000000006',
      'a1000000-0000-7000-8000-000000000007',
      'a1000000-0000-7000-8000-000000000008',
      'a1000000-0000-7000-8000-00000000000e'
    )
    order by storage_id
  $$,
  $$values
    ('a1000000-0000-7000-8000-000000000003'::uuid, 'reserved'::text),
    ('a1000000-0000-7000-8000-000000000004'::uuid, 'reserved'::text),
    ('a1000000-0000-7000-8000-000000000005'::uuid, 'reserved'::text),
    ('a1000000-0000-7000-8000-000000000006'::uuid, 'reserved'::text),
    ('a1000000-0000-7000-8000-000000000007'::uuid, 'reserved'::text),
    ('a1000000-0000-7000-8000-000000000008'::uuid, 'reserved'::text),
    ('a1000000-0000-7000-8000-00000000000e'::uuid, 'reserved'::text)
  $$,
  'every object-set validation failure leaves the reservation durably reserved for explicit release'
);

select pg_catalog.set_config(
  'context_relay_test.storage_before_finalize',
  (select used_bytes::text || ':' || reserved_bytes::text
   from public.accounts
   where id = '20000000-0000-7000-8000-000000000005'),
  true
);

set local role service_role;
select lives_ok(
  $$select public.service_finalize_blob_upload('a1000000-0000-7000-8000-000000000002')$$,
  'exact two-part Storage object set finalizes successfully'
);
reset role;

select results_eq(
  $$
    select account_id, workspace_id, storage_id, ciphertext_digest,
      total_ciphertext_bytes, ciphertext_part_sizes, part_count,
      creator_device_id, device_certificate_id
    from public.blob_manifests
    where storage_id = 'a1000000-0000-7000-8000-000000000002'
  $$,
  $$values (
    '20000000-0000-7000-8000-000000000005'::uuid,
    '70000000-0000-7000-8000-000000000051'::uuid,
    'a1000000-0000-7000-8000-000000000002'::uuid,
    decode(repeat('12', 32), 'hex'),
    8::bigint,
    '[3, 5]'::jsonb,
    2,
    '50000000-0000-7000-8000-000000000051'::uuid,
    '60000000-0000-7000-8000-000000000051'::uuid
  )$$,
  'finalization creates one exact manifest from reservation identity, digest, order, and sizes'
);

select results_eq(
  $$select used_bytes, reserved_bytes from public.accounts where id = '20000000-0000-7000-8000-000000000005'$$,
  $$select split_part(value, ':', 1)::bigint + 8,
      split_part(value, ':', 2)::bigint - 8
    from (values (pg_catalog.current_setting('context_relay_test.storage_before_finalize'))) as expected(value)$$,
  'finalization moves exact bytes from reserved to used once without changing their sum'
);

set local role service_role;
select lives_ok(
  $$select public.service_finalize_blob_upload('a1000000-0000-7000-8000-000000000002')$$,
  'exact already-finalized replay is idempotent'
);
reset role;

update public.blob_manifests
set ciphertext_digest = decode(repeat('ff', 32), 'hex')
where storage_id = 'a1000000-0000-7000-8000-000000000002';

set local role service_role;
select throws_ok(
  $$select public.service_finalize_blob_upload('a1000000-0000-7000-8000-000000000002')$$,
  'finalization replay rejects a manifest whose digest disagrees with the reservation'
);
reset role;

update public.blob_manifests
set ciphertext_digest = decode(repeat('12', 32), 'hex')
where storage_id = 'a1000000-0000-7000-8000-000000000002';

set local role service_role;
select throws_ok(
  $$select public.service_release_blob_upload('a1000000-0000-7000-8000-000000000002', 'cancelled')$$,
  'release cannot refund an already-finalized reservation'
);
select lives_ok(
  $$select public.service_release_blob_upload(storage_id, 'cancelled')
    from (values
      ('a1000000-0000-7000-8000-000000000003'::uuid),
      ('a1000000-0000-7000-8000-000000000004'::uuid),
      ('a1000000-0000-7000-8000-000000000005'::uuid),
      ('a1000000-0000-7000-8000-000000000006'::uuid),
      ('a1000000-0000-7000-8000-000000000007'::uuid),
      ('a1000000-0000-7000-8000-000000000008'::uuid),
      ('a1000000-0000-7000-8000-00000000000e'::uuid)
    ) as invalid(storage_id)$$,
  'explicit cancellation refunds all failed-finalization reservations exactly once'
);
select throws_ok(
  $$select public.service_release_blob_upload('a1000000-0000-7000-8000-000000000009', 'expired')$$,
  'an unexpired reserved upload cannot be released as expired'
);
select lives_ok(
  $$select public.service_release_blob_upload('a1000000-0000-7000-8000-000000000009', 'cancelled')$$,
  'reserved upload cancellation succeeds'
);
select lives_ok(
  $$select public.service_release_blob_upload('a1000000-0000-7000-8000-000000000009', 'cancelled')$$,
  'same-terminal cancelled replay is a no-op'
);
select throws_ok(
  $$select public.service_release_blob_upload('a1000000-0000-7000-8000-000000000009', 'expired')$$,
  'different-terminal release replay is rejected'
);
reset role;

update context_relay_private.blob_upload_reservations
set expires_at = pg_catalog.statement_timestamp() - interval '1 second'
where storage_id = 'a1000000-0000-7000-8000-00000000000a';

set local role service_role;
select throws_ok(
  $$select public.service_finalize_blob_upload('a1000000-0000-7000-8000-00000000000a')$$,
  'expired reservation cannot finalize and remains reserved until explicit expiry release'
);
select lives_ok(
  $$select public.service_release_blob_upload('a1000000-0000-7000-8000-00000000000a', 'expired')$$,
  'expired release refunds a genuinely expired reservation'
);
select lives_ok(
  $$select public.service_release_blob_upload('a1000000-0000-7000-8000-00000000000a', 'expired')$$,
  'same-terminal expired replay is a no-op'
);
select throws_ok(
  $$select public.service_release_blob_upload('a1000000-0000-7000-8000-00000000000a', 'cancelled')$$,
  'expired reservation cannot be replayed as cancelled'
);
reset role;

select results_eq(
  $$
    select used_bytes, reserved_bytes,
      (select count(*) from public.blob_manifests where storage_id = 'a1000000-0000-7000-8000-000000000002')
    from public.accounts
    where id = '20000000-0000-7000-8000-000000000005'
  $$,
  $$values (108::bigint, 0::bigint, 1::bigint)$$,
  'all release paths refund reserved once, never reduce used, and finalization creates one manifest'
);

set local role authenticated;
select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000005","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000051"}', true);
select results_eq(
  $$select name from storage.objects where name like '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/%' order by name$$,
  $$values
    ('20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/00000000.bin'::text),
    ('20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/00000001.bin'::text)
  $$,
  'active owner can read exactly the finalized ciphertext parts'
);

do $$
begin
  update storage.objects
  set metadata = pg_catalog.jsonb_set(metadata, '{eTag}', '"forbidden-update"'::jsonb)
  where id = 'b1000000-0000-7000-8000-000000000001';
exception
  when insufficient_privilege then null;
end
$$;
select results_eq(
  $$select metadata->>'eTag' from storage.objects where id = 'b1000000-0000-7000-8000-000000000001'$$,
  $$values ('fixture-valid-0'::text)$$,
  'an authenticated UPDATE attempt leaves finalized object metadata unchanged'
);

do $$
begin
  delete from storage.objects
  where id = 'b1000000-0000-7000-8000-000000000002';
exception
  when insufficient_privilege then null;
end
$$;
select is(
  (select count(*) from storage.objects where name like '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/%'),
  2::bigint,
  'an authenticated DELETE attempt leaves every finalized object in place'
);

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000005","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000055"}', true);
select results_eq(
  $$select name from storage.objects where name like '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/%' order by name$$,
  $$values
    ('20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/00000000.bin'::text),
    ('20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/00000001.bin'::text)
  $$,
  'a second active device in the account may read all finalized ciphertext parts'
);

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000002","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000005"}', true);
select is(
  (select count(*) from storage.objects where name like '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/%'),
  0::bigint,
  'another account cannot read finalized ciphertext parts'
);

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000005","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000052"}', true);
select results_eq(
  $$select context_relay_private.can_upload_ciphertext_object('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/00000000.bin', '{"size":3}'::jsonb), context_relay_private.can_read_ciphertext_object('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/00000000.bin')$$,
  $$values (false, false)$$,
  'pending session cannot upload or read ciphertext objects'
);
select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000005","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000053"}', true);
select results_eq(
  $$select context_relay_private.can_upload_ciphertext_object('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/00000000.bin', '{"size":3}'::jsonb), context_relay_private.can_read_ciphertext_object('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/00000000.bin')$$,
  $$values (false, false)$$,
  'revoked session cannot upload or read ciphertext objects'
);
select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000005","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000054"}', true);
select results_eq(
  $$select context_relay_private.can_upload_ciphertext_object('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/00000000.bin', '{"size":3}'::jsonb), context_relay_private.can_read_ciphertext_object('ciphertext', '20000000-0000-7000-8000-000000000005/a1000000-0000-7000-8000-000000000002/00000000.bin')$$,
  $$values (false, false)$$,
  'expired session cannot upload or read ciphertext objects'
);
reset role;

set local role service_role;
select lives_ok(
  $$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000004', '50000000-0000-7000-8000-000000000006', 'a1000000-0000-7000-8000-00000000000b', decode(repeat('1b', 32), 'hex'), array[1::bigint], now() + interval '1 hour')$$,
  'active deletion-test account may reserve before entering pending delete'
);
reset role;

update public.accounts
set deletion_state = 'pending_delete',
    deletion_requested_at = pg_catalog.statement_timestamp(),
    deletion_scheduled_for = pg_catalog.statement_timestamp() + interval '7 days'
where id = '20000000-0000-7000-8000-000000000004';

set local role authenticated;
select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000004","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000006"}', true);
select is(
  context_relay_private.can_read_ciphertext_object(
    'ciphertext',
    '20000000-0000-7000-8000-000000000004/85000000-0000-7000-8000-000000000004/00000000.bin'
  ),
  true,
  'pending-delete account retains finalized ciphertext read access'
);
select is(
  context_relay_private.can_upload_ciphertext_object(
    'ciphertext',
    '20000000-0000-7000-8000-000000000004/a1000000-0000-7000-8000-00000000000b/00000000.bin',
    '{"size":1}'::jsonb
  ),
  false,
  'pending-delete account cannot upload against an existing reservation'
);
select throws_ok(
  $$insert into storage.objects (id, bucket_id, name, owner_id, metadata) values (
    'b2000000-0000-7000-8000-000000000007',
    'ciphertext',
    '20000000-0000-7000-8000-000000000004/a1000000-0000-7000-8000-00000000000b/00000000.bin',
    '10000000-0000-0000-0000-000000000004',
    '{"size":1}'::jsonb
  )$$,
  'pending-delete authenticated upload fails through the actual INSERT policy'
);
reset role;

insert into storage.objects (id, bucket_id, name, owner_id, metadata) values (
  'b2000000-0000-7000-8000-000000000009',
  'ciphertext',
  '20000000-0000-7000-8000-000000000004/a1000000-0000-7000-8000-00000000000b/00000000.bin',
  '10000000-0000-0000-0000-000000000004',
  '{"size":1}'::jsonb
);

set local role service_role;
select throws_ok(
  $$select public.service_finalize_blob_upload('a1000000-0000-7000-8000-00000000000b')$$,
  '55000',
  'account state does not permit blob finalization',
  'pending-delete account cannot finalize an otherwise complete reserved upload'
);
reset role;

select results_eq(
  $$select account.reserved_bytes, reservation.state::text
    from public.accounts account
    join context_relay_private.blob_upload_reservations reservation
      on reservation.account_id = account.id
    where reservation.storage_id = 'a1000000-0000-7000-8000-00000000000b'$$,
  $$values (1::bigint, 'reserved'::text)$$,
  'pending-delete finalization failure keeps exact quota reserved until explicit release'
);

set local role service_role;
select lives_ok(
  $$select public.service_release_blob_upload('a1000000-0000-7000-8000-00000000000b', 'cancelled')$$,
  'pending-delete account may release its reservation without stranding quota'
);
reset role;

select results_eq(
  $$select account.deletion_state::text, account.reserved_bytes, reservation.state::text
    from public.accounts account
    join context_relay_private.blob_upload_reservations reservation
      on reservation.account_id = account.id
    where reservation.storage_id = 'a1000000-0000-7000-8000-00000000000b'$$,
  $$values ('pending_delete'::text, 0::bigint, 'cancelled'::text)$$,
  'pending-delete cleanup refunds quota and records the terminal reservation state'
);

update public.accounts
set deletion_state = 'active',
    deletion_requested_at = null,
    deletion_scheduled_for = null
where id = '20000000-0000-7000-8000-000000000004';

set local role service_role;
select lives_ok(
  $$select public.service_reserve_blob_upload('20000000-0000-7000-8000-000000000004', '50000000-0000-7000-8000-000000000006', 'a1000000-0000-7000-8000-00000000000c', decode(repeat('1c', 32), 'hex'), array[2::bigint], now() + interval '1 hour')$$,
  'active device may create a reservation before its session is revoked'
);
reset role;

insert into storage.objects (id, bucket_id, name, owner_id, metadata) values (
  'b2000000-0000-7000-8000-00000000000a',
  'ciphertext',
  '20000000-0000-7000-8000-000000000004/a1000000-0000-7000-8000-00000000000c/00000000.bin',
  '10000000-0000-0000-0000-000000000004',
  '{"size":2}'::jsonb
);

update public.device_bindings
set state = 'revoked',
    revoked_at = pg_catalog.statement_timestamp(),
    revocation_reason = 'quota-release-test',
    cutoff_device_sequence = 1,
    cutoff_hash = decode(repeat('1d', 32), 'hex'),
    cutoff_signature = decode(repeat('1e', 64), 'hex'),
    updated_at = pg_catalog.statement_timestamp()
where id = '30000000-0000-0000-0000-000000000006';

set local role service_role;
select throws_ok(
  $$select public.service_finalize_blob_upload('a1000000-0000-7000-8000-00000000000c')$$,
  '55000',
  'active creator device binding required for blob finalization',
  'revoked creator device cannot finalize an otherwise complete reserved upload'
);
reset role;

select results_eq(
  $$select account.reserved_bytes, reservation.state::text
    from public.accounts account
    join context_relay_private.blob_upload_reservations reservation
      on reservation.account_id = account.id
    where reservation.storage_id = 'a1000000-0000-7000-8000-00000000000c'$$,
  $$values (2::bigint, 'reserved'::text)$$,
  'revoked-device finalization failure keeps exact quota reserved until explicit release'
);

set local role service_role;
select lives_ok(
  $$select public.service_release_blob_upload('a1000000-0000-7000-8000-00000000000c', 'cancelled')$$,
  'reservation release remains available after the uploader session is revoked'
);
reset role;

select results_eq(
  $$select account.reserved_bytes, reservation.state::text
    from public.accounts account
    join context_relay_private.blob_upload_reservations reservation
      on reservation.account_id = account.id
    where reservation.storage_id = 'a1000000-0000-7000-8000-00000000000c'$$,
  $$values (0::bigint, 'cancelled'::text)$$,
  'post-revocation release refunds quota exactly once without a live identity'
);

update public.device_bindings
set state = 'active',
    revoked_at = null,
    revocation_reason = null,
    cutoff_device_sequence = null,
    cutoff_hash = null,
    cutoff_signature = null,
    updated_at = pg_catalog.statement_timestamp()
where id = '30000000-0000-0000-0000-000000000006';

select results_eq(
  $$
    select schema_version, id, account_id, workspace_id, project_id, record_id,
      record_kind, mutation_kind, device_id, device_sequence::text,
      causal_frontier, control_epoch, key_epoch, previous_device_hash, nonce,
      pg_catalog.octet_length(ciphertext), ciphertext_hash, blob_refs,
      created_hlc, signature
    from public.sync_operations
    where id = '90000000-0000-7000-8000-000000000001'
  $$,
  $$values (
    1, '90000000-0000-7000-8000-000000000001'::uuid,
    '20000000-0000-7000-8000-000000000001'::uuid,
    '70000000-0000-7000-8000-000000000001'::uuid, null::uuid,
    '91000000-0000-7000-8000-000000000001'::uuid, 'memory'::text,
    'upsert'::text, '50000000-0000-7000-8000-000000000001'::uuid, '0'::text,
    '[{"deviceId":"50000000-0000-7000-8000-000000000001","sequence":"0"}]'::jsonb,
    0::bigint, 0::bigint, decode(repeat('30', 32), 'hex'),
    decode(repeat('31', 24), 'hex'), 1, decode(repeat('33', 32), 'hex'),
    '[]'::jsonb,
    '{"physicalMs":"0","logical":0,"node":"50000000-0000-7000-8000-000000000001"}'::jsonb,
    decode(repeat('34', 64), 'hex')
  )$$,
  'SyncOperationV1 fixture round-trips every protocol field without printing ciphertext'
);

select results_eq(
  $$
    select schema_version, previous_checkpoint_hash, causal_frontier, state_hash,
      key_epoch, creator_device_id, created_hlc, signature
    from public.sync_checkpoints
    where id = '93000000-0000-7000-8000-000000000001'
  $$,
  $$values (
    1, decode(repeat('60', 32), 'hex'),
    '[{"deviceId":"50000000-0000-7000-8000-000000000001","sequence":"0"}]'::jsonb,
    decode(repeat('61', 32), 'hex'), 0::bigint,
    '50000000-0000-7000-8000-000000000001'::uuid,
    '{"physicalMs":"0","logical":0,"node":"50000000-0000-7000-8000-000000000001"}'::jsonb,
    decode(repeat('62', 64), 'hex')
  )$$,
  'CheckpointV1 fixture round-trips every protocol field'
);

select pg_catalog.set_config(
  'context_relay_test.quota_before_max_operation',
  (select used_bytes::text from public.accounts where id = '20000000-0000-7000-8000-000000000003'),
  true
);

set local role context_relay_rls_owner;
insert into public.sync_operations (
  id, account_id, workspace_id, project_id, record_id, record_kind,
  mutation_kind, device_id, device_certificate_id, schema_version,
  device_sequence, causal_frontier, control_epoch, key_epoch,
  previous_device_hash, nonce, ciphertext, ciphertext_hash, blob_refs,
  created_hlc, signature, received_at
) values (
  '90000000-0000-7000-8000-000000000003',
  '20000000-0000-7000-8000-000000000003',
  '70000000-0000-7000-8000-000000000003',
  '72000000-0000-7000-8000-000000000003',
  '91000000-0000-7000-8000-000000000003',
  'project', 'tombstone',
  '50000000-0000-7000-8000-000000000003',
  '60000000-0000-7000-8000-000000000003',
  1, 18446744073709551615,
  '[{"deviceId":"50000000-0000-7000-8000-000000000003","sequence":"18446744073709551615"}]'::jsonb,
  4294967295, 4294967295,
  decode(repeat('a0', 32), 'hex'), decode(repeat('a1', 24), 'hex'),
  decode(repeat('a2', 4194304), 'hex'), decode(repeat('a3', 32), 'hex'),
  pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
    'digest', repeat('a4', 32), 'ciphertextBytes', '524288000',
    'storageId', repeat('s', 512)
  )),
  '{"physicalMs":"18446744073709551615","logical":4294967295,"node":"50000000-0000-7000-8000-000000000003"}'::jsonb,
  decode(repeat('a5', 64), 'hex'),
  '2026-08-04 00:00:03+00'::timestamptz
);

insert into public.sync_checkpoints (
  id, account_id, workspace_id, creator_device_id, device_certificate_id,
  schema_version, previous_checkpoint_hash, causal_frontier, state_hash,
  key_epoch, created_hlc, signature, received_at
) values (
  '93000000-0000-7000-8000-000000000003',
  '20000000-0000-7000-8000-000000000003',
  '70000000-0000-7000-8000-000000000003',
  '50000000-0000-7000-8000-000000000003',
  '60000000-0000-7000-8000-000000000003',
  1, decode(repeat('b0', 32), 'hex'),
  '[{"deviceId":"50000000-0000-7000-8000-000000000003","sequence":"18446744073709551615"}]'::jsonb,
  decode(repeat('b1', 32), 'hex'), 4294967295,
  '{"physicalMs":"18446744073709551615","logical":4294967295,"node":"50000000-0000-7000-8000-000000000003"}'::jsonb,
  decode(repeat('b2', 64), 'hex'),
  '2026-08-04 00:00:03+00'::timestamptz
);
reset role;

select is(
  (select used_bytes from public.accounts where id = '20000000-0000-7000-8000-000000000003'),
  pg_catalog.current_setting('context_relay_test.quota_before_max_operation')::bigint + 4194304,
  'a privileged operation insert atomically increments used bytes by exactly its ciphertext length'
);

select results_eq(
  $$
    select device_sequence::text, (causal_frontier->0->>'sequence')::text,
      control_epoch, key_epoch, pg_catalog.octet_length(previous_device_hash),
      pg_catalog.octet_length(nonce), pg_catalog.octet_length(ciphertext),
      pg_catalog.octet_length(ciphertext_hash), blob_refs->0->>'ciphertextBytes',
      pg_catalog.octet_length(blob_refs->0->>'storageId'),
      created_hlc->>'physicalMs', (created_hlc->>'logical')::bigint,
      pg_catalog.octet_length(signature)
    from public.sync_operations
    where id = '90000000-0000-7000-8000-000000000003'
  $$,
  $$values (
    '18446744073709551615'::text, '18446744073709551615'::text,
    4294967295::bigint, 4294967295::bigint, 32, 24, 4194304, 32,
    '524288000'::text, 512, '18446744073709551615'::text,
    4294967295::bigint, 64
  )$$,
  'maximum legal SyncOperationV1 widths and unsigned values round-trip without truncation or ciphertext output'
);

select results_eq(
  $$
    select (causal_frontier->0->>'sequence')::text, key_epoch,
      pg_catalog.octet_length(previous_checkpoint_hash),
      pg_catalog.octet_length(state_hash), created_hlc->>'physicalMs',
      (created_hlc->>'logical')::bigint, pg_catalog.octet_length(signature)
    from public.sync_checkpoints
    where id = '93000000-0000-7000-8000-000000000003'
  $$,
  $$values (
    '18446744073709551615'::text, 4294967295::bigint, 32, 32,
    '18446744073709551615'::text, 4294967295::bigint, 64
  )$$,
  'maximum legal CheckpointV1 widths and unsigned values round-trip without truncation'
);

create temporary table context_relay_test_sentinel (id integer);

create function pg_temp.insert_sync_operation(
  p_id uuid,
  p_account_id uuid default '20000000-0000-7000-8000-000000000003',
  p_workspace_id uuid default '70000000-0000-7000-8000-000000000003',
  p_project_id uuid default '72000000-0000-7000-8000-000000000003',
  p_record_kind text default 'memory',
  p_mutation_kind text default 'upsert',
  p_device_id uuid default '50000000-0000-7000-8000-000000000003',
  p_certificate_id uuid default '60000000-0000-7000-8000-000000000003',
  p_schema_version integer default 1,
  p_device_sequence numeric default 1,
  p_causal_frontier jsonb default '[]'::jsonb,
  p_control_epoch bigint default 0,
  p_key_epoch bigint default 0,
  p_previous_hash bytea default decode(repeat('c0', 32), 'hex'),
  p_nonce bytea default decode(repeat('c1', 24), 'hex'),
  p_ciphertext bytea default decode('c2', 'hex'),
  p_ciphertext_hash bytea default decode(repeat('c3', 32), 'hex'),
  p_blob_refs jsonb default '[]'::jsonb,
  p_created_hlc jsonb default '{"physicalMs":"3","logical":3,"node":"50000000-0000-7000-8000-000000000003"}'::jsonb,
  p_signature bytea default decode(repeat('c4', 64), 'hex')
)
returns void
language sql
set search_path = ''
as $$
  insert into public.sync_operations (
    id, account_id, workspace_id, project_id, record_id, record_kind,
    mutation_kind, device_id, device_certificate_id, schema_version,
    device_sequence, causal_frontier, control_epoch, key_epoch,
    previous_device_hash, nonce, ciphertext, ciphertext_hash, blob_refs,
    created_hlc, signature
  ) values (
    p_id, p_account_id, p_workspace_id, p_project_id,
    '91000000-0000-7000-8000-000000000030', p_record_kind,
    p_mutation_kind, p_device_id, p_certificate_id, p_schema_version,
    p_device_sequence, p_causal_frontier, p_control_epoch, p_key_epoch,
    p_previous_hash, p_nonce, p_ciphertext, p_ciphertext_hash, p_blob_refs,
    p_created_hlc, p_signature
  )
$$;

create function pg_temp.insert_sync_checkpoint(
  p_id uuid,
  p_account_id uuid default '20000000-0000-7000-8000-000000000003',
  p_workspace_id uuid default '70000000-0000-7000-8000-000000000003',
  p_device_id uuid default '50000000-0000-7000-8000-000000000003',
  p_certificate_id uuid default '60000000-0000-7000-8000-000000000003',
  p_schema_version integer default 1,
  p_previous_hash bytea default decode(repeat('d0', 32), 'hex'),
  p_causal_frontier jsonb default '[]'::jsonb,
  p_state_hash bytea default decode(repeat('d1', 32), 'hex'),
  p_key_epoch bigint default 0,
  p_created_hlc jsonb default '{"physicalMs":"3","logical":3,"node":"50000000-0000-7000-8000-000000000003"}'::jsonb,
  p_signature bytea default decode(repeat('d2', 64), 'hex')
)
returns void
language sql
set search_path = ''
as $$
  insert into public.sync_checkpoints (
    id, account_id, workspace_id, creator_device_id, device_certificate_id,
    schema_version, previous_checkpoint_hash, causal_frontier, state_hash,
    key_epoch, created_hlc, signature
  ) values (
    p_id, p_account_id, p_workspace_id, p_device_id, p_certificate_id,
    p_schema_version, p_previous_hash, p_causal_frontier, p_state_hash,
    p_key_epoch, p_created_hlc, p_signature
  )
$$;

set local role context_relay_rls_owner;

select throws_ok(
  $$select pg_temp.insert_sync_operation('9a000000-0000-7000-8000-000000000001', p_ciphertext => decode(repeat('ee', 4194305), 'hex'))$$,
  'SyncOperationV1 rejects ciphertext above 4194304 bytes'
);

select throws_ok(pg_catalog.format(
  'select pg_temp.insert_sync_operation(''9a000000-0000-7000-8000-000000000002'', %s => decode(repeat(''e1'', %s), ''hex''))',
  invalid.argument_name, invalid.byte_count
), format('SyncOperationV1 rejects a %s with the wrong byte width', invalid.description))
from (values
  ('p_previous_hash', 31, 'previous-device hash'),
  ('p_nonce', 23, 'nonce'),
  ('p_ciphertext_hash', 31, 'ciphertext hash'),
  ('p_signature', 63, 'signature')
) as invalid(argument_name, byte_count, description);

select throws_ok(pg_catalog.format(
  'select pg_temp.insert_sync_checkpoint(''9a000000-0000-7000-8000-000000000003'', %s => decode(repeat(''e2'', %s), ''hex''))',
  invalid.argument_name, invalid.byte_count
), format('CheckpointV1 rejects a %s with the wrong byte width', invalid.description))
from (values
  ('p_previous_hash', 31, 'previous-checkpoint hash'),
  ('p_state_hash', 31, 'state hash'),
  ('p_signature', 63, 'signature')
) as invalid(argument_name, byte_count, description);

select throws_ok(pg_catalog.format(
  $test$
    insert into public.device_certificates (
      id, account_id, workspace_id, control_epoch, request_nonce, device_id,
      issuer_kind, issuer_recovery_public_key, issuer_signing_public_key,
      device_signing_public_key, device_wrapping_public_key, signature
    )
    select '6a000000-0000-7000-8000-000000000003', account_id, workspace_id,
      control_epoch, request_nonce, '5a000000-0000-7000-8000-000000000003',
      issuer_kind, %s, %s, %s, %s, signature
    from public.device_certificates
    where id = '60000000-0000-7000-8000-000000000003'
  $test$,
  case when invalid.key_name = 'recovery' then 'decode(repeat(''e3'', 31), ''hex'')' else 'issuer_recovery_public_key' end,
  case when invalid.key_name = 'issuer' then 'decode(repeat(''e3'', 31), ''hex'')' else 'issuer_signing_public_key' end,
  case when invalid.key_name = 'signing' then 'decode(repeat(''e3'', 31), ''hex'')' else 'device_signing_public_key' end,
  case when invalid.key_name = 'wrapping' then 'decode(repeat(''e3'', 31), ''hex'')' else 'device_wrapping_public_key' end
), format('device certificate rejects a wrong-width %s key', invalid.key_name))
from (values ('recovery'), ('issuer'), ('signing'), ('wrapping')) as invalid(key_name);

select throws_ok(pg_catalog.format(
  'select pg_temp.%s(''9a000000-0000-7000-8000-000000000004'', %s => %s)',
  invalid.helper_name, invalid.argument_name, invalid.invalid_value
), format('%s rejects negative %s', invalid.envelope_name, invalid.description))
from (values
  ('insert_sync_operation', 'p_device_sequence', '-1', 'SyncOperationV1', 'device sequence'),
  ('insert_sync_operation', 'p_control_epoch', '-1', 'SyncOperationV1', 'control epoch'),
  ('insert_sync_operation', 'p_key_epoch', '-1', 'SyncOperationV1', 'key epoch'),
  ('insert_sync_operation', 'p_blob_refs', '''[{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ciphertextBytes":"-1","storageId":"x"}]''::jsonb', 'SyncOperationV1', 'blob ciphertext size'),
  ('insert_sync_operation', 'p_created_hlc', '''{"physicalMs":"-1","logical":0,"node":"50000000-0000-7000-8000-000000000003"}''::jsonb', 'SyncOperationV1', 'HLC physical time'),
  ('insert_sync_operation', 'p_created_hlc', '''{"physicalMs":"0","logical":-1,"node":"50000000-0000-7000-8000-000000000003"}''::jsonb', 'SyncOperationV1', 'HLC logical time'),
  ('insert_sync_checkpoint', 'p_key_epoch', '-1', 'CheckpointV1', 'key epoch')
) as invalid(helper_name, argument_name, invalid_value, envelope_name, description);

select throws_ok(
  $$select pg_temp.insert_sync_operation(
    '9a000000-0000-7000-8000-000000000012',
    p_device_sequence => 1.5
  )$$,
  'SyncOperationV1 rejects a fractional device sequence instead of rounding it'
);

select throws_ok(pg_catalog.format(
  'select pg_temp.insert_sync_operation(''9a000000-0000-7000-8000-000000000005'', %s => %s)',
  invalid.argument_name, invalid.invalid_value
), format('SyncOperationV1 rejects %s above its unsigned width', invalid.description))
from (values
  ('p_device_sequence', '18446744073709551616', 'device sequence'),
  ('p_control_epoch', '4294967296', 'control epoch')
) as invalid(argument_name, invalid_value, description);

select throws_ok(pg_catalog.format(
  'select pg_temp.%s(''9a000000-0000-7000-8000-000000000006'', p_schema_version => 2)',
  invalid.helper_name
), format('%s rejects schema versions other than one', invalid.envelope_name))
from (values
  ('insert_sync_operation', 'SyncOperationV1'),
  ('insert_sync_checkpoint', 'CheckpointV1')
) as invalid(helper_name, envelope_name);

select throws_ok(pg_catalog.format(
  'select pg_temp.insert_sync_operation(''9a000000-0000-7000-8000-000000000007'', %s => ''invalid'')',
  invalid.argument_name
), format('SyncOperationV1 rejects an invalid %s', invalid.description))
from (values
  ('p_record_kind', 'record kind'),
  ('p_mutation_kind', 'mutation kind')
) as invalid(argument_name, description);

select throws_ok(pg_catalog.format(
  'select pg_temp.%s(''9a000000-0000-7000-8000-000000000008'', %s => %L::jsonb)',
  invalid.helper_name, invalid.argument_name, invalid.json_value
), format('%s rejects a noncanonical %s shape', invalid.envelope_name, invalid.description))
from (values
  ('insert_sync_operation', 'p_causal_frontier', '[{"deviceId":"50000000-0000-7000-8000-000000000003"}]', 'SyncOperationV1', 'causal frontier'),
  ('insert_sync_operation', 'p_blob_refs', '[{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ciphertextBytes":"1","storageId":"x","extra":true}]', 'SyncOperationV1', 'blob reference'),
  ('insert_sync_checkpoint', 'p_created_hlc', '{"physicalMs":"0","logical":0}', 'CheckpointV1', 'HLC'),
  ('insert_sync_operation', 'p_causal_frontier', '[{"deviceId":"50000000-0000-7000-8000-000000000004","sequence":"0"},{"deviceId":"50000000-0000-7000-8000-000000000003","sequence":"0"}]', 'SyncOperationV1', 'reversed causal frontier'),
  ('insert_sync_operation', 'p_causal_frontier', '[{"deviceId":"50000000-0000-7000-8000-000000000003","sequence":"0"},{"deviceId":"50000000-0000-7000-8000-000000000003","sequence":"1"}]', 'SyncOperationV1', 'duplicate-device causal frontier'),
  ('insert_sync_checkpoint', 'p_causal_frontier', '[{"deviceId":"50000000-0000-7000-8000-000000000004","sequence":"0"},{"deviceId":"50000000-0000-7000-8000-000000000003","sequence":"0"}]', 'CheckpointV1', 'reversed causal frontier'),
  ('insert_sync_checkpoint', 'p_causal_frontier', '[{"deviceId":"50000000-0000-7000-8000-000000000003","sequence":"0"},{"deviceId":"50000000-0000-7000-8000-000000000003","sequence":"1"}]', 'CheckpointV1', 'duplicate-device causal frontier'),
  ('insert_sync_operation', 'p_created_hlc', '{"physicalMs":"0","logical":0.0,"node":"50000000-0000-7000-8000-000000000003"}', 'SyncOperationV1', 'decimal-form HLC logical value'),
  ('insert_sync_checkpoint', 'p_created_hlc', '{"physicalMs":"0","logical":1.0,"node":"50000000-0000-7000-8000-000000000003"}', 'CheckpointV1', 'decimal-form HLC logical value'),
  ('insert_sync_operation', 'p_blob_refs', '[{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ciphertextBytes":"1","storageId":"\t"}]', 'SyncOperationV1', 'tab-only blob storage ID'),
  ('insert_sync_operation', 'p_blob_refs', '[{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ciphertextBytes":"1","storageId":"\n"}]', 'SyncOperationV1', 'newline-only blob storage ID'),
  ('insert_sync_operation', 'p_blob_refs', U&'[{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ciphertextBytes":"1","storageId":"\00A0"}]', 'SyncOperationV1', 'non-breaking-space-only blob storage ID'),
  ('insert_sync_operation', 'p_blob_refs', U&'[{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ciphertextBytes":"1","storageId":"\3000"}]', 'SyncOperationV1', 'ideographic-space-only blob storage ID')
) as invalid(helper_name, argument_name, json_value, envelope_name, description);

select throws_ok(
  $$select pg_temp.insert_sync_operation(
    '9a000000-0000-7000-8000-000000000009',
    p_causal_frontier => (select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'deviceId', '5a000000-0000-7000-8000-' || pg_catalog.lpad(value::text, 12, '0'),
      'sequence', '0'
    )) from pg_catalog.generate_series(1, 10001) as series(value))
  )$$,
  'SyncOperationV1 rejects a causal frontier above 10000 items'
);

select throws_ok(
  $$select pg_temp.insert_sync_operation(
    '9a000000-0000-7000-8000-00000000000a',
    p_blob_refs => (select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'digest', repeat('aa', 32), 'ciphertextBytes', '1', 'storageId', value::text
    )) from pg_catalog.generate_series(1, 10001) as series(value))
  )$$,
  'SyncOperationV1 rejects blob references above 10000 items'
);

select throws_ok(
  $$select pg_temp.insert_sync_checkpoint(
    '9a000000-0000-7000-8000-00000000000b',
    p_causal_frontier => (select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'deviceId', '5b000000-0000-7000-8000-' || pg_catalog.lpad(value::text, 12, '0'),
      'sequence', '0'
    )) from pg_catalog.generate_series(1, 10001) as series(value))
  )$$,
  'CheckpointV1 rejects a causal frontier above 10000 items'
);

select pg_catalog.set_config(
  'context_relay_test.quota_before_duplicate_operations',
  (select used_bytes::text from public.accounts where id = '20000000-0000-7000-8000-000000000003'),
  true
);

select throws_ok(
  $$select pg_temp.insert_sync_operation('90000000-0000-7000-8000-000000000003')$$,
  'duplicate operation IDs fail'
);

select throws_ok(
  $$select pg_temp.insert_sync_operation('9a000000-0000-7000-8000-00000000000c', p_device_sequence => 18446744073709551615)$$,
  'duplicate account-device-sequence tuples fail'
);

select is(
  (select used_bytes from public.accounts where id = '20000000-0000-7000-8000-000000000003'),
  pg_catalog.current_setting('context_relay_test.quota_before_duplicate_operations')::bigint,
  'duplicate and constraint-failing inserts roll back their provisional quota increments'
);

select throws_ok(
  $$select pg_temp.insert_sync_operation(
    '9a000000-0000-7000-8000-00000000000d',
    p_account_id => '20000000-0000-7000-8000-000000000001'
  )$$,
  'operation compound certificate reference rejects cross-account attachment'
);

select throws_ok(
  $$select pg_temp.insert_sync_checkpoint(
    '9a000000-0000-7000-8000-00000000000e',
    p_account_id => '20000000-0000-7000-8000-000000000001'
  )$$,
  'checkpoint compound certificate reference rejects cross-account attachment'
);

reset role;

set local role context_relay_rls_owner;
update public.accounts
set reserved_bytes = quota_limit_bytes - used_bytes - 1
where id = '20000000-0000-7000-8000-000000000003';
reset role;

select pg_catalog.set_config(
  'context_relay_test.quota_before_remaining_byte',
  (select used_bytes::text || ':' || reserved_bytes::text
   from public.accounts
   where id = '20000000-0000-7000-8000-000000000003'),
  true
);

set local role context_relay_rls_owner;
select throws_ok(
  $$select pg_temp.insert_sync_operation(
    '9a000000-0000-7000-8000-00000000000f',
    p_device_sequence => 1,
    p_ciphertext => decode('eeee', 'hex')
  )$$,
  'operation ciphertext exceeding the exact remaining quota by one byte fails'
);
reset role;

select results_eq(
  $$select used_bytes, reserved_bytes from public.accounts where id = '20000000-0000-7000-8000-000000000003'$$,
  $$select split_part(value, ':', 1)::bigint, split_part(value, ':', 2)::bigint
    from (values (pg_catalog.current_setting('context_relay_test.quota_before_remaining_byte'))) as expected(value)$$,
  'quota rejection preserves counters containing finalized blob and reservation bytes'
);

set local role context_relay_rls_owner;
select lives_ok(
  $$select pg_temp.insert_sync_operation(
    '9a000000-0000-7000-8000-000000000010',
    p_device_sequence => 1,
    p_ciphertext => decode('ef', 'hex')
  )$$,
  'operation ciphertext may consume the exact final quota byte'
);
reset role;

select results_eq(
  $$select used_bytes, reserved_bytes, quota_limit_bytes from public.accounts where id = '20000000-0000-7000-8000-000000000003'$$,
  $$select split_part(value, ':', 1)::bigint + 1,
      split_part(value, ':', 2)::bigint,
      524288000::bigint
    from (values (pg_catalog.current_setting('context_relay_test.quota_before_remaining_byte'))) as expected(value)$$,
  'exact-boundary append increments only used bytes and reaches used plus reserved equal to quota'
);

set local role context_relay_rls_owner;
select throws_ok(
  $$select pg_temp.insert_sync_operation(
    '9a000000-0000-7000-8000-000000000011',
    p_device_sequence => 2,
    p_ciphertext => decode('f0', 'hex')
  )$$,
  'operation insert fails on a quota-exhausted account'
);
reset role;

select ok(
  (select used_bytes + reserved_bytes = quota_limit_bytes
   from public.accounts
   where id = '20000000-0000-7000-8000-000000000003'),
  'failed exhausted-account append leaves the exact quota invariant unchanged'
);

insert into realtime.messages (
  id, topic, extension, payload, event, private, inserted_at, updated_at
)
values
  (
    'd1000000-0000-7000-8000-000000000001',
    'account:20000000-0000-7000-8000-000000000001:sync',
    'broadcast',
    '{"version":1,"kind":"pull_now"}'::jsonb,
    'sync_hint',
    true,
    pg_catalog.now(),
    pg_catalog.now()
  ),
  (
    'd1000000-0000-7000-8000-000000000002',
    'account:20000000-0000-7000-8000-000000000002:sync',
    'broadcast',
    '{"version":1,"kind":"pull_now"}'::jsonb,
    'sync_hint',
    true,
    pg_catalog.now(),
    pg_catalog.now()
  ),
  (
    'd1000000-0000-7000-8000-000000000003',
    'account:20000000-0000-7000-8000-000000000001:sync',
    'presence',
    '{"version":1,"kind":"pull_now"}'::jsonb,
    'sync_hint',
    true,
    pg_catalog.now(),
    pg_catalog.now()
  ),
  (
    'd1000000-0000-7000-8000-000000000004',
    'account:20000000-0000-7000-8000-000000000004:sync',
    'broadcast',
    '{"version":1,"kind":"pull_now"}'::jsonb,
    'sync_hint',
    true,
    pg_catalog.now(),
    pg_catalog.now()
  );

select pg_catalog.set_config('request.jwt.claims', '{}', true);
select is(context_relay_private.current_session_id(), null::uuid, 'missing session claim yields NULL');

set local role anon;
select pg_catalog.set_config('realtime.topic', 'account:20000000-0000-7000-8000-000000000001:sync', true);
select is(
  (select count(*) from realtime.messages where id = 'd1000000-0000-7000-8000-000000000001'),
  0::bigint,
  'anonymous SELECT cannot read the private account sync Broadcast row'
);
reset role;

set local role authenticated;

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000001"}', true);
select is(context_relay_private.current_read_account_id(), '20000000-0000-7000-8000-000000000001'::uuid, 'active session gets read account');
select is(context_relay_private.current_write_account_id(), '20000000-0000-7000-8000-000000000001'::uuid, 'active session gets write account');
select is(context_relay_private.current_read_device_id(), '50000000-0000-7000-8000-000000000001'::uuid, 'active session gets read device');
select is(context_relay_private.current_write_device_id(), '50000000-0000-7000-8000-000000000001'::uuid, 'active session gets write device');

select pg_catalog.set_config('realtime.topic', 'account:20000000-0000-7000-8000-000000000001:sync', true);
select is(
  (select count(*) from realtime.messages where id = 'd1000000-0000-7000-8000-000000000001'),
  1::bigint,
  'active A session reads its Broadcast row on the exact private sync topic through RLS'
);
select throws_ok(
  $$insert into realtime.messages (id, topic, extension, payload, event, private, inserted_at, updated_at)
    values (
      'd1000000-0000-7000-8000-000000000005',
      'account:20000000-0000-7000-8000-000000000001:sync',
      'broadcast',
      '{"version":1,"kind":"pull_now"}'::jsonb,
      'sync_hint',
      true,
      pg_catalog.now(),
      pg_catalog.now()
    )$$,
  'authenticated cannot INSERT a client Broadcast send row'
);
select pg_catalog.set_config('realtime.topic', 'account:20000000-0000-7000-8000-000000000002:sync', true);
select is(
  (select count(*) from realtime.messages where id = 'd1000000-0000-7000-8000-000000000002'),
  0::bigint,
  'active A session cannot read the B account Broadcast row through RLS'
);
select pg_catalog.set_config('realtime.topic', 'account:not-a-uuid:sync', true);
select is(
  (select count(*) from realtime.messages where id = 'd1000000-0000-7000-8000-000000000001'),
  0::bigint,
  'active A session cannot read its Broadcast row with a malformed authorization topic'
);
select pg_catalog.set_config('realtime.topic', 'prefix:account:20000000-0000-7000-8000-000000000001:sync', true);
select is(
  (select count(*) from realtime.messages where id = 'd1000000-0000-7000-8000-000000000001'),
  0::bigint,
  'active A session cannot read its Broadcast row with a prefix-expanded authorization topic'
);
select pg_catalog.set_config('realtime.topic', 'account:20000000-0000-7000-8000-000000000001:sync:extra', true);
select is(
  (select count(*) from realtime.messages where id = 'd1000000-0000-7000-8000-000000000001'),
  0::bigint,
  'active A session cannot read its Broadcast row with a suffix-expanded authorization topic'
);
select pg_catalog.set_config('realtime.topic', 'account:20000000-0000-7000-8000-000000000001:sync', true);
select is(
  (select count(*) from realtime.messages where id = 'd1000000-0000-7000-8000-000000000003'),
  0::bigint,
  'active A session cannot read a Presence row on its exact sync topic through RLS'
);

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000002"}', true);
select results_eq('select context_relay_private.current_read_account_id(), context_relay_private.current_write_account_id(), context_relay_private.current_read_device_id(), context_relay_private.current_write_device_id()', 'values (null::uuid, null::uuid, null::uuid, null::uuid)', 'pending binding has no identity context');
select pg_catalog.set_config('realtime.topic', 'account:20000000-0000-7000-8000-000000000001:sync', true);
select is(
  (select count(*) from realtime.messages where id = 'd1000000-0000-7000-8000-000000000001'),
  0::bigint,
  'pending binding cannot read the account sync Broadcast row through RLS'
);

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000003"}', true);
select results_eq('select context_relay_private.current_read_account_id(), context_relay_private.current_write_account_id(), context_relay_private.current_read_device_id(), context_relay_private.current_write_device_id()', 'values (null::uuid, null::uuid, null::uuid, null::uuid)', 'revoked binding has no identity context');
select pg_catalog.set_config('realtime.topic', 'account:20000000-0000-7000-8000-000000000001:sync', true);
select is(
  (select count(*) from realtime.messages where id = 'd1000000-0000-7000-8000-000000000001'),
  0::bigint,
  'revoked binding cannot read the account sync Broadcast row through RLS'
);

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000004"}', true);
select results_eq('select context_relay_private.current_read_account_id(), context_relay_private.current_write_account_id(), context_relay_private.current_read_device_id(), context_relay_private.current_write_device_id()', 'values (null::uuid, null::uuid, null::uuid, null::uuid)', 'expired binding has no identity context');
select pg_catalog.set_config('realtime.topic', 'account:20000000-0000-7000-8000-000000000001:sync', true);
select is(
  (select count(*) from realtime.messages where id = 'd1000000-0000-7000-8000-000000000001'),
  0::bigint,
  'expired binding cannot read the account sync Broadcast row through RLS'
);

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated"}', true);
select results_eq('select context_relay_private.current_read_account_id(), context_relay_private.current_write_account_id(), context_relay_private.current_read_device_id(), context_relay_private.current_write_device_id()', 'values (null::uuid, null::uuid, null::uuid, null::uuid)', 'absent session claim has no identity context');

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated","session_id":"not-a-uuid"}', true);
select results_eq('select context_relay_private.current_read_account_id(), context_relay_private.current_write_account_id(), context_relay_private.current_read_device_id(), context_relay_private.current_write_device_id()', 'values (null::uuid, null::uuid, null::uuid, null::uuid)', 'malformed session claim has no identity context');

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000002","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000001"}', true);
select results_eq('select context_relay_private.current_read_account_id(), context_relay_private.current_write_account_id(), context_relay_private.current_read_device_id(), context_relay_private.current_write_device_id()', 'values (null::uuid, null::uuid, null::uuid, null::uuid)', 'user and session mismatch has no identity context');
select results_eq('select (select count(*) from public.accounts), (select count(*) from public.device_bindings), (select count(*) from public.device_certificates), (select count(*) from public.sync_operations), (select count(*) from public.sync_checkpoints), (select count(*) from public.blob_manifests)', 'values (0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint)', 'split user and session claims cannot expose either account on any read relation');

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000004","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000006"}', true);
select results_eq('select context_relay_private.current_read_account_id(), context_relay_private.current_write_account_id(), context_relay_private.current_read_device_id(), context_relay_private.current_write_device_id()', 'values (''20000000-0000-7000-8000-000000000004''::uuid, ''20000000-0000-7000-8000-000000000004''::uuid, ''50000000-0000-7000-8000-000000000006''::uuid, ''50000000-0000-7000-8000-000000000006''::uuid)', 'active deletion-test account starts with read and write identity');

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000002","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000005"}', true);
select results_eq('select context_relay_private.current_read_account_id(), context_relay_private.current_write_account_id(), context_relay_private.current_read_device_id(), context_relay_private.current_write_device_id()', 'values (''20000000-0000-7000-8000-000000000002''::uuid, ''20000000-0000-7000-8000-000000000002''::uuid, ''50000000-0000-7000-8000-000000000005''::uuid, ''50000000-0000-7000-8000-000000000005''::uuid)', 'a second user resolves only its own binding');

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000001","account_id":"20000000-0000-7000-8000-000000000002","device_id":"50000000-0000-7000-8000-000000000005","user_metadata":{"admin":true},"unexpected":"ignored"}', true);
select results_eq('select context_relay_private.current_read_account_id(), context_relay_private.current_write_account_id(), context_relay_private.current_read_device_id(), context_relay_private.current_write_device_id()', 'values (''20000000-0000-7000-8000-000000000001''::uuid, ''20000000-0000-7000-8000-000000000001''::uuid, ''50000000-0000-7000-8000-000000000001''::uuid, ''50000000-0000-7000-8000-000000000001''::uuid)', 'caller-controlled unrelated claims cannot change identity');

select results_eq('select id from public.accounts order by id', 'values (''20000000-0000-7000-8000-000000000001''::uuid)', 'user A sees exactly its account');
select results_eq('select id from public.device_bindings order by id', 'values (''30000000-0000-0000-0000-000000000001''::uuid), (''30000000-0000-0000-0000-000000000002''::uuid), (''30000000-0000-0000-0000-000000000003''::uuid), (''30000000-0000-0000-0000-000000000004''::uuid)', 'user A sees exactly its account bindings');
select results_eq('select id from public.device_certificates order by id', 'values (''60000000-0000-7000-8000-000000000001''::uuid)', 'user A sees exactly its certificates');
select results_eq('select id from public.sync_operations order by id', 'values (''90000000-0000-7000-8000-000000000001''::uuid)', 'user A sees exactly its operations');
select results_eq('select id from public.sync_checkpoints order by id', 'values (''93000000-0000-7000-8000-000000000001''::uuid)', 'user A sees exactly its checkpoints');
select results_eq('select id from public.blob_manifests order by id', 'values (''84000000-0000-7000-8000-000000000001''::uuid)', 'user A sees exactly its finalized manifests');

select results_eq(
  $$select id from public.sync_operations
    where account_id = '20000000-0000-7000-8000-000000000001'
      and workspace_id = '70000000-0000-7000-8000-000000000001'
      and (received_at, id) > ('2026-08-04 00:00:00+00'::timestamptz, '00000000-0000-0000-0000-000000000000'::uuid)
    order by received_at, id limit 1$$,
  $$values ('90000000-0000-7000-8000-000000000001'::uuid)$$,
  'user A can keyset-page its read-only operations by receipt and ID'
);
select results_eq(
  $$select id from public.sync_checkpoints
    where account_id = '20000000-0000-7000-8000-000000000001'
      and workspace_id = '70000000-0000-7000-8000-000000000001'
      and (received_at, id) > ('2026-08-04 00:00:00+00'::timestamptz, '00000000-0000-0000-0000-000000000000'::uuid)
    order by received_at, id limit 1$$,
  $$values ('93000000-0000-7000-8000-000000000001'::uuid)$$,
  'user A can keyset-page its read-only checkpoints by receipt and ID'
);

select throws_ok(command.sql, format('user A cannot %s', command.description))
from (values
  ('select pg_temp.insert_sync_operation(''9b000000-0000-7000-8000-000000000001'', p_account_id => ''20000000-0000-7000-8000-000000000001'', p_workspace_id => ''70000000-0000-7000-8000-000000000001'', p_project_id => null, p_device_id => ''50000000-0000-7000-8000-000000000001'', p_certificate_id => ''60000000-0000-7000-8000-000000000001'', p_device_sequence => 1)', 'INSERT a legitimate operation'),
  ('update public.sync_operations set signature = signature where id = ''90000000-0000-7000-8000-000000000001''', 'UPDATE its operation'),
  ('delete from public.sync_operations where id = ''90000000-0000-7000-8000-000000000001''', 'DELETE its operation'),
  ('truncate table public.sync_operations', 'TRUNCATE operations'),
  ('insert into public.sync_operations select * from public.sync_operations where id = ''90000000-0000-7000-8000-000000000001'' on conflict (id) do update set signature = excluded.signature', 'conflict-UPSERT its operation'),
  ('select pg_temp.insert_sync_checkpoint(''9b000000-0000-7000-8000-000000000002'', p_account_id => ''20000000-0000-7000-8000-000000000001'', p_workspace_id => ''70000000-0000-7000-8000-000000000001'', p_device_id => ''50000000-0000-7000-8000-000000000001'', p_certificate_id => ''60000000-0000-7000-8000-000000000001'')', 'INSERT a legitimate checkpoint'),
  ('update public.sync_checkpoints set signature = signature where id = ''93000000-0000-7000-8000-000000000001''', 'UPDATE its checkpoint'),
  ('delete from public.sync_checkpoints where id = ''93000000-0000-7000-8000-000000000001''', 'DELETE its checkpoint'),
  ('truncate table public.sync_checkpoints', 'TRUNCATE checkpoints'),
  ('insert into public.sync_checkpoints select * from public.sync_checkpoints where id = ''93000000-0000-7000-8000-000000000001'' on conflict (id) do update set signature = excluded.signature', 'conflict-UPSERT its checkpoint')
) as command(sql, description);

select is((select count(*) from public.accounts where id = '20000000-0000-7000-8000-000000000002'), 0::bigint, 'A cannot select B by account filter');
select is((select count(*) from public.device_bindings where account_id = '20000000-0000-7000-8000-000000000002' or device_id = '50000000-0000-7000-8000-000000000005'), 0::bigint, 'A cannot select B bindings by account or device filter');
select is((select count(*) from public.device_certificates where account_id = '20000000-0000-7000-8000-000000000002' or workspace_id = '70000000-0000-7000-8000-000000000002' or device_id = '50000000-0000-7000-8000-000000000005'), 0::bigint, 'A cannot select B certificates by account, workspace, or device filter');
select is((select count(*) from public.sync_operations where account_id = '20000000-0000-7000-8000-000000000002' or workspace_id = '70000000-0000-7000-8000-000000000002' or device_id = '50000000-0000-7000-8000-000000000005' or blob_refs @> '[{"storageId":"opaque-b-storage-id"}]'), 0::bigint, 'A cannot expose B operations through routing filters or synthetic payload JSON');
select is((select count(*) from public.sync_checkpoints where account_id = '20000000-0000-7000-8000-000000000002' or workspace_id = '70000000-0000-7000-8000-000000000002' or creator_device_id = '50000000-0000-7000-8000-000000000005'), 0::bigint, 'A cannot select B checkpoints by routing filters');
select is((select count(*) from public.blob_manifests where account_id = '20000000-0000-7000-8000-000000000002' or workspace_id = '70000000-0000-7000-8000-000000000002' or storage_id = '85000000-0000-7000-8000-000000000002' or creator_device_id = '50000000-0000-7000-8000-000000000005'), 0::bigint, 'A cannot select B manifests by routing filters');

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000002","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000005"}', true);
select results_eq('select id from public.accounts order by id', 'values (''20000000-0000-7000-8000-000000000002''::uuid)', 'user B sees exactly its account');
select results_eq('select id from public.device_bindings order by id', 'values (''30000000-0000-0000-0000-000000000005''::uuid), (''30000000-0000-0000-0000-000000000007''::uuid)', 'user B sees exactly its active and historical bindings');
select results_eq('select id from public.device_certificates order by id', 'values (''60000000-0000-7000-8000-000000000002''::uuid)', 'user B sees exactly its certificate');
select results_eq('select id from public.sync_operations order by id', 'values (''90000000-0000-7000-8000-000000000002''::uuid)', 'user B sees exactly its operation');
select results_eq('select id from public.sync_checkpoints order by id', 'values (''93000000-0000-7000-8000-000000000002''::uuid)', 'user B sees exactly its checkpoint');
select results_eq('select id from public.blob_manifests order by id', 'values (''84000000-0000-7000-8000-000000000002''::uuid)', 'user B sees exactly its finalized manifest');

select results_eq(
  $$select id from public.sync_operations
    where account_id = '20000000-0000-7000-8000-000000000002'
      and workspace_id = '70000000-0000-7000-8000-000000000002'
      and (received_at, id) > ('2026-08-04 00:00:00+00'::timestamptz, '00000000-0000-0000-0000-000000000000'::uuid)
    order by received_at, id limit 1$$,
  $$values ('90000000-0000-7000-8000-000000000002'::uuid)$$,
  'user B can keyset-page its read-only operations by receipt and ID'
);
select results_eq(
  $$select id from public.sync_checkpoints
    where account_id = '20000000-0000-7000-8000-000000000002'
      and workspace_id = '70000000-0000-7000-8000-000000000002'
      and (received_at, id) > ('2026-08-04 00:00:00+00'::timestamptz, '00000000-0000-0000-0000-000000000000'::uuid)
    order by received_at, id limit 1$$,
  $$values ('93000000-0000-7000-8000-000000000002'::uuid)$$,
  'user B can keyset-page its read-only checkpoints by receipt and ID'
);

select throws_ok(command.sql, format('user B cannot %s', command.description))
from (values
  ('select pg_temp.insert_sync_operation(''9b000000-0000-7000-8000-000000000003'', p_account_id => ''20000000-0000-7000-8000-000000000002'', p_workspace_id => ''70000000-0000-7000-8000-000000000002'', p_project_id => null, p_device_id => ''50000000-0000-7000-8000-000000000005'', p_certificate_id => ''60000000-0000-7000-8000-000000000002'', p_device_sequence => 1)', 'INSERT a legitimate operation'),
  ('update public.sync_operations set signature = signature where id = ''90000000-0000-7000-8000-000000000002''', 'UPDATE its operation'),
  ('delete from public.sync_operations where id = ''90000000-0000-7000-8000-000000000002''', 'DELETE its operation'),
  ('truncate table public.sync_operations', 'TRUNCATE operations'),
  ('insert into public.sync_operations select * from public.sync_operations where id = ''90000000-0000-7000-8000-000000000002'' on conflict (id) do update set signature = excluded.signature', 'conflict-UPSERT its operation'),
  ('select pg_temp.insert_sync_checkpoint(''9b000000-0000-7000-8000-000000000004'', p_account_id => ''20000000-0000-7000-8000-000000000002'', p_workspace_id => ''70000000-0000-7000-8000-000000000002'', p_device_id => ''50000000-0000-7000-8000-000000000005'', p_certificate_id => ''60000000-0000-7000-8000-000000000002'')', 'INSERT a legitimate checkpoint'),
  ('update public.sync_checkpoints set signature = signature where id = ''93000000-0000-7000-8000-000000000002''', 'UPDATE its checkpoint'),
  ('delete from public.sync_checkpoints where id = ''93000000-0000-7000-8000-000000000002''', 'DELETE its checkpoint'),
  ('truncate table public.sync_checkpoints', 'TRUNCATE checkpoints'),
  ('insert into public.sync_checkpoints select * from public.sync_checkpoints where id = ''93000000-0000-7000-8000-000000000002'' on conflict (id) do update set signature = excluded.signature', 'conflict-UPSERT its checkpoint')
) as command(sql, description);

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000002"}', true);
select results_eq('select (select count(*) from public.accounts), (select count(*) from public.device_bindings), (select count(*) from public.device_certificates), (select count(*) from public.sync_operations), (select count(*) from public.sync_checkpoints), (select count(*) from public.blob_manifests)', 'values (0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint)', 'pending binding sees no rows on all six read relations');
select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000003"}', true);
select results_eq('select (select count(*) from public.accounts), (select count(*) from public.device_bindings), (select count(*) from public.device_certificates), (select count(*) from public.sync_operations), (select count(*) from public.sync_checkpoints), (select count(*) from public.blob_manifests)', 'values (0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint)', 'revoked binding sees no rows on all six read relations');
select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000004"}', true);
select results_eq('select (select count(*) from public.accounts), (select count(*) from public.device_bindings), (select count(*) from public.device_certificates), (select count(*) from public.sync_operations), (select count(*) from public.sync_checkpoints), (select count(*) from public.blob_manifests)', 'values (0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint)', 'expired binding sees no rows on all six read relations');

select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000001"}', true);
select throws_ok(command.sql, format('authenticated cannot %s %s', command.verb, relation.qualified_name))
from (values
  ('public.accounts'), ('public.device_bindings'), ('public.device_certificates'),
  ('public.sync_operations'), ('public.sync_checkpoints'), ('public.blob_manifests'),
  ('public.pairing_requests'), ('public.recovery_roots'), ('public.github_installations'),
  ('public.deletion_requests'), ('context_relay_private.blob_upload_reservations')
) as relation(qualified_name)
cross join lateral (values
  ('insert', format('insert into %s default values', relation.qualified_name)),
  ('update', format('update %s set id = id where false', relation.qualified_name)),
  ('delete', format('delete from %s where false', relation.qualified_name)),
  ('truncate', format('truncate table %s', relation.qualified_name))
) as command(verb, sql);

reset role;

set local role anon;
select throws_ok(format('select * from %s', relation.qualified_name), format('anon cannot read %s', relation.qualified_name))
from (values
  ('public.accounts'), ('public.device_bindings'), ('public.device_certificates'),
  ('public.sync_operations'), ('public.sync_checkpoints'), ('public.blob_manifests')
) as relation(qualified_name);

select throws_ok(command.sql, format('anon cannot %s %s', command.verb, relation.qualified_name))
from (values
  ('public.accounts'), ('public.device_bindings'), ('public.device_certificates'),
  ('public.sync_operations'), ('public.sync_checkpoints'), ('public.blob_manifests'),
  ('public.pairing_requests'), ('public.recovery_roots'), ('public.github_installations'),
  ('public.deletion_requests'), ('context_relay_private.blob_upload_reservations')
) as relation(qualified_name)
cross join lateral (values
  ('insert', format('insert into %s default values', relation.qualified_name)),
  ('update', format('update %s set id = id where false', relation.qualified_name)),
  ('delete', format('delete from %s where false', relation.qualified_name)),
  ('truncate', format('truncate table %s', relation.qualified_name))
) as command(verb, sql);

reset role;

set local role service_role;
select isnt(
  public.service_begin_account_deletion('20000000-0000-7000-8000-000000000004'),
  null::uuid,
  'service role begins account deletion and receives a request ID'
);
reset role;

select pg_catalog.set_config(
  'context_relay_test.deletion_request_id',
  (select id::text from public.deletion_requests where account_id = '20000000-0000-7000-8000-000000000004'),
  true
);
select ok(
  (select account.deletion_state = 'pending_delete'
     and account.deletion_requested_at = request.requested_at
     and account.deletion_scheduled_for = request.grace_deadline
     and request.state = 'pending_delete'
     and request.grace_deadline = request.requested_at + interval '7 days'
     and request.cancelled_at is null
     and request.purged_at is null
   from public.accounts account
   join public.deletion_requests request on request.account_id = account.id
   where account.id = '20000000-0000-7000-8000-000000000004'),
  'begin deletion atomically stores one database-timestamped seven-day request and account state'
);

set local role context_relay_rls_owner;
select throws_ok(
  $$select pg_temp.insert_sync_operation(
    '9c000000-0000-7000-8000-000000000004',
    p_account_id => '20000000-0000-7000-8000-000000000004',
    p_workspace_id => '70000000-0000-7000-8000-000000000004',
    p_project_id => null,
    p_device_id => '50000000-0000-7000-8000-000000000006',
    p_certificate_id => '60000000-0000-7000-8000-000000000004',
    p_device_sequence => 1
  )$$,
  'privileged operation insert fails while the account is pending delete'
);
reset role;

set local role authenticated;
select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000004","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000006"}', true);
select results_eq('select context_relay_private.current_read_account_id(), context_relay_private.current_write_account_id(), context_relay_private.current_read_device_id(), context_relay_private.current_write_device_id()', 'values (''20000000-0000-7000-8000-000000000004''::uuid, null::uuid, ''50000000-0000-7000-8000-000000000006''::uuid, null::uuid)', 'pending-delete retains read identity and loses write identity');
select pg_catalog.set_config('realtime.topic', 'account:20000000-0000-7000-8000-000000000004:sync', true);
select is(
  (select count(*) from realtime.messages where id = 'd1000000-0000-7000-8000-000000000004'),
  1::bigint,
  'active pending-delete session reads its private Broadcast row for export pulls through RLS'
);
select results_eq('select id from public.accounts order by id', 'values (''20000000-0000-7000-8000-000000000004''::uuid)', 'pending-delete user sees its account');
select results_eq('select id from public.device_bindings order by id', 'values (''30000000-0000-0000-0000-000000000006''::uuid)', 'pending-delete user sees its binding');
select results_eq('select id from public.device_certificates order by id', 'values (''60000000-0000-7000-8000-000000000004''::uuid)', 'pending-delete user sees its certificate');
select results_eq('select id from public.sync_operations order by id', 'values (''90000000-0000-7000-8000-000000000004''::uuid)', 'pending-delete user sees its operation');
select results_eq('select id from public.sync_checkpoints order by id', 'values (''93000000-0000-7000-8000-000000000004''::uuid)', 'pending-delete user sees its checkpoint');
select results_eq('select id from public.blob_manifests order by id', 'values (''84000000-0000-7000-8000-000000000004''::uuid)', 'pending-delete user sees its finalized manifest');
reset role;

set local role service_role;
select is(
  public.service_begin_account_deletion('20000000-0000-7000-8000-000000000004'),
  pg_catalog.current_setting('context_relay_test.deletion_request_id')::uuid,
  'exact pending deletion replay returns the existing request ID'
);
select lives_ok(
  $$select public.service_cancel_account_deletion('20000000-0000-7000-8000-000000000004')$$,
  'service role cancels pending deletion before the deadline'
);
reset role;

select ok(
  (select account.deletion_state = 'active'
     and account.deletion_requested_at is null
     and account.deletion_scheduled_for is null
     and request.state = 'active'
     and request.cancelled_at is not null
     and request.purged_at is null
   from public.accounts account
   join public.deletion_requests request on request.account_id = account.id
   where account.id = '20000000-0000-7000-8000-000000000004'),
  'cancellation atomically restores active account state and records cancellation'
);

set local role authenticated;
select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000004","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000006"}', true);
select results_eq('select context_relay_private.current_read_account_id(), context_relay_private.current_write_account_id(), context_relay_private.current_read_device_id(), context_relay_private.current_write_device_id()', 'values (''20000000-0000-7000-8000-000000000004''::uuid, ''20000000-0000-7000-8000-000000000004''::uuid, ''50000000-0000-7000-8000-000000000006''::uuid, ''50000000-0000-7000-8000-000000000006''::uuid)', 'cancellation restores the same binding write identity without changing read scope');
reset role;

set local role service_role;
select lives_ok(
  $$select public.service_cancel_account_deletion('20000000-0000-7000-8000-000000000004')$$,
  'exact valid cancellation replay is idempotent'
);
select is(
  public.service_begin_account_deletion('20000000-0000-7000-8000-000000000004'),
  pg_catalog.current_setting('context_relay_test.deletion_request_id')::uuid,
  'a new deletion lifecycle reuses the cancelled request record'
);
select throws_ok(
  $$select public.service_cancel_account_deletion('20000000-0000-7000-8000-000000000002')$$,
  'cancellation fails when no deletion request exists'
);
reset role;

select is(
  (select count(*) from public.deletion_requests where account_id = '20000000-0000-7000-8000-000000000004'),
  1::bigint,
  'repeated deletion lifecycles keep exactly one request row'
);
set local role service_role;
select lives_ok(
  $$select public.service_cancel_account_deletion('20000000-0000-7000-8000-000000000004')$$,
  'the reused pending lifecycle remains cancellable before its deadline'
);
reset role;

update public.deletion_requests
set state = 'pending_delete',
    requested_at = pg_catalog.statement_timestamp() - interval '8 days',
    grace_deadline = pg_catalog.statement_timestamp() - interval '1 day',
    cancelled_at = null,
    purged_at = null,
    updated_at = pg_catalog.statement_timestamp()
where account_id = '20000000-0000-7000-8000-000000000004';
update public.accounts
set deletion_state = 'pending_delete',
    deletion_requested_at = (select requested_at from public.deletion_requests where account_id = '20000000-0000-7000-8000-000000000004'),
    deletion_scheduled_for = (select grace_deadline from public.deletion_requests where account_id = '20000000-0000-7000-8000-000000000004'),
    updated_at = pg_catalog.statement_timestamp()
where id = '20000000-0000-7000-8000-000000000004';

set local role service_role;
select throws_ok(
  $$select public.service_cancel_account_deletion('20000000-0000-7000-8000-000000000004')$$,
  'cancellation fails after the grace deadline'
);
reset role;
select ok(
  (select deletion_state = 'pending_delete' from public.accounts where id = '20000000-0000-7000-8000-000000000004')
  and (select state = 'pending_delete' and cancelled_at is null from public.deletion_requests where account_id = '20000000-0000-7000-8000-000000000004'),
  'expired cancellation failure leaves account and request pending'
);

update public.deletion_requests
set state = 'purged', purged_at = pg_catalog.statement_timestamp(), updated_at = pg_catalog.statement_timestamp()
where account_id = '20000000-0000-7000-8000-000000000004';
update public.accounts
set deletion_state = 'purged', updated_at = pg_catalog.statement_timestamp()
where id = '20000000-0000-7000-8000-000000000004';

set local role service_role;
select throws_ok(
  $$select public.service_cancel_account_deletion('20000000-0000-7000-8000-000000000004')$$,
  'cancellation never changes purged state'
);
select throws_ok(
  $$select public.service_begin_account_deletion('20000000-0000-7000-8000-000000000004')$$,
  'begin deletion never reopens purged state'
);
reset role;

set local role service_role;
select throws_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000001', '50000000-0000-7000-8000-000000000004', 1, decode(repeat('91', 32), 'hex'), decode(repeat('92', 64), 'hex'))$$,
  'revocation rejects an expired active binding'
);
select throws_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000004', '50000000-0000-7000-8000-000000000006', 1, decode(repeat('93', 32), 'hex'), decode(repeat('94', 64), 'hex'))$$,
  'revocation rejects a target on a purged account'
);
reset role;

select results_eq(
  $$select state::text, cutoff_device_sequence, cutoff_hash, cutoff_signature, control_epoch, key_epoch from public.device_bindings join public.accounts on accounts.id = device_bindings.account_id where device_bindings.id = '30000000-0000-0000-0000-000000000004'$$,
  $$values ('active'::text, null::bigint, null::bytea, null::bytea, 0::bigint, 0::bigint)$$,
  'expired-target rejection leaves its binding, cutoff, and account epochs unchanged'
);
select results_eq(
  $$select device_bindings.state::text, cutoff_device_sequence, cutoff_hash, cutoff_signature, deletion_state::text, control_epoch, key_epoch from public.device_bindings join public.accounts on accounts.id = device_bindings.account_id where device_bindings.id = '30000000-0000-0000-0000-000000000006'$$,
  $$values ('active'::text, null::bigint, null::bytea, null::bytea, 'purged'::text, 0::bigint, 0::bigint)$$,
  'purged-account rejection leaves its binding, cutoff, state, and epochs unchanged'
);

set local role service_role;
select lives_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000002', '50000000-0000-7000-8000-000000000005', 7, decode(repeat('a1', 32), 'hex'), decode(repeat('a2', 64), 'hex'))$$,
  'exact historical cutoff replay succeeds before considering the replacement binding'
);
reset role;
select results_eq(
  $$select state::text, cutoff_device_sequence, cutoff_hash, cutoff_signature, control_epoch, key_epoch from public.device_bindings join public.accounts on accounts.id = device_bindings.account_id where device_bindings.id = '30000000-0000-0000-0000-000000000005'$$,
  $$values ('active'::text, null::bigint, null::bytea, null::bytea, 0::bigint, 0::bigint)$$,
  'historical replay leaves the active replacement and epochs unchanged'
);

set local role service_role;
select throws_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000002', '50000000-0000-7000-8000-000000000005', 6, decode(repeat('b1', 32), 'hex'), decode(repeat('b2', 64), 'hex'))$$,
  'cutoff below historical maximum is stale and fails'
);
select throws_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000002', '50000000-0000-7000-8000-000000000005', 7, decode(repeat('b1', 32), 'hex'), decode(repeat('b2', 64), 'hex'))$$,
  'equal-sequence conflicting historical cutoff fails'
);
reset role;
select results_eq(
  $$select state::text, cutoff_device_sequence, control_epoch, key_epoch from public.device_bindings join public.accounts on accounts.id = device_bindings.account_id where device_bindings.id = '30000000-0000-0000-0000-000000000005'$$,
  $$values ('active'::text, null::bigint, 0::bigint, 0::bigint)$$,
  'stale and conflicting history leave the replacement and epochs unchanged'
);

set local role service_role;
select lives_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000002', '50000000-0000-7000-8000-000000000005', 8, decode(repeat('b1', 32), 'hex'), decode(repeat('b2', 64), 'hex'))$$,
  'higher cutoff revokes the active replacement'
);
reset role;
select results_eq(
  $$select state::text, cutoff_device_sequence, cutoff_hash, cutoff_signature, control_epoch, key_epoch from public.device_bindings join public.accounts on accounts.id = device_bindings.account_id where device_bindings.id = '30000000-0000-0000-0000-000000000005'$$,
  $$values ('revoked'::text, 8::bigint, decode(repeat('b1', 32), 'hex'), decode(repeat('b2', 64), 'hex'), 1::bigint, 1::bigint)$$,
  'higher replacement cutoff is stored and advances both epochs exactly once'
);
set local role service_role;
select lives_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000002', '50000000-0000-7000-8000-000000000005', 8, decode(repeat('b1', 32), 'hex'), decode(repeat('b2', 64), 'hex'))$$,
  'exact replacement revocation replay is idempotent'
);
reset role;
select results_eq(
  $$select cutoff_device_sequence, control_epoch, key_epoch from public.device_bindings join public.accounts on accounts.id = device_bindings.account_id where device_bindings.id = '30000000-0000-0000-0000-000000000005'$$,
  $$values (8::bigint, 1::bigint, 1::bigint)$$,
  'replacement replay does not advance epochs again'
);

select results_eq(
  $$select state::text, control_epoch, key_epoch from public.device_bindings join public.accounts on accounts.id = device_bindings.account_id where device_bindings.id = '30000000-0000-0000-0000-000000000001'$$,
  $$values ('active'::text, 0::bigint, 0::bigint)$$,
  'revocation fixture begins active at zero epochs'
);

set local role service_role;
select throws_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000001', '50000000-0000-7000-8000-000000000001', -1, decode(repeat('81', 32), 'hex'), decode(repeat('82', 64), 'hex'))$$,
  'revocation rejects a negative cutoff sequence'
);
select throws_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000001', '50000000-0000-7000-8000-000000000001', 9, decode(repeat('81', 31), 'hex'), decode(repeat('82', 64), 'hex'))$$,
  'revocation rejects an invalid cutoff hash width'
);
select throws_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000001', '50000000-0000-7000-8000-000000000001', 9, decode(repeat('81', 32), 'hex'), decode(repeat('82', 63), 'hex'))$$,
  'revocation rejects an invalid cutoff signature width'
);
select throws_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000001', '50000000-0000-7000-8000-000000000002', 9, decode(repeat('81', 32), 'hex'), decode(repeat('82', 64), 'hex'))$$,
  'revocation rejects a pending binding rather than treating it as live active'
);
reset role;

select results_eq(
  $$select state::text, cutoff_device_sequence, cutoff_hash, cutoff_signature, control_epoch, key_epoch from public.device_bindings join public.accounts on accounts.id = device_bindings.account_id where device_bindings.id = '30000000-0000-0000-0000-000000000001'$$,
  $$values ('active'::text, null::bigint, null::bytea, null::bytea, 0::bigint, 0::bigint)$$,
  'invalid revocation attempts leave binding cutoff and account epochs unchanged'
);

set local role service_role;
select lives_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000001', '50000000-0000-7000-8000-000000000001', 9, decode(repeat('81', 32), 'hex'), decode(repeat('82', 64), 'hex'))$$,
  'service role revokes the live active binding'
);
reset role;
select results_eq(
  $$select state::text, cutoff_device_sequence, cutoff_hash, cutoff_signature, control_epoch, key_epoch from public.device_bindings join public.accounts on accounts.id = device_bindings.account_id where device_bindings.id = '30000000-0000-0000-0000-000000000001'$$,
  $$values ('revoked'::text, 9::bigint, decode(repeat('81', 32), 'hex'), decode(repeat('82', 64), 'hex'), 1::bigint, 1::bigint)$$,
  'revocation atomically stores the full cutoff and advances both epochs exactly once'
);

set local role service_role;
select lives_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000001', '50000000-0000-7000-8000-000000000001', 9, decode(repeat('81', 32), 'hex'), decode(repeat('82', 64), 'hex'))$$,
  'exact revocation replay is idempotent'
);
select throws_ok(
  $$select public.service_revoke_device_binding('20000000-0000-7000-8000-000000000001', '50000000-0000-7000-8000-000000000001', 10, decode(repeat('81', 32), 'hex'), decode(repeat('82', 64), 'hex'))$$,
  'conflicting revocation replay fails'
);
reset role;

select results_eq(
  $$select state::text, cutoff_device_sequence, control_epoch, key_epoch from public.device_bindings join public.accounts on accounts.id = device_bindings.account_id where device_bindings.id = '30000000-0000-0000-0000-000000000001'$$,
  $$values ('revoked'::text, 9::bigint, 1::bigint, 1::bigint)$$,
  'replays do not advance epochs or replace the signed cutoff'
);

set local role authenticated;
select pg_catalog.set_config('request.jwt.claims', '{"sub":"10000000-0000-0000-0000-000000000001","role":"authenticated","session_id":"40000000-0000-0000-0000-000000000001"}', true);
select results_eq('select (select count(*) from public.accounts), (select count(*) from public.device_bindings), (select count(*) from public.device_certificates), (select count(*) from public.sync_operations), (select count(*) from public.sync_checkpoints), (select count(*) from public.blob_manifests)', 'values (0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint)', 'fresh policy evaluation immediately denies the revoked session on all six relations');
reset role;

select * from finish();
rollback;
