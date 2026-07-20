CREATE TABLE native_plans (
    plan_id TEXT PRIMARY KEY,
    approval_hash BLOB NOT NULL CHECK (length(approval_hash) = 32),
    payload BLOB NOT NULL CHECK (length(payload) > 0),
    created_ms INTEGER NOT NULL CHECK (created_ms >= 0),
    expires_ms INTEGER NOT NULL CHECK (expires_ms >= created_ms)
);

CREATE TABLE native_transactions (
    transaction_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL UNIQUE REFERENCES native_plans(plan_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'committed', 'restoring', 'restored', 'conflict')
    ),
    sandbox_cleanup_state TEXT NOT NULL DEFAULT 'pending' CHECK (
        sandbox_cleanup_state IN ('pending', 'cleaned', 'conflict')
    ),
    current_step INTEGER NOT NULL DEFAULT 0 CHECK (current_step BETWEEN 0 AND 20),
    entered_step INTEGER NOT NULL DEFAULT 0 CHECK (
        entered_step BETWEEN current_step AND 20
    ),
    created_ms INTEGER NOT NULL CHECK (created_ms >= 0),
    updated_ms INTEGER NOT NULL CHECK (updated_ms >= created_ms),
    committed_ms INTEGER,
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'macos')),
    windows_moniker TEXT,
    windows_sid BLOB,
    mac_generation_id TEXT UNIQUE,
    mac_bundle_id TEXT UNIQUE,
    mac_container BLOB UNIQUE,
    mac_guardian_pgid INTEGER CHECK (
        mac_guardian_pgid IS NULL OR mac_guardian_pgid BETWEEN 1 AND 2147483647
    ),
    mac_bundle_root BLOB CHECK (
        mac_bundle_root IS NULL OR length(mac_bundle_root) = 64
    ),
    mac_signed_digest BLOB CHECK (
        mac_signed_digest IS NULL OR length(mac_signed_digest) = 32
    ),
    mac_container_root BLOB CHECK (
        mac_container_root IS NULL OR length(mac_container_root) = 64
    ),
    mac_generation_substate TEXT CHECK (
        mac_generation_substate IS NULL
        OR mac_generation_substate IN (
            'reserved', 'guardian_bound', 'bundle_bound', 'finalized', 'container_bound'
        )
    ),
    mac_generation_state TEXT CHECK (
        mac_generation_state IS NULL
        OR mac_generation_state IN ('prepared', 'active', 'retired', 'poisoned')
    ),
    CHECK (
        (
            platform = 'windows'
            AND windows_moniker IS NOT NULL
            AND length(windows_moniker) > 0
            AND windows_sid IS NOT NULL
            AND length(windows_sid) > 0
            AND mac_generation_id IS NULL
            AND mac_bundle_id IS NULL
            AND mac_container IS NULL
            AND mac_guardian_pgid IS NULL
            AND mac_bundle_root IS NULL
            AND mac_signed_digest IS NULL
            AND mac_container_root IS NULL
            AND mac_generation_substate IS NULL
            AND mac_generation_state IS NULL
        )
        OR (
            platform = 'macos'
            AND windows_moniker IS NULL
            AND windows_sid IS NULL
            AND mac_generation_id IS NOT NULL
            AND length(mac_generation_id) = 32
            AND mac_bundle_id IS NOT NULL
            AND length(mac_bundle_id) > 0
            AND mac_container IS NOT NULL
            AND length(mac_container) > 0
            AND mac_generation_substate IS NOT NULL
            AND mac_generation_state IS NOT NULL
            AND (
                (
                    mac_generation_substate = 'reserved'
                    AND mac_guardian_pgid IS NULL
                    AND mac_bundle_root IS NULL
                    AND mac_signed_digest IS NULL
                    AND mac_container_root IS NULL
                )
                OR (
                    mac_generation_substate = 'guardian_bound'
                    AND mac_guardian_pgid IS NOT NULL
                    AND mac_bundle_root IS NULL
                    AND mac_signed_digest IS NULL
                    AND mac_container_root IS NULL
                )
                OR (
                    mac_generation_substate = 'bundle_bound'
                    AND mac_guardian_pgid IS NOT NULL
                    AND mac_bundle_root IS NOT NULL
                    AND mac_signed_digest IS NULL
                    AND mac_container_root IS NULL
                )
                OR (
                    mac_generation_substate = 'finalized'
                    AND mac_guardian_pgid IS NOT NULL
                    AND mac_bundle_root IS NOT NULL
                    AND mac_signed_digest IS NOT NULL
                    AND mac_container_root IS NULL
                )
                OR (
                    mac_generation_substate = 'container_bound'
                    AND mac_guardian_pgid IS NOT NULL
                    AND mac_bundle_root IS NOT NULL
                    AND mac_signed_digest IS NOT NULL
                    AND mac_container_root IS NOT NULL
                )
            )
            AND (
                mac_generation_state IN ('prepared', 'poisoned')
                OR mac_generation_substate = 'container_bound'
            )
        )
    ),
    CHECK (
        (status = 'committed' AND committed_ms IS NOT NULL)
        OR (status != 'committed' AND committed_ms IS NULL)
    ),
    CHECK (
        (sandbox_cleanup_state = 'pending' AND current_step < 20)
        OR (
            sandbox_cleanup_state = 'conflict'
            AND current_step = 19
            AND entered_step IN (19, 20)
            AND status IN ('committed', 'restored', 'conflict')
        )
        OR (
            sandbox_cleanup_state IN ('cleaned', 'conflict')
            AND current_step = 20
            AND entered_step = 20
            AND status IN ('committed', 'restored', 'conflict')
        )
    )
);

CREATE TABLE native_mutation_wal (
    transaction_id TEXT NOT NULL REFERENCES native_transactions(transaction_id) ON DELETE RESTRICT,
    target_sequence INTEGER NOT NULL CHECK (target_sequence >= 0),
    target_json BLOB NOT NULL CHECK (length(target_json) > 0),
    object_volume BLOB NOT NULL CHECK (length(object_volume) > 0),
    object_id BLOB NOT NULL CHECK (length(object_id) > 0),
    object_topology BLOB NOT NULL CHECK (length(object_topology) > 0),
    applied_object_volume BLOB CHECK (applied_object_volume IS NULL OR length(applied_object_volume) > 0),
    applied_object_id BLOB CHECK (applied_object_id IS NULL OR length(applied_object_id) > 0),
    applied_object_topology BLOB CHECK (applied_object_topology IS NULL OR length(applied_object_topology) > 0),
    restored_object_volume BLOB CHECK (restored_object_volume IS NULL OR length(restored_object_volume) > 0),
    restored_object_id BLOB CHECK (restored_object_id IS NULL OR length(restored_object_id) > 0),
    restored_object_topology BLOB CHECK (restored_object_topology IS NULL OR length(restored_object_topology) > 0),
    absence_rebind_target_sequence INTEGER CHECK (
        absence_rebind_target_sequence IS NULL OR absence_rebind_target_sequence >= 0
    ),
    absence_rebind_old_volume BLOB CHECK (absence_rebind_old_volume IS NULL OR length(absence_rebind_old_volume) > 0),
    absence_rebind_old_id BLOB CHECK (absence_rebind_old_id IS NULL OR length(absence_rebind_old_id) > 0),
    absence_rebind_old_topology BLOB CHECK (absence_rebind_old_topology IS NULL OR length(absence_rebind_old_topology) > 0),
    absence_rebind_new_volume BLOB CHECK (absence_rebind_new_volume IS NULL OR length(absence_rebind_new_volume) > 0),
    absence_rebind_new_id BLOB CHECK (absence_rebind_new_id IS NULL OR length(absence_rebind_new_id) > 0),
    absence_rebind_new_topology BLOB CHECK (absence_rebind_new_topology IS NULL OR length(absence_rebind_new_topology) > 0),
    before_image_id TEXT NOT NULL REFERENCES before_images(id) ON DELETE RESTRICT,
    operation_kind TEXT NOT NULL CHECK (
        operation_kind IN ('payload', 'executable_disabled', 'activation_reference')
    ),
    expected_fingerprint BLOB NOT NULL CHECK (length(expected_fingerprint) = 32),
    intended_applied_fingerprint BLOB NOT NULL CHECK (length(intended_applied_fingerprint) = 32),
    intended_restored_fingerprint BLOB NOT NULL CHECK (length(intended_restored_fingerprint) = 32),
    state TEXT NOT NULL CHECK (
        state IN ('prepared', 'applied', 'restore_prepared', 'restored', 'conflict')
    ),
    CHECK (
        (applied_object_volume IS NULL AND applied_object_id IS NULL AND applied_object_topology IS NULL)
        OR
        (applied_object_volume IS NOT NULL AND applied_object_id IS NOT NULL AND applied_object_topology IS NOT NULL)
    ),
    CHECK (
        (restored_object_volume IS NULL AND restored_object_id IS NULL AND restored_object_topology IS NULL)
        OR
        (restored_object_volume IS NOT NULL AND restored_object_id IS NOT NULL AND restored_object_topology IS NOT NULL)
    ),
    CHECK (
        (
            absence_rebind_target_sequence IS NULL
            AND absence_rebind_old_volume IS NULL
            AND absence_rebind_old_id IS NULL
            AND absence_rebind_old_topology IS NULL
            AND absence_rebind_new_volume IS NULL
            AND absence_rebind_new_id IS NULL
            AND absence_rebind_new_topology IS NULL
        )
        OR
        (
            absence_rebind_target_sequence IS NOT NULL
            AND absence_rebind_old_volume IS NOT NULL
            AND absence_rebind_old_id IS NOT NULL
            AND absence_rebind_old_topology IS NOT NULL
            AND absence_rebind_new_volume IS NOT NULL
            AND absence_rebind_new_id IS NOT NULL
            AND absence_rebind_new_topology IS NOT NULL
        )
    ),
    PRIMARY KEY (transaction_id, target_sequence),
    UNIQUE (transaction_id, target_json)
);

CREATE TABLE native_ownership (
    stable_id TEXT PRIMARY KEY CHECK (length(stable_id) > 0),
    transaction_id TEXT NOT NULL REFERENCES native_transactions(transaction_id) ON DELETE RESTRICT,
    structural_location TEXT NOT NULL CHECK (length(structural_location) > 0),
    semantic_digest BLOB NOT NULL CHECK (length(semantic_digest) = 32),
    native_digest BLOB NOT NULL CHECK (length(native_digest) = 32)
);

CREATE TABLE native_receipts (
    plan_id TEXT PRIMARY KEY REFERENCES receipts(plan_id) ON DELETE RESTRICT,
    transaction_id TEXT NOT NULL UNIQUE REFERENCES native_transactions(transaction_id) ON DELETE RESTRICT,
    target_count INTEGER NOT NULL CHECK (target_count >= 0),
    payload_json BLOB NOT NULL CHECK (length(payload_json) > 0)
);

CREATE INDEX native_transactions_status_idx
    ON native_transactions(status, updated_ms, transaction_id);
CREATE INDEX native_mutation_wal_state_idx
    ON native_mutation_wal(transaction_id, state, target_sequence);
CREATE INDEX native_ownership_transaction_idx
    ON native_ownership(transaction_id, stable_id);
