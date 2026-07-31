mod support;

use context_relay_core::vault::{
    NativePlanWrite, NativeSandboxIdentity, SetupPlanAction, SetupPlanClaim, SetupPlanLifecycle,
    SetupPlanWrite, Vault, VaultError,
};
use context_relay_protocol::{PlanId, Sha256Digest};

use support::{ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "setup-plan-vault-v1";
const REAL_APPCONTAINER_SID: &[u8] =
    b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541";

fn write<'a>(
    plan_id: &'a PlanId,
    approval_hash: &'a Sha256Digest,
    payload: &'a [u8],
    expires_ms: u64,
) -> SetupPlanWrite<'a> {
    SetupPlanWrite {
        plan_id,
        schema_version: 1,
        approval_version: 2,
        approval_hash,
        payload,
        created_ms: 10,
        expires_ms,
    }
}

fn native_write<'a>(
    plan_id: &'a PlanId,
    approval_hash: &'a Sha256Digest,
    payload: &'a [u8],
) -> NativePlanWrite<'a> {
    NativePlanWrite {
        plan_id,
        approval_hash,
        payload,
        created_ms: 10,
        expires_ms: 20,
    }
}

fn identity() -> NativeSandboxIdentity {
    NativeSandboxIdentity::Windows {
        moniker: "context-relay.native.0123456789abcdef0123456789abcdef".to_owned(),
        sid: REAL_APPCONTAINER_SID.to_vec(),
    }
}

#[test]
fn preview_plan_round_trips_exact_sealed_bytes_and_rejects_id_reuse() {
    let path = TempVault::new("setup-plan-round-trip");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = ID_1.parse::<PlanId>().unwrap();
    let approval_hash = Sha256Digest([7; 32]);
    let payload = br#"{"schemaVersion":1,"nativePlan":{"exact":"bytes"}}"#;

    vault
        .put_setup_plan(write(&plan_id, &approval_hash, payload, 20))
        .unwrap();
    let stored = vault.setup_plan(&plan_id).unwrap().unwrap();
    assert_eq!(stored.plan_id, plan_id);
    assert_eq!(stored.schema_version, 1);
    assert_eq!(stored.approval_version, 2);
    assert_eq!(stored.approval_hash, approval_hash);
    assert_eq!(stored.payload, payload);
    assert_eq!(stored.lifecycle, SetupPlanLifecycle::Previewed);

    vault
        .put_setup_plan(write(&plan_id, &approval_hash, payload, 20))
        .unwrap();
    let altered = br#"{"schemaVersion":1,"nativePlan":{"exact":"bytez"}}"#;
    assert!(matches!(
        vault.put_setup_plan(write(&plan_id, &approval_hash, altered, 20)),
        Err(VaultError::Validation(_))
    ));
    let altered_hash = Sha256Digest([8; 32]);
    assert!(matches!(
        vault.put_setup_plan(write(&plan_id, &altered_hash, payload, 20)),
        Err(VaultError::Validation(_))
    ));
    assert_eq!(
        vault.setup_plan(&plan_id).unwrap().unwrap().payload,
        payload
    );
}

#[test]
fn lifecycle_claims_are_cas_bound_and_successful_apply_and_rollback_replay() {
    let path = TempVault::new("setup-plan-lifecycle");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = ID_1.parse::<PlanId>().unwrap();
    let hash = Sha256Digest([9; 32]);
    vault
        .put_setup_plan(write(&plan_id, &hash, b"sealed-plan", 20))
        .unwrap();

    assert_eq!(
        vault
            .claim_setup_plan(&plan_id, SetupPlanAction::Apply, 11)
            .unwrap(),
        SetupPlanClaim::Claimed
    );
    assert!(matches!(
        vault.claim_setup_plan(&plan_id, SetupPlanAction::Apply, 11),
        Err(VaultError::Validation(_))
    ));
    vault
        .finish_setup_plan(&plan_id, SetupPlanLifecycle::Applied)
        .unwrap();
    assert_eq!(
        vault
            .claim_setup_plan(&plan_id, SetupPlanAction::Apply, 11)
            .unwrap(),
        SetupPlanClaim::Replay
    );

    assert_eq!(
        vault
            .claim_setup_plan(&plan_id, SetupPlanAction::Rollback, 12)
            .unwrap(),
        SetupPlanClaim::Claimed
    );
    vault
        .finish_setup_plan(&plan_id, SetupPlanLifecycle::RolledBack)
        .unwrap();
    assert_eq!(
        vault
            .claim_setup_plan(&plan_id, SetupPlanAction::Rollback, 12)
            .unwrap(),
        SetupPlanClaim::Replay
    );
    assert_eq!(
        vault.setup_plan(&plan_id).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::RolledBack
    );
}

#[test]
fn expired_preview_cannot_be_claimed_and_is_durably_marked_expired() {
    let path = TempVault::new("setup-plan-expired");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = ID_2.parse::<PlanId>().unwrap();
    let hash = Sha256Digest([11; 32]);
    vault
        .put_setup_plan(write(&plan_id, &hash, b"expired-plan", 20))
        .unwrap();

    assert!(matches!(
        vault.claim_setup_plan(&plan_id, SetupPlanAction::Apply, 20),
        Err(VaultError::Validation(_))
    ));
    assert_eq!(
        vault.setup_plan(&plan_id).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::Expired
    );
}

#[test]
fn native_begin_requires_claimed_lifecycle_but_preserves_legacy_internal_plans() {
    let path = TempVault::new("setup-plan-begin-claim");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let hash = Sha256Digest([13; 32]);
    let payload = b"sealed-plan";

    let previewed = ID_1.parse::<PlanId>().unwrap();
    vault
        .put_setup_plan(write(&previewed, &hash, payload, 20))
        .unwrap();
    assert!(matches!(
        vault.begin_native_transaction(
            "previewed-bypass",
            native_write(&previewed, &hash, payload),
            identity(),
        ),
        Err(VaultError::Validation(_))
    ));

    let expired = ID_2.parse::<PlanId>().unwrap();
    vault
        .put_setup_plan(write(&expired, &hash, payload, 20))
        .unwrap();
    assert!(
        vault
            .claim_setup_plan(&expired, SetupPlanAction::Apply, 20)
            .is_err()
    );
    assert!(matches!(
        vault.begin_native_transaction(
            "expired-bypass",
            native_write(&expired, &hash, payload),
            identity(),
        ),
        Err(VaultError::Validation(_))
    ));

    let applying = ID_3.parse::<PlanId>().unwrap();
    vault
        .put_setup_plan(write(&applying, &hash, payload, 20))
        .unwrap();
    vault
        .claim_setup_plan(&applying, SetupPlanAction::Apply, 11)
        .unwrap();
    vault
        .begin_native_transaction(
            "claimed-apply",
            native_write(&applying, &hash, payload),
            identity(),
        )
        .unwrap();

    let applied = ID_4.parse::<PlanId>().unwrap();
    vault
        .put_setup_plan(write(&applied, &hash, payload, 20))
        .unwrap();
    vault
        .claim_setup_plan(&applied, SetupPlanAction::Apply, 11)
        .unwrap();
    vault
        .finish_setup_plan(&applied, SetupPlanLifecycle::Applied)
        .unwrap();
    assert!(matches!(
        vault.begin_native_transaction(
            "applied-replay-bypass",
            native_write(&applied, &hash, payload),
            identity(),
        ),
        Err(VaultError::Validation(_))
    ));

    let rolling_back = ID_5.parse::<PlanId>().unwrap();
    vault
        .put_setup_plan(write(&rolling_back, &hash, payload, 20))
        .unwrap();
    vault
        .claim_setup_plan(&rolling_back, SetupPlanAction::Apply, 11)
        .unwrap();
    vault
        .finish_setup_plan(&rolling_back, SetupPlanLifecycle::Applied)
        .unwrap();
    vault
        .claim_setup_plan(&rolling_back, SetupPlanAction::Rollback, 12)
        .unwrap();
    vault
        .begin_native_transaction(
            "claimed-rollback",
            native_write(&rolling_back, &hash, payload),
            identity(),
        )
        .unwrap();

    let rolled_back = ID_6.parse::<PlanId>().unwrap();
    vault
        .put_setup_plan(write(&rolled_back, &hash, payload, 20))
        .unwrap();
    vault
        .claim_setup_plan(&rolled_back, SetupPlanAction::Apply, 11)
        .unwrap();
    vault
        .finish_setup_plan(&rolled_back, SetupPlanLifecycle::Applied)
        .unwrap();
    vault
        .claim_setup_plan(&rolled_back, SetupPlanAction::Rollback, 12)
        .unwrap();
    vault
        .finish_setup_plan(&rolled_back, SetupPlanLifecycle::RolledBack)
        .unwrap();
    assert!(matches!(
        vault.begin_native_transaction(
            "rolled-back-replay-bypass",
            native_write(&rolled_back, &hash, payload),
            identity(),
        ),
        Err(VaultError::Validation(_))
    ));

    let legacy = ID_7.parse::<PlanId>().unwrap();
    vault
        .begin_native_transaction(
            "legacy-internal",
            native_write(&legacy, &hash, payload),
            identity(),
        )
        .unwrap();
}
