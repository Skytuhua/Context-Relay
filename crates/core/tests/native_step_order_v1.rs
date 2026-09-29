//! Guards on the native transaction step state machine in the vault.
//!
//! The frozen twenty-step order itself is asserted elsewhere; these cover the
//! *transition guard* — that the vault refuses to enter a step out of order and
//! refuses to move a transaction that is no longer pending. Without these, the
//! ordering checks in `enter_native_step` could regress silently: the machine
//! would still report the right step list while accepting a jump that skips
//! mutation, validation and the compare-and-swap entirely.

mod support;

use context_relay_core::native_transaction::model::TransactionStep;
use context_relay_core::vault::{
    NativePlanWrite, NativeSandboxIdentity, SetupPlanAction, SetupPlanWrite, Vault,
};
use context_relay_protocol::PlanId;
use sha2::{Digest as _, Sha256};

use support::{ID_1, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "native-step-order-v1";
const TRANSACTION_ID: &str = "native-step-order";

fn identity() -> NativeSandboxIdentity {
    NativeSandboxIdentity::Windows {
        moniker: "context-relay.native.0123456789abcdef0123456789abcdef".to_owned(),
        sid:
            b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541"
                .to_vec(),
    }
}

fn open_pending_transaction() -> (TempVault, Vault) {
    let path = TempVault::new("native-step-order");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = ID_1.parse::<PlanId>().unwrap();
    let approval_hash = context_relay_protocol::Sha256Digest(Sha256::digest(b"step-order").into());
    let payload = b"canonical-plan";
    vault
        .put_setup_plan(SetupPlanWrite {
            plan_id: &plan_id,
            schema_version: 1,
            approval_version: 2,
            approval_hash: &approval_hash,
            payload,
            created_ms: 10,
            expires_ms: 20,
        })
        .unwrap();
    vault
        .claim_setup_plan(&plan_id, SetupPlanAction::Apply, 11)
        .unwrap();
    vault
        .begin_native_transaction(
            TRANSACTION_ID,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &approval_hash,
                payload,
                created_ms: 10,
                expires_ms: 20,
            },
            identity(),
        )
        .unwrap();
    (path, vault)
}

/// A fresh transaction sits at step 0. Reaching any later step requires
/// completing each step before it, so jumping straight to `WritePayloads` —
/// which is what actually mutates target files — must fail.
#[test]
fn entering_a_step_much_later_in_the_order_is_refused() {
    let (_path, mut vault) = open_pending_transaction();
    let error = vault
        .enter_native_step(TRANSACTION_ID, TransactionStep::WritePayloads)
        .expect_err("WritePayloads must not be reachable while AcquireLock is open");
    assert!(
        matches!(error, context_relay_core::vault::VaultError::Validation(ref message) if message.contains("out of order")),
        "expected an out-of-order validation error, got {error:?}"
    );
    let _ = vault;
}

/// The same guard must hold one step past the current one: entering
/// `ReprobeLiveState` without completing `AcquireLock` is not a valid transition.
#[test]
fn skipping_a_single_intermediate_step_is_refused() {
    let (_path, mut vault) = open_pending_transaction();
    let error = vault
        .enter_native_step(TRANSACTION_ID, TransactionStep::CompareApprovedDigests)
        .expect_err("CompareApprovedDigests must not be reachable before AcquireLock completes");
    assert!(
        matches!(error, context_relay_core::vault::VaultError::Validation(ref message) if message.contains("out of order")),
        "expected an out-of-order validation error, got {error:?}"
    );
    let _ = vault;
}

/// Entering steps in order is what recovery depends on, so the happy path has
/// to keep working: this is the path a crash-replay reuses.
#[test]
fn consecutive_steps_in_order_are_accepted() {
    let (_path, mut vault) = open_pending_transaction();
    // begin_native_transaction leaves both cursors at 0, so AcquireLock has to
    // be entered and then completed; completing it is what advances
    // current_step and makes the next step reachable.
    vault
        .enter_native_step(TRANSACTION_ID, TransactionStep::AcquireLock)
        .unwrap();
    vault
        .complete_native_step(TRANSACTION_ID, TransactionStep::AcquireLock)
        .unwrap();
    vault
        .enter_native_step(TRANSACTION_ID, TransactionStep::ReprobeLiveState)
        .unwrap();
    vault
        .complete_native_step(TRANSACTION_ID, TransactionStep::ReprobeLiveState)
        .unwrap();
    vault
        .enter_native_step(TRANSACTION_ID, TransactionStep::CompareApprovedDigests)
        .unwrap();
    let snapshot = vault
        .native_transaction(TRANSACTION_ID)
        .unwrap()
        .expect("transaction must still exist");
    assert_eq!(
        snapshot.entered_step,
        TransactionStep::CompareApprovedDigests as u8,
        "entered_step must track the last step entered"
    );
    assert_eq!(
        snapshot.current_step,
        TransactionStep::ReprobeLiveState as u8,
        "current_step must still be the last completed step"
    );
}

/// Re-entering the step already entered is how a crash between `enter_step` and
/// `complete_step` is replayed, so it has to stay idempotent rather than
/// erroring or advancing the cursor.
#[test]
fn reentering_the_current_step_is_idempotent() {
    let (_path, mut vault) = open_pending_transaction();
    vault
        .enter_native_step(TRANSACTION_ID, TransactionStep::AcquireLock)
        .unwrap();
    vault
        .enter_native_step(TRANSACTION_ID, TransactionStep::AcquireLock)
        .expect("re-entering the current step must be tolerated");
    let snapshot = vault.native_transaction(TRANSACTION_ID).unwrap().unwrap();
    assert_eq!(snapshot.entered_step, TransactionStep::AcquireLock as u8);
    assert_eq!(
        snapshot.current_step, 0,
        "a re-entered step must not advance"
    );
}

/// An unknown transaction must not create one.
#[test]
fn entering_a_step_on_an_unknown_transaction_fails() {
    let (_path, mut vault) = open_pending_transaction();
    let error = vault
        .enter_native_step("no-such-transaction", TransactionStep::AcquireLock)
        .expect_err("an unknown transaction id must be rejected");
    assert!(
        matches!(error, context_relay_core::vault::VaultError::Validation(ref message) if message.contains("does not exist")),
        "expected a not-found validation error, got {error:?}"
    );
    let _ = vault;
}
