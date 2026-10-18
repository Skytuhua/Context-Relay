//! Pairing state that nothing reads must not accumulate: an invite expires on
//! its own timestamp, and an anonymous join session id cannot grow the map
//! without bound.

use std::str::FromStr;

use context_relay_core::{
    devices::{memory_transport::InMemoryPairingProvider, transport::PairingApprovalTransport},
    sync::SyncScope,
};
use context_relay_protocol::{AccountId, DeviceId, WorkspaceId};

const ACCOUNT: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074012";
const WORKSPACE: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074010";
const DEVICE: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074011";
const HOUR_MS: u64 = 3_600_000;

fn provider(entropy: usize) -> InMemoryPairingProvider {
    InMemoryPairingProvider::with_test_entropy(
        [0x11; 32],
        (0_u8..=entropy as u8).map(|value| [value; 32]).collect(),
    )
}

fn approver(
    provider: &InMemoryPairingProvider,
) -> context_relay_core::devices::memory_transport::InMemoryPairingApprovalClient {
    provider.existing_device_client(
        SyncScope {
            account_id: AccountId::from_str(ACCOUNT).unwrap(),
            workspace_id: WorkspaceId::from_str(WORKSPACE).unwrap(),
        },
        DeviceId::from_str(DEVICE).unwrap(),
    )
}

#[test]
fn an_invite_nobody_reads_still_expires() {
    let provider = provider(250);
    let client = approver(&provider);

    // One invite per hour for 20 hours, each with a 10 minute lifetime. No
    // invite is ever read back, so nothing observes them expiring.
    for hour in 0..20_u64 {
        client.create_invite(hour * HOUR_MS).unwrap();
    }

    // Retention is bounded by the grace window, not by how many were created:
    // invites from the last hour are still inside it, the rest are gone.
    let (retained, _) = provider.retained_state_counts().unwrap();
    assert!(
        retained <= 2,
        "20 invites created over 20 hours retained {retained}; expiry must not \
         depend on the invite being read"
    );
}

#[test]
fn retention_does_not_grow_with_the_number_of_expired_invites() {
    let provider = provider(250);
    let client = approver(&provider);

    for hour in 0..20_u64 {
        client.create_invite(hour * HOUR_MS).unwrap();
    }
    let (after_20, _) = provider.retained_state_counts().unwrap();

    for hour in 20..200_u64 {
        client.create_invite(hour * HOUR_MS).unwrap();
    }
    let (after_120, _) = provider.retained_state_counts().unwrap();

    assert_eq!(
        after_20, after_120,
        "retention must be bounded by live invites, not by how many were ever made"
    );
}

#[test]
fn a_lapsed_invite_reports_expired_when_it_is_eventually_read() {
    let provider = provider(250);
    let client = approver(&provider);

    let invite = client.create_invite(0).unwrap();
    // Just past the 10 minute lifetime but inside the retention grace, with no
    // read in between. Expiry surfaces as an error, not as a status state.
    assert_eq!(
        client.invite_status(invite.pairing_id, 20 * 60_000),
        Err(context_relay_core::devices::transport::PairingTransportError::Expired),
        "an invite read long after its lifetime must report Expired"
    );
}

#[test]
fn anonymous_join_sessions_are_capped() {
    let provider = provider(250);

    // Well past the cap, using ids no authenticated party ever chose.
    let mut accepted = 0_usize;
    let mut refused = 0_usize;
    for index in 0..500 {
        match provider.join_session_client(&format!("anonymous-{index}")) {
            Ok(_) => accepted += 1,
            Err(_) => refused += 1,
        }
    }

    assert!(refused > 0, "the session map must stop growing");
    let (invites, sessions) = provider.retained_state_counts().unwrap();
    assert_eq!(
        sessions, accepted,
        "the retained session count must match what was accepted"
    );
    assert!(
        sessions <= 64,
        "retained {sessions} sessions, expected the cap to hold"
    );
    let _ = invites;
}

#[test]
fn an_existing_session_id_still_works_once_the_map_is_full() {
    let provider = provider(250);
    let established_session = "already-established";
    provider.join_session_client(established_session).unwrap();

    for index in 0..500 {
        let _ = provider.join_session_client(&format!("filler-{index}"));
    }

    // Capping the map must not lock out a session that is already tracked.
    assert!(provider.join_session_client(established_session).is_ok());
}
