use context_relay_protocol::{
    AccountId, ClockError, DeviceId, HybridLogicalClock, JsonRpcRequestV1, ProtocolVersion,
    ProtocolVersionRange, RecordId, negotiate_version,
};
use std::str::FromStr;

const DEVICE: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";

#[test]
fn uuid_v7_is_strict_and_json_is_canonical() {
    let id = DeviceId::from_str(DEVICE).unwrap();
    assert_eq!(
        serde_json::to_string(&id).unwrap(),
        format!(r#""{DEVICE}""#)
    );
    assert!(DeviceId::from_str("550e8400-e29b-41d4-a716-446655440000").is_err());
}

#[test]
fn hlc_ticks_observes_orders_and_reports_overflow() {
    let node = DeviceId::from_str(DEVICE).unwrap();
    let clock = HybridLogicalClock::new(10, 0, node);
    let ticked = clock.tick(10).unwrap();
    assert_eq!((ticked.physical_ms, ticked.logical), (10, 1));
    let remote = HybridLogicalClock::new(12, 4, node);
    let observed = ticked.observe(&remote, 11).unwrap();
    assert_eq!((observed.physical_ms, observed.logical), (12, 5));
    assert!(observed > ticked);
    let exhausted = HybridLogicalClock::new(12, u32::MAX, node);
    assert_eq!(exhausted.tick(12), Err(ClockError::ClockExhausted));
    assert_eq!(serde_json::to_value(observed).unwrap()["physicalMs"], "12");
}

#[test]
fn version_negotiation_uses_greatest_shared_minor() {
    let local = ProtocolVersionRange {
        min: ProtocolVersion { major: 1, minor: 0 },
        max: ProtocolVersion { major: 1, minor: 3 },
    };
    let peer = ProtocolVersionRange {
        min: ProtocolVersion { major: 1, minor: 1 },
        max: ProtocolVersion { major: 1, minor: 2 },
    };
    assert_eq!(
        negotiate_version(local, peer).unwrap(),
        ProtocolVersion { major: 1, minor: 2 }
    );
    assert!(
        negotiate_version(
            local,
            ProtocolVersionRange {
                min: ProtocolVersion { major: 2, minor: 0 },
                max: ProtocolVersion { major: 2, minor: 0 }
            }
        )
        .is_err()
    );
    let unsupported = ProtocolVersionRange {
        min: ProtocolVersion { major: 2, minor: 0 },
        max: ProtocolVersion { major: 2, minor: 3 },
    };
    assert!(negotiate_version(unsupported, unsupported).is_err());
    let _: AccountId = AccountId::from_str(DEVICE).unwrap();
    let _: RecordId = RecordId::from_str(DEVICE).unwrap();
}

#[test]
fn v1_request_rejects_an_unsupported_protocol_major() {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": DEVICE,
        "protocol": { "major": 2, "minor": 0 },
        "daemonInstanceNonce": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "method": "health",
        "params": {}
    });

    assert!(serde_json::from_value::<JsonRpcRequestV1>(request).is_err());
}
