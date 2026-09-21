use context_relay_protocol::{LocalRequest, LocalResult};
use serde_json::json;

#[test]
fn search_progress_requires_the_new_exact_local_wire_version() {
    use context_relay_protocol::{
        PROTOCOL_VERSION, ProtocolVersion, ProtocolVersionRange, negotiate_version,
    };
    let previous = ProtocolVersion {
        major: 1,
        minor: 10,
    };
    assert!(
        negotiate_version(
            ProtocolVersionRange {
                min: previous,
                max: previous
            },
            ProtocolVersionRange {
                min: PROTOCOL_VERSION,
                max: PROTOCOL_VERSION
            },
        )
        .is_err()
    );
}

#[test]
fn search_index_status_and_retry_have_strict_wire_contracts() {
    for method in ["search_index_status", "search_index_retry"] {
        let wire = json!({"method": method, "params": {}});
        let request: LocalRequest = serde_json::from_value(wire.clone()).unwrap();
        request.validate().unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), wire);
    }
    for phase in ["disabled", "preparing", "ready", "failed"] {
        let wire = json!({"kind": "search_index", "data": {"status": {
            "phase": phase, "revision": "18446744073709551615"
        }}});
        let result: LocalResult = serde_json::from_value(wire.clone()).unwrap();
        result.validate().unwrap();
        assert_eq!(serde_json::to_value(result).unwrap(), wire);
    }
    for status in [
        json!({"phase": "ready", "revision": 1}),
        json!({"phase": "ready"}),
        json!({"phase": "ready", "revision": "1", "recordCount": 8}),
        json!({"phase": "unknown", "revision": "1"}),
    ] {
        assert!(
            serde_json::from_value::<LocalResult>(json!({
                "kind": "search_index", "data": {"status": status}
            }))
            .is_err()
        );
    }
}
