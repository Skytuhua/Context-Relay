use context_relay_protocol::LocalRequest;
#[test]
fn connection_check_start_requires_saved_note_binding() {
    let parsed = serde_json::from_value::<LocalRequest>(
        serde_json::json!({"method":"connection_check_start","params":{"selection":{"harness":"codex","projectId":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f","hermesProfile":null},"memoryId":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f","expectedRevision":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f"}}),
    );
    assert!(
        parsed.is_ok(),
        "fresh saved-note checks must be supported: {parsed:?}"
    );
}

#[test]
fn connection_check_rejects_global_and_extra_input() {
    let mut value = serde_json::json!({"method":"connection_check_start","params":{"selection":{"harness":"codex","projectId":null,"hermesProfile":null},"memoryId":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f","expectedRevision":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f"}});
    let request: LocalRequest = serde_json::from_value(value.clone()).unwrap();
    assert!(request.validate().is_err());
    value["params"]["secret"] = serde_json::json!("not-accepted");
    assert!(serde_json::from_value::<LocalRequest>(value).is_err());
}

#[test]
fn launch_info_resolves_selection_without_accepting_caller_paths() {
    let value = serde_json::json!({"method":"harness_launch_info","params":{"harness":"codex","projectId":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f","hermesProfile":null}});
    let request = serde_json::from_value::<LocalRequest>(value);
    assert!(
        request.is_ok(),
        "launch information must be resolved from saved selection: {request:?}"
    );
}

#[test]
fn connection_check_status_is_closed_and_cannot_claim_verification_without_timestamp() {
    use context_relay_protocol::LocalResult;
    let id = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
    let mut value = serde_json::json!({"kind":"connection_check","data":{"status":{"checkId":id,"selection":{"harness":"codex","projectId":id,"hermesProfile":null},"memoryId":id,"expectedRevision":id,"phase":"waiting","expiresInSeconds":300,"verifiedAt":null}}});
    assert!(serde_json::from_value::<LocalResult>(value.clone()).is_ok());
    value["data"]["status"]["phase"] = serde_json::json!("verified");
    assert!(serde_json::from_value::<LocalResult>(value.clone()).is_err());
    value["data"]["status"]["verifiedAt"] = serde_json::json!("1");
    assert!(serde_json::from_value::<LocalResult>(value.clone()).is_ok());
    value["data"]["status"]["expiresInSeconds"] = serde_json::json!(301);
    assert!(serde_json::from_value::<LocalResult>(value).is_err());
}

#[test]
fn connection_check_protocol_requires_coordinated_desktop_daemon_upgrade() {
    use context_relay_protocol::{
        PROTOCOL_VERSION, ProtocolVersion, ProtocolVersionRange, negotiate_version,
    };
    let previous = ProtocolVersionRange {
        min: ProtocolVersion {
            major: 1,
            minor: 11,
        },
        max: ProtocolVersion {
            major: 1,
            minor: 11,
        },
    };
    let current = ProtocolVersionRange {
        min: PROTOCOL_VERSION,
        max: PROTOCOL_VERSION,
    };
    assert!(negotiate_version(previous, current).is_err());
    assert_eq!(
        negotiate_version(current, current).unwrap(),
        PROTOCOL_VERSION
    );
}
