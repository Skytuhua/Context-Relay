mod support;

use context_relay_protocol::{
    ApprovalClass, ExportChunkParams, ExportId, ExportParams, JsonRpcRequestV1, LocalRequest,
    NativePlatform, NetworkEndpoint, NetworkScheme, PairingCode, SetupPlan, WireNativeValue,
};

#[test]
fn local_rpc_rejects_unknown_fields_and_errors_are_stable() {
    let mut value = serde_json::to_value(support::rpc_request()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), true.into());
    assert!(serde_json::from_value::<JsonRpcRequestV1>(value).is_err());
    let error = context_relay_protocol::ClientError::vault_locked();
    assert_eq!(serde_json::to_value(error).unwrap()["code"], "vault_locked");
}

#[test]
fn setup_plan_round_trips_lossless_native_values_and_approval() {
    let mut plan = support::setup_plan();
    plan.executable_path = WireNativeValue {
        platform: NativePlatform::Windows,
        bytes: vec![0x41, 0, 0x3d, 0xd8],
        display: Some("sanitized".into()),
    };
    plan.approval_class = ApprovalClass::Active;
    let without_network = serde_json::to_value(&plan).unwrap();
    plan.network_delta.added.push(NetworkEndpoint {
        scheme: NetworkScheme::Https,
        host: "api.example.com".into(),
        port: 443,
    });
    assert_ne!(serde_json::to_value(&plan).unwrap(), without_network);
    let decoded: SetupPlan = serde_json::from_value(serde_json::to_value(&plan).unwrap()).unwrap();
    assert_eq!(decoded, plan);
    assert_eq!(decoded.executable_path.bytes, vec![0x41, 0, 0x3d, 0xd8]);
}

#[test]
fn export_create_and_chunk_requests_round_trip() {
    use std::str::FromStr;
    let mut request = support::rpc_request();
    request.request = LocalRequest::ExportRecords(ExportParams {
        project_id: None,
        include_archived: true,
    });
    let json = serde_json::to_value(&request).unwrap();
    assert!(matches!(
        serde_json::from_value::<JsonRpcRequestV1>(json)
            .unwrap()
            .request,
        LocalRequest::ExportRecords(_)
    ));

    request.request = LocalRequest::ExportChunk(ExportChunkParams {
        export_id: ExportId::from_str(support::ID).unwrap(),
        chunk_index: 1,
    });
    let json = serde_json::to_value(&request).unwrap();
    assert!(matches!(
        serde_json::from_value::<JsonRpcRequestV1>(json)
            .unwrap()
            .request,
        LocalRequest::ExportChunk(_)
    ));
}

#[test]
fn pairing_codes_and_network_hosts_are_strict() {
    assert!(PairingCode::new("01234-ABCDE".into()).is_ok());
    for invalid in [
        "01234-ABIDE",
        "01234-ABLDE",
        "01234-ABODE",
        "01234-ABUDE",
        "01234-abcde",
        "01234ABCDE",
    ] {
        assert!(PairingCode::new(invalid.into()).is_err(), "{invalid}");
    }
    let long_label = format!("{}.example", "a".repeat(64));
    for host in [
        "-api.example.com",
        "api-.example.com",
        "api..example.com",
        long_label.as_str(),
    ] {
        assert!(
            NetworkEndpoint {
                scheme: NetworkScheme::Https,
                host: host.into(),
                port: 443
            }
            .validate()
            .is_err(),
            "{host}"
        );
    }
}

#[test]
fn json_rpc_errors_use_numeric_codes_and_typed_data() {
    use context_relay_protocol::{
        CONTEXT_RELAY_APPLICATION_ERROR, ClientError, JsonRpcErrorObject,
    };
    let error = JsonRpcErrorObject {
        code: CONTEXT_RELAY_APPLICATION_ERROR,
        message: "vault locked".into(),
        data: ClientError::vault_locked(),
    };
    let value = serde_json::to_value(error).unwrap();
    assert!(value["code"].is_i64());
    assert_eq!(value["data"]["code"], "vault_locked");
}
