mod support;

use context_relay_protocol::{
    ApprovalClass, ExportChunkParams, ExportId, ExportParams, JsonRpcRequestV1, JsonRpcSuccessV1,
    JsonRpcVersion, LocalRequest, LocalResult, NativePlatform, NetworkEndpoint, NetworkScheme,
    PairingCode, ProjectIdentity, SetupPlan, WireNativeValue,
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

#[test]
fn project_identity_serde_boundary_rejects_invalid_repository_metadata() {
    let valid = serde_json::json!({
        "projectId": support::ID,
        "githubRepositoryId": "1",
        "gitRemoteFingerprint": "0101010101010101010101010101010101010101010101010101010101010101",
        "monorepoSubdirectory": "crates/protocol",
        "name": "Project"
    });
    let project: ProjectIdentity = serde_json::from_value(valid.clone()).unwrap();
    assert_eq!(serde_json::to_value(&project).unwrap(), valid);

    for path in [
        "",
        "../outside",
        "a/../b",
        "/absolute",
        "C:/drive",
        "a//b",
        "a/./b",
        r"a\b",
    ] {
        let mut invalid = valid.clone();
        invalid["monorepoSubdirectory"] = path.into();
        assert!(
            serde_json::from_value::<ProjectIdentity>(invalid).is_err(),
            "{path}"
        );
    }

    for (field, value) in [
        ("githubRepositoryId", serde_json::json!("0")),
        ("gitRemoteFingerprint", serde_json::json!("00")),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(serde_json::from_value::<ProjectIdentity>(invalid).is_err());
    }

    let mut unknown = valid;
    unknown["ignored"] = true.into();
    assert!(serde_json::from_value::<ProjectIdentity>(unknown).is_err());

    let mut invalid = project;
    invalid.monorepo_subdirectory = Some("../outside".into());
    assert!(serde_json::to_value(invalid).is_err());
}

#[test]
fn local_success_serde_boundary_is_strict_and_recursive() {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": support::ID,
        "result": {
            "kind": "projects",
            "data": {
                "projects": [{
                    "projectId": support::ID,
                    "githubRepositoryId": null,
                    "gitRemoteFingerprint": null,
                    "monorepoSubdirectory": "crates/protocol",
                    "name": "Project"
                }]
            }
        }
    });
    let decoded: JsonRpcSuccessV1 = serde_json::from_value(response.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), response);

    let mut invalid_path = response.clone();
    invalid_path["result"]["data"]["projects"][0]["monorepoSubdirectory"] = "../outside".into();
    assert!(serde_json::from_value::<JsonRpcSuccessV1>(invalid_path).is_err());

    let mut blank_memory = serde_json::json!({
        "jsonrpc": "2.0",
        "id": support::ID,
        "result": {
            "kind": "memory",
            "data": {"memory": serde_json::to_value(support::memory_record()).unwrap()}
        }
    });
    blank_memory["result"]["data"]["memory"]["title"] = " ".into();
    assert!(serde_json::from_value::<JsonRpcSuccessV1>(blank_memory).is_err());

    let mut envelope_unknown = response.clone();
    envelope_unknown["ignored"] = true.into();
    assert!(serde_json::from_value::<JsonRpcSuccessV1>(envelope_unknown).is_err());

    let mut variant_unknown = response.clone();
    variant_unknown["result"]["data"]["ignored"] = true.into();
    assert!(serde_json::from_value::<JsonRpcSuccessV1>(variant_unknown).is_err());

    let mut nested_unknown = response;
    nested_unknown["result"]["data"]["projects"][0]["ignored"] = true.into();
    assert!(serde_json::from_value::<JsonRpcSuccessV1>(nested_unknown).is_err());

    let mut memory = support::memory_record();
    memory.title = " ".into();
    let invalid = JsonRpcSuccessV1 {
        jsonrpc: JsonRpcVersion::V2,
        id: support::ID.parse().unwrap(),
        result: LocalResult::Memory {
            memory: Some(memory),
        },
    };
    assert!(serde_json::to_value(invalid).is_err());
}

#[test]
fn every_local_result_variant_validates_its_nested_domain_content() {
    let memory = serde_json::to_value(support::memory_record()).unwrap();
    let mut blank_memory = memory.clone();
    blank_memory["title"] = " ".into();
    let task = serde_json::json!({
        "id": support::ID,
        "projectId": support::ID,
        "title": " ",
        "bodyMarkdown": "Body",
        "status": "open",
        "evidence": [],
        "revision": support::ID
    });
    let digest = "0101010101010101010101010101010101010101010101010101010101010101";

    for result in [
        serde_json::json!({"kind": "health", "data": {"protocol": {"major": 2, "minor": 0}, "vaultLocked": false}}),
        serde_json::json!({"kind": "memories", "data": {"memories": [blank_memory.clone()]}}),
        serde_json::json!({"kind": "candidates", "data": {"candidates": [{
            "id": support::ID,
            "proposedMemory": memory,
            "evidenceSummary": " ",
            "sourceHarness": "codex",
            "state": "pending"
        }]}}),
        serde_json::json!({"kind": "tasks", "data": {"tasks": [task]}}),
        serde_json::json!({"kind": "handoff", "data": {
            "handoffId": support::ID,
            "payload": {
                "project": null,
                "markdown": " ",
                "memories": [],
                "decisions": [],
                "tasks": [],
                "instructionRefs": []
            }
        }}),
        serde_json::json!({"kind": "status", "data": {"status": {
            "protocol": {"min": {"major": 1, "minor": 2}, "max": {"major": 1, "minor": 1}},
            "vault": "locked",
            "resolvedProject": null,
            "sync": "idle",
            "access": {"mode": "default"}
        }}}),
        serde_json::json!({"kind": "devices", "data": {"devices": [{
            "deviceId": support::ID,
            "name": " ",
            "platform": "windows",
            "state": "active",
            "isCurrent": true
        }]}}),
        serde_json::json!({"kind": "pairing", "data": {
            "request": {
                "pairingId": support::ID,
                "code": "01234-ABCDE",
                "deviceName": " ",
                "platform": "windows",
                "requestedAt": "1",
                "keyFingerprint": digest,
                "requestDigest": digest
            },
            "status": "pending"
        }}),
        serde_json::json!({"kind": "export", "data": {"payload": {
            "exportId": support::ID,
            "chunkIndex": 0,
            "chunkCount": 0,
            "chunk": "",
            "chunkDigest": digest,
            "totalBytes": "0",
            "recordCount": 0
        }}}),
    ] {
        assert!(
            serde_json::from_value::<LocalResult>(result.clone()).is_err(),
            "{result}"
        );
    }
}

fn valid_handoff_result() -> serde_json::Value {
    serde_json::json!({
        "kind": "handoff",
        "data": {
            "handoffId": support::ID,
            "payload": {
                "project": null,
                "markdown": "# Handoff",
                "memories": [],
                "decisions": [],
                "tasks": [],
                "instructionRefs": []
            }
        }
    })
}

#[test]
fn local_handoff_rejects_non_decision_records_in_decisions() {
    let mut result = valid_handoff_result();
    result["data"]["payload"]["decisions"] = serde_json::json!([support::memory_record()]);
    assert!(serde_json::from_value::<LocalResult>(result).is_err());
}

#[test]
fn local_handoff_rejects_duplicate_instruction_refs() {
    let mut result = valid_handoff_result();
    result["data"]["payload"]["instructionRefs"] = serde_json::json!([support::ID, support::ID]);
    assert!(serde_json::from_value::<LocalResult>(result).is_err());
}

#[test]
fn local_handoff_rejects_over_limit_record_collections() {
    let mut result = valid_handoff_result();
    result["data"]["payload"]["memories"] =
        serde_json::Value::Array(vec![
            serde_json::to_value(support::memory_record()).unwrap();
            context_relay_protocol::MAX_EVIDENCE_ITEMS + 1
        ]);
    assert!(serde_json::from_value::<LocalResult>(result).is_err());
}
