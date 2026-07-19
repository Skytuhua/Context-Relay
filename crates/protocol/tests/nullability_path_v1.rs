use context_relay_protocol::{
    CandidateListParams, ClientError, CompletionEvidenceInput, ExpectedNativeDigest,
    ExportEnvelopeV1, ExportParams, GetOutput, HandoffPayload, HarnessParams, JsonRpcErrorV1,
    ListTasksInput, LocalResult, MemoryUpdateParams, ProbeContext, ProbeReport, ProjectIdentity,
    Provenance, SearchInput, SearchParams, SetupPlan, StatusOutput, SyncOperationV1, TaskEvidence,
    TaskUpsertParams, UpsertTaskInput, WireNativeValue, validate_mcp_fixture,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";

fn fixture(path: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture must exist"))
        .expect("fixture must be valid JSON")
}

fn without(mut value: Value, field: &str) -> Value {
    value
        .as_object_mut()
        .expect("test value must be an object")
        .remove(field);
    value
}

fn assert_required_nullable<T: DeserializeOwned + serde::Serialize>(value: Value, field: &str) {
    assert!(
        serde_json::from_value::<T>(without(value.clone(), field)).is_err(),
        "omitted {field} must fail"
    );
    let mut explicit_null = value;
    explicit_null[field] = Value::Null;
    let decoded = serde_json::from_value::<T>(explicit_null)
        .unwrap_or_else(|_| panic!("explicit null {field} must succeed"));
    let encoded = serde_json::to_value(decoded).expect("required nullable value must serialize");
    assert_eq!(
        encoded.get(field),
        Some(&Value::Null),
        "required nullable {field} must serialize as explicit null"
    );
}

#[test]
fn required_nullable_shared_and_output_fields_distinguish_omission_from_null() {
    let hlc = json!({"physicalMs":"1","logical":0,"node":ID});
    assert_required_nullable::<Provenance>(
        json!({"originDevice":ID,"harness":null,"source":null,"createdHlc":hlc}),
        "harness",
    );
    assert_required_nullable::<Provenance>(
        json!({"originDevice":ID,"harness":null,"source":null,"createdHlc":hlc}),
        "source",
    );
    assert_required_nullable::<TaskEvidence>(
        json!({"summary":"Done","evidenceKind":"result","reference":null,"recordedHlc":hlc}),
        "reference",
    );
    let project = json!({
        "projectId":ID,
        "githubRepositoryId":null,
        "gitRemoteFingerprint":null,
        "monorepoSubdirectory":null,
        "name":"Relay project"
    });
    for field in [
        "githubRepositoryId",
        "gitRemoteFingerprint",
        "monorepoSubdirectory",
    ] {
        assert_required_nullable::<ProjectIdentity>(project.clone(), field);
    }
    assert_required_nullable::<GetOutput>(json!({"record":null}), "record");
    assert_required_nullable::<HandoffPayload>(
        json!({
            "project":null,
            "markdown":"# Handoff",
            "memories":[],
            "decisions":[],
            "tasks":[],
            "instructionRefs":[]
        }),
        "project",
    );
    assert_required_nullable::<StatusOutput>(
        json!({
            "protocol":{"min":{"major":1,"minor":0},"max":{"major":1,"minor":0}},
            "vault":"unlocked",
            "resolvedProject":null,
            "sync":"idle",
            "access":{"mode":"default"}
        }),
        "resolvedProject",
    );
}

#[test]
fn required_nullable_fields_stay_required_through_mcp_outputs_and_exports() {
    let outputs = fixture("tests/fixtures/mcp-output-valid.json");
    for name in [
        "context_relay_get",
        "context_relay_create_handoff",
        "context_relay_status",
    ] {
        assert!(validate_mcp_fixture(name, false, &outputs[name]).is_ok());
    }

    let get = without(outputs["context_relay_get"].clone(), "record");
    assert!(validate_mcp_fixture("context_relay_get", false, &get).is_err());

    let mut handoff = outputs["context_relay_create_handoff"].clone();
    handoff["payload"]
        .as_object_mut()
        .unwrap()
        .remove("project");
    assert!(validate_mcp_fixture("context_relay_create_handoff", false, &handoff).is_err());

    let status = without(outputs["context_relay_status"].clone(), "resolvedProject");
    assert!(validate_mcp_fixture("context_relay_status", false, &status).is_err());

    for field in ["harness", "source"] {
        let mut remember = outputs["context_relay_remember"].clone();
        remember["memory"]["provenance"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(validate_mcp_fixture("context_relay_remember", false, &remember).is_err());
    }

    let mut complete = outputs["context_relay_complete_task"].clone();
    complete["task"]["evidence"][0]
        .as_object_mut()
        .unwrap()
        .remove("reference");
    assert!(validate_mcp_fixture("context_relay_complete_task", false, &complete).is_err());

    let project = json!({
        "projectId":ID,
        "githubRepositoryId":null,
        "gitRemoteFingerprint":null,
        "monorepoSubdirectory":null,
        "name":"Relay project"
    });
    for field in [
        "githubRepositoryId",
        "gitRemoteFingerprint",
        "monorepoSubdirectory",
    ] {
        let mut handoff = outputs["context_relay_create_handoff"].clone();
        handoff["payload"]["project"] = without(project.clone(), field);
        assert!(validate_mcp_fixture("context_relay_create_handoff", false, &handoff).is_err());
    }

    let export = fixture("tests/fixtures/export-v1-valid.json");
    assert!(serde_json::from_value::<ExportEnvelopeV1>(export.clone()).is_ok());
    for field in ["harness", "source"] {
        let mut omitted = export.clone();
        omitted["records"][0]["provenance"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(serde_json::from_value::<ExportEnvelopeV1>(omitted).is_err());
    }
}

#[test]
fn sync_and_local_result_nullable_outputs_require_explicit_null() {
    let runtime = fixture("tests/fixtures/runtime-contracts-v1.json");
    let operation = runtime["syncOperation"].clone();
    assert!(serde_json::from_value::<SyncOperationV1>(operation.clone()).is_ok());
    assert!(
        serde_json::from_value::<SyncOperationV1>(without(operation.clone(), "projectId")).is_err()
    );
    let mut null_project = operation;
    null_project["projectId"] = Value::Null;
    assert!(serde_json::from_value::<SyncOperationV1>(null_project).is_ok());

    for (value, field) in [
        (json!({"kind":"memory","data":{"memory":null}}), "memory"),
        (
            json!({"kind":"recovery","data":{"state":"idle","recoveryPhraseWords":null}}),
            "recoveryPhraseWords",
        ),
        (
            json!({"kind":"account_deletion","data":{"state":"active","purgeDeadline":null,"exportAvailable":false}}),
            "purgeDeadline",
        ),
    ] {
        assert!(serde_json::from_value::<LocalResult>(value.clone()).is_ok());
        let mut omitted = value;
        omitted["data"].as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<LocalResult>(omitted).is_err(),
            "omitted LocalResult.{field} must fail"
        );
    }
}

#[test]
fn strict_local_result_nested_nullable_outputs_require_explicit_null() {
    let report = json!({
        "executable":null,
        "executableSha256":null,
        "harnessVersion":null,
        "installationMethod":"unknown",
        "configRoots":[],
        "activeProfile":null,
        "policyConflicts":[],
        "capability":"missing"
    });
    for field in [
        "executable",
        "executableSha256",
        "harnessVersion",
        "activeProfile",
    ] {
        assert_required_nullable::<ProbeReport>(report.clone(), field);
        let mut local = json!({"kind":"probe","data":{"report":report.clone()}});
        local["data"]["report"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            serde_json::from_value::<LocalResult>(local).is_err(),
            "omitted LocalResult.probe.report.{field} must fail"
        );
    }

    let mut plan = fixture("tests/fixtures/runtime-contracts-v1.json")["setupPlan"].clone();
    plan["expectedNativeDigests"] = json!([{
        "target":{"platform":"macos","bytes":"YQ"},
        "expectedDigest":null
    }]);
    assert!(serde_json::from_value::<SetupPlan>(plan.clone()).is_ok());
    assert_required_nullable::<ExpectedNativeDigest>(
        plan["expectedNativeDigests"][0].clone(),
        "expectedDigest",
    );
    plan["expectedNativeDigests"][0]
        .as_object_mut()
        .unwrap()
        .remove("expectedDigest");
    assert!(serde_json::from_value::<SetupPlan>(plan.clone()).is_err());
    assert!(
        serde_json::from_value::<LocalResult>(json!({"kind":"plan","data":{"plan":plan}})).is_err()
    );
}

#[test]
fn every_other_nullable_protocol_property_remains_required() {
    assert_required_nullable::<ProbeContext>(
        json!({"harness":"codex","requestedProfile":null}),
        "requestedProfile",
    );
    assert_required_nullable::<ClientError>(
        json!({"code":"invalid_request","message":"Bad request","fieldPath":null,"retryable":false}),
        "fieldPath",
    );

    let memory_update = json!({
        "operationId":ID,
        "memoryId":ID,
        "expectedRevision":ID,
        "title":null,
        "bodyMarkdown":null,
        "tags":null
    });
    for field in ["title", "bodyMarkdown", "tags"] {
        assert_required_nullable::<MemoryUpdateParams>(memory_update.clone(), field);
    }
    assert_required_nullable::<CandidateListParams>(json!({"projectId":null}), "projectId");
    assert_required_nullable::<SearchParams>(
        json!({"query":"needle","projectId":null}),
        "projectId",
    );

    let task_upsert = json!({
        "operationId":ID,
        "taskId":null,
        "projectId":ID,
        "title":"Task",
        "bodyMarkdown":"Body",
        "status":"open",
        "expectedRevision":null
    });
    for field in ["taskId", "expectedRevision"] {
        assert_required_nullable::<TaskUpsertParams>(task_upsert.clone(), field);
    }
    assert_required_nullable::<HarnessParams>(
        json!({"harness":"codex","projectId":null}),
        "projectId",
    );
    assert_required_nullable::<ExportParams>(
        json!({"projectId":null,"includeArchived":false}),
        "projectId",
    );
    assert_required_nullable::<JsonRpcErrorV1>(
        json!({
            "jsonrpc":"2.0",
            "id":null,
            "error":{
                "code":-32600,
                "message":"Bad request",
                "data":{
                    "code":"invalid_request",
                    "message":"Bad request",
                    "fieldPath":null,
                    "retryable":false
                }
            }
        }),
        "id",
    );
}

#[test]
fn genuinely_optional_inputs_omit_none_and_accept_omitted_or_null() {
    let cases: Vec<(Value, Value)> = vec![
        (
            json!({"query":"needle"}),
            serde_json::to_value(
                serde_json::from_value::<SearchInput>(json!({"query":"needle"})).unwrap(),
            )
            .unwrap(),
        ),
        (
            json!({}),
            serde_json::to_value(serde_json::from_value::<ListTasksInput>(json!({})).unwrap())
                .unwrap(),
        ),
        (
            json!({"summary":"Done","kind":"result"}),
            serde_json::to_value(
                serde_json::from_value::<CompletionEvidenceInput>(
                    json!({"summary":"Done","kind":"result"}),
                )
                .unwrap(),
            )
            .unwrap(),
        ),
        (
            json!({"platform":"macos","bytes":"YQ"}),
            serde_json::to_value(
                serde_json::from_value::<WireNativeValue>(json!({"platform":"macos","bytes":"YQ"}))
                    .unwrap(),
            )
            .unwrap(),
        ),
    ];
    for (expected, actual) in cases {
        assert_eq!(actual, expected);
    }

    assert!(
        serde_json::from_value::<SearchInput>(json!({"query":"needle","scope":null,"limit":null}))
            .is_ok()
    );
    assert!(serde_json::from_value::<ListTasksInput>(json!({"status":null})).is_ok());
    assert!(
        serde_json::from_value::<CompletionEvidenceInput>(
            json!({"summary":"Done","kind":"result","reference":null})
        )
        .is_ok()
    );
    assert!(
        serde_json::from_value::<WireNativeValue>(
            json!({"platform":"macos","bytes":"YQ","display":null})
        )
        .is_ok()
    );
}

#[test]
fn upsert_task_absent_and_null_are_none_but_uuids_must_be_paired() {
    let base = json!({
        "operationId":ID,
        "title":"Task",
        "bodyMarkdown":"Body",
        "status":"open"
    });
    for task_id in [None, Some(Value::Null)] {
        for expected_revision in [None, Some(Value::Null)] {
            let mut value = base.clone();
            if let Some(task_id) = task_id.clone() {
                value["taskId"] = task_id;
            }
            if let Some(expected_revision) = expected_revision.clone() {
                value["expectedRevision"] = expected_revision;
            }
            assert!(validate_mcp_fixture("context_relay_upsert_task", true, &value).is_ok());
            let encoded =
                serde_json::to_value(serde_json::from_value::<UpsertTaskInput>(value).unwrap())
                    .unwrap();
            assert!(encoded.get("taskId").is_none());
            assert!(encoded.get("expectedRevision").is_none());
        }
    }

    assert!(
        validate_mcp_fixture(
            "context_relay_upsert_task",
            true,
            &json!({
                "operationId":ID,"taskId":ID,"title":"Task","bodyMarkdown":"Body",
                "status":"open","expectedRevision":ID
            }),
        )
        .is_ok()
    );
    for value in [
        json!({"operationId":ID,"taskId":ID,"title":"Task","bodyMarkdown":"Body","status":"open"}),
        json!({"operationId":ID,"taskId":ID,"title":"Task","bodyMarkdown":"Body","status":"open","expectedRevision":null}),
        json!({"operationId":ID,"title":"Task","bodyMarkdown":"Body","status":"open","expectedRevision":ID}),
        json!({"operationId":ID,"taskId":null,"title":"Task","bodyMarkdown":"Body","status":"open","expectedRevision":ID}),
    ] {
        assert!(validate_mcp_fixture("context_relay_upsert_task", true, &value).is_err());
    }
}

#[test]
fn monorepo_subdirectory_rejects_empty_segments_trailing_slashes_and_line_or_c1_controls() {
    for path in [
        "a//b",
        "a/",
        "a\u{007f}b",
        "a\u{0085}b",
        "a\u{009f}b",
        "a\u{2028}b",
        "a\u{2029}b",
    ] {
        let value = json!({
            "projectId":ID,
            "githubRepositoryId":null,
            "gitRemoteFingerprint":null,
            "monorepoSubdirectory":path,
            "name":"Relay project"
        });
        assert!(
            serde_json::from_value::<ProjectIdentity>(value).is_err(),
            "accepted {path:?}"
        );
    }
}
