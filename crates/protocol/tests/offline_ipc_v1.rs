use context_relay_protocol::{LocalRequest, StatusOutput, SyncState};

#[test]
fn project_upsert_validates_the_project_identity() {
    let valid: LocalRequest = serde_json::from_value(serde_json::json!({
        "method": "project_upsert",
        "params": {
            "project": {
                "projectId": "018f22e2-79b0-7cc8-98c4-dc0c0c07398f",
                "githubRepositoryId": null,
                "gitRemoteFingerprint": null,
                "monorepoSubdirectory": null,
                "name": "Context Relay"
            }
        }
    }))
    .unwrap();
    valid.validate().unwrap();

    let invalid = serde_json::from_value::<LocalRequest>(serde_json::json!({
        "method": "project_upsert",
        "params": {
            "project": {
                "projectId": "018f22e2-79b0-7cc8-98c4-dc0c0c07398f",
                "githubRepositoryId": null,
                "gitRemoteFingerprint": null,
                "monorepoSubdirectory": null,
                "name": ""
            }
        }
    }));
    assert!(invalid.is_err());
}

#[test]
fn offline_is_an_additive_sync_state() {
    let status: StatusOutput = serde_json::from_value(serde_json::json!({
        "protocol": {
            "min": {"major": 1, "minor": 4},
            "max": {"major": 1, "minor": 4}
        },
        "vault": "unlocked",
        "resolvedProject": null,
        "sync": "offline",
        "access": {"mode": "default"}
    }))
    .unwrap();

    assert_eq!(status.sync, SyncState::Offline);
    status.validate().unwrap();
}
