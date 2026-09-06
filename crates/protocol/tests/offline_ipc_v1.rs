use context_relay_protocol::{LocalRequest, StatusOutput, SyncState};

#[test]
fn project_registration_requires_identity_and_path_in_one_strict_request() {
    let request = serde_json::json!({
        "method": "project_register",
        "params": {
            "project": {
                "projectId": "018f22e2-79b0-7cc8-98c4-dc0c0c07398f",
                "githubRepositoryId": null, "gitRemoteFingerprint": null,
                "monorepoSubdirectory": null, "name": "Research"
            },
            "path": {"platform": "windows", "bytes": "QwA6AFwAUgA", "display": "C:\\R"}
        }
    });
    serde_json::from_value::<LocalRequest>(request.clone())
        .unwrap()
        .validate()
        .unwrap();
    for field in ["project", "path"] {
        let mut missing = request.clone();
        missing["params"].as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<LocalRequest>(missing).is_err());
    }
    let mut unknown = request.clone();
    unknown["params"]["unreviewed"] = true.into();
    assert!(serde_json::from_value::<LocalRequest>(unknown).is_err());
    let mut invalid = request;
    invalid["params"]["path"]["bytes"] = "AA".into();
    assert!(serde_json::from_value::<LocalRequest>(invalid).is_err());
}

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
            "min": {"major": 1, "minor": 10},
            "max": {"major": 1, "minor": 10}
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
