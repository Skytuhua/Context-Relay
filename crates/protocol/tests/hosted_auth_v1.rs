use context_relay_protocol::{HostedAuthStartParams, HostedAuthStatus, LocalRequest, LocalResult};
use serde_json::json;

const ID: &str = "019924bb-5300-7000-8000-000000000001";

#[test]
fn hosted_controls_are_bound_and_do_not_accept_credentials() {
    let params = json!({"operationId":ID,"expectedGeneration":ID});
    let start: HostedAuthStartParams = serde_json::from_value(params.clone()).unwrap();
    let request = LocalRequest::HostedAuthStart(start);
    assert!(request.validate().is_ok());
    for field in [
        "accessToken",
        "refreshToken",
        "authorizationCode",
        "projectUrl",
    ] {
        let mut injected = params.clone();
        injected[field] = json!("unexpected");
        assert!(serde_json::from_value::<HostedAuthStartParams>(injected).is_err());
    }
    assert!(serde_json::from_value::<HostedAuthStartParams>(json!({"operationId":ID})).is_err());
    let status: HostedAuthStatus = serde_json::from_value(
        json!({"generation":ID,"state":{"phase":"signed_out","remoteRevoked":false}}),
    )
    .unwrap();
    let result = LocalResult::HostedAuth { status };
    let wire = serde_json::to_value(&result).unwrap();
    assert_eq!(wire["kind"], "hosted_auth");
    assert!(serde_json::from_value::<LocalResult>(wire).is_ok());
    for state in [
        json!({"phase":"disabled"}),
        json!({"phase":"signing_in"}),
        json!({"phase":"restoring"}),
        json!({"phase":"connected"}),
        json!({"phase":"signing_out"}),
        json!({"phase":"signed_out","remoteRevoked":null}),
        json!({"phase":"failed","reason":"credential_store"}),
    ] {
        assert!(
            serde_json::from_value::<HostedAuthStatus>(json!({"generation":ID,"state":state}))
                .is_ok()
        );
        let mut injected = state;
        injected["accessToken"] = json!("forbidden");
        assert!(
            serde_json::from_value::<HostedAuthStatus>(json!({"generation":ID,"state":injected}))
                .is_err()
        );
    }
    for state in [
        json!({"phase":"signed_out"}),
        json!({"phase":"failed","reason":"provider-secret"}),
    ] {
        assert!(
            serde_json::from_value::<HostedAuthStatus>(json!({"generation":ID,"state":state}))
                .is_err()
        );
    }
    assert!(
        serde_json::from_value::<HostedAuthStartParams>(
            json!({"operationId":ID,"expectedGeneration":"bad"})
        )
        .is_err()
    );
}
