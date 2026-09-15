use context_relay_protocol::{LocalRequest, LocalResult, PROTOCOL_VERSION, ProtocolVersion};
use serde_json::json;

const OPERATION: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074101";
const NEXT_OPERATION: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074102";
const DEVICE: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074103";

#[test]
fn protocol_1_17_requires_one_revocation_operation_id_across_mutation_and_retry_controls() {
    assert_eq!(
        PROTOCOL_VERSION,
        ProtocolVersion {
            major: 1,
            minor: 17
        }
    );
    for (method, params) in [
        (
            "device_revoke",
            json!({"operationId": OPERATION, "deviceId": DEVICE}),
        ),
        (
            "device_revocation_status",
            json!({"operationId": OPERATION}),
        ),
        (
            "device_revocation_cancel",
            json!({"operationId": OPERATION}),
        ),
        ("device_revocation_intents", json!({"after": null})),
    ] {
        let request = json!({"method": method, "params": params});
        let decoded: LocalRequest = serde_json::from_value(request.clone()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), request);
    }
    assert!(
        serde_json::from_value::<LocalRequest>(
            json!({"method":"device_revoke","params":{"deviceId":DEVICE}})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<LocalRequest>(
            json!({"method":"device_revocation_intents","params":{}})
        )
        .is_err()
    );
}

#[test]
fn revocation_status_keeps_send_cancellation_separate_from_strict_outcome() {
    let status = |operation_id, outcome| {
        json!({"operationId":operation_id,"deviceId":DEVICE,"sendCanceled":false,
            "access":"ready","outcome":outcome})
    };
    let accepted = status(
        OPERATION,
        json!({"state":"accepted","acceptedEndpoint":{
            "stateSha256":"12".repeat(32),"controlEpoch":2,"keyEpoch":2
        }}),
    );
    let reply = json!({"kind":"device_revocation","data":{"status":accepted}});
    let decoded: LocalResult = serde_json::from_value(reply.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), reply);

    let page = json!({"kind":"device_revocation_intents","data":{"intents":[
        status(OPERATION,json!({"state":"prepared"})),
        status(NEXT_OPERATION,json!({"state":"unconfirmed"}))
    ]}});
    let decoded: LocalResult = serde_json::from_value(page.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), page);

    let unordered = json!({"kind":"device_revocation_intents","data":{"intents":[
        status(NEXT_OPERATION,json!({"state":"prepared"})),
        status(OPERATION,json!({"state":"prepared"}))
    ]}});
    assert!(serde_json::from_value::<LocalResult>(unordered).is_err());

    let mut unknown = reply;
    unknown["data"]["status"]["outcome"]["receipt"] = json!("must stay native");
    assert!(serde_json::from_value::<LocalResult>(unknown).is_err());
}
