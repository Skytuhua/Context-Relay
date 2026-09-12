use context_relay_protocol::LocalRequest;
use serde_json::json;

#[test]
fn prepare_accepts_only_valid_record_writes() {
    let request = json!({"method":"desktop_write_prepare","params":{"write":{
        "method":"memory_create","params":{
            "operationId":"018f6b54-1111-7111-8111-111111111111",
            "scope":{"scope":"global"},"kind":"note","title":"Title",
            "bodyMarkdown":"Body","tags":[]
        }
    }}});
    let decoded: LocalRequest = serde_json::from_value(request.clone()).unwrap();
    decoded.validate().unwrap();
    for method in [
        "shutdown",
        "harness_apply",
        "desktop_write_prepare",
        "account_deletion_begin",
    ] {
        let mut invalid = request.clone();
        invalid["params"]["write"] = json!({"method":method,"params":{}});
        assert!(serde_json::from_value::<LocalRequest>(invalid).is_err());
    }
    let mut invalid = request;
    invalid["params"]["write"]["params"]["bodyMarkdown"] = json!("");
    assert!(
        serde_json::from_value::<LocalRequest>(invalid)
            .unwrap()
            .validate()
            .is_err()
    );
}
