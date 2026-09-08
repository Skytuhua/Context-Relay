use context_relay_protocol::LocalRequest;
use serde_json::json;

#[test]
fn lifecycle_mutations_require_a_strict_caller_operation_id() {
    for method in ["account_deletion_begin", "account_deletion_cancel"] {
        let mut params = json!({"operationId":"018f22e2-79b0-7cc8-98c4-dc0c0c07a102"});
        if method == "account_deletion_begin" {
            params["confirmation"] = json!("delete");
        }
        let request = json!({"method":method,"params":params});
        let decoded: LocalRequest = serde_json::from_value(request.clone()).unwrap();
        decoded.validate().unwrap();
        let mut missing = request.clone();
        missing["params"]
            .as_object_mut()
            .unwrap()
            .remove("operationId");
        assert!(serde_json::from_value::<LocalRequest>(missing).is_err());
        let mut malformed = request;
        malformed["params"]["operationId"] = json!("not-an-operation");
        assert!(serde_json::from_value::<LocalRequest>(malformed).is_err());
    }
}
