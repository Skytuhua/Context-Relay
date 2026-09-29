mod support;

use std::str::FromStr;

use context_relay_protocol::{
    DecimalTimestamp, DeviceCertificateId, DeviceId, DeviceState, DeviceSummary, LocalRequest,
    LocalResult, NativePlatform, PairingApprovalInfo, PairingCode, PairingCompletionInfo,
    PairingConfirmParams, PairingDecisionParams, PairingId, PairingIdParams, PairingInviteInfo,
    PairingInviteStatusInfo, PairingJoinParams, PairingRequestInfo, PairingSafetyNumber,
    PairingState, Sha256Digest,
};

#[test]
fn pairing_join_accepts_only_the_code_and_user_visible_name() {
    let params = PairingJoinParams {
        code: PairingCode::new("01234-ABCDE".into()).unwrap(),
        device_name: "new laptop".into(),
    };
    let request = LocalRequest::PairingJoin(params);
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(
        value["params"],
        serde_json::json!({"code":"01234-ABCDE","deviceName":"new laptop"})
    );
    assert_eq!(
        serde_json::from_value::<LocalRequest>(value.clone()).unwrap(),
        request
    );

    let unknown = value;
    for field in [
        "deviceId",
        "platform",
        "requestNonce",
        "signingPublicKey",
        "wrappingPublicKey",
    ] {
        let mut supplied_by_caller = unknown.clone();
        supplied_by_caller["params"]
            .as_object_mut()
            .unwrap()
            .insert(field.into(), true.into());
        assert!(
            serde_json::from_value::<LocalRequest>(supplied_by_caller).is_err(),
            "caller-controlled {field} must be rejected"
        );
    }
}

#[test]
fn pairing_decision_is_bound_to_request_digest() {
    let decision = PairingDecisionParams {
        pairing_id: PairingId::from_str(support::ID).unwrap(),
        request_digest: Sha256Digest([11; 32]),
        approve: true,
    };
    let value = serde_json::to_value(&decision).unwrap();
    assert_eq!(value["requestDigest"], "0b".repeat(32));
    assert_eq!(
        serde_json::from_value::<PairingDecisionParams>(value).unwrap(),
        decision
    );
}

#[test]
fn pairing_confirmation_accepts_only_the_full_safety_number() {
    let pairing_id = PairingId::from_str(support::ID).unwrap();
    let safety_number = PairingSafetyNumber::new("0123-4567-89AB-CDEF-0123".into()).unwrap();
    let request = LocalRequest::PairingConfirm(PairingConfirmParams {
        pairing_id,
        safety_number: safety_number.clone(),
    });
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(
        value["params"],
        serde_json::json!({
            "pairingId": support::ID,
            "safetyNumber": "0123-4567-89AB-CDEF-0123",
        })
    );
    assert_eq!(
        serde_json::from_value::<LocalRequest>(value).unwrap(),
        request
    );
    assert_eq!(
        format!("{safety_number:?}"),
        "PairingSafetyNumber([REDACTED])"
    );

    for invalid in [
        "0123-4567-89AB-CDEF",
        "0123-4567-89AB-CDEF-012",
        "0123-4567-89AB-CDEF-01234",
        "0123-4567-89AB-CDEF-012G",
        "0123-4567-89ab-CDEF-0123",
        "01234567-89AB-CDEF-0123",
    ] {
        assert!(
            PairingSafetyNumber::new(invalid.into()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn device_certificate_id_is_a_distinct_uuid_v7_type() {
    let certificate_id = DeviceCertificateId::from_str(support::ID).unwrap();
    assert_eq!(certificate_id.to_string(), support::ID);
}

#[test]
fn pairing_code_debug_is_redacted_directly_and_when_nested() {
    let code = PairingCode::new("01234-ABCDE".into()).unwrap();
    assert_eq!(format!("{code:?}"), "PairingCode([REDACTED])");

    let result = LocalResult::PairingInvite {
        invite: PairingInviteInfo {
            pairing_id: PairingId::from_str(support::ID).unwrap(),
            code,
            created_at: DecimalTimestamp(1),
            expires_at: DecimalTimestamp(600_001),
        },
        status: PairingState::Pending,
    };
    let nested = format!("{result:?}");
    assert!(!nested.contains("01234-ABCDE"));
    assert!(nested.contains("PairingCode([REDACTED])"));
}

#[test]
fn pairing_id_is_used_by_request_status_and_cancel_dtos() {
    let pairing_id = PairingId::from_str(support::ID).unwrap();
    let invite = PairingInviteInfo {
        pairing_id,
        code: PairingCode::new("01234-ABCDE".into()).unwrap(),
        created_at: DecimalTimestamp(1),
        expires_at: DecimalTimestamp(600_001),
    };
    let result = LocalResult::PairingInvite {
        invite: invite.clone(),
        status: PairingState::Pending,
    };
    let value = serde_json::to_value(&result).unwrap();
    assert_eq!(value["kind"], "pairing_invite");
    assert_eq!(value["data"]["invite"]["code"], "01234-ABCDE");
    assert!(value["data"].get("request").is_none());
    assert_eq!(
        serde_json::from_value::<LocalResult>(value).unwrap(),
        result
    );

    let restored_invite = PairingInviteStatusInfo {
        pairing_id,
        created_at: invite.created_at,
        expires_at: invite.expires_at,
    };
    let restored_value = serde_json::to_value(LocalResult::PairingInviteStatus {
        invite: restored_invite.clone(),
        status: PairingState::Pending,
    })
    .unwrap();
    assert_eq!(restored_value["kind"], "pairing_invite_status");
    assert!(restored_value["data"]["invite"].get("code").is_none());
    assert_eq!(
        serde_json::from_value::<LocalResult>(restored_value).unwrap(),
        LocalResult::PairingInviteStatus {
            invite: restored_invite,
            status: PairingState::Pending,
        }
    );

    let request = PairingRequestInfo {
        pairing_id,
        device_name: "new laptop".into(),
        platform: NativePlatform::Macos,
        requested_at: DecimalTimestamp(7),
        key_fingerprint: Sha256Digest([13; 32]),
        request_digest: Sha256Digest([17; 32]),
    };
    let request_value = serde_json::to_value(LocalResult::PairingRequest {
        request: request.clone(),
        status: PairingState::Pending,
    })
    .unwrap();
    assert_eq!(request_value["kind"], "pairing_request");
    assert!(request_value["data"]["request"].get("code").is_none());

    let approval = PairingApprovalInfo {
        request,
        safety_number: PairingSafetyNumber::new("0123-4567-89AB-CDEF-0123".into()).unwrap(),
    };
    let approval_value = serde_json::to_value(LocalResult::PairingApproval { approval }).unwrap();
    assert_eq!(approval_value["kind"], "pairing_approval");
    assert_eq!(
        approval_value["data"]["approval"]["safetyNumber"],
        "0123-4567-89AB-CDEF-0123"
    );
    let nested = format!(
        "{:?}",
        serde_json::from_value::<LocalResult>(approval_value).unwrap()
    );
    assert!(!nested.contains("0123-4567-89AB-CDEF-0123"));
    assert!(nested.contains("PairingSafetyNumber([REDACTED])"));

    let completion = PairingCompletionInfo {
        pairing_id,
        device: DeviceSummary {
            device_id: DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073990").unwrap(),
            name: "new laptop".into(),
            platform: NativePlatform::Macos,
            state: DeviceState::Active,
            is_current: true,
        },
    };
    let completion_value =
        serde_json::to_value(LocalResult::PairingCompletion { completion }).unwrap();
    assert_eq!(completion_value["kind"], "pairing_completion");
    assert_eq!(
        completion_value["data"]["completion"]["device"]["state"],
        "active"
    );

    assert_eq!(
        serde_json::from_value::<PairingInviteInfo>(serde_json::to_value(&invite).unwrap())
            .unwrap(),
        invite
    );
    for request in [
        LocalRequest::PairingStatus(PairingIdParams { pairing_id }),
        LocalRequest::PairingCancel(PairingIdParams { pairing_id }),
    ] {
        assert_eq!(
            serde_json::to_value(request).unwrap()["params"]["pairingId"],
            support::ID
        );
    }
}
