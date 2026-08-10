#[test]
fn ntfs_security_metadata_uses_the_documented_file_object_apis() {
    let source = include_str!("../src/native_fs/windows.rs");

    for forbidden in [
        concat!("GetKernel", "ObjectSecurity"),
        concat!("SetKernel", "ObjectSecurity"),
    ] {
        assert!(
            !source.contains(forbidden),
            "NTFS metadata must not use {forbidden}"
        );
    }
    for required in ["GetSecurityInfo", "SetSecurityInfo", "SE_FILE_OBJECT"] {
        assert!(
            source.contains(required),
            "NTFS metadata must use the handle-bound {required} contract"
        );
    }
}

#[test]
fn ntfs_restore_preserves_optional_descriptor_components_and_validates_layout() {
    let source = include_str!("../src/native_fs/windows.rs");
    let capture = source
        .split_once("fn security_descriptor")
        .and_then(|(_, suffix)| suffix.split_once("struct LocalSecurityDescriptor"))
        .map(|(capture, _)| capture.split_whitespace().collect::<String>())
        .expect("security descriptor capture source");
    let setter = source
        .split_once("fn set_security_descriptor")
        .and_then(|(_, suffix)| suffix.split_once("fn flush_handle"))
        .map(|(setter, _)| setter.split_whitespace().collect::<String>())
        .expect("security descriptor setter source");

    assert!(
        capture.contains("restorable_security_descriptor(&descriptor)?;"),
        "capture must reject valid but non-round-trippable descriptor state"
    );
    for required in [
        "letparts=restorable_security_descriptor(descriptor)?;",
        "if!owner.is_null(){information|=OWNER_SECURITY_INFORMATION;}",
        "if!group.is_null(){information|=GROUP_SECURITY_INFORMATION;}",
        "ifdacl_present!=0{information|=DACL_SECURITY_INFORMATION;",
    ] {
        assert!(
            setter.contains(required),
            "NTFS restore is missing optional-component contract: {required}"
        );
    }
    let validator = source
        .split_once("fn restorable_security_descriptor")
        .and_then(|(_, suffix)| suffix.split_once("fn flush_handle"))
        .map(|(validator, _)| validator.split_whitespace().collect::<String>())
        .expect("round-trip validator source");
    assert!(validator.contains("owner.is_null()||group.is_null()||dacl_present==0"));
    assert!(validator.contains("validate_self_relative_security_descriptor(descriptor)?;"));
}
