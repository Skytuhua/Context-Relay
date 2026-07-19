use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use context_relay_protocol::{
    BoundedBytes, BoundedCiphertext, ExportEnvelopeV1, MAX_EXTENSION_TEXT_BYTES,
    NamespacedExtension, PackageComponent, PackageManifestV1,
};

const PAYLOAD_BYTES: usize = 256 * 1024;

struct TrackingAllocator;

static TRACK_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static TRACKED_ALLOCATION_SIZE: AtomicUsize = AtomicUsize::new(0);
static MATCHING_ALLOCATION_EVENTS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            record_allocation(new_size);
        }
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn record_allocation(size: usize) {
    if TRACK_ALLOCATIONS.load(Ordering::Relaxed)
        && size == TRACKED_ALLOCATION_SIZE.load(Ordering::Relaxed)
    {
        MATCHING_ALLOCATION_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

fn matching_allocation_events(size: usize, run: impl FnOnce()) -> usize {
    TRACKED_ALLOCATION_SIZE.store(size, Ordering::Relaxed);
    MATCHING_ALLOCATION_EVENTS.store(0, Ordering::Relaxed);
    TRACK_ALLOCATIONS.store(true, Ordering::Relaxed);
    run();
    TRACK_ALLOCATIONS.store(false, Ordering::Relaxed);
    MATCHING_ALLOCATION_EVENTS.load(Ordering::Relaxed)
}

#[test]
fn validated_package_and_export_serialization_do_not_deep_clone_payloads() {
    let mut package: PackageManifestV1 =
        serde_json::from_str(include_str!("fixtures/package-v1-valid.json")).unwrap();
    let PackageComponent::Instruction { body_markdown, .. } = &mut package.components[0] else {
        panic!("fixture instruction component");
    };
    *body_markdown = "x".repeat(PAYLOAD_BYTES);
    package.extensions = Some(std::collections::BTreeMap::from([(
        "com.example".into(),
        NamespacedExtension {
            data: std::collections::BTreeMap::from([(
                "metadata".into(),
                "x".repeat(MAX_EXTENSION_TEXT_BYTES),
            )]),
        },
    )]));
    package.validate().unwrap();

    let mut export: ExportEnvelopeV1 =
        serde_json::from_str(include_str!("fixtures/export-v1-valid.json")).unwrap();
    export.records[0].encrypted_payload = BoundedCiphertext::new(vec![7; PAYLOAD_BYTES]).unwrap();
    export.validate().unwrap();

    let package_allocations = matching_allocation_events(PAYLOAD_BYTES, || {
        serde_json::to_writer(std::io::sink(), &package).unwrap();
    });
    let export_allocations = matching_allocation_events(PAYLOAD_BYTES, || {
        serde_json::to_writer(std::io::sink(), &export).unwrap();
    });
    let extension = package.extensions.as_ref().unwrap()["com.example"].clone();
    let extension_validation_allocations =
        matching_allocation_events(MAX_EXTENSION_TEXT_BYTES, || extension.validate().unwrap());
    let extension_serialization_allocations =
        matching_allocation_events(MAX_EXTENSION_TEXT_BYTES, || {
            serde_json::to_writer(std::io::sink(), &extension).unwrap();
        });

    assert_eq!(
        (package_allocations, export_allocations),
        (0, 0),
        "validated serializers retained deep clones of the large payloads"
    );
    assert_eq!(
        extension_serialization_allocations, extension_validation_allocations,
        "extension serialization allocated a second large value"
    );
}

#[test]
fn bounded_bytes_keep_strict_unpadded_base64url_json() {
    let ciphertext = BoundedCiphertext::new(vec![0xfb, 0xff]).unwrap();
    let bytes = BoundedBytes::new(vec![0xfb, 0xff]).unwrap();

    assert_eq!(serde_json::to_string(&ciphertext).unwrap(), r#""-_8""#);
    assert_eq!(serde_json::to_string(&bytes).unwrap(), r#""-_8""#);
    assert_eq!(
        serde_json::from_str::<BoundedCiphertext>(r#""-_8""#).unwrap(),
        ciphertext
    );
    assert_eq!(
        serde_json::from_str::<BoundedBytes>(r#""-_8""#).unwrap(),
        bytes
    );

    assert!(serde_json::from_str::<BoundedCiphertext>(r#""+/8""#).is_err());
    assert!(serde_json::from_str::<BoundedCiphertext>(r#""-_8=""#).is_err());
    assert!(serde_json::from_str::<BoundedBytes>(r#""-_8=""#).is_err());
    assert!(serde_json::from_str::<BoundedBytes>("[251,255]").is_err());
}
