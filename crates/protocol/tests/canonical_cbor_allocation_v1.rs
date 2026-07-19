mod support;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use context_relay_protocol::{
    MAX_CIPHERTEXT_BYTES, ProtocolError, decode_sync_operation_v1, encode_sync_operation_v1,
};

struct TrackingAllocator;

static TRACK_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static LARGEST_ALLOCATION: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn record(size: usize) {
    if TRACK_ALLOCATIONS.load(Ordering::Relaxed) {
        LARGEST_ALLOCATION.fetch_max(size, Ordering::Relaxed);
    }
}

#[test]
fn oversized_ciphertext_is_rejected_before_copying() {
    let mut bytes = encode_sync_operation_v1(&support::sync_operation()).unwrap();
    let marker = [0x0f, 0x43, 0x03, 0x04, 0x05];
    let at = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("ciphertext marker");
    let oversized = MAX_CIPHERTEXT_BYTES + 1;
    let mut replacement = Vec::with_capacity(5 + oversized);
    replacement.push(0x5a);
    replacement.extend_from_slice(&(oversized as u32).to_be_bytes());
    replacement.resize(5 + oversized, 0);
    bytes.splice(at + 1..at + marker.len(), replacement);

    LARGEST_ALLOCATION.store(0, Ordering::Relaxed);
    TRACK_ALLOCATIONS.store(true, Ordering::Relaxed);
    let result = decode_sync_operation_v1(&bytes);
    TRACK_ALLOCATIONS.store(false, Ordering::Relaxed);

    assert_eq!(result, Err(ProtocolError::InvalidCbor("ciphertext")));
    assert!(
        LARGEST_ALLOCATION.load(Ordering::Relaxed) < oversized,
        "decoder copied oversized ciphertext before rejecting it"
    );
}
