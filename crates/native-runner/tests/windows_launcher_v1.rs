#![cfg(windows)]

extern crate context_relay_native_runner as context_relay_windows_launcher_harness;

#[path = "windows-launcher-harness/tests/policy.rs"]
mod policy;

#[path = "windows-launcher-harness/tests/profile_native.rs"]
mod profile_native;
