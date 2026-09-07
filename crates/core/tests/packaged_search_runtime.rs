#![cfg(windows)]

use context_relay_core::search::{EmbeddingPurpose, PinnedModelEmbedder};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn copy_artifacts(source: &Path, destination: &Path, manifest: &str) {
    fs::create_dir_all(destination).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(manifest).unwrap();
    for artifact in manifest["artifacts"].as_array().unwrap() {
        let file = artifact["file"].as_str().unwrap();
        fs::copy(source.join(file), destination.join(file)).unwrap();
    }
}

#[test]
#[ignore = "requires explicitly selected pinned model/runtime assets; run release with static CRT"]
fn packaged_runtime_rejects_tampering_before_loading_and_runs_real_search() {
    run_child("packaged_runtime_child");
}

#[test]
#[ignore = "requires explicitly selected pinned model/runtime assets; run release with static CRT"]
fn packaged_runtime_rejects_a_previously_selected_renamed_runtime() {
    run_child("renamed_runtime_child");
}

#[allow(
    clippy::assertions_on_constants,
    reason = "ignored qualification must compile for ordinary non-static test builds"
)]
fn run_child(test: &str) {
    use std::os::windows::process::CommandExt;
    assert!(
        cfg!(target_feature = "crt-static"),
        "run this test with static CRT"
    );
    let root = tempfile::Builder::new()
        .prefix("context-relay-packaged-search-專案-")
        .tempdir()
        .unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", test, "--nocapture"])
        .env("CONTEXT_RELAY_PACKAGED_TEST_ROOT", root.path())
        .env("ORT_DYLIB_PATH", root.path().join("unrelated-runtime.dll"))
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("PACKAGED_RUNTIME_CHILD_OK"));
    // The child owns native modules/guards until exit. Only then can its parent
    // remove the entire disposable package, including DLLs held against deletion.
    root.close().unwrap();
}

#[test]
#[ignore = "child entry point for prior-runtime qualification"]
fn renamed_runtime_child() {
    let Some(root) = std::env::var_os("CONTEXT_RELAY_PACKAGED_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    copy_artifacts(
        &PathBuf::from(std::env::var_os("CONTEXT_RELAY_MODEL_DIR").unwrap()),
        &root.join("model"),
        include_str!("../models/bge-small-en-v1.5/manifest.json"),
    );
    copy_artifacts(
        &PathBuf::from(std::env::var_os("CONTEXT_RELAY_RUNTIME_DIR").unwrap()),
        &root.join("runtime"),
        include_str!("../models/onnxruntime-win-x64-1.24.2/manifest.json"),
    );
    let renamed = root.join("runtime/renamed-onnxruntime.dll");
    fs::copy(root.join("runtime/onnxruntime.dll"), &renamed).unwrap();
    // Select a real renamed ORT without committing its environment, reproducing
    // init_from's global-library retention independently of our origin marker.
    let _uncommitted = ort::init_from(&renamed).unwrap();
    assert!(PinnedModelEmbedder::load_packaged(&root).is_err());
    println!("PACKAGED_RUNTIME_CHILD_OK");
}

#[test]
#[ignore = "child entry point for packaged runtime qualification"]
fn packaged_runtime_child() {
    let Some(root) = std::env::var_os("CONTEXT_RELAY_PACKAGED_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let model_source = PathBuf::from(
        std::env::var_os("CONTEXT_RELAY_MODEL_DIR").expect("verified model directory"),
    );
    let runtime_source = PathBuf::from(
        std::env::var_os("CONTEXT_RELAY_RUNTIME_DIR").expect("verified runtime directory"),
    );
    copy_artifacts(
        &model_source,
        &root.join("model"),
        include_str!("../models/bge-small-en-v1.5/manifest.json"),
    );
    assert!(
        PinnedModelEmbedder::load_packaged(&root).is_err(),
        "a package missing its runtime must fail before native model loading"
    );
    copy_artifacts(
        &runtime_source,
        &root.join("runtime"),
        include_str!("../models/onnxruntime-win-x64-1.24.2/manifest.json"),
    );
    let damaged = root.join("runtime/msvcp140_1.dll");
    let good = fs::read(&damaged).unwrap();
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 1;
    fs::write(&damaged, bad).unwrap();
    assert!(
        PinnedModelEmbedder::load_packaged(&root).is_err(),
        "a tampered dependency must not be executed"
    );
    fs::write(&damaged, good).unwrap();
    let mut model = PinnedModelEmbedder::load_packaged(&root).unwrap();
    assert!(
        fs::OpenOptions::new().write(true).open(&damaged).is_err(),
        "loaded native files must remain pinned against replacement"
    );
    assert!(
        fs::rename(root.join("runtime"), root.join("replaced-runtime")).is_err(),
        "the native directory must remain pinned"
    );
    let query = model
        .embed(EmbeddingPurpose::Query, "automobile maintenance")
        .unwrap();
    let relevant = model
        .embed(
            EmbeddingPurpose::Passage,
            "Keep the car engine serviced and replace its oil regularly.",
        )
        .unwrap();
    let unrelated = model
        .embed(
            EmbeddingPurpose::Passage,
            "Whisk eggs and flour to bake a cake.",
        )
        .unwrap();
    let score = |passage: &context_relay_core::search::Embedding384| -> f32 {
        query
            .as_slice()
            .iter()
            .zip(passage.as_slice())
            .map(|(a, b)| a * b)
            .sum()
    };
    assert!(score(&relevant) > score(&unrelated));
    println!("PACKAGED_RUNTIME_CHILD_OK");
}
