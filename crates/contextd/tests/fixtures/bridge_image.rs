//! Shared identification and byte lease for the closed test-only MCP image.
use std::{path::Path, process::Stdio, time::Duration};
use tokio::io::AsyncReadExt as _;
pub(crate) fn hold_fixture_image(path: &Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt as _;
    // Read sharing permits execution; deny write/delete until all round trips finish.
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(path)
        .unwrap()
}

pub(crate) async fn identify_fixture(path: &Path) {
    let mut child = tokio::process::Command::new(path)
        .arg("--fixture-info")
        .env_clear()
        .creation_flags(0x0800_0000)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .take(128)
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        assert_eq!(bytes, b"context-relay-isolated-codex-bridge-fixture-v1\n");
        assert!(child.wait().await.unwrap().success());
    })
    .await
    .expect("test-only bridge identification deadline");
}
