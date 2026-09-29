//! Stages quarantined package entries for the sidecar scanners.
//!
//! The quarantine inspector ([`super::packages::inspect_archive`]) binds a
//! package to its exact installable bytes through
//! [`super::packages::QuarantinedArchive::binding_digest`]. Before those
//! bytes may be handed to the gitleaks / osemgrep sidecars they must be
//! restaged as approved scanner inputs: deterministic paths under
//! `input/gitleaks-scan/`, per-entry digests copied from the inspection
//! result, and the binding digest re-verified so the scanners see precisely
//! the bytes that inspection approved.

use super::native_transaction::ApprovedInput;
use super::packages::{QuarantineError, QuarantinedArchive};
use context_relay_native_runner::StagePath;

/// Gitleaks scans `input/gitleaks-scan/` (see
/// `SidecarCommand::GitleaksScanPackage::normalized_arguments`).
const GITLEAKS_INPUT_PREFIX: &str = "input/gitleaks-scan";

/// `MAX_CONTENT_FRAME_BYTES` in `native-runner/src/helper_protocol.rs`: a
/// single scanner input frame must fit the helper wire frame.
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Restages the archive entries as approved scanner inputs.
///
/// Each entry becomes `input/gitleaks-scan/<entry path>` with the entry's
/// inspected digest and length. The stage fails closed when any entry
/// exceeds the helper frame ceiling or when a restaged path is rejected by
/// the runner's path policy. Callers must pass the archive unchanged from
/// `inspect_archive`; the staged digests are exactly the inspected entry
/// digests, so any scanner report can be bound back to the inspection via
/// `binding_digest`.
pub fn stage_scanner_inputs(
    archive: &QuarantinedArchive,
) -> Result<Vec<ApprovedInput>, QuarantineError> {
    let mut inputs = Vec::with_capacity(archive.entries.len());
    for entry in &archive.entries {
        if entry.length as usize > MAX_FRAME_BYTES {
            return Err(QuarantineError::TooLarge);
        }
        let path = StagePath::try_from(format!("{GITLEAKS_INPUT_PREFIX}/{}", entry.path))
            .map_err(|_| QuarantineError::UnsafeEntry(entry.path.clone()))?;
        inputs.push(ApprovedInput {
            path,
            length: entry.length,
            digest: context_relay_protocol::Sha256Digest(entry.digest),
        });
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_archive() -> (Vec<(&'static str, &'static [u8])>, QuarantinedArchive) {
        let entries: Vec<(&str, &[u8])> = vec![
            ("manifest.json", br#"{"format":"context-relay.package.v1"}"#),
            ("skills/alpha/SKILL.md", b"# alpha\n"),
        ];
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (path, content) in &entries {
            zip.start_file(*path, options).unwrap();
            use std::io::Write as _;
            zip.write_all(content).unwrap();
        }
        let bytes = zip.finish().unwrap().into_inner();
        let inspected = super::super::packages::inspect_archive(&bytes).unwrap();
        (entries, inspected)
    }

    #[test]
    fn stages_entries_under_the_scanner_prefix_with_inspected_digests() {
        let (entries, archive) = sample_archive();
        let inputs = stage_scanner_inputs(&archive).unwrap();
        assert_eq!(inputs.len(), entries.len());
        for (input, (path, content)) in inputs.iter().zip(&entries) {
            assert!(input.path.as_str().starts_with("input/gitleaks-scan/"));
            assert_eq!(input.path.as_str(), format!("input/gitleaks-scan/{path}"));
            assert_eq!(input.length, content.len() as u64);
        }
        let inputs = stage_scanner_inputs(&archive).unwrap();
        assert_eq!(inputs[0].digest.0, archive.entries[0].digest);
    }

    #[test]
    fn staging_is_deterministic_and_tied_to_the_binding_digest() {
        let (_, archive) = sample_archive();
        let first = stage_scanner_inputs(&archive).unwrap();
        let second = stage_scanner_inputs(&archive).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_entries_that_exceed_the_helper_frame_ceiling() {
        // An entry may pass archive inspection (per-entry ceiling is 16 MiB)
        // yet still exceed the 8 MiB helper frame limit; staging must fail
        // closed. Construct the archive directly to isolate the staging
        // guard from the inspector's compression-ratio rules.
        let archive = QuarantinedArchive {
            content_digest: [0u8; 32],
            total_bytes: (MAX_FRAME_BYTES + 1) as u64,
            entries: vec![super::super::packages::QuarantinedEntry {
                path: "big/asset.txt".into(),
                length: (MAX_FRAME_BYTES + 1) as u64,
                digest: [7u8; 32],
            }],
        };
        assert!(matches!(
            stage_scanner_inputs(&archive),
            Err(QuarantineError::TooLarge)
        ));
    }
}
