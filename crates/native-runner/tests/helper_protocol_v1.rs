use std::io::{self, Cursor, Read, Write};

use context_relay_native_runner::{
    ClosureMaterial, ContentFrame, FailureCode, HelperRunRequest, MAX_WIRE_PAYLOAD_BYTES,
    RunDisposition, RunLimits, RunRequest, RunResponse, RunStats, SidecarCommand, StagePath,
    closure_material_digest, read_helper_request, read_run_request, read_run_response,
    read_run_response_for, write_helper_request, write_run_request, write_run_response,
    write_run_response_for,
};
use minicbor::Encoder;

fn path(value: &str) -> StagePath {
    StagePath::try_from(value).unwrap()
}

fn request() -> RunRequest {
    RunRequest::new(
        [0x11; 16],
        [0x22; 32],
        SidecarCommand::OsemgrepScanPackage,
        vec![
            ContentFrame::new(
                path("input/semgrep-target/main.rs"),
                b"fn main() {}".to_vec(),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn encoded_request() -> Vec<u8> {
    let mut bytes = Vec::new();
    write_run_request(&mut bytes, &request()).unwrap();
    bytes
}

#[test]
fn semgrep_has_a_bounded_startup_envelope_beyond_the_other_sidecars() {
    assert_eq!(
        RunLimits::for_command(&SidecarCommand::GitleaksScanPackage).timeout_ms(),
        30_000
    );
    assert_eq!(
        RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage).timeout_ms(),
        90_000
    );
}

#[test]
fn request_round_trip_handles_partial_reads_and_writes() {
    let expected = request();
    let encoded = encoded_request();
    let mut reader = OneByteReader(Cursor::new(encoded.clone()));
    assert_eq!(read_run_request(&mut reader).unwrap(), expected);

    let mut writer = OneByteWriter::default();
    write_run_request(&mut writer, &expected).unwrap();
    assert_eq!(writer.0, encoded);
}

#[test]
fn framing_rejects_invalid_header_length_and_trailing_bytes() {
    let valid = encoded_request();
    for offset in [0_usize, 4, 5, 6, 7] {
        let mut malformed = valid.clone();
        malformed[offset] ^= 0x7f;
        assert!(read_run_request(&mut Cursor::new(malformed)).is_err());
    }
    assert!(read_run_response(&mut Cursor::new(valid.clone())).is_err());

    let mut oversized = valid.clone();
    oversized[8..12].copy_from_slice(&((MAX_WIRE_PAYLOAD_BYTES as u32) + 1).to_be_bytes());
    oversized.truncate(12);
    assert!(read_run_request(&mut Cursor::new(oversized)).is_err());

    let mut trailing = valid;
    let payload_length = u32::from_be_bytes(trailing[8..12].try_into().unwrap()) + 1;
    trailing[8..12].copy_from_slice(&payload_length.to_be_bytes());
    trailing.push(0);
    assert!(read_run_request(&mut Cursor::new(trailing)).is_err());
}

#[test]
fn protocol_rejects_noncanonical_keys_and_content_digest_changes() {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).unwrap();
    encoder.u8(1).unwrap().bytes(&[0x22; 32]).unwrap();
    encoder.u8(0).unwrap().bytes(&[0x11; 16]).unwrap();
    encoder.u8(2).unwrap().map(1).unwrap();
    encoder.u8(0).unwrap().u8(2).unwrap();
    encoder.u8(3).unwrap().array(0).unwrap();
    let noncanonical = wire_frame(1, encoder.into_writer());
    assert!(read_run_request(&mut Cursor::new(noncanonical)).is_err());

    let mut changed = encoded_request();
    *changed.last_mut().unwrap() ^= 1;
    assert!(read_run_request(&mut Cursor::new(changed)).is_err());
}

#[test]
fn requests_canonicalize_paths_and_reject_duplicates() {
    let command = SidecarCommand::OsemgrepScanPackage;
    let request = RunRequest::new(
        [1; 16],
        [2; 32],
        command.clone(),
        vec![
            ContentFrame::new(path("input/semgrep-target/z"), vec![]).unwrap(),
            ContentFrame::new(path("input/semgrep-target/a"), vec![]).unwrap(),
        ],
    )
    .unwrap();
    assert_eq!(
        request.inputs()[0].path().as_str(),
        "input/semgrep-target/a"
    );

    assert!(
        RunRequest::new(
            [1; 16],
            [2; 32],
            command,
            vec![
                ContentFrame::new(path("input/semgrep-target/a"), vec![]).unwrap(),
                ContentFrame::new(path("input/semgrep-target/a"), vec![]).unwrap(),
            ],
        )
        .is_err()
    );
}

#[test]
fn response_limits_and_schema_exclude_secret_diagnostics() {
    let limits = RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage)
        .tightened(2, 4, 5)
        .unwrap();
    assert!(
        RunResponse::completed(
            RunDisposition::Clean,
            vec![ContentFrame::new(path("output/a"), vec![0; 5]).unwrap()],
            RunStats::new(1, 5, 1),
            limits,
        )
        .is_err()
    );
    assert!(
        RunResponse::completed(
            RunDisposition::Clean,
            vec![
                ContentFrame::new(path("output/a"), vec![0; 3]).unwrap(),
                ContentFrame::new(path("output/b"), vec![0; 3]).unwrap(),
            ],
            RunStats::new(2, 6, 1),
            limits,
        )
        .is_err()
    );

    let response = RunResponse::failed(FailureCode::InvalidOutput);
    let mut encoded = Vec::new();
    write_run_response(&mut encoded, &response).unwrap();
    assert_eq!(
        read_run_response(&mut Cursor::new(encoded)).unwrap(),
        response
    );

    let mut encoder = Encoder::new(Vec::new());
    encoder.map(3).unwrap();
    encoder.u8(0).unwrap().u8(1).unwrap();
    encoder.u8(1).unwrap().u8(0).unwrap();
    encoder
        .u8(2)
        .unwrap()
        .str("secret-bearing diagnostic")
        .unwrap();
    assert!(read_run_response(&mut Cursor::new(wire_frame(2, encoder.into_writer()))).is_err());
}

#[test]
fn response_is_bound_to_the_exact_request_nonce_and_closure() {
    let expected_request = request();
    let response = RunResponse::failed(FailureCode::InvalidOutput);
    let mut encoded = Vec::new();
    write_run_response_for(&mut encoded, &expected_request, &response).unwrap();
    assert_eq!(
        read_run_response_for(&mut Cursor::new(encoded.clone()), &expected_request).unwrap(),
        response
    );

    let wrong_nonce = RunRequest::new(
        [0x12; 16],
        *expected_request.expected_closure_sha256(),
        expected_request.command().clone(),
        expected_request.inputs().to_vec(),
    )
    .unwrap();
    assert!(read_run_response_for(&mut Cursor::new(encoded.clone()), &wrong_nonce).is_err());

    let wrong_closure = RunRequest::new(
        *expected_request.nonce(),
        [0x23; 32],
        expected_request.command().clone(),
        expected_request.inputs().to_vec(),
    )
    .unwrap();
    assert!(read_run_response_for(&mut Cursor::new(encoded), &wrong_closure).is_err());
}

#[test]
fn helper_request_binds_a_bounded_multifile_runtime_closure() {
    let materials = vec![
        ClosureMaterial::new(path("bin/osemgrep.exe"), 3, [0x31; 32], true).unwrap(),
        ClosureMaterial::new(path("bin/libtree-sitter.dll"), 5, [0x32; 32], false).unwrap(),
    ];
    let request = RunRequest::new(
        [0x41; 16],
        closure_material_digest(&materials).unwrap(),
        SidecarCommand::OsemgrepScanPackage,
        vec![ContentFrame::new(path("input/semgrep-target/METADATA"), b"safe".to_vec()).unwrap()],
    )
    .unwrap();
    let expected = HelperRunRequest::new(request, materials).unwrap();
    let mut encoded = Vec::new();
    write_helper_request(&mut encoded, &expected).unwrap();
    assert_eq!(
        read_helper_request(&mut OneByteReader(Cursor::new(encoded))).unwrap(),
        expected
    );
}

#[test]
fn helper_request_separately_binds_a_resigned_runtime_to_the_source_request() {
    let source = vec![ClosureMaterial::new(path("bin/rulesync"), 3, [0x31; 32], true).unwrap()];
    let runtime = vec![ClosureMaterial::new(path("bin/rulesync"), 5, [0x32; 32], true).unwrap()];
    let request = RunRequest::new(
        [0x41; 16],
        closure_material_digest(&source).unwrap(),
        SidecarCommand::RuleSyncGenerate {
            target: context_relay_native_runner::RuleSyncTarget::ClaudeCode,
            features: context_relay_native_runner::RuleSyncFeatures::new(&[
                context_relay_native_runner::RuleSyncFeature::Rules,
            ])
            .unwrap(),
        },
        vec![ContentFrame::new(path("input/.rulesync/rules/probe.md"), b"safe".to_vec()).unwrap()],
    )
    .unwrap();
    let expected = HelperRunRequest::for_resigned_runtime(request, runtime).unwrap();
    assert_ne!(
        expected.runtime_closure_sha256(),
        expected.request().expected_closure_sha256()
    );
    let mut encoded = Vec::new();
    write_helper_request(&mut encoded, &expected).unwrap();
    assert_eq!(
        read_helper_request(&mut OneByteReader(Cursor::new(encoded))).unwrap(),
        expected
    );
}

#[test]
fn helper_request_rejects_unbound_or_python_semgrep_closure_members() {
    let native = ClosureMaterial::new(path("bin/osemgrep.exe"), 3, [0x31; 32], true).unwrap();
    let python = ClosureMaterial::new(
        path("python/site-packages/runtime.dll"),
        5,
        [0x32; 32],
        false,
    )
    .unwrap();
    let request = RunRequest::new(
        [0x41; 16],
        closure_material_digest(std::slice::from_ref(&native)).unwrap(),
        SidecarCommand::OsemgrepScanPackage,
        vec![ContentFrame::new(path("input/semgrep-target/METADATA"), b"safe".to_vec()).unwrap()],
    )
    .unwrap();
    assert!(HelperRunRequest::new(request.clone(), vec![native.clone(), python]).is_err());
    assert!(
        HelperRunRequest::new(
            RunRequest::new(
                *request.nonce(),
                [0x99; 32],
                request.command().clone(),
                request.inputs().to_vec(),
            )
            .unwrap(),
            vec![native],
        )
        .is_err()
    );
}

#[test]
fn response_rejects_reports_over_the_dedicated_eight_mibibyte_cap() {
    let reports = vec![
        ContentFrame::new(path("reports/a.json"), vec![0; 5 * 1024 * 1024]).unwrap(),
        ContentFrame::new(path("reports/b.json"), vec![0; 5 * 1024 * 1024]).unwrap(),
    ];
    let limits = RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage);

    assert!(
        RunResponse::completed(
            RunDisposition::Clean,
            reports.clone(),
            RunStats::new(1, 1, 1),
            limits,
        )
        .is_err()
    );

    let unchecked = RunResponse::Completed {
        disposition: RunDisposition::Clean,
        outputs: reports,
        stats: RunStats::new(1, 1, 1),
    };
    let mut encoded = Vec::new();
    write_run_response(&mut encoded, &unchecked).unwrap();
    assert!(read_run_response(&mut Cursor::new(encoded)).is_err());
}

fn wire_frame(kind: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut frame = b"CRNR".to_vec();
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.push(kind);
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

struct OneByteReader<R>(R);

impl<R: Read> Read for OneByteReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = buffer.len().min(1);
        self.0.read(&mut buffer[..length])
    }
}

#[derive(Default)]
struct OneByteWriter(Vec<u8>);

impl Write for OneByteWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let length = buffer.len().min(1);
        self.0.extend_from_slice(&buffer[..length]);
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
