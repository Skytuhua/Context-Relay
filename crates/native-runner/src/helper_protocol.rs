use std::io::{Read, Write};

use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::{
    RuleSyncFeatures, RuleSyncTarget, RunnerError, RuntimeTarget, SidecarCommand, StagePath,
    VerifiedClosure, validate_path_set,
};

const MAGIC: [u8; 4] = *b"CRNR";
const VERSION: u16 = 1;
const REQUEST_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const HEADER_BYTES: usize = 12;
const MAX_CONTENT_FRAMES: usize = 1_024;
const MAX_CONTENT_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOTAL_CONTENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
const MAX_RUNTIME_MS: u32 = 30_000;
const MAX_CLOSURE_MATERIALS: usize = 256;
const MAX_CLOSURE_MATERIAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CLOSURE_BYTES: u64 = 768 * 1024 * 1024;
pub const MAX_WIRE_PAYLOAD_BYTES: usize = 68 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentFrame {
    path: StagePath,
    sha256: [u8; 32],
    bytes: Vec<u8>,
}

impl ContentFrame {
    pub fn new(path: StagePath, bytes: Vec<u8>) -> Result<Self, RunnerError> {
        if bytes.len() > MAX_CONTENT_FRAME_BYTES {
            return Err(RunnerError::LimitExceeded);
        }
        let sha256 = Sha256::digest(&bytes).into();
        Ok(Self {
            path,
            sha256,
            bytes,
        })
    }

    pub fn path(&self) -> &StagePath {
        &self.path
    }

    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunLimits {
    max_files: usize,
    max_file_bytes: usize,
    max_total_bytes: usize,
    max_report_bytes: usize,
    timeout_ms: u32,
}

impl RunLimits {
    pub const fn for_command(_command: &SidecarCommand) -> Self {
        Self {
            max_files: MAX_CONTENT_FRAMES,
            max_file_bytes: MAX_CONTENT_FRAME_BYTES,
            max_total_bytes: MAX_TOTAL_CONTENT_BYTES,
            max_report_bytes: MAX_REPORT_BYTES,
            timeout_ms: MAX_RUNTIME_MS,
        }
    }

    pub fn tightened(
        self,
        max_files: usize,
        max_file_bytes: usize,
        max_total_bytes: usize,
    ) -> Result<Self, RunnerError> {
        if max_files == 0
            || max_file_bytes == 0
            || max_total_bytes == 0
            || max_files > self.max_files
            || max_file_bytes > self.max_file_bytes
            || max_total_bytes > self.max_total_bytes
        {
            return Err(RunnerError::LimitExceeded);
        }
        Ok(Self {
            max_files,
            max_file_bytes,
            max_total_bytes,
            ..self
        })
    }

    pub const fn max_files(self) -> usize {
        self.max_files
    }

    pub const fn max_file_bytes(self) -> usize {
        self.max_file_bytes
    }

    pub const fn max_total_bytes(self) -> usize {
        self.max_total_bytes
    }

    pub const fn max_report_bytes(self) -> usize {
        self.max_report_bytes
    }

    pub const fn timeout_ms(self) -> u32 {
        self.timeout_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRequest {
    nonce: [u8; 16],
    expected_closure_sha256: [u8; 32],
    command: SidecarCommand,
    inputs: Vec<ContentFrame>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureMaterial {
    path: StagePath,
    size: u64,
    sha256: [u8; 32],
    executable: bool,
}

impl ClosureMaterial {
    pub fn new(
        path: StagePath,
        size: u64,
        sha256: [u8; 32],
        executable: bool,
    ) -> Result<Self, RunnerError> {
        if size == 0 || size > MAX_CLOSURE_MATERIAL_BYTES {
            return Err(RunnerError::LimitExceeded);
        }
        Ok(Self {
            path,
            size,
            sha256,
            executable,
        })
    }

    pub fn path(&self) -> &StagePath {
        &self.path
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub const fn executable(&self) -> bool {
        self.executable
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperRunRequest {
    request: RunRequest,
    runtime_closure_sha256: [u8; 32],
    closure: Vec<ClosureMaterial>,
}

impl HelperRunRequest {
    pub fn new(request: RunRequest, closure: Vec<ClosureMaterial>) -> Result<Self, RunnerError> {
        let helper_request = Self::for_resigned_runtime(request, closure)?;
        if &helper_request.runtime_closure_sha256
            != helper_request.request.expected_closure_sha256()
        {
            return Err(RunnerError::ClosureMismatch);
        }
        Ok(helper_request)
    }

    pub fn for_resigned_runtime(
        request: RunRequest,
        mut closure: Vec<ClosureMaterial>,
    ) -> Result<Self, RunnerError> {
        normalize_closure_materials(&mut closure)?;
        let runtime_closure_sha256 = closure_material_digest(&closure)?;
        let executable = closure
            .iter()
            .filter(|material| material.executable)
            .collect::<Vec<_>>();
        if executable.len() != 1
            || !expected_executable_name(
                request.command(),
                executable[0]
                    .path
                    .as_str()
                    .rsplit('/')
                    .next()
                    .ok_or(RunnerError::InvalidFrame)?,
            )
            || (matches!(request.command(), SidecarCommand::OsemgrepScanPackage)
                && closure.iter().any(forbidden_semgrep_material))
        {
            return Err(RunnerError::InvalidFrame);
        }
        Ok(Self {
            request,
            runtime_closure_sha256,
            closure,
        })
    }

    pub fn from_verified(
        request: &RunRequest,
        closure: &VerifiedClosure,
    ) -> Result<Self, RunnerError> {
        if closure.sidecar() != request.command().sidecar()
            || closure.closure_sha256() != request.expected_closure_sha256()
        {
            return Err(RunnerError::ClosureMismatch);
        }
        let materials = closure
            .materials()
            .iter()
            .map(|material| {
                ClosureMaterial::new(
                    material.path().clone(),
                    material.size(),
                    *material.sha256(),
                    material.executable(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(request.clone(), materials)
    }

    pub const fn request(&self) -> &RunRequest {
        &self.request
    }

    pub const fn runtime_closure_sha256(&self) -> &[u8; 32] {
        &self.runtime_closure_sha256
    }

    pub fn closure(&self) -> &[ClosureMaterial] {
        &self.closure
    }
}

pub fn closure_material_digest(materials: &[ClosureMaterial]) -> Result<[u8; 32], RunnerError> {
    let mut materials = materials.to_vec();
    normalize_closure_materials(&mut materials)?;
    let mut hasher = Sha256::new();
    hasher.update(b"context-relay/sidecar-closure/v1\0");
    for material in materials {
        hasher.update(material.path.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(material.size.to_be_bytes());
        hasher.update(material.sha256);
        hasher.update([u8::from(material.executable)]);
    }
    Ok(hasher.finalize().into())
}

impl RunRequest {
    pub fn new(
        nonce: [u8; 16],
        expected_closure_sha256: [u8; 32],
        command: SidecarCommand,
        mut inputs: Vec<ContentFrame>,
    ) -> Result<Self, RunnerError> {
        command.validate()?;
        let limits = RunLimits::for_command(&command);
        validate_frames(&mut inputs, limits)?;
        for input in &inputs {
            command.validate_input(input.path(), input.bytes())?;
        }
        command.validate_inputs(&inputs)?;
        Ok(Self {
            nonce,
            expected_closure_sha256,
            command,
            inputs,
        })
    }

    pub const fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }

    pub const fn expected_closure_sha256(&self) -> &[u8; 32] {
        &self.expected_closure_sha256
    }

    pub const fn command(&self) -> &SidecarCommand {
        &self.command
    }

    pub fn inputs(&self) -> &[ContentFrame] {
        &self.inputs
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunDisposition {
    Generated,
    Clean,
    Findings(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunStats {
    scanned_files: u32,
    scanned_bytes: u64,
    duration_ms: u32,
}

impl RunStats {
    pub const fn new(scanned_files: u32, scanned_bytes: u64, duration_ms: u32) -> Self {
        Self {
            scanned_files,
            scanned_bytes,
            duration_ms,
        }
    }

    pub const fn scanned_files(self) -> u32 {
        self.scanned_files
    }

    pub const fn scanned_bytes(self) -> u64 {
        self.scanned_bytes
    }

    pub const fn duration_ms(self) -> u32 {
        self.duration_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureCode {
    InvalidOutput,
    ToolFailed,
    TimedOut,
    LimitExceeded,
    ClosureMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunResponse {
    Completed {
        disposition: RunDisposition,
        outputs: Vec<ContentFrame>,
        stats: RunStats,
    },
    Failed(FailureCode),
}

impl RunResponse {
    pub fn completed(
        disposition: RunDisposition,
        mut outputs: Vec<ContentFrame>,
        stats: RunStats,
        limits: RunLimits,
    ) -> Result<Self, RunnerError> {
        validate_frames(&mut outputs, limits)?;
        if !matches!(disposition, RunDisposition::Generated) {
            let report_bytes = outputs.iter().try_fold(0_usize, |total, frame| {
                total
                    .checked_add(frame.bytes.len())
                    .ok_or(RunnerError::LimitExceeded)
            })?;
            if report_bytes > limits.max_report_bytes {
                return Err(RunnerError::LimitExceeded);
            }
        }
        if stats.duration_ms > limits.timeout_ms {
            return Err(RunnerError::LimitExceeded);
        }
        Ok(Self::Completed {
            disposition,
            outputs,
            stats,
        })
    }

    pub const fn failed(code: FailureCode) -> Self {
        Self::Failed(code)
    }
}

fn validate_frames(frames: &mut [ContentFrame], limits: RunLimits) -> Result<(), RunnerError> {
    if frames.len() > limits.max_files {
        return Err(RunnerError::LimitExceeded);
    }
    let mut total = 0_usize;
    for frame in frames.iter() {
        if frame.bytes.len() > limits.max_file_bytes {
            return Err(RunnerError::LimitExceeded);
        }
        total = total
            .checked_add(frame.bytes.len())
            .ok_or(RunnerError::LimitExceeded)?;
        if total > limits.max_total_bytes {
            return Err(RunnerError::LimitExceeded);
        }
    }
    frames.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    if frames.windows(2).any(|pair| pair[0].path == pair[1].path) {
        return Err(RunnerError::InvalidFrame);
    }
    let paths = frames
        .iter()
        .map(|frame| frame.path.clone())
        .collect::<Vec<_>>();
    validate_path_set(RuntimeTarget::WindowsX86_64, &paths)?;
    validate_path_set(RuntimeTarget::MacosArm64, &paths)
}

fn normalize_closure_materials(materials: &mut [ClosureMaterial]) -> Result<(), RunnerError> {
    if materials.is_empty() || materials.len() > MAX_CLOSURE_MATERIALS {
        return Err(RunnerError::LimitExceeded);
    }
    let total = materials.iter().try_fold(0_u64, |total, material| {
        total
            .checked_add(material.size)
            .ok_or(RunnerError::LimitExceeded)
    })?;
    if total > MAX_CLOSURE_BYTES {
        return Err(RunnerError::LimitExceeded);
    }
    materials.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    if materials
        .windows(2)
        .any(|pair| pair[0].path == pair[1].path)
    {
        return Err(RunnerError::InvalidFrame);
    }
    let paths = materials
        .iter()
        .map(|material| material.path.clone())
        .collect::<Vec<_>>();
    validate_path_set(RuntimeTarget::WindowsX86_64, &paths)?;
    validate_path_set(RuntimeTarget::MacosArm64, &paths)
}

fn expected_executable_name(command: &SidecarCommand, name: &str) -> bool {
    let stem = match command {
        SidecarCommand::RuleSyncGenerate { .. } => "rulesync",
        SidecarCommand::GitleaksScanPackage => "gitleaks",
        SidecarCommand::OsemgrepScanPackage => "osemgrep",
    };
    name == stem || name == format!("{stem}.exe")
}

fn forbidden_semgrep_material(material: &ClosureMaterial) -> bool {
    material.path.as_str().split('/').any(|component| {
        let normalized = component
            .nfkc()
            .flat_map(char::to_lowercase)
            .collect::<String>();
        [
            "python",
            "pysemgrep",
            "site-packages",
            "wheelhouse",
            "semgrep-core",
        ]
        .iter()
        .any(|forbidden| normalized.contains(forbidden))
    })
}

pub fn write_run_request<W: Write>(
    writer: &mut W,
    request: &RunRequest,
) -> Result<(), RunnerError> {
    write_message(writer, REQUEST_KIND, &encode_request_payload(request)?)
}

pub fn read_run_request<R: Read>(reader: &mut R) -> Result<RunRequest, RunnerError> {
    let payload = read_message(reader, REQUEST_KIND)?;
    decode_request_payload(&payload)
}

pub fn write_helper_request<W: Write>(
    writer: &mut W,
    request: &HelperRunRequest,
) -> Result<(), RunnerError> {
    write_message(
        writer,
        REQUEST_KIND,
        &encode_helper_request_payload(request)?,
    )
}

pub fn read_helper_request<R: Read>(reader: &mut R) -> Result<HelperRunRequest, RunnerError> {
    let payload = read_message(reader, REQUEST_KIND)?;
    decode_helper_request_payload(&payload)
}

pub fn write_run_response<W: Write>(
    writer: &mut W,
    response: &RunResponse,
) -> Result<(), RunnerError> {
    write_message(writer, RESPONSE_KIND, &encode_response_payload(response)?)
}

pub fn read_run_response<R: Read>(reader: &mut R) -> Result<RunResponse, RunnerError> {
    let payload = read_message(reader, RESPONSE_KIND)?;
    decode_response_payload(&payload)
}

pub fn write_run_response_for<W: Write>(
    writer: &mut W,
    request: &RunRequest,
    response: &RunResponse,
) -> Result<(), RunnerError> {
    write_message(
        writer,
        RESPONSE_KIND,
        &encode_bound_response_payload(request, response)?,
    )
}

pub fn read_run_response_for<R: Read>(
    reader: &mut R,
    request: &RunRequest,
) -> Result<RunResponse, RunnerError> {
    let payload = read_message(reader, RESPONSE_KIND)?;
    decode_bound_response_payload(&payload, request)
}

fn write_message<W: Write>(writer: &mut W, kind: u8, payload: &[u8]) -> Result<(), RunnerError> {
    if payload.is_empty() || payload.len() > MAX_WIRE_PAYLOAD_BYTES {
        return Err(RunnerError::FrameTooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| RunnerError::FrameTooLarge)?;
    let mut header = [0_u8; HEADER_BYTES];
    header[..4].copy_from_slice(&MAGIC);
    header[4..6].copy_from_slice(&VERSION.to_be_bytes());
    header[6] = kind;
    header[8..12].copy_from_slice(&length.to_be_bytes());
    writer.write_all(&header).map_err(|_| RunnerError::Io)?;
    writer.write_all(payload).map_err(|_| RunnerError::Io)
}

fn read_message<R: Read>(reader: &mut R, expected_kind: u8) -> Result<Vec<u8>, RunnerError> {
    let mut header = [0_u8; HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .map_err(|_| RunnerError::Io)?;
    if header[..4] != MAGIC
        || u16::from_be_bytes(
            header[4..6]
                .try_into()
                .map_err(|_| RunnerError::InvalidFrame)?,
        ) != VERSION
        || header[6] != expected_kind
        || header[7] != 0
    {
        return Err(RunnerError::InvalidFrame);
    }
    let length = u32::from_be_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| RunnerError::InvalidFrame)?,
    ) as usize;
    if length == 0 || length > MAX_WIRE_PAYLOAD_BYTES {
        return Err(RunnerError::FrameTooLarge);
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|_| RunnerError::Io)?;
    Ok(payload)
}

fn encode_request_payload(request: &RunRequest) -> Result<Vec<u8>, RunnerError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).map_err(enc)?;
    key(&mut encoder, 0)?;
    encoder.bytes(&request.nonce).map_err(enc)?;
    key(&mut encoder, 1)?;
    encoder
        .bytes(&request.expected_closure_sha256)
        .map_err(enc)?;
    key(&mut encoder, 2)?;
    encode_command(&mut encoder, &request.command)?;
    key(&mut encoder, 3)?;
    encode_content_frames(&mut encoder, &request.inputs)?;
    Ok(encoder.into_writer())
}

fn decode_request_payload(payload: &[u8]) -> Result<RunRequest, RunnerError> {
    let mut decoder = Decoder::new(payload);
    require_map(&mut decoder, 4)?;
    expect_key(&mut decoder, 0)?;
    let nonce = read_fixed::<16>(&mut decoder)?;
    expect_key(&mut decoder, 1)?;
    let closure = read_fixed::<32>(&mut decoder)?;
    expect_key(&mut decoder, 2)?;
    let command = decode_command(&mut decoder)?;
    expect_key(&mut decoder, 3)?;
    let inputs = decode_content_frames(&mut decoder)?;
    if decoder.position() != payload.len() {
        return Err(RunnerError::InvalidFrame);
    }
    let request = RunRequest::new(nonce, closure, command, inputs)?;
    if encode_request_payload(&request)? != payload {
        return Err(RunnerError::InvalidFrame);
    }
    Ok(request)
}

fn encode_helper_request_payload(request: &HelperRunRequest) -> Result<Vec<u8>, RunnerError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6).map_err(enc)?;
    key(&mut encoder, 0)?;
    encoder.bytes(request.request.nonce()).map_err(enc)?;
    key(&mut encoder, 1)?;
    encoder
        .bytes(request.request.expected_closure_sha256())
        .map_err(enc)?;
    key(&mut encoder, 2)?;
    encode_command(&mut encoder, request.request.command())?;
    key(&mut encoder, 3)?;
    encode_content_frames(&mut encoder, request.request.inputs())?;
    key(&mut encoder, 4)?;
    encode_closure_materials(&mut encoder, request.closure())?;
    key(&mut encoder, 5)?;
    encoder
        .bytes(request.runtime_closure_sha256())
        .map_err(enc)?;
    Ok(encoder.into_writer())
}

fn decode_helper_request_payload(payload: &[u8]) -> Result<HelperRunRequest, RunnerError> {
    let mut decoder = Decoder::new(payload);
    require_map(&mut decoder, 6)?;
    expect_key(&mut decoder, 0)?;
    let nonce = read_fixed::<16>(&mut decoder)?;
    expect_key(&mut decoder, 1)?;
    let closure_sha256 = read_fixed::<32>(&mut decoder)?;
    expect_key(&mut decoder, 2)?;
    let command = decode_command(&mut decoder)?;
    expect_key(&mut decoder, 3)?;
    let inputs = decode_content_frames(&mut decoder)?;
    expect_key(&mut decoder, 4)?;
    let closure = decode_closure_materials(&mut decoder)?;
    expect_key(&mut decoder, 5)?;
    let runtime_closure_sha256 = read_fixed::<32>(&mut decoder)?;
    if decoder.position() != payload.len() {
        return Err(RunnerError::InvalidFrame);
    }
    let request = HelperRunRequest::for_resigned_runtime(
        RunRequest::new(nonce, closure_sha256, command, inputs)?,
        closure,
    )?;
    if request.runtime_closure_sha256 != runtime_closure_sha256 {
        return Err(RunnerError::ClosureMismatch);
    }
    if encode_helper_request_payload(&request)? != payload {
        return Err(RunnerError::InvalidFrame);
    }
    Ok(request)
}

fn encode_closure_materials(
    encoder: &mut Encoder<Vec<u8>>,
    materials: &[ClosureMaterial],
) -> Result<(), RunnerError> {
    encoder
        .array(u64::try_from(materials.len()).map_err(|_| RunnerError::LimitExceeded)?)
        .map_err(enc)?;
    for material in materials {
        encoder.map(4).map_err(enc)?;
        key(encoder, 0)?;
        encoder.str(material.path.as_str()).map_err(enc)?;
        key(encoder, 1)?;
        encoder.u64(material.size).map_err(enc)?;
        key(encoder, 2)?;
        encoder.bytes(&material.sha256).map_err(enc)?;
        key(encoder, 3)?;
        encoder.bool(material.executable).map_err(enc)?;
    }
    Ok(())
}

fn decode_closure_materials(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<ClosureMaterial>, RunnerError> {
    let count = decoder
        .array()
        .map_err(dec)?
        .ok_or(RunnerError::InvalidFrame)?;
    let count = usize::try_from(count).map_err(|_| RunnerError::LimitExceeded)?;
    if count == 0 || count > MAX_CLOSURE_MATERIALS {
        return Err(RunnerError::LimitExceeded);
    }
    let mut materials = Vec::with_capacity(count);
    for _ in 0..count {
        require_map(decoder, 4)?;
        expect_key(decoder, 0)?;
        let path = StagePath::try_from(decoder.str().map_err(dec)?)?;
        expect_key(decoder, 1)?;
        let size = decoder.u64().map_err(dec)?;
        expect_key(decoder, 2)?;
        let sha256 = read_fixed::<32>(decoder)?;
        expect_key(decoder, 3)?;
        let executable = decoder.bool().map_err(dec)?;
        materials.push(ClosureMaterial::new(path, size, sha256, executable)?);
    }
    Ok(materials)
}

fn encode_response_payload(response: &RunResponse) -> Result<Vec<u8>, RunnerError> {
    let mut encoder = Encoder::new(Vec::new());
    match response {
        RunResponse::Completed {
            disposition,
            outputs,
            stats,
        } => {
            encoder.map(4).map_err(enc)?;
            key(&mut encoder, 0)?;
            encoder.u8(0).map_err(enc)?;
            key(&mut encoder, 1)?;
            encode_disposition(&mut encoder, *disposition)?;
            key(&mut encoder, 2)?;
            encode_content_frames(&mut encoder, outputs)?;
            key(&mut encoder, 3)?;
            encode_stats(&mut encoder, *stats)?;
        }
        RunResponse::Failed(code) => {
            encoder.map(2).map_err(enc)?;
            key(&mut encoder, 0)?;
            encoder.u8(1).map_err(enc)?;
            key(&mut encoder, 1)?;
            encoder.u8(failure_code(*code)).map_err(enc)?;
        }
    }
    Ok(encoder.into_writer())
}

fn decode_response_payload(payload: &[u8]) -> Result<RunResponse, RunnerError> {
    let mut decoder = Decoder::new(payload);
    let size = decoder
        .map()
        .map_err(dec)?
        .ok_or(RunnerError::InvalidFrame)?;
    expect_key(&mut decoder, 0)?;
    let response = match decoder.u8().map_err(dec)? {
        0 if size == 4 => {
            expect_key(&mut decoder, 1)?;
            let disposition = decode_disposition(&mut decoder)?;
            expect_key(&mut decoder, 2)?;
            let outputs = decode_content_frames(&mut decoder)?;
            expect_key(&mut decoder, 3)?;
            let stats = decode_stats(&mut decoder)?;
            RunResponse::completed(
                disposition,
                outputs,
                stats,
                RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage),
            )?
        }
        1 if size == 2 => {
            expect_key(&mut decoder, 1)?;
            RunResponse::Failed(decode_failure_code(decoder.u8().map_err(dec)?)?)
        }
        _ => return Err(RunnerError::InvalidFrame),
    };
    if decoder.position() != payload.len() || encode_response_payload(&response)? != payload {
        return Err(RunnerError::InvalidFrame);
    }
    Ok(response)
}

fn encode_bound_response_payload(
    request: &RunRequest,
    response: &RunResponse,
) -> Result<Vec<u8>, RunnerError> {
    let mut encoder = Encoder::new(Vec::new());
    let (size, kind) = match response {
        RunResponse::Completed { .. } => (6, 0),
        RunResponse::Failed(_) => (4, 1),
    };
    encoder.map(size).map_err(enc)?;
    key(&mut encoder, 0)?;
    encoder.u8(kind).map_err(enc)?;
    key(&mut encoder, 1)?;
    encoder.bytes(request.nonce()).map_err(enc)?;
    key(&mut encoder, 2)?;
    encoder
        .bytes(request.expected_closure_sha256())
        .map_err(enc)?;
    match response {
        RunResponse::Completed {
            disposition,
            outputs,
            stats,
        } => {
            key(&mut encoder, 3)?;
            encode_disposition(&mut encoder, *disposition)?;
            key(&mut encoder, 4)?;
            encode_content_frames(&mut encoder, outputs)?;
            key(&mut encoder, 5)?;
            encode_stats(&mut encoder, *stats)?;
        }
        RunResponse::Failed(code) => {
            key(&mut encoder, 3)?;
            encoder.u8(failure_code(*code)).map_err(enc)?;
        }
    }
    Ok(encoder.into_writer())
}

fn decode_bound_response_payload(
    payload: &[u8],
    request: &RunRequest,
) -> Result<RunResponse, RunnerError> {
    let mut decoder = Decoder::new(payload);
    let size = decoder
        .map()
        .map_err(dec)?
        .ok_or(RunnerError::InvalidFrame)?;
    expect_key(&mut decoder, 0)?;
    let kind = decoder.u8().map_err(dec)?;
    if !matches!((kind, size), (0, 6) | (1, 4)) {
        return Err(RunnerError::InvalidFrame);
    }
    expect_key(&mut decoder, 1)?;
    if &read_fixed::<16>(&mut decoder)? != request.nonce() {
        return Err(RunnerError::InvalidFrame);
    }
    expect_key(&mut decoder, 2)?;
    if &read_fixed::<32>(&mut decoder)? != request.expected_closure_sha256() {
        return Err(RunnerError::InvalidFrame);
    }
    let response = match kind {
        0 => {
            expect_key(&mut decoder, 3)?;
            let disposition = decode_disposition(&mut decoder)?;
            expect_key(&mut decoder, 4)?;
            let outputs = decode_content_frames(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let stats = decode_stats(&mut decoder)?;
            RunResponse::completed(
                disposition,
                outputs,
                stats,
                RunLimits::for_command(request.command()),
            )?
        }
        1 => {
            expect_key(&mut decoder, 3)?;
            RunResponse::Failed(decode_failure_code(decoder.u8().map_err(dec)?)?)
        }
        _ => return Err(RunnerError::InvalidFrame),
    };
    if decoder.position() != payload.len()
        || encode_bound_response_payload(request, &response)? != payload
    {
        return Err(RunnerError::InvalidFrame);
    }
    Ok(response)
}

fn encode_command(
    encoder: &mut Encoder<Vec<u8>>,
    command: &SidecarCommand,
) -> Result<(), RunnerError> {
    match command {
        SidecarCommand::RuleSyncGenerate { target, features } => {
            encoder.map(3).map_err(enc)?;
            key(encoder, 0)?;
            encoder.u8(0).map_err(enc)?;
            key(encoder, 1)?;
            encoder.u8(target.code()).map_err(enc)?;
            key(encoder, 2)?;
            encoder.u16(features.bits()).map_err(enc)?;
        }
        SidecarCommand::GitleaksScanPackage => {
            encoder.map(1).map_err(enc)?;
            key(encoder, 0)?;
            encoder.u8(1).map_err(enc)?;
        }
        SidecarCommand::OsemgrepScanPackage => {
            encoder.map(1).map_err(enc)?;
            key(encoder, 0)?;
            encoder.u8(2).map_err(enc)?;
        }
    }
    Ok(())
}

fn decode_command(decoder: &mut Decoder<'_>) -> Result<SidecarCommand, RunnerError> {
    let size = decoder
        .map()
        .map_err(dec)?
        .ok_or(RunnerError::InvalidFrame)?;
    expect_key(decoder, 0)?;
    match decoder.u8().map_err(dec)? {
        0 if size == 3 => {
            expect_key(decoder, 1)?;
            let target = RuleSyncTarget::from_code(decoder.u8().map_err(dec)?)?;
            expect_key(decoder, 2)?;
            let features = RuleSyncFeatures::from_bits(decoder.u16().map_err(dec)?)?;
            Ok(SidecarCommand::RuleSyncGenerate { target, features })
        }
        1 if size == 1 => Ok(SidecarCommand::GitleaksScanPackage),
        2 if size == 1 => Ok(SidecarCommand::OsemgrepScanPackage),
        _ => Err(RunnerError::InvalidFrame),
    }
}

fn encode_content_frames(
    encoder: &mut Encoder<Vec<u8>>,
    frames: &[ContentFrame],
) -> Result<(), RunnerError> {
    encoder
        .array(u64::try_from(frames.len()).map_err(|_| RunnerError::LimitExceeded)?)
        .map_err(enc)?;
    for frame in frames {
        encoder.map(3).map_err(enc)?;
        key(encoder, 0)?;
        encoder.str(frame.path.as_str()).map_err(enc)?;
        key(encoder, 1)?;
        encoder.bytes(&frame.sha256).map_err(enc)?;
        key(encoder, 2)?;
        encoder.bytes(&frame.bytes).map_err(enc)?;
    }
    Ok(())
}

fn decode_content_frames(decoder: &mut Decoder<'_>) -> Result<Vec<ContentFrame>, RunnerError> {
    let length = decoder
        .array()
        .map_err(dec)?
        .ok_or(RunnerError::InvalidFrame)?;
    if length > MAX_CONTENT_FRAMES as u64 {
        return Err(RunnerError::LimitExceeded);
    }
    let mut frames = Vec::with_capacity(length as usize);
    for _ in 0..length {
        require_map(decoder, 3)?;
        expect_key(decoder, 0)?;
        let path = StagePath::try_from(decoder.str().map_err(dec)?)?;
        expect_key(decoder, 1)?;
        let claimed_digest = read_fixed::<32>(decoder)?;
        expect_key(decoder, 2)?;
        let bytes = decoder.bytes().map_err(dec)?;
        if bytes.len() > MAX_CONTENT_FRAME_BYTES {
            return Err(RunnerError::LimitExceeded);
        }
        let frame = ContentFrame::new(path, bytes.to_vec())?;
        if frame.sha256 != claimed_digest {
            return Err(RunnerError::DigestMismatch);
        }
        frames.push(frame);
    }
    Ok(frames)
}

fn encode_disposition(
    encoder: &mut Encoder<Vec<u8>>,
    disposition: RunDisposition,
) -> Result<(), RunnerError> {
    encoder.map(2).map_err(enc)?;
    key(encoder, 0)?;
    let (kind, findings) = match disposition {
        RunDisposition::Generated => (0, 0),
        RunDisposition::Clean => (1, 0),
        RunDisposition::Findings(count) => (2, count),
    };
    encoder.u8(kind).map_err(enc)?;
    key(encoder, 1)?;
    encoder.u32(findings).map_err(enc)?;
    Ok(())
}

fn decode_disposition(decoder: &mut Decoder<'_>) -> Result<RunDisposition, RunnerError> {
    require_map(decoder, 2)?;
    expect_key(decoder, 0)?;
    let kind = decoder.u8().map_err(dec)?;
    expect_key(decoder, 1)?;
    let findings = decoder.u32().map_err(dec)?;
    match (kind, findings) {
        (0, 0) => Ok(RunDisposition::Generated),
        (1, 0) => Ok(RunDisposition::Clean),
        (2, count) if count > 0 => Ok(RunDisposition::Findings(count)),
        _ => Err(RunnerError::InvalidFrame),
    }
}

fn encode_stats(encoder: &mut Encoder<Vec<u8>>, stats: RunStats) -> Result<(), RunnerError> {
    encoder.map(3).map_err(enc)?;
    key(encoder, 0)?;
    encoder.u32(stats.scanned_files).map_err(enc)?;
    key(encoder, 1)?;
    encoder.u64(stats.scanned_bytes).map_err(enc)?;
    key(encoder, 2)?;
    encoder.u32(stats.duration_ms).map_err(enc)?;
    Ok(())
}

fn decode_stats(decoder: &mut Decoder<'_>) -> Result<RunStats, RunnerError> {
    require_map(decoder, 3)?;
    expect_key(decoder, 0)?;
    let scanned_files = decoder.u32().map_err(dec)?;
    expect_key(decoder, 1)?;
    let scanned_bytes = decoder.u64().map_err(dec)?;
    expect_key(decoder, 2)?;
    let duration_ms = decoder.u32().map_err(dec)?;
    if duration_ms > MAX_RUNTIME_MS {
        return Err(RunnerError::LimitExceeded);
    }
    Ok(RunStats::new(scanned_files, scanned_bytes, duration_ms))
}

const fn failure_code(code: FailureCode) -> u8 {
    match code {
        FailureCode::InvalidOutput => 0,
        FailureCode::ToolFailed => 1,
        FailureCode::TimedOut => 2,
        FailureCode::LimitExceeded => 3,
        FailureCode::ClosureMismatch => 4,
    }
}

const fn decode_failure_code(value: u8) -> Result<FailureCode, RunnerError> {
    match value {
        0 => Ok(FailureCode::InvalidOutput),
        1 => Ok(FailureCode::ToolFailed),
        2 => Ok(FailureCode::TimedOut),
        3 => Ok(FailureCode::LimitExceeded),
        4 => Ok(FailureCode::ClosureMismatch),
        _ => Err(RunnerError::InvalidFrame),
    }
}

fn key(encoder: &mut Encoder<Vec<u8>>, value: u8) -> Result<(), RunnerError> {
    encoder.u8(value).map(|_| ()).map_err(enc)
}

fn expect_key(decoder: &mut Decoder<'_>, value: u8) -> Result<(), RunnerError> {
    (decoder.u8().map_err(dec)? == value)
        .then_some(())
        .ok_or(RunnerError::InvalidFrame)
}

fn require_map(decoder: &mut Decoder<'_>, size: u64) -> Result<(), RunnerError> {
    (decoder.map().map_err(dec)? == Some(size))
        .then_some(())
        .ok_or(RunnerError::InvalidFrame)
}

fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], RunnerError> {
    decoder
        .bytes()
        .map_err(dec)?
        .try_into()
        .map_err(|_| RunnerError::InvalidFrame)
}

fn enc<E>(_: minicbor::encode::Error<E>) -> RunnerError {
    RunnerError::InvalidFrame
}

fn dec(_: minicbor::decode::Error) -> RunnerError {
    RunnerError::InvalidFrame
}
