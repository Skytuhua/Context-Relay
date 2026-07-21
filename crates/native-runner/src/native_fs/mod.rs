use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};

use crate::{
    ContentFrame, RunLimits, RunnerError, RuntimeTarget, StageDirectory, StageLayout, StagePath,
    validate_path_set,
};

const MAX_STATE_BYTES: usize = 200 * 1024 * 1024;
const MAX_SECURITY_DESCRIPTOR_BYTES: usize = 1024 * 1024;
const MAX_ALTERNATE_STREAMS: usize = 128;

#[derive(Debug)]
enum CaptureError {
    Missing,
    Runner(RunnerError),
}

impl From<RunnerError> for CaptureError {
    fn from(value: RunnerError) -> Self {
        Self::Runner(value)
    }
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

const ABSENT_TOKEN_TAG: u32 = u32::MAX;

#[cfg(target_os = "macos")]
use macos::{
    capture_absent_parent, capture_file, capture_node, create_new_file, identity_matches_path,
};
#[cfg(windows)]
use windows::{
    capture_absent_parent, capture_file, capture_node, create_new_file, identity_matches_path,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeObjectToken {
    volume: u64,
    object: [u8; 16],
    reparse_tag: u32,
    parent_volume: u64,
    parent_object: [u8; 16],
}

impl NativeObjectToken {
    pub const fn from_parts(
        volume: u64,
        object: [u8; 16],
        reparse_tag: u32,
        parent_volume: u64,
        parent_object: [u8; 16],
    ) -> Self {
        Self {
            volume,
            object,
            reparse_tag,
            parent_volume,
            parent_object,
        }
    }

    pub const fn volume(&self) -> u64 {
        self.volume
    }

    pub const fn object(&self) -> &[u8; 16] {
        &self.object
    }

    pub const fn reparse_tag(&self) -> u32 {
        self.reparse_tag
    }

    pub const fn parent_volume(&self) -> u64 {
        self.parent_volume
    }

    pub const fn parent_object(&self) -> &[u8; 16] {
        &self.parent_object
    }

    pub fn has_same_parent_binding(&self, expected: &Self) -> bool {
        self.volume == expected.volume
            && self.parent_volume == expected.parent_volume
            && self.parent_object == expected.parent_object
    }

    pub const fn is_absence_generation(&self) -> bool {
        self.reparse_tag == ABSENT_TOKEN_TAG
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlternateStream {
    name: String,
    bytes: Vec<u8>,
}

impl AlternateStream {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMetadata {
    file_attributes: u32,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    security_descriptor: Vec<u8>,
    alternate_streams: Vec<AlternateStream>,
    link_count: u64,
    parent_attributes: u32,
    parent_link_count: u64,
}

impl NativeMetadata {
    pub const fn file_attributes(&self) -> u32 {
        self.file_attributes
    }

    pub fn security_descriptor(&self) -> &[u8] {
        &self.security_descriptor
    }

    pub fn alternate_streams(&self) -> &[AlternateStream] {
        &self.alternate_streams
    }

    pub const fn creation_time(&self) -> i64 {
        self.creation_time
    }

    pub const fn last_access_time(&self) -> i64 {
        self.last_access_time
    }

    pub const fn last_write_time(&self) -> i64 {
        self.last_write_time
    }

    pub const fn change_time(&self) -> i64 {
        self.change_time
    }

    pub const fn link_count(&self) -> u64 {
        self.link_count
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeState {
    Absent {
        parent_attributes: u32,
        parent_link_count: u64,
    },
    RegularFile {
        bytes: Vec<u8>,
        metadata: NativeMetadata,
    },
}

impl NativeState {
    pub const fn absent(parent_attributes: u32, parent_link_count: u64) -> Self {
        Self::Absent {
            parent_attributes,
            parent_link_count,
        }
    }

    pub fn regular_file(bytes: Vec<u8>, metadata: NativeMetadata) -> Self {
        Self::RegularFile { bytes, metadata }
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint(self)
    }

    pub fn encode_v1(&self) -> Result<Vec<u8>, RunnerError> {
        let mut encoder = Encoder::new(Vec::new());
        match self {
            Self::Absent {
                parent_attributes,
                parent_link_count,
            } => {
                encoder.array(4).map_err(codec_error)?;
                encoder.u8(1).map_err(codec_error)?;
                encoder.u8(0).map_err(codec_error)?;
                encoder.u32(*parent_attributes).map_err(codec_error)?;
                encoder.u64(*parent_link_count).map_err(codec_error)?;
            }
            Self::RegularFile { bytes, metadata } => {
                validate_state(bytes, metadata)?;
                encoder.array(3).map_err(codec_error)?;
                encoder.u8(1).map_err(codec_error)?;
                encoder.u8(1).map_err(codec_error)?;
                encoder.array(10).map_err(codec_error)?;
                encoder.bytes(bytes).map_err(codec_error)?;
                encoder.u32(metadata.file_attributes).map_err(codec_error)?;
                encoder.i64(metadata.creation_time).map_err(codec_error)?;
                encoder
                    .i64(metadata.last_access_time)
                    .map_err(codec_error)?;
                encoder.i64(metadata.last_write_time).map_err(codec_error)?;
                encoder.i64(metadata.change_time).map_err(codec_error)?;
                encoder
                    .bytes(&metadata.security_descriptor)
                    .map_err(codec_error)?;
                encoder
                    .array(metadata.alternate_streams.len() as u64)
                    .map_err(codec_error)?;
                for stream in &metadata.alternate_streams {
                    encoder.array(2).map_err(codec_error)?;
                    encoder.str(&stream.name).map_err(codec_error)?;
                    encoder.bytes(&stream.bytes).map_err(codec_error)?;
                }
                encoder.u64(metadata.link_count).map_err(codec_error)?;
                encoder
                    .array(2)
                    .map_err(codec_error)?
                    .u32(metadata.parent_attributes)
                    .map_err(codec_error)?
                    .u64(metadata.parent_link_count)
                    .map_err(codec_error)?;
            }
        }
        Ok(encoder.into_writer())
    }

    pub fn decode_v1(bytes: &[u8]) -> Result<Self, RunnerError> {
        let mut decoder = Decoder::new(bytes);
        let fields = decoder
            .array()
            .map_err(decode_error)?
            .ok_or(RunnerError::InvalidNativeState)?;
        if decoder.u8().map_err(decode_error)? != 1 {
            return Err(RunnerError::InvalidNativeState);
        }
        let state = match (fields, decoder.u8().map_err(decode_error)?) {
            (4, 0) => Self::Absent {
                parent_attributes: decoder.u32().map_err(decode_error)?,
                parent_link_count: decoder.u64().map_err(decode_error)?,
            },
            (3, 1) => {
                require_array(&mut decoder, 10)?;
                let content = decoder.bytes().map_err(decode_error)?;
                if content.len() > MAX_STATE_BYTES {
                    return Err(RunnerError::LimitExceeded);
                }
                let file_attributes = decoder.u32().map_err(decode_error)?;
                let creation_time = decoder.i64().map_err(decode_error)?;
                let last_access_time = decoder.i64().map_err(decode_error)?;
                let last_write_time = decoder.i64().map_err(decode_error)?;
                let change_time = decoder.i64().map_err(decode_error)?;
                let security_descriptor = decoder.bytes().map_err(decode_error)?;
                if security_descriptor.len() > MAX_SECURITY_DESCRIPTOR_BYTES {
                    return Err(RunnerError::LimitExceeded);
                }
                let stream_count = decoder
                    .array()
                    .map_err(decode_error)?
                    .ok_or(RunnerError::InvalidNativeState)?;
                if stream_count > MAX_ALTERNATE_STREAMS as u64 {
                    return Err(RunnerError::LimitExceeded);
                }
                let mut streams = Vec::with_capacity(stream_count as usize);
                for _ in 0..stream_count {
                    require_array(&mut decoder, 2)?;
                    streams.push(AlternateStream {
                        name: decoder.str().map_err(decode_error)?.to_owned(),
                        bytes: decoder.bytes().map_err(decode_error)?.to_vec(),
                    });
                }
                let link_count = decoder.u64().map_err(decode_error)?;
                require_array(&mut decoder, 2)?;
                let metadata = NativeMetadata {
                    file_attributes,
                    creation_time,
                    last_access_time,
                    last_write_time,
                    change_time,
                    security_descriptor: security_descriptor.to_vec(),
                    alternate_streams: streams,
                    link_count,
                    parent_attributes: decoder.u32().map_err(decode_error)?,
                    parent_link_count: decoder.u64().map_err(decode_error)?,
                };
                validate_state(content, &metadata)?;
                Self::RegularFile {
                    bytes: content.to_vec(),
                    metadata,
                }
            }
            _ => return Err(RunnerError::InvalidNativeState),
        };
        if decoder.position() != bytes.len() {
            return Err(RunnerError::InvalidNativeState);
        }
        Ok(state)
    }
}

fn validate_state(bytes: &[u8], metadata: &NativeMetadata) -> Result<(), RunnerError> {
    if bytes.len() > MAX_STATE_BYTES
        || metadata.security_descriptor.is_empty()
        || metadata.security_descriptor.len() > MAX_SECURITY_DESCRIPTOR_BYTES
        || metadata.alternate_streams.len() > MAX_ALTERNATE_STREAMS
        || metadata.link_count != 1
        || unsafe_native_attributes(metadata)
    {
        return Err(RunnerError::InvalidNativeState);
    }
    let mut names = BTreeSet::new();
    let mut total = bytes.len();
    for stream in &metadata.alternate_streams {
        total = total
            .checked_add(stream.bytes.len())
            .ok_or(RunnerError::LimitExceeded)?;
        if total > MAX_STATE_BYTES
            || stream.name.is_empty()
            || !stream.name.starts_with(':')
            || !stream.name.ends_with(":$DATA")
            || stream.name == "::$DATA"
            || stream.name.contains('\0')
            || !names.insert(stream.name.as_str())
        {
            return Err(RunnerError::InvalidNativeState);
        }
    }
    Ok(())
}

#[cfg(windows)]
const fn unsafe_native_attributes(metadata: &NativeMetadata) -> bool {
    metadata.file_attributes & 0x400 != 0 || metadata.parent_attributes & 0x400 != 0
}

#[cfg(not(windows))]
const fn unsafe_native_attributes(_metadata: &NativeMetadata) -> bool {
    false
}

fn require_array(decoder: &mut Decoder<'_>, size: u64) -> Result<(), RunnerError> {
    (decoder.array().map_err(decode_error)? == Some(size))
        .then_some(())
        .ok_or(RunnerError::InvalidNativeState)
}

fn codec_error<E>(_: minicbor::encode::Error<E>) -> RunnerError {
    RunnerError::InvalidNativeState
}

fn decode_error(_: minicbor::decode::Error) -> RunnerError {
    RunnerError::InvalidNativeState
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeSnapshot {
    state: NativeState,
    object_token: Option<NativeObjectToken>,
    fingerprint: [u8; 32],
}

impl NativeSnapshot {
    pub const fn state(&self) -> &NativeState {
        &self.state
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        match &self.state {
            NativeState::Absent { .. } => None,
            NativeState::RegularFile { bytes, .. } => Some(bytes),
        }
    }

    pub const fn metadata(&self) -> Option<&NativeMetadata> {
        match &self.state {
            NativeState::Absent { .. } => None,
            NativeState::RegularFile { metadata, .. } => Some(metadata),
        }
    }

    pub const fn object_token(&self) -> Option<&NativeObjectToken> {
        self.object_token.as_ref()
    }

    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    pub fn absent_state(&self) -> NativeState {
        match &self.state {
            NativeState::Absent { .. } => self.state.clone(),
            NativeState::RegularFile { metadata, .. } => {
                NativeState::absent(metadata.parent_attributes, metadata.parent_link_count)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMutationOutcome {
    wrote: bool,
    snapshot: NativeSnapshot,
    installed_token: Option<NativeObjectToken>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRecoveryDisposition {
    Restored,
    Abandoned,
}

impl NativeMutationOutcome {
    pub const fn wrote(&self) -> bool {
        self.wrote
    }

    pub const fn snapshot(&self) -> &NativeSnapshot {
        &self.snapshot
    }

    pub const fn installed_token(&self) -> Option<&NativeObjectToken> {
        self.installed_token.as_ref()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct NativeMutationFailure {
    error: RunnerError,
    installed_token: Option<NativeObjectToken>,
}

impl NativeMutationFailure {
    pub const fn error(&self) -> &RunnerError {
        &self.error
    }

    pub const fn installed_token(&self) -> Option<&NativeObjectToken> {
        self.installed_token.as_ref()
    }

    pub fn into_error(self) -> RunnerError {
        self.error
    }

    pub(super) const fn installed(error: RunnerError, token: NativeObjectToken) -> Self {
        Self {
            error,
            installed_token: Some(token),
        }
    }
}

impl From<RunnerError> for NativeMutationFailure {
    fn from(error: RunnerError) -> Self {
        Self {
            error,
            installed_token: None,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum RecoveryProvenance<'a> {
    FingerprintOnly,
    Attributed(Option<&'a NativeObjectToken>),
}

impl RecoveryProvenance<'_> {
    pub(super) fn accepts_applied(self, actual: Option<&NativeObjectToken>) -> bool {
        match self {
            Self::FingerprintOnly => true,
            Self::Attributed(Some(expected)) => actual == Some(expected),
            Self::Attributed(None) => false,
        }
    }

    pub(super) const fn permits_unattributed_missing_restore(self) -> bool {
        !matches!(self, Self::Attributed(Some(_)))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OsNativeFileSystem;

impl OsNativeFileSystem {
    pub const fn new() -> Self {
        Self
    }

    pub fn snapshot(&self, path: &Path) -> Result<NativeSnapshot, RunnerError> {
        #[cfg(windows)]
        {
            windows::snapshot(path)
        }
        #[cfg(target_os = "macos")]
        {
            macos::snapshot(path)
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            snapshot(path)
        }
    }

    pub fn recover_interrupted_replace(
        &self,
        path: &Path,
        before_fingerprint: &[u8; 32],
        applied_fingerprint: &[u8; 32],
        transaction_nonce: &[u8; 16],
    ) -> Result<(), RunnerError> {
        self.recover_interrupted_replace_observed(
            path,
            before_fingerprint,
            applied_fingerprint,
            transaction_nonce,
            None,
        )
    }

    pub fn cleanup_committed_delete_observed(
        &self,
        path: &Path,
        before_fingerprint: &[u8; 32],
        transaction_nonce: &[u8; 16],
        original_token: &NativeObjectToken,
    ) -> Result<(), RunnerError> {
        self.cleanup_committed_delete_observed_after_parent_entries_removed(
            path,
            before_fingerprint,
            transaction_nonce,
            original_token,
            0,
        )
    }

    pub fn cleanup_committed_delete_observed_after_parent_entries_removed(
        &self,
        path: &Path,
        before_fingerprint: &[u8; 32],
        transaction_nonce: &[u8; 16],
        original_token: &NativeObjectToken,
        removed_parent_entries: u64,
    ) -> Result<(), RunnerError> {
        #[cfg(windows)]
        {
            windows::cleanup_committed_delete(
                path,
                before_fingerprint,
                transaction_nonce,
                original_token,
                removed_parent_entries,
            )
        }
        #[cfg(target_os = "macos")]
        {
            macos::cleanup_committed_delete(
                path,
                before_fingerprint,
                transaction_nonce,
                original_token,
                removed_parent_entries,
            )
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = (
                path,
                before_fingerprint,
                transaction_nonce,
                original_token,
                removed_parent_entries,
            );
            Err(RunnerError::UnsupportedTarget)
        }
    }

    pub fn recover_interrupted_replace_observed(
        &self,
        path: &Path,
        before_fingerprint: &[u8; 32],
        applied_fingerprint: &[u8; 32],
        transaction_nonce: &[u8; 16],
        expected_parent_binding: Option<&NativeObjectToken>,
    ) -> Result<(), RunnerError> {
        self.recover_interrupted_replace_with_guards(
            path,
            before_fingerprint,
            applied_fingerprint,
            transaction_nonce,
            expected_parent_binding,
            None,
            RecoveryProvenance::FingerprintOnly,
        )
        .map(|_| ())
    }

    pub fn recover_interrupted_replace_observed_with_provenance(
        &self,
        path: &Path,
        before_fingerprint: &[u8; 32],
        applied_fingerprint: &[u8; 32],
        transaction_nonce: &[u8; 16],
        expected_parent_binding: Option<&NativeObjectToken>,
        installed_token: Option<&NativeObjectToken>,
    ) -> Result<NativeRecoveryDisposition, RunnerError> {
        self.recover_interrupted_replace_with_guards(
            path,
            before_fingerprint,
            applied_fingerprint,
            transaction_nonce,
            expected_parent_binding,
            None,
            RecoveryProvenance::Attributed(installed_token),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recover_interrupted_replace_observed_with_provenance_and_backup_token(
        &self,
        path: &Path,
        before_fingerprint: &[u8; 32],
        applied_fingerprint: &[u8; 32],
        transaction_nonce: &[u8; 16],
        expected_parent_binding: Option<&NativeObjectToken>,
        expected_backup_token: &NativeObjectToken,
        installed_token: Option<&NativeObjectToken>,
    ) -> Result<NativeRecoveryDisposition, RunnerError> {
        self.recover_interrupted_replace_with_guards(
            path,
            before_fingerprint,
            applied_fingerprint,
            transaction_nonce,
            expected_parent_binding,
            Some(expected_backup_token),
            RecoveryProvenance::Attributed(installed_token),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_interrupted_replace_with_guards(
        &self,
        path: &Path,
        before_fingerprint: &[u8; 32],
        applied_fingerprint: &[u8; 32],
        transaction_nonce: &[u8; 16],
        expected_parent_binding: Option<&NativeObjectToken>,
        expected_backup_token: Option<&NativeObjectToken>,
        provenance: RecoveryProvenance<'_>,
    ) -> Result<NativeRecoveryDisposition, RunnerError> {
        #[cfg(windows)]
        {
            windows::recover_interrupted_replace(
                path,
                before_fingerprint,
                applied_fingerprint,
                transaction_nonce,
                expected_parent_binding,
                expected_backup_token,
                provenance,
            )
        }
        #[cfg(target_os = "macos")]
        {
            macos::recover_interrupted_replace(
                path,
                before_fingerprint,
                applied_fingerprint,
                transaction_nonce,
                expected_parent_binding,
                expected_backup_token,
                provenance,
            )
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = transaction_nonce;
            let _ = expected_backup_token;
            let current = self.snapshot(path)?;
            if expected_parent_binding.is_some_and(|expected| {
                current
                    .object_token()
                    .is_none_or(|actual| !actual.has_same_parent_binding(expected))
            }) {
                return Err(RunnerError::ConcurrentChange);
            }
            if current.fingerprint() == before_fingerprint {
                Ok(NativeRecoveryDisposition::Restored)
            } else if current.fingerprint() == applied_fingerprint {
                if provenance.accepts_applied(current.object_token()) {
                    Ok(NativeRecoveryDisposition::Restored)
                } else {
                    Ok(NativeRecoveryDisposition::Abandoned)
                }
            } else {
                Err(RunnerError::ConcurrentChange)
            }
        }
    }

    pub fn compare_and_swap(
        &self,
        path: &Path,
        expected: &[u8; 32],
        desired: &NativeState,
        transaction_nonce: &[u8; 16],
    ) -> Result<NativeMutationOutcome, RunnerError> {
        self.compare_and_swap_with_nonce(path, expected, desired, transaction_nonce)
    }

    pub fn compare_and_swap_with_nonce(
        &self,
        path: &Path,
        expected: &[u8; 32],
        desired: &NativeState,
        transaction_nonce: &[u8; 16],
    ) -> Result<NativeMutationOutcome, RunnerError> {
        self.compare_and_swap_observed(path, expected, None, desired, transaction_nonce)
    }

    pub fn compare_and_swap_observed(
        &self,
        path: &Path,
        expected: &[u8; 32],
        expected_token: Option<&NativeObjectToken>,
        desired: &NativeState,
        transaction_nonce: &[u8; 16],
    ) -> Result<NativeMutationOutcome, RunnerError> {
        self.compare_and_swap_observed_with_provenance(
            path,
            expected,
            expected_token,
            desired,
            transaction_nonce,
        )
        .map_err(NativeMutationFailure::into_error)
    }

    pub fn compare_and_swap_observed_with_provenance(
        &self,
        path: &Path,
        expected: &[u8; 32],
        expected_token: Option<&NativeObjectToken>,
        desired: &NativeState,
        transaction_nonce: &[u8; 16],
    ) -> Result<NativeMutationOutcome, NativeMutationFailure> {
        self.compare_and_swap_observed_with_candidate_provenance(
            path,
            expected,
            expected_token,
            desired,
            transaction_nonce,
            &mut |_| Ok(()),
        )
    }

    pub fn compare_and_swap_observed_with_candidate_provenance(
        &self,
        path: &Path,
        expected: &[u8; 32],
        expected_token: Option<&NativeObjectToken>,
        desired: &NativeState,
        transaction_nonce: &[u8; 16],
        persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), RunnerError>,
    ) -> Result<NativeMutationOutcome, NativeMutationFailure> {
        #[cfg(windows)]
        {
            windows::compare_and_swap_with_provenance(
                path,
                expected,
                expected_token,
                desired,
                transaction_nonce,
                persist_candidate,
            )
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = (
                path,
                expected,
                expected_token,
                desired,
                transaction_nonce,
                persist_candidate,
            );
            return Err(RunnerError::UnsupportedTarget.into());
        }
        #[cfg(target_os = "macos")]
        {
            macos::compare_and_swap_with_provenance(
                path,
                expected,
                expected_token,
                desired,
                transaction_nonce,
                persist_candidate,
            )
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InventoryEntry {
    path: StagePath,
    token: NativeObjectToken,
    fingerprint: [u8; 32],
    directory: bool,
}

#[derive(Clone, Copy)]
struct InventoryLimits {
    preflight_sizes: bool,
    max_files: usize,
    max_directories: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
}

impl InventoryLimits {
    const fn unbounded() -> Self {
        Self {
            preflight_sizes: false,
            max_files: usize::MAX,
            max_directories: usize::MAX,
            max_file_bytes: u64::MAX,
            max_total_bytes: u64::MAX,
        }
    }

    fn for_outputs(limits: RunLimits) -> Self {
        Self {
            preflight_sizes: true,
            max_files: limits.max_files(),
            max_directories: limits.max_files(),
            max_file_bytes: limits.max_file_bytes() as u64,
            max_total_bytes: limits.max_total_bytes() as u64,
        }
    }
}

struct InventoryBudget {
    limits: InventoryLimits,
    files: usize,
    directories: usize,
    total_bytes: u64,
}

impl InventoryBudget {
    const fn new(limits: InventoryLimits) -> Self {
        Self {
            limits,
            files: 0,
            directories: 0,
            total_bytes: 0,
        }
    }

    fn observe(&mut self, directory: bool, size: u64) -> Result<(), RunnerError> {
        if directory {
            self.directories = self
                .directories
                .checked_add(1)
                .ok_or(RunnerError::LimitExceeded)?;
            if self.directories > self.limits.max_directories {
                return Err(RunnerError::LimitExceeded);
            }
            return Ok(());
        }

        self.files = self
            .files
            .checked_add(1)
            .ok_or(RunnerError::LimitExceeded)?;
        self.total_bytes = self
            .total_bytes
            .checked_add(size)
            .ok_or(RunnerError::LimitExceeded)?;
        if self.files > self.limits.max_files
            || size > self.limits.max_file_bytes
            || self.total_bytes > self.limits.max_total_bytes
        {
            return Err(RunnerError::LimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTreeInventory {
    root: PathBuf,
    target: RuntimeTarget,
    entries: Vec<InventoryEntry>,
}

impl NativeTreeInventory {
    pub fn verify_unchanged(&self) -> Result<(), RunnerError> {
        let current = inspect_native_tree(&self.root, self.target)?;
        (current.entries == self.entries)
            .then_some(())
            .ok_or(RunnerError::ConcurrentChange)
    }
}

pub fn inspect_native_tree(
    root: &Path,
    target: RuntimeTarget,
) -> Result<NativeTreeInventory, RunnerError> {
    inspect_native_tree_with_limits(root, target, InventoryLimits::unbounded())
}

fn inspect_native_tree_with_limits(
    root: &Path,
    target: RuntimeTarget,
    limits: InventoryLimits,
) -> Result<NativeTreeInventory, RunnerError> {
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (root, target);
        return Err(RunnerError::UnsupportedTarget);
    }
    #[cfg(any(windows, target_os = "macos"))]
    {
        let root_node = capture_node(root, false)?;
        if !root_node.directory || root_node.unsafe_topology() {
            return Err(RunnerError::UnsafeTopology);
        }
        let root_token = root_node.token.clone();
        let mut entries = Vec::new();
        let mut budget = InventoryBudget::new(limits);
        enumerate_tree(root, root, &mut entries, &mut budget)?;
        let paths = entries
            .iter()
            .map(|entry: &InventoryEntry| entry.path.clone())
            .collect::<Vec<_>>();
        validate_path_set(target, &paths)?;
        let mut identities = BTreeSet::new();
        if entries.iter().any(|entry| {
            entry.token.volume != root_token.volume
                || !identities.insert((entry.token.volume, entry.token.object))
        }) {
            return Err(RunnerError::UnsafeTopology);
        }
        if capture_node(root, false)?.token != root_token {
            return Err(RunnerError::ConcurrentChange);
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(NativeTreeInventory {
            root: root.to_path_buf(),
            target,
            entries,
        })
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn enumerate_tree(
    root: &Path,
    directory: &Path,
    output: &mut Vec<InventoryEntry>,
    budget: &mut InventoryBudget,
) -> Result<(), RunnerError> {
    for entry in fs::read_dir(directory).map_err(|_| RunnerError::Io)? {
        let entry = entry.map_err(|_| RunnerError::Io)?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| RunnerError::UnsafeTopology)?;
        let relative = relative
            .components()
            .map(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .ok_or(RunnerError::UnsafeTopology)
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("/");
        let relative = StagePath::try_from(relative).map_err(|_| RunnerError::UnsafeTopology)?;
        let expected_directory = if budget.limits.preflight_sizes {
            let metadata = fs::symlink_metadata(&path).map_err(|_| RunnerError::Io)?;
            if metadata.file_type().is_symlink() || !(metadata.is_dir() || metadata.is_file()) {
                return Err(RunnerError::UnsafeTopology);
            }
            budget.observe(metadata.is_dir(), metadata.len())?;
            Some(metadata.is_dir())
        } else {
            None
        };
        let node = capture_node(&path, true)?;
        if expected_directory.is_some_and(|directory| directory != node.directory) {
            return Err(RunnerError::ConcurrentChange);
        }
        if expected_directory.is_none() {
            budget.observe(node.directory, 0)?;
        }
        if node.unsafe_topology() {
            return Err(RunnerError::UnsafeTopology);
        }
        output.push(InventoryEntry {
            path: relative,
            token: node.token,
            fingerprint: node.fingerprint,
            directory: node.directory,
        });
        if node.directory {
            enumerate_tree(root, &path, output, budget)?;
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct PrivateStage {
    layout: StageLayout,
    target: RuntimeTarget,
    sealed: bool,
    #[cfg(target_os = "macos")]
    cleanup: Option<macos::PrivateStageCleanup>,
}

impl PartialEq for PrivateStage {
    fn eq(&self, other: &Self) -> bool {
        self.layout == other.layout && self.target == other.target && self.sealed == other.sealed
    }
}

impl Eq for PrivateStage {}

impl PrivateStage {
    pub fn create(
        parent: &Path,
        nonce: [u8; 16],
        target: RuntimeTarget,
    ) -> Result<Self, RunnerError> {
        if !parent.is_absolute() || !parent.is_dir() {
            return Err(RunnerError::InvalidStage);
        }
        #[cfg(any(windows, target_os = "macos"))]
        if capture_node(parent, false)?.unsafe_topology() {
            return Err(RunnerError::UnsafeTopology);
        }
        let name = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        #[cfg(target_os = "macos")]
        let mut cleanup = Some(macos::PrivateStageCleanup::create(parent, &name)?);
        let root = parent.join(name);
        #[cfg(not(target_os = "macos"))]
        fs::create_dir(&root).map_err(|_| RunnerError::InvalidStage)?;
        let layout = StageLayout::new(root.clone())?;
        let initialized = (|| -> Result<(), RunnerError> {
            for directory in [
                StageDirectory::Input,
                StageDirectory::Output,
                StageDirectory::Home,
                StageDirectory::Config,
                StageDirectory::Data,
                StageDirectory::Cache,
                StageDirectory::Temp,
                StageDirectory::Runtime,
                StageDirectory::Reports,
            ] {
                fs::create_dir(layout.path(directory)).map_err(|_| RunnerError::InvalidStage)?;
            }
            Ok(())
        })();
        if let Err(error) = initialized {
            #[cfg(target_os = "macos")]
            if let Some(cleanup) = cleanup.as_mut() {
                let _ = cleanup.cleanup();
            }
            #[cfg(not(target_os = "macos"))]
            let _ = fs::remove_dir_all(root);
            return Err(error);
        }
        Ok(Self {
            layout,
            target,
            sealed: false,
            #[cfg(target_os = "macos")]
            cleanup,
        })
    }

    pub fn initialize_existing(root: PathBuf, target: RuntimeTarget) -> Result<Self, RunnerError> {
        if !root.is_absolute() || !root.is_dir() {
            return Err(RunnerError::InvalidStage);
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = target;
            return Err(RunnerError::UnsupportedTarget);
        }
        #[cfg(any(windows, target_os = "macos"))]
        {
            let root_node = capture_node(&root, false)?;
            if !root_node.directory || root_node.unsafe_topology() {
                return Err(RunnerError::UnsafeTopology);
            }
            let layout = StageLayout::new(root)?;
            for directory in [
                StageDirectory::Home,
                StageDirectory::Config,
                StageDirectory::Data,
                StageDirectory::Cache,
                StageDirectory::Temp,
                StageDirectory::Runtime,
                StageDirectory::Reports,
            ] {
                let node = capture_node(&layout.path(directory), false)?;
                if !node.directory || node.unsafe_topology() {
                    return Err(RunnerError::UnsafeTopology);
                }
            }
            for directory in [StageDirectory::Input, StageDirectory::Output] {
                fs::create_dir(layout.path(directory)).map_err(|_| RunnerError::InvalidStage)?;
            }
            Ok(Self {
                layout,
                target,
                sealed: false,
                #[cfg(target_os = "macos")]
                cleanup: None,
            })
        }
    }

    pub const fn layout(&self) -> &StageLayout {
        &self.layout
    }

    #[cfg(target_os = "macos")]
    pub fn cleanup(&mut self) -> Result<(), RunnerError> {
        self.cleanup
            .as_mut()
            .map_or(Ok(()), macos::PrivateStageCleanup::cleanup)
    }

    pub fn write_and_seal_inputs(
        &mut self,
        frames: &[ContentFrame],
    ) -> Result<NativeTreeInventory, RunnerError> {
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = frames;
            return Err(RunnerError::UnsupportedTarget);
        }
        #[cfg(any(windows, target_os = "macos"))]
        {
            if self.sealed {
                return Err(RunnerError::InvalidStage);
            }
            let paths = frames
                .iter()
                .map(|frame| frame.path().clone())
                .collect::<Vec<_>>();
            validate_path_set(self.target, &paths)?;
            for frame in frames {
                let relative = frame
                    .path()
                    .as_str()
                    .strip_prefix("input/")
                    .filter(|path| !path.is_empty())
                    .ok_or(RunnerError::InvalidStage)?;
                let destination = relative.split('/').fold(
                    self.layout.path(StageDirectory::Input),
                    |path, component| path.join(component),
                );
                create_parent_directories(&self.layout.path(StageDirectory::Input), &destination)?;
                let mut file = create_new_file(&destination)?;
                use std::io::Write as _;
                file.write_all(frame.bytes()).map_err(|_| RunnerError::Io)?;
                file.sync_all().map_err(|_| RunnerError::Io)?;
                if !identity_matches_path(&file, &destination)? {
                    return Err(RunnerError::ConcurrentChange);
                }
                let mut permissions = file.metadata().map_err(|_| RunnerError::Io)?.permissions();
                permissions.set_readonly(true);
                fs::set_permissions(&destination, permissions).map_err(|_| RunnerError::Io)?;
            }
            self.sealed = true;
            inspect_native_tree(&self.layout.path(StageDirectory::Input), self.target)
        }
    }

    pub fn read_outputs(&self, limits: RunLimits) -> Result<Vec<ContentFrame>, RunnerError> {
        let root = self.layout.path(StageDirectory::Output);
        let inventory = inspect_native_tree_with_limits(
            &root,
            self.target,
            InventoryLimits::for_outputs(limits),
        )?;
        let files = inventory
            .entries
            .iter()
            .filter(|entry| !entry.directory)
            .collect::<Vec<_>>();
        if files.len() > limits.max_files() {
            return Err(RunnerError::LimitExceeded);
        }
        let mut total = 0_usize;
        let mut frames = Vec::with_capacity(files.len());
        for entry in files {
            let path = entry
                .path
                .as_str()
                .split('/')
                .fold(root.clone(), |path, component| path.join(component));
            let snapshot = snapshot(&path)?;
            let bytes = snapshot.bytes().ok_or(RunnerError::UnsafeTopology)?;
            if bytes.len() > limits.max_file_bytes() {
                return Err(RunnerError::LimitExceeded);
            }
            total = total
                .checked_add(bytes.len())
                .ok_or(RunnerError::LimitExceeded)?;
            if total > limits.max_total_bytes() {
                return Err(RunnerError::LimitExceeded);
            }
            frames.push(ContentFrame::new(
                StagePath::try_from(format!("output/{}", entry.path.as_str()))?,
                bytes.to_vec(),
            )?);
        }
        inventory.verify_unchanged()?;
        Ok(frames)
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn create_parent_directories(root: &Path, destination: &Path) -> Result<(), RunnerError> {
    let parent = destination.parent().ok_or(RunnerError::InvalidStage)?;
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| RunnerError::InvalidStage)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let node = capture_node(&current, false)?;
                if !node.directory || node.unsafe_topology() {
                    return Err(RunnerError::UnsafeTopology);
                }
            }
            Err(_) => return Err(RunnerError::Io),
        }
    }
    Ok(())
}

#[cfg(any(windows, target_os = "macos"))]
fn snapshot(path: &Path) -> Result<NativeSnapshot, RunnerError> {
    match capture_file(path) {
        Ok(captured) => {
            let state = NativeState::RegularFile {
                bytes: captured.bytes,
                metadata: captured.metadata,
            };
            let fingerprint = fingerprint(&state);
            Ok(NativeSnapshot {
                state,
                object_token: Some(captured.token),
                fingerprint,
            })
        }
        Err(CaptureError::Missing) => {
            let (parent_attributes, parent_links) = capture_absent_parent(path)?;
            let state = NativeState::absent(parent_attributes, parent_links);
            Ok(NativeSnapshot {
                fingerprint: fingerprint(&state),
                state,
                object_token: None,
            })
        }
        Err(CaptureError::Runner(error)) => Err(error),
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn snapshot(_path: &Path) -> Result<NativeSnapshot, RunnerError> {
    Err(RunnerError::UnsupportedTarget)
}

fn fingerprint(state: &NativeState) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"context-relay/restorable-native-state/v1\0");
    match state {
        NativeState::Absent {
            parent_attributes,
            parent_link_count,
        } => {
            hash.update([0]);
            hash.update(parent_attributes.to_be_bytes());
            hash.update(parent_link_count.to_be_bytes());
        }
        NativeState::RegularFile { bytes, metadata } => {
            hash.update([1]);
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
            hash.update(metadata.file_attributes.to_be_bytes());
            for time in [metadata.creation_time, metadata.last_write_time] {
                hash.update(time.to_be_bytes());
            }
            #[cfg(windows)]
            hash.update(metadata.change_time.to_be_bytes());
            hash.update(metadata.link_count.to_be_bytes());
            hash.update(metadata.parent_attributes.to_be_bytes());
            hash.update(metadata.parent_link_count.to_be_bytes());
            let security = stable_security_descriptor(&metadata.security_descriptor);
            hash.update((security.len() as u64).to_be_bytes());
            hash.update(security);
            for stream in &metadata.alternate_streams {
                hash.update((stream.name.len() as u64).to_be_bytes());
                hash.update(stream.name.as_bytes());
                hash.update((stream.bytes.len() as u64).to_be_bytes());
                hash.update(&stream.bytes);
            }
        }
    }
    hash.finalize().into()
}

#[cfg(windows)]
fn absent_fingerprint(parent_attributes: u32, parent_links: u64) -> [u8; 32] {
    fingerprint(&NativeState::absent(parent_attributes, parent_links))
}

#[cfg(not(windows))]
fn stable_security_descriptor(descriptor: &[u8]) -> Vec<u8> {
    descriptor.to_vec()
}

#[cfg(windows)]
fn stable_security_descriptor(descriptor: &[u8]) -> Vec<u8> {
    let mut stable = descriptor.to_vec();
    if stable.len() >= 4 {
        let mut control = u16::from_le_bytes([stable[2], stable[3]]);
        control &= !0x0f00;
        stable[2..4].copy_from_slice(&control.to_le_bytes());
    }
    stable
}

#[cfg(test)]
mod provenance_tests {
    use super::{
        NativeMutationOutcome, NativeObjectToken, NativeSnapshot, NativeState, fingerprint,
    };

    fn token(object: u8) -> NativeObjectToken {
        NativeObjectToken::from_parts(7, [object; 16], 0, 11, [3; 16])
    }

    #[test]
    fn successful_mutation_keeps_activation_identity_separate_from_later_snapshot() {
        let installed = token(1);
        let concurrent_snapshot = token(2);
        let state = NativeState::absent(0, 1);
        let outcome = NativeMutationOutcome {
            wrote: true,
            snapshot: NativeSnapshot {
                state,
                object_token: Some(concurrent_snapshot.clone()),
                fingerprint: fingerprint(&NativeState::absent(0, 1)),
            },
            installed_token: Some(installed.clone()),
        };

        assert_eq!(outcome.installed_token(), Some(&installed));
        assert_eq!(
            outcome.snapshot().object_token(),
            Some(&concurrent_snapshot)
        );
    }
}
