use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
};

use context_relay_protocol::{HarnessAccessPolicy, McpScopeSelector, ProjectId};
use fastembed::{
    InitOptionsUserDefined, Pooling, QuantizationMode, TextEmbedding, TokenizerFiles,
    UserDefinedEmbeddingModel,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const EMBEDDING_DIMENSIONS: usize = 384;
pub const BGE_QUERY_PREFIX: &str = "Represent this sentence for searching relevant passages: ";
const RRF_K: f64 = 60.0;
const MAX_MODEL_INPUT_BYTES: usize = 16 * 1024;
const PINNED_MODEL_MANIFEST: &[u8] = include_bytes!("../models/bge-small-en-v1.5/manifest.json");

pub(crate) fn semantic_passage_input(title: &str, tags: &str, body: &str) -> String {
    // Keep tags before long bodies so truncation cannot discard all tag metadata.
    format!("{title}\n{tags}\n{body}")
}

pub(crate) fn semantic_input_digest(title: &str, tags: &str, body: &str) -> [u8; 32] {
    Sha256::digest(semantic_passage_input(title, tags, body).as_bytes()).into()
}

pub(crate) fn semantic_model_fingerprint() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PINNED_MODEL_MANIFEST);
    hash.update(BGE_QUERY_PREFIX);
    hash.update(
        b"title-newline-tags-newline-body/v1;cls;static;max512;normalized-f32-384;fastembed-5.17.3",
    );
    hash.update(b"utf8-prefix-before-tokenization/v1");
    hash.update((MAX_MODEL_INPUT_BYTES as u64).to_le_bytes());
    hash.finalize().into()
}

#[derive(Clone, Debug, PartialEq)]
pub struct Embedding384([f32; EMBEDDING_DIMENSIONS]);

impl Embedding384 {
    pub fn as_slice(&self) -> &[f32] {
        &self.0
    }

    pub fn to_le_bytes(&self) -> Vec<u8> {
        self.0
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    pub fn from_le_bytes(bytes: &[u8]) -> Result<Self, SearchError> {
        if bytes.len() != EMBEDDING_DIMENSIONS * size_of::<f32>() {
            return Err(SearchError::InvalidEmbedding);
        }
        let values: [f32; EMBEDDING_DIMENSIONS] = bytes
            .chunks_exact(size_of::<f32>())
            .map(|chunk| f32::from_le_bytes(chunk.try_into().expect("four-byte chunk")))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| SearchError::InvalidEmbedding)?;
        if values.iter().any(|value| !value.is_finite()) {
            return Err(SearchError::InvalidEmbedding);
        }
        let squared_norm = values
            .iter()
            .map(|value| f64::from(*value) * f64::from(*value))
            .sum::<f64>();
        if !squared_norm.is_finite() || (squared_norm - 1.0).abs() > 1e-4 {
            return Err(SearchError::InvalidEmbedding);
        }
        Ok(Self(values))
    }

    pub(crate) fn cosine_similarity(&self, other: &Self) -> f64 {
        self.0
            .iter()
            .zip(other.0.iter())
            .map(|(left, right)| f64::from(*left) * f64::from(*right))
            .sum()
    }
}

impl TryFrom<Vec<f32>> for Embedding384 {
    type Error = SearchError;

    fn try_from(mut values: Vec<f32>) -> Result<Self, Self::Error> {
        if values.len() != EMBEDDING_DIMENSIONS || values.iter().any(|value| !value.is_finite()) {
            return Err(SearchError::InvalidEmbedding);
        }
        let squared_norm = values
            .iter()
            .map(|value| f64::from(*value) * f64::from(*value))
            .sum::<f64>();
        if !squared_norm.is_finite() || squared_norm == 0.0 {
            return Err(SearchError::InvalidEmbedding);
        }
        let norm = squared_norm.sqrt();
        for value in &mut values {
            *value = (f64::from(*value) / norm) as f32;
        }
        let values: [f32; EMBEDDING_DIMENSIONS] = values
            .try_into()
            .map_err(|_| SearchError::InvalidEmbedding)?;
        Ok(Self(values))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScopeGrant {
    Global,
    Project(ProjectId),
    GlobalAndProject(ProjectId),
}

/// A search scope resolved from trusted daemon state and the caller's access policy.
/// Its private grant prevents callers from constructing a broader scope directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllowedSearchScope {
    grant: ScopeGrant,
}

impl AllowedSearchScope {
    pub fn resolve(
        requested: Option<McpScopeSelector>,
        policy: &HarnessAccessPolicy,
        active_project: Option<ProjectId>,
    ) -> Result<Self, SearchError> {
        let grant = match policy {
            HarnessAccessPolicy::Disabled => return Err(SearchError::ScopeDenied),
            HarnessAccessPolicy::GlobalOnly { .. } => match requested {
                None | Some(McpScopeSelector::Global) => ScopeGrant::Global,
                Some(McpScopeSelector::ActiveProject) => {
                    return Err(SearchError::ScopeDenied);
                }
            },
            HarnessAccessPolicy::ActiveProjectOnly { .. } => match requested {
                Some(McpScopeSelector::Global) => return Err(SearchError::ScopeDenied),
                None | Some(McpScopeSelector::ActiveProject) => {
                    ScopeGrant::Project(active_project.ok_or(SearchError::ActiveProjectRequired)?)
                }
            },
            HarnessAccessPolicy::SelectedProject { project_id, .. } => match requested {
                Some(McpScopeSelector::Global) => return Err(SearchError::ScopeDenied),
                Some(McpScopeSelector::ActiveProject) => {
                    let active = active_project.ok_or(SearchError::ActiveProjectRequired)?;
                    if active != *project_id {
                        return Err(SearchError::ScopeDenied);
                    }
                    ScopeGrant::Project(*project_id)
                }
                None => ScopeGrant::Project(*project_id),
            },
            HarnessAccessPolicy::Default | HarnessAccessPolicy::ReadOnly => match requested {
                Some(McpScopeSelector::Global) => ScopeGrant::Global,
                Some(McpScopeSelector::ActiveProject) => {
                    ScopeGrant::Project(active_project.ok_or(SearchError::ActiveProjectRequired)?)
                }
                None => active_project.map_or(ScopeGrant::Global, ScopeGrant::GlobalAndProject),
            },
        };
        Ok(Self { grant })
    }

    pub(crate) const fn allows_global(&self) -> bool {
        matches!(
            self.grant,
            ScopeGrant::Global | ScopeGrant::GlobalAndProject(_)
        )
    }

    pub(crate) const fn project_id(&self) -> Option<ProjectId> {
        match self.grant {
            ScopeGrant::Project(project_id) | ScopeGrant::GlobalAndProject(project_id) => {
                Some(project_id)
            }
            ScopeGrant::Global => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SearchHit {
    record_id: String,
    pub score: f64,
}

impl SearchHit {
    pub fn record_id(&self) -> &str {
        &self.record_id
    }
}

pub(crate) fn reciprocal_rank_fusion(
    lexical: &[String],
    semantic: &[String],
    limit: usize,
) -> Vec<SearchHit> {
    let mut scores = BTreeMap::<String, f64>::new();
    for ranking in [lexical, semantic] {
        for (index, record_id) in ranking.iter().enumerate() {
            *scores.entry(record_id.clone()).or_default() += 1.0 / (RRF_K + (index + 1) as f64);
        }
    }
    let mut hits = scores
        .into_iter()
        .map(|(record_id, score)| SearchHit { record_id, score })
        .collect::<Vec<_>>();
    hits.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.record_id.cmp(&right.record_id))
    });
    hits.truncate(limit);
    hits
}

pub(crate) fn quote_fts_query(query: &str) -> Option<String> {
    let query = query.trim();
    (!query.is_empty()).then(|| format!("\"{}\"", query.replace('"', "\"\"")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddingPurpose {
    Query,
    Passage,
}

pub fn bge_model_input<'a>(purpose: EmbeddingPurpose, input: &'a str) -> Cow<'a, str> {
    match purpose {
        EmbeddingPurpose::Query => Cow::Owned(format!("{BGE_QUERY_PREFIX}{input}")),
        EmbeddingPurpose::Passage => Cow::Borrowed(input),
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SearchError {
    #[error("embedding must be a finite, nonzero 384-dimensional vector")]
    InvalidEmbedding,
    #[error("search scope is denied")]
    ScopeDenied,
    #[error("an active project is required")]
    ActiveProjectRequired,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("invalid model manifest")]
    InvalidManifest,
    #[error("model artifact is missing: {0}")]
    MissingArtifact(String),
    #[error("model artifact size does not match: {0}")]
    SizeMismatch(String),
    #[error("model artifact hash does not match: {0}")]
    HashMismatch(String),
    #[error("local embedding runtime could not be initialized")]
    RuntimeInitialization,
    #[error("local embedding inference failed")]
    Inference,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelManifest {
    schema_version: u32,
    model: String,
    revision: String,
    dimensions: usize,
    license: String,
    artifacts: Vec<ModelArtifact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelArtifact {
    file: String,
    bytes: u64,
    sha256: String,
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_manifest(bytes: &[u8]) -> Result<ModelManifest, ModelError> {
    let manifest: ModelManifest =
        serde_json::from_slice(bytes).map_err(|_| ModelError::InvalidManifest)?;
    let mut files = BTreeSet::new();
    let valid = manifest.schema_version == 1
        && !manifest.model.trim().is_empty()
        && lowercase_hex(&manifest.revision, 40)
        && manifest.dimensions == EMBEDDING_DIMENSIONS
        && !manifest.license.trim().is_empty()
        && !manifest.artifacts.is_empty()
        && manifest.artifacts.iter().all(|artifact| {
            artifact.bytes > 0
                && lowercase_hex(&artifact.sha256, 64)
                && Path::new(&artifact.file).components().count() == 1
                && matches!(
                    Path::new(&artifact.file).components().next(),
                    Some(Component::Normal(_))
                )
                && files.insert(artifact.file.clone())
        });
    valid.then_some(manifest).ok_or(ModelError::InvalidManifest)
}

pub fn verify_model_manifest(directory: &Path, manifest_bytes: &[u8]) -> Result<(), ModelError> {
    for artifact in parse_manifest(manifest_bytes)?.artifacts {
        copy_verified_artifact(directory, &artifact, &mut std::io::sink())?;
    }
    Ok(())
}

fn read_model_artifacts(
    directory: &Path,
    manifest_bytes: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, ModelError> {
    let manifest = parse_manifest(manifest_bytes)?;
    let mut artifacts = BTreeMap::new();
    for artifact in manifest.artifacts {
        let mut bytes = Vec::new();
        copy_verified_artifact(directory, &artifact, &mut bytes)?;
        artifacts.insert(artifact.file, bytes);
    }
    Ok(artifacts)
}

fn copy_verified_artifact(
    directory: &Path,
    artifact: &ModelArtifact,
    output: &mut impl Write,
) -> Result<(), ModelError> {
    let file = File::open(directory.join(&artifact.file))
        .map_err(|_| ModelError::MissingArtifact(artifact.file.clone()))?;
    let metadata = file
        .metadata()
        .map_err(|_| ModelError::MissingArtifact(artifact.file.clone()))?;
    if !metadata.is_file() {
        return Err(ModelError::MissingArtifact(artifact.file.clone()));
    }
    if metadata.len() != artifact.bytes {
        return Err(ModelError::SizeMismatch(artifact.file.clone()));
    }
    let mut input = file.take(artifact.bytes.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut count = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|_| ModelError::HashMismatch(artifact.file.clone()))?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > artifact.bytes {
            return Err(ModelError::SizeMismatch(artifact.file.clone()));
        }
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|_| ModelError::HashMismatch(artifact.file.clone()))?;
    }
    if count != artifact.bytes {
        return Err(ModelError::SizeMismatch(artifact.file.clone()));
    }
    if format!("{:x}", hasher.finalize()) != artifact.sha256 {
        return Err(ModelError::HashMismatch(artifact.file.clone()));
    }
    Ok(())
}

pub fn verify_pinned_model(directory: &Path) -> Result<(), ModelError> {
    verify_model_manifest(directory, PINNED_MODEL_MANIFEST)
}

pub struct PinnedModelEmbedder {
    model: TextEmbedding,
    #[cfg(feature = "test-support")]
    fail_next_inference: bool,
}

#[cfg(windows)]
mod packaged_runtime;

fn bounded_model_input(input: &str) -> &str {
    // Token limits alone still tokenize an entire megabyte-sized note first.
    // Bound preprocessing too; full text remains in the vault and FTS index.
    &input[..input.floor_char_boundary(MAX_MODEL_INPUT_BYTES.min(input.len()))]
}

/// Derived vectors are local to a vault and a single verified model instance.
pub(crate) struct SemanticSearch {
    model: PinnedModelEmbedder,
    passages: BTreeMap<String, ([u8; 32], Embedding384)>,
    snapshot: Option<SemanticSnapshot>,
}

struct SemanticSnapshot {
    project_id: Option<ProjectId>,
    allows_global: bool,
    database_revision: (u64, i64),
    record_ids: Vec<String>,
}

impl SemanticSearch {
    pub(crate) fn new(model: PinnedModelEmbedder) -> Self {
        Self {
            model,
            passages: BTreeMap::new(),
            snapshot: None,
        }
    }

    pub(crate) fn query(&mut self, query: &str) -> Result<Embedding384, ModelError> {
        self.model.embed(EmbeddingPurpose::Query, query)
    }

    pub(crate) fn cached_scores(
        &self,
        scope: &AllowedSearchScope,
        database_revision: (u64, i64),
        query: &Embedding384,
    ) -> Option<Vec<(String, f64)>> {
        let snapshot = self.snapshot.as_ref()?;
        if snapshot.project_id != scope.project_id()
            || snapshot.allows_global != scope.allows_global()
            || snapshot.database_revision != database_revision
        {
            return None;
        }
        snapshot
            .record_ids
            .iter()
            .map(|id| {
                let (_, embedding) = self.passages.get(id)?;
                Some((id.clone(), embedding.cosine_similarity(query)))
            })
            .collect()
    }

    pub(crate) fn remember_scope(
        &mut self,
        scope: &AllowedSearchScope,
        database_revision: (u64, i64),
        scores: &[(String, f64)],
    ) {
        // Keep only the most recent scope, avoiding quadratic lists when many
        // project scopes include the same global records.
        self.snapshot = (scores.len() <= 16_384).then(|| SemanticSnapshot {
            project_id: scope.project_id(),
            allows_global: scope.allows_global(),
            database_revision,
            record_ids: scores.iter().map(|(id, _)| id.clone()).collect(),
        });
    }

    pub(crate) fn cache_passage(
        &mut self,
        record_id: &str,
        digest: [u8; 32],
        embedding: Embedding384,
    ) {
        // Bound derived state even when many different project scopes are queried.
        if self.passages.len() >= 16_384 && !self.passages.contains_key(record_id) {
            self.passages.pop_first();
        }
        self.passages
            .insert(record_id.to_owned(), (digest, embedding));
    }

    pub(crate) fn embed_passage(&mut self, input: &str) -> Result<Embedding384, ModelError> {
        self.model.embed(EmbeddingPurpose::Passage, input)
    }
}

impl PinnedModelEmbedder {
    pub fn load_packaged(directory: &Path) -> Result<Self, ModelError> {
        #[cfg(windows)]
        {
            let artifacts = read_model_artifacts(&directory.join("model"), PINNED_MODEL_MANIFEST)?;
            packaged_runtime::initialize_packaged(&directory.join("runtime"))?;
            Self::from_artifacts(artifacts)
        }
        #[cfg(not(windows))]
        {
            let _ = directory;
            Err(ModelError::RuntimeInitialization)
        }
    }

    pub fn load(directory: &Path) -> Result<Self, ModelError> {
        let artifacts = read_model_artifacts(directory, PINNED_MODEL_MANIFEST)?;
        // Context search is local; initialize before creating any model session.
        #[cfg(windows)]
        packaged_runtime::initialize_ambient()?;
        #[cfg(not(windows))]
        ort::init().with_telemetry(false).commit();
        Self::from_artifacts(artifacts)
    }

    fn from_artifacts(mut artifacts: BTreeMap<String, Vec<u8>>) -> Result<Self, ModelError> {
        // Move the bytes that passed verification into the runtime. Reopening
        // filenames here would allow replacement between verification and use.
        let mut read = |name: &str| {
            artifacts
                .remove(name)
                .ok_or_else(|| ModelError::MissingArtifact(name.to_owned()))
        };
        let tokenizer_files = TokenizerFiles {
            tokenizer_file: read("tokenizer.json")?,
            config_file: read("config.json")?,
            special_tokens_map_file: read("special_tokens_map.json")?,
            tokenizer_config_file: read("tokenizer_config.json")?,
        };
        let user_model =
            UserDefinedEmbeddingModel::new(read("model_optimized.onnx")?, tokenizer_files)
                .with_pooling(Pooling::Cls)
                .with_quantization(QuantizationMode::Static);
        // Queries and individual context records are small. A full-machine
        // intra-op pool competes with the vault worker between inferences.
        let model = TextEmbedding::try_new_from_user_defined(
            user_model,
            InitOptionsUserDefined::default()
                .with_intra_threads(1)
                .with_max_length(512),
        )
        .map_err(|_| ModelError::RuntimeInitialization)?;
        Ok(Self {
            model,
            #[cfg(feature = "test-support")]
            fail_next_inference: false,
        })
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn fail_next_inference_for_test(&mut self) {
        self.fail_next_inference = true;
    }

    pub fn embed(
        &mut self,
        purpose: EmbeddingPurpose,
        input: &str,
    ) -> Result<Embedding384, ModelError> {
        #[cfg(feature = "test-support")]
        if std::mem::take(&mut self.fail_next_inference) {
            return Err(ModelError::Inference);
        }
        let model_input = bge_model_input(purpose, input);
        let mut output = self
            .model
            .embed([bounded_model_input(model_input.as_ref())], None)
            .map_err(|_| ModelError::Inference)?;
        if output.len() != 1 {
            return Err(ModelError::Inference);
        }
        Embedding384::try_from(output.remove(0)).map_err(|_| ModelError::Inference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_input_bound_preserves_utf8_and_short_text() {
        let text = format!("xx{}", "界".repeat(MAX_MODEL_INPUT_BYTES));
        let bounded = bounded_model_input(&text);
        assert!(bounded.len() <= MAX_MODEL_INPUT_BYTES);
        assert!(bounded.len() > MAX_MODEL_INPUT_BYTES - 3);
        assert!(text.starts_with(bounded));
        assert_eq!(bounded_model_input("short note"), "short note");
    }

    #[test]
    fn verified_model_bytes_are_retained_after_source_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tiny.bin");
        std::fs::write(&path, b"abc").unwrap();
        let manifest = br#"{"schemaVersion":1,"model":"fixture/model","revision":"0123456789abcdef0123456789abcdef01234567","dimensions":384,"license":"MIT","artifacts":[{"file":"tiny.bin","bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}]}"#;
        let mut verified = read_model_artifacts(directory.path(), manifest).unwrap();
        std::fs::write(&path, b"abd").unwrap();
        assert_eq!(verified.remove("tiny.bin").unwrap(), b"abc");
        assert!(matches!(
            read_model_artifacts(directory.path(), manifest),
            Err(ModelError::HashMismatch(_))
        ));
    }

    #[test]
    fn rrf_ties_break_by_record_id() {
        let hits = reciprocal_rank_fusion(
            &["a".to_owned(), "b".to_owned()],
            &["b".to_owned(), "a".to_owned()],
            2,
        );
        assert_eq!(hits[0].record_id(), "a");
        assert_eq!(hits[1].record_id(), "b");
        assert_eq!(hits[0].score, hits[1].score);
    }

    #[test]
    fn fts_query_is_always_a_literal_phrase() {
        assert_eq!(
            quote_fts_query("needle\") OR *: ("),
            Some("\"needle\"\") OR *: (\"".to_owned())
        );
        assert_eq!(quote_fts_query("  "), None);
    }
}
