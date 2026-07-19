use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
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
const PINNED_MODEL_MANIFEST: &[u8] = include_bytes!("../models/bge-small-en-v1.5/manifest.json");

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
    let manifest = parse_manifest(manifest_bytes)?;
    for artifact in manifest.artifacts {
        let path = directory.join(&artifact.file);
        let mut file =
            File::open(&path).map_err(|_| ModelError::MissingArtifact(artifact.file.clone()))?;
        let metadata = file
            .metadata()
            .map_err(|_| ModelError::MissingArtifact(artifact.file.clone()))?;
        if !metadata.is_file() {
            return Err(ModelError::MissingArtifact(artifact.file));
        }
        if metadata.len() != artifact.bytes {
            return Err(ModelError::SizeMismatch(artifact.file));
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| ModelError::HashMismatch(artifact.file.clone()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        if format!("{:x}", hasher.finalize()) != artifact.sha256 {
            return Err(ModelError::HashMismatch(artifact.file));
        }
    }
    Ok(())
}

pub fn verify_pinned_model(directory: &Path) -> Result<(), ModelError> {
    verify_model_manifest(directory, PINNED_MODEL_MANIFEST)
}

pub struct PinnedModelEmbedder {
    model: TextEmbedding,
}

impl PinnedModelEmbedder {
    pub fn load(directory: &Path) -> Result<Self, ModelError> {
        verify_pinned_model(directory)?;
        let read = |name: &str| {
            std::fs::read(directory.join(name))
                .map_err(|_| ModelError::MissingArtifact(name.to_owned()))
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
        let model =
            TextEmbedding::try_new_from_user_defined(user_model, InitOptionsUserDefined::default())
                .map_err(|_| ModelError::RuntimeInitialization)?;
        Ok(Self { model })
    }

    pub fn embed(
        &mut self,
        purpose: EmbeddingPurpose,
        input: &str,
    ) -> Result<Embedding384, ModelError> {
        let model_input = bge_model_input(purpose, input);
        let mut output = self
            .model
            .embed([model_input.as_ref()], None)
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
