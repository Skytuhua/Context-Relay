use crate::ValidationError;

pub fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize>::deserialize(deserializer)
}
pub const MAX_TITLE_BYTES: usize = 512;
pub const MAX_MARKDOWN_BYTES: usize = 1024 * 1024;
pub const MAX_TAGS: usize = 64;
pub const MAX_TAG_BYTES: usize = 128;
pub const MAX_EVIDENCE_ITEMS: usize = 64;
pub const MAX_EVIDENCE_BYTES: usize = 16 * 1024;
pub const MAX_COMPONENT_METADATA_BYTES: usize = 64 * 1024;
pub const MAX_CBOR_OPERATION_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_CBOR_BATCH_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_BATCH_OPERATIONS: usize = 10_000;
pub const MAX_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_BLOB_BYTES: usize = 500 * 1024 * 1024;
pub const MAX_ARBITRARY_BYTES: usize = 1024 * 1024;

pub fn required_text(
    value: &str,
    field: &'static str,
    limit: usize,
) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::EmptyRequired(field));
    }
    if value.len() > limit {
        return Err(ValidationError::TooLarge { field, limit });
    }
    Ok(())
}
