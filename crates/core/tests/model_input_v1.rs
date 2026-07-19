use std::borrow::Cow;

use context_relay_core::search::{BGE_QUERY_PREFIX, EmbeddingPurpose, bge_model_input};

#[test]
fn bge_adapter_prefixes_only_queries_with_the_model_card_instruction() {
    assert_eq!(
        bge_model_input(EmbeddingPurpose::Query, "needle"),
        Cow::<str>::Owned(format!("{BGE_QUERY_PREFIX}needle"))
    );
    assert_eq!(
        bge_model_input(EmbeddingPurpose::Passage, "needle"),
        Cow::<str>::Borrowed("needle")
    );
    assert_eq!(
        BGE_QUERY_PREFIX,
        "Represent this sentence for searching relevant passages: "
    );
}
