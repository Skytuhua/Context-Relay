//! Package import approval binding.
//!
//! Plan rule: packages are untrusted until scanned and approved, and another
//! approval is required when any approved byte or plan field changes. This
//! module defines the deterministic approval preimage for an inspected
//! package: the archive binding digest (exact installable bytes), the
//! dependency closure digest (the resolved immutable dependency set) and the
//! sidecar scanner result hash. Any change to any member yields a different
//! approval hash, so a recorded approval cannot outlive the bytes, closure or
//! scans it covered.

use context_relay_protocol::{PackageManifestV1, Sha256Digest};
use sha2::{Digest, Sha256};

use super::packages::{ClosureError, QuarantineError, resolve_dependency_closure};

/// Domain separator for package import approval preimages, following the
/// `APPROVAL_DOMAIN_V1`/`V2` pattern in `native_transaction::approval`.
pub const APPROVAL_DOMAIN_PACKAGE: &[u8] = b"context-relay/package-import/v1\0";

/// Approval-binding error for package imports.
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum PackageApprovalError {
    #[error(transparent)]
    Quarantine(#[from] QuarantineError),
    #[error(transparent)]
    Closure(#[from] ClosureError),
}

/// Deterministic digest over the resolved dependency closure of a manifest.
///
/// The manifest must pass [`resolve_dependency_closure`] first; the digest
/// then covers every component (ordered by its stable id rendering) with its
/// kind and each immutable dependency name + digest, so adding, removing,
/// reordering-relevantly or re-digesting any dependency changes the closure.
pub fn closure_digest(manifest: &PackageManifestV1) -> Result<Sha256Digest, PackageApprovalError> {
    resolve_dependency_closure(manifest)?;
    let mut hasher = Sha256::new();
    hasher.update(b"context-relay/package-closure/v1\0");
    for component in &manifest.components {
        hasher.update(component.id().to_string().as_bytes());
        hasher.update([0]);
        match component {
            context_relay_protocol::PackageComponent::Instruction { .. }
            | context_relay_protocol::PackageComponent::Rule { .. } => {
                hasher.update(b"declarative");
                hasher.update([0]);
            }
            context_relay_protocol::PackageComponent::Skill { dependencies, .. }
            | context_relay_protocol::PackageComponent::Plugin { dependencies, .. } => {
                hasher.update(b"dependency_set");
                hasher.update([0]);
                for dependency in dependencies {
                    hasher.update(dependency.name.as_bytes());
                    hasher.update([0]);
                    hasher.update(dependency.digest.0);
                }
            }
            context_relay_protocol::PackageComponent::McpServer { package, .. } => {
                hasher.update(b"mcp_server");
                hasher.update([0]);
                hasher.update(package.name.as_bytes());
                hasher.update([0]);
                hasher.update(package.digest.0);
            }
            context_relay_protocol::PackageComponent::Hook { .. } => {
                hasher.update(b"hook");
                hasher.update([0]);
            }
            context_relay_protocol::PackageComponent::PermissionDeclaration {
                permissions, ..
            } => {
                hasher.update(b"permission_declaration");
                hasher.update([0]);
                for permission in permissions {
                    hasher.update(permission.as_bytes());
                    hasher.update([0]);
                }
            }
        }
    }
    Ok(Sha256Digest(hasher.finalize().into()))
}

/// Computes the package import approval hash.
///
/// `binding_digest` is [`super::packages::QuarantinedArchive::binding_digest`]
/// over the exact installable bytes, `closure` is [`closure_digest`] over the
/// validated manifest, and `scanner_result_hash` is the digest of the sidecar
/// scan reports for those same staged bytes. The preimage is
/// domain || binding || closure || scanner; nothing else may influence it.
pub fn package_approval_hash(
    binding_digest: &[u8; 32],
    closure: &Sha256Digest,
    scanner_result_hash: &Sha256Digest,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(APPROVAL_DOMAIN_PACKAGE);
    hasher.update(binding_digest);
    hasher.update(closure.0);
    hasher.update(scanner_result_hash.0);
    Sha256Digest(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use context_relay_protocol::{ImmutableDependency, PackageComponent, ScopeRef};

    fn component(id: &str, dependency_name: &str, dependency_digest: [u8; 32]) -> PackageComponent {
        PackageComponent::Skill {
            id: id.parse().unwrap(),
            scope: ScopeRef::Global,
            name: "sample".into(),
            body_markdown: "body".into(),
            dependencies: vec![ImmutableDependency {
                name: dependency_name.into(),
                version: "1.0.0".into(),
                digest: Sha256Digest(dependency_digest),
                immutable_source_ref: "https://example.test/archive.zip".into(),
            }],
        }
    }

    /// A skill that provides `name`, whose content digest is deterministic
    /// from its own fields; `dependency_digest_for` computes what a consumer
    /// must declare to resolve against it.
    fn provider(name: &str) -> PackageComponent {
        PackageComponent::Skill {
            id: format!(
                "018f22e2-79b0-7cc8-98c4-{:012x}",
                u128::from_be_bytes(name_sha_prefix(name)) % 1_000_000_000_000
            )
            .parse()
            .unwrap(),
            scope: ScopeRef::Global,
            name: name.to_owned(),
            body_markdown: format!("provider {name}"),
            dependencies: Vec::new(),
        }
    }

    fn name_sha_prefix(name: &str) -> [u8; 16] {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(name.as_bytes());
        let mut prefix = [0_u8; 16];
        prefix.copy_from_slice(&digest[..16]);
        prefix
    }

    fn digest_of(component: &PackageComponent) -> Sha256Digest {
        super::super::packages::component_content_digest(component).unwrap()
    }

    fn manifest(components: Vec<PackageComponent>) -> PackageManifestV1 {
        PackageManifestV1 {
            format: "context-relay.package.v1".into(),
            package_id: "018f22e2-79b0-7cc8-98c4-dc0c0c074200".parse().unwrap(),
            components,
            secret_refs: Vec::new(),
            harness_targets: vec![context_relay_protocol::HarnessId::ClaudeCode],
            extensions: None,
        }
    }

    #[test]
    fn closure_digest_is_stable_and_sensitive_to_dependency_changes() {
        let dep = provider("dep-a");
        let dep_digest = digest_of(&dep);
        let first = manifest(vec![
            dep.clone(),
            component(
                "018f22e2-79b0-7cc8-98c4-dc0c0c074203",
                "dep-a",
                dep_digest.0,
            ),
        ]);
        let again = manifest(vec![
            dep.clone(),
            component(
                "018f22e2-79b0-7cc8-98c4-dc0c0c074203",
                "dep-a",
                dep_digest.0,
            ),
        ]);
        assert_eq!(
            closure_digest(&first).unwrap(),
            closure_digest(&again).unwrap()
        );

        // A different dependency name changes the closure preimage.
        let other = provider("dep-b");
        let changed_name = manifest(vec![
            other.clone(),
            component(
                "018f22e2-79b0-7cc8-98c4-dc0c0c074203",
                "dep-b",
                digest_of(&other).0,
            ),
        ]);
        assert_ne!(
            closure_digest(&first).unwrap(),
            closure_digest(&changed_name).unwrap()
        );

        // The closure digest covers provider content: changing the
        // provider's body changes the digest its consumers must declare.
        let mutated_provider = PackageComponent::Skill {
            id: "018f22e2-79b0-7cc8-98c4-dc0c0c074299".parse().unwrap(),
            scope: ScopeRef::Global,
            name: "dep-a".into(),
            body_markdown: "provider dep-a v2".into(),
            dependencies: Vec::new(),
        };
        let mutated = manifest(vec![
            mutated_provider.clone(),
            component(
                "018f22e2-79b0-7cc8-98c4-dc0c0c074203",
                "dep-a",
                digest_of(&mutated_provider).0,
            ),
        ]);
        assert_ne!(
            closure_digest(&first).unwrap(),
            closure_digest(&mutated).unwrap()
        );
    }

    #[test]
    fn closure_digest_fails_closed_on_an_unresolved_closure() {
        let missing = manifest(vec![component(
            "018f22e2-79b0-7cc8-98c4-dc0c0c074203",
            "ghost-lib",
            [1_u8; 32],
        )]);
        assert!(matches!(
            closure_digest(&missing),
            Err(PackageApprovalError::Closure(
                ClosureError::MissingProvider { .. }
            ))
        ));
    }

    #[test]
    fn approval_hash_binds_every_member() {
        let binding_a = [1_u8; 32];
        let binding_b = [2_u8; 32];
        let dep_a = provider("dep-a");
        let dep_a_digest = digest_of(&dep_a);
        let dep_b = provider("dep-b");
        let dep_b_digest = digest_of(&dep_b);
        let closure_a = closure_digest(&manifest(vec![
            dep_a.clone(),
            component(
                "018f22e2-79b0-7cc8-98c4-dc0c0c074203",
                "dep-a",
                dep_a_digest.0,
            ),
        ]))
        .unwrap();
        let closure_b = closure_digest(&manifest(vec![
            dep_b.clone(),
            component(
                "018f22e2-79b0-7cc8-98c4-dc0c0c074203",
                "dep-b",
                dep_b_digest.0,
            ),
        ]))
        .unwrap();
        let scan_a = Sha256Digest([3_u8; 32]);
        let scan_b = Sha256Digest([4_u8; 32]);

        let base = package_approval_hash(&binding_a, &closure_a, &scan_a);
        assert_eq!(package_approval_hash(&binding_a, &closure_a, &scan_a), base);
        assert_ne!(package_approval_hash(&binding_b, &closure_a, &scan_a), base);
        assert_ne!(package_approval_hash(&binding_a, &closure_b, &scan_a), base);
        assert_ne!(package_approval_hash(&binding_a, &closure_a, &scan_b), base);
    }
}
