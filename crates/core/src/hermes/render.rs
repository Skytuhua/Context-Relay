use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use context_relay_native_runner::{NativeState, OsNativeFileSystem};
use context_relay_protocol::{
    ChangeClass, ClassifiedChanges, ClientError, ComponentKind, ComponentRecord, DesiredState,
    ErrorCode, HarnessId, MAX_MARKDOWN_BYTES, RenderedFile, RenderedState, ScopeRef, SemanticDiff,
    Sha256Digest,
};
use serde_json::Value as JsonValue;
use serde_yaml_ng::Value as YamlValue;
use sha2::{Digest as _, Sha256};

use crate::mcp::install::{
    BRIDGE_SERVER_NAME, is_canonical_bridge_body, is_managed_bridge_component,
};
use crate::native_memory::{
    NativeMemoryAdapter, NativeMemoryCapabilities, NativeMemoryDisable, NativeMemoryDocumentKind,
    is_primary_memory_instruction_component, native_memory_source,
};
use crate::native_transaction::model::{
    ApprovedMutation, MutationKind, RestorableStateFingerprint,
};

use super::{
    HermesAdapter, HermesMemoryKind, MANAGED_END, MANAGED_START,
    gateway::{self, GatewayStatus},
    import, invalid, profile, wire_path,
};

const LOSSY_REASONS: [&str; 7] = [
    "approval_mode_not_portable",
    "approval_timeout_not_portable",
    "deny_pattern_not_portable",
    "permanent_allowlist_not_portable",
    "cron_permission_not_portable",
    "confirmation_switch_not_portable",
    "unknown_permission_semantics",
];

impl HermesAdapter {
    pub fn plan_native_config(
        &self,
        desired: &DesiredState,
    ) -> Result<Option<ApprovedMutation>, ClientError> {
        self.require_apply_supported()?;
        self.validate_desired(desired)?;
        gateway::require_gateway_idle(&self.layout.profile)?;
        let path = self.layout.profile.hermes_home.join("config.yaml");
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid("Hermes config cannot be safely inspected"))?;
        let NativeState::RegularFile { bytes, metadata } = snapshot.state() else {
            return Err(invalid("Hermes config must be a regular file"));
        };
        let rendered = self.render_config(bytes, desired)?;
        self.approved_regular_file(&path, &snapshot, rendered, metadata.clone())
    }

    /// Coalesces the capability-derived native-memory disable projection with
    /// the ordinary Hermes config projection. Both start from the same live
    /// before-image, so applying them as separate mutations would create a
    /// duplicate-target ambiguity and could lose one of the two changes.
    pub fn plan_native_config_with_memory_disable(
        &self,
        desired: &DesiredState,
        disable_mutations: &[ApprovedMutation],
    ) -> Result<Option<ApprovedMutation>, ClientError> {
        self.require_apply_supported()?;
        self.validate_desired(desired)?;
        gateway::require_gateway_idle(&self.layout.profile)?;
        let path = self.layout.profile.hermes_home.join("config.yaml");
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid("Hermes config cannot be safely inspected"))?;
        let NativeState::RegularFile { bytes, metadata } = snapshot.state() else {
            return Err(invalid("Hermes config must be a regular file"));
        };
        let (base_bytes, base_metadata) = match disable_mutations {
            [] => (bytes.clone(), metadata.clone()),
            [mutation]
                if mutation.target == wire_path(&path)
                    && mutation.expected.0.0 == *snapshot.fingerprint() =>
            {
                let state = NativeState::decode_v1(&mutation.content)
                    .map_err(|_| invalid("Hermes memory disable state is invalid"))?;
                if state.fingerprint() != mutation.intended.0.0 {
                    return Err(invalid("Hermes memory disable state is invalid"));
                }
                let NativeState::RegularFile { bytes, metadata } = state else {
                    return Err(invalid("Hermes memory disable state is invalid"));
                };
                (bytes, metadata)
            }
            _ => return Err(invalid("Hermes memory disable projection is ambiguous")),
        };
        let rendered = self.render_config(&base_bytes, desired)?;
        self.approved_regular_file(&path, &snapshot, rendered, base_metadata)
    }

    pub fn plan_native_markdown(
        &self,
        component: &ComponentRecord,
    ) -> Result<Option<ApprovedMutation>, ClientError> {
        self.require_apply_supported()?;
        self.validate_component(component)?;
        if !matches!(
            component.kind,
            ComponentKind::Instruction | ComponentKind::Rule | ComponentKind::Skill
        ) {
            return Err(invalid("Hermes Markdown component is invalid"));
        }
        if is_primary_memory_instruction_component(HarnessId::Hermes, component) {
            let (path, expected, current, intended) =
                self.primary_memory_instruction_projection(component)?;
            if current.fingerprint() == intended.fingerprint() {
                return Ok(None);
            }
            return Ok(Some(self.approved_state(&path, &expected, intended)?));
        }
        let path = self.markdown_path(component)?;
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid("Hermes Markdown cannot be safely inspected"))?;
        let NativeState::RegularFile { bytes, metadata } = snapshot.state() else {
            return Err(invalid("Hermes Markdown must be a regular file"));
        };
        let rendered =
            render_managed_markdown(bytes, &component.body_markdown, component.archived)?;
        self.approved_regular_file(&path, &snapshot, rendered, metadata.clone())
    }

    fn primary_memory_instruction_projection(
        &self,
        component: &ComponentRecord,
    ) -> Result<(PathBuf, [u8; 32], NativeState, NativeState), ClientError> {
        let path = self.markdown_path(component)?;
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid("Hermes Markdown cannot be safely inspected"))?;
        let current = snapshot.state().clone();
        let intended = match snapshot.state() {
            NativeState::RegularFile { bytes, metadata } => NativeState::regular_file(
                render_managed_markdown(bytes, &component.body_markdown, component.archived)?,
                metadata.clone(),
            ),
            NativeState::Absent { .. } if component.archived => current.clone(),
            NativeState::Absent { .. } => {
                let template_path = path.with_file_name("HERMES.md");
                let template =
                    OsNativeFileSystem::new()
                        .snapshot(&template_path)
                        .map_err(|_| {
                            invalid("Hermes primary instruction metadata template is unsafe")
                        })?;
                let NativeState::RegularFile { metadata, .. } = template.state() else {
                    return Err(invalid(
                        "Hermes primary instruction needs an existing project-root metadata template",
                    ));
                };
                let metadata = metadata
                    .for_absent_sibling_creation(&current)
                    .map_err(|_| {
                        invalid(
                            "Hermes primary instruction metadata template is not bound to the target parent",
                        )
                    })?;
                NativeState::regular_file(
                    render_managed_markdown(&[], &component.body_markdown, false)?,
                    metadata,
                )
            }
        };
        Ok((path, *snapshot.fingerprint(), current, intended))
    }

    pub fn plan_native_memory(
        &self,
        kind: HermesMemoryKind,
        body_markdown: &str,
    ) -> Result<Option<ApprovedMutation>, ClientError> {
        self.require_apply_supported()?;
        if body_markdown.chars().count() > MAX_MARKDOWN_BYTES {
            return Err(invalid("Hermes memory exceeds the character limit"));
        }
        super::yaml::scan_text_secret(body_markdown.as_bytes(), "profile:memory")?;
        let relative = match kind {
            HermesMemoryKind::Agent => "memories/MEMORY.md",
            HermesMemoryKind::User => "memories/USER.md",
        };
        let path = self.layout.profile.hermes_home.join(relative);
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid("Hermes memory cannot be safely inspected"))?;
        let NativeState::RegularFile { bytes, metadata } = snapshot.state() else {
            return Err(invalid("Hermes memory must be a regular file"));
        };
        let rendered = render_managed_markdown(bytes, body_markdown, false)?;
        self.approved_regular_file(&path, &snapshot, rendered, metadata.clone())
    }

    pub fn plan_native_gateway_hook(
        &self,
        manifest: &ComponentRecord,
        handler: Option<&ComponentRecord>,
    ) -> Result<Vec<ApprovedMutation>, ClientError> {
        self.require_apply_supported()?;
        self.validate_gateway_hook_pair(manifest, handler)?;
        gateway::require_gateway_idle(&self.layout.profile)?;
        let creation_metadata = std::iter::once(manifest)
            .chain(handler)
            .filter_map(|component| {
                let path = self.gateway_hook_path(component).ok()?;
                let snapshot = OsNativeFileSystem::new().snapshot(&path).ok()?;
                match snapshot.state() {
                    NativeState::RegularFile { metadata, .. } => Some(metadata.clone()),
                    NativeState::Absent { .. } => None,
                }
            })
            .next()
            .or_else(|| {
                let path = self.layout.profile.hermes_home.join("config.yaml");
                let snapshot = OsNativeFileSystem::new().snapshot(&path).ok()?;
                match snapshot.state() {
                    NativeState::RegularFile { metadata, .. } => Some(metadata.clone()),
                    NativeState::Absent { .. } => None,
                }
            });
        let mut mutations = Vec::new();
        for component in std::iter::once(manifest).chain(handler) {
            let path = self.gateway_hook_path(component)?;
            let snapshot = OsNativeFileSystem::new()
                .snapshot(&path)
                .map_err(|_| invalid("Hermes gateway hook cannot be safely inspected"))?;
            let intended = if component.archived {
                snapshot.absent_state()
            } else {
                super::yaml::scan_text_secret(
                    component.body_markdown.as_bytes(),
                    "profile:gateway-hook",
                )?;
                match snapshot.state() {
                    NativeState::RegularFile { metadata, .. } => NativeState::regular_file(
                        component.body_markdown.as_bytes().to_vec(),
                        metadata.clone(),
                    ),
                    NativeState::Absent { .. } => NativeState::regular_file(
                        component.body_markdown.as_bytes().to_vec(),
                        creation_metadata.clone().ok_or_else(|| {
                            invalid("Hermes new gateway hook needs an existing metadata template")
                        })?,
                    ),
                }
            };
            if intended.fingerprint() == *snapshot.fingerprint() {
                continue;
            }
            mutations.push(self.approved_state(&path, snapshot.fingerprint(), intended)?);
        }
        mutations.sort_by(|left, right| left.target.bytes.cmp(&right.target.bytes));
        Ok(mutations)
    }

    pub(super) fn render_desired(
        &self,
        desired: &DesiredState,
    ) -> Result<RenderedState, ClientError> {
        self.require_apply_supported()?;
        self.validate_desired(desired)?;
        let config_path = self.layout.profile.hermes_home.join("config.yaml");
        let config_existing = read_regular(&config_path, "Hermes config must be a regular file")?;
        let parsed = super::yaml::parse_config(&config_existing)?;
        let current_config = self.project_current_config(&parsed)?;
        self.validate_config_authority(&current_config, desired)?;
        let config_requested = desired.components.iter().any(|component| {
            is_config_component(component)
                || current_config
                    .iter()
                    .any(|current| current.id == component.id)
        });
        let active = config_requested || desired.components.iter().any(is_gateway_hook_component);
        if active {
            gateway::require_gateway_idle(&self.layout.profile)?;
        }
        let mut files = Vec::new();
        if config_requested {
            let rendered = self.render_config(&config_existing, desired)?;
            if rendered != config_existing {
                files.push(rendered_file(config_path, &rendered));
            }
        }
        let mut gateway_hooks =
            BTreeMap::<String, (Option<&ComponentRecord>, Option<&ComponentRecord>)>::new();
        for component in &desired.components {
            if is_config_component(component) {
                continue;
            }
            if is_gateway_hook_component(component) {
                let location = structural_location(component)?;
                let directory = location
                    .strip_prefix("profile:hooks/")
                    .and_then(|rest| rest.rsplit_once('/').map(|(directory, _)| directory))
                    .ok_or_else(|| invalid("Hermes gateway hook location is invalid"))?;
                let entry = gateway_hooks.entry(directory.to_owned()).or_default();
                if location.ends_with("/HOOK.yaml") {
                    if entry.0.replace(component).is_some() {
                        return Err(invalid("Hermes gateway hook manifest is repeated"));
                    }
                } else if location.ends_with("/handler.py") && entry.1.replace(component).is_some()
                {
                    return Err(invalid("Hermes gateway hook handler is repeated"));
                }
                continue;
            }
            if matches!(
                component.kind,
                ComponentKind::Instruction | ComponentKind::Rule | ComponentKind::Skill
            ) {
                if is_primary_memory_instruction_component(HarnessId::Hermes, component) {
                    let (path, _, current, intended) =
                        self.primary_memory_instruction_projection(component)?;
                    if current.fingerprint() != intended.fingerprint()
                        && let NativeState::RegularFile { bytes, .. } = intended
                    {
                        files.push(rendered_file(path, &bytes));
                    }
                    continue;
                }
                let path = self.markdown_path(component)?;
                let existing = read_regular(&path, "Hermes Markdown must be a regular file")?;
                let rendered = render_managed_markdown(
                    &existing,
                    &component.body_markdown,
                    component.archived,
                )?;
                if rendered != existing {
                    files.push(rendered_file(path, &rendered));
                }
            }
        }
        for (_, (manifest, handler)) in gateway_hooks {
            let manifest =
                manifest.ok_or_else(|| invalid("Hermes gateway hook manifest is required"))?;
            self.validate_gateway_hook_pair(manifest, handler)?;
            for component in std::iter::once(manifest).chain(handler) {
                let path = self.gateway_hook_path(component)?;
                let existing = read_optional_regular(&path)?;
                let rendered = if component.archived {
                    Vec::new()
                } else {
                    component.body_markdown.as_bytes().to_vec()
                };
                if existing.as_deref() != Some(rendered.as_slice()) {
                    files.push(rendered_file(path, &rendered));
                }
            }
        }
        files.sort_by(|left, right| left.path.bytes.cmp(&right.path.bytes));
        Ok(RenderedState {
            files,
            cli_operations: vec![],
        })
    }

    pub(super) fn classify_changes(
        &self,
        diff: &SemanticDiff,
    ) -> Result<ClassifiedChanges, ClientError> {
        diff.validate()
            .map_err(|_| invalid("Hermes semantic diff is invalid"))?;
        let permission_paths = self.reviewed_permission_paths()?;
        let gateway_status = gateway::inspect_gateway(&self.layout.profile)?;
        let mut changes = Vec::with_capacity(diff.changes.len());
        for change in &diff.changes {
            let mut classified = change.clone();
            if change.target.starts_with("hermes-permission|") {
                let parts = change.target.split('|').collect::<Vec<_>>();
                if parts.len() != 5
                    || parts[0] != "hermes-permission"
                    || parts[1] != self.layout.profile.name
                    || !permission_paths.contains(parts[3])
                {
                    return Err(invalid("Hermes permission change target is invalid"));
                }
                let (fidelity, reason) = import::permission_mapping(&self.layout.version, parts[3])
                    .ok_or_else(|| invalid("Hermes permission change target is invalid"))?;
                if parts[2] != fidelity || parts[4] != reason {
                    return Err(invalid("Hermes permission change target is invalid"));
                }
                match fidelity {
                    "exact" if reason == "native_equivalent" => {}
                    "lossy" if LOSSY_REASONS.contains(&reason) => {
                        classified.class = ChangeClass::Conflict;
                        classified.summary = format!("lossy Hermes permission mapping: {reason}");
                    }
                    _ => return Err(invalid("Hermes permission change target is invalid")),
                }
            } else if !valid_nonpermission_target(&change.target, &self.layout.profile.name) {
                return Err(invalid("Hermes change target is invalid"));
            }
            if is_passive_change_target(&change.target)
                && matches!(
                    gateway_status,
                    GatewayStatus::Live | GatewayStatus::Unverifiable
                )
                && !classified.summary.contains("frozen_session_snapshot")
            {
                classified.summary.push_str(" [frozen_session_snapshot]");
            }
            changes.push(classified);
        }
        Ok(ClassifiedChanges(changes))
    }

    pub(super) fn require_apply_supported(&self) -> Result<(), ClientError> {
        (self.capability() == context_relay_protocol::CapabilityLevel::Full)
            .then_some(())
            .ok_or_else(|| ClientError {
                code: ErrorCode::HarnessUnsupported,
                message: "This Hermes installation is import-only".into(),
                field_path: None,
                retryable: false,
            })?;
        profile::validate_profile_binding(&self.layout.default_hermes_home, &self.layout.profile)
    }

    fn validate_desired(&self, desired: &DesiredState) -> Result<(), ClientError> {
        desired
            .validate()
            .map_err(|_| invalid("Desired Hermes state is invalid"))?;
        let mut scopes = BTreeSet::new();
        for scope in &desired.scopes {
            let scope = import::validate_bound_scope(self, scope)?;
            if !scopes.insert(scope_key(&scope)) {
                return Err(invalid("Desired Hermes state repeated a scope"));
            }
        }
        for component in &desired.components {
            self.validate_component(component)?;
            let expected_scope = match &component.scope {
                ScopeRef::Global => "global".to_owned(),
                ScopeRef::Project { project_id } => format!("project:{project_id}"),
            };
            if !scopes.contains(&expected_scope) {
                return Err(invalid("Hermes component scope is not bound"));
            }
        }
        Ok(())
    }

    fn validate_component(&self, component: &ComponentRecord) -> Result<(), ClientError> {
        component
            .validate()
            .map_err(|_| invalid("Hermes component is invalid"))?;
        if !is_managed_bridge_component(HarnessId::Hermes, component)
            && !is_primary_memory_instruction_component(HarnessId::Hermes, component)
        {
            if component.provenance.harness != Some(HarnessId::Hermes) {
                return Err(invalid("Hermes component provenance is invalid"));
            }
            if metadata(component, "profile") != Some(self.layout.profile.name.as_str()) {
                return Err(invalid(
                    "Hermes component profile does not match the adapter",
                ));
            }
        }
        if component.body_markdown.contains(MANAGED_START)
            || component.body_markdown.contains(MANAGED_END)
            || component.body_markdown.contains("<redacted>")
        {
            return Err(invalid("Hermes desired body contains a forbidden sentinel"));
        }
        super::yaml::scan_text_secret(component.body_markdown.as_bytes(), "desired:component")?;
        for (_, value) in &component.metadata {
            if value == "<redacted>" || super::yaml::secret_scalar(value) {
                return Err(invalid("Hermes desired metadata contains secret-like text"));
            }
        }
        Ok(())
    }

    fn validate_config_authority(
        &self,
        current: &[ComponentRecord],
        desired: &DesiredState,
    ) -> Result<(), ClientError> {
        let current_by_location = current
            .iter()
            .filter_map(|component| {
                metadata(component, "structuralLocation")
                    .map(|location| (location.to_owned(), component))
            })
            .collect::<BTreeMap<_, _>>();
        for component in &desired.components {
            let location = structural_location(component)?;
            if is_managed_bridge_component(HarnessId::Hermes, component) {
                if current_by_location
                    .get(location)
                    .is_some_and(|native| !self.is_native_managed_bridge(native))
                {
                    return Err(invalid(
                        "Hermes bridge location is occupied by unmanaged native state",
                    ));
                }
                continue;
            }
            if let Some(native) = current.iter().find(|native| native.id == component.id) {
                if metadata(native, "structuralLocation") != Some(location)
                    || native.kind != component.kind
                    || native.name != component.name
                {
                    return Err(invalid(
                        "Hermes component identity does not match native state",
                    ));
                }
                if metadata(native, "redacted") != metadata(component, "redacted")
                    || metadata(native, "secretReferenceNames")
                        != metadata(component, "secretReferenceNames")
                {
                    return Err(invalid(
                        "Hermes component redaction metadata does not match native state",
                    ));
                }
                if native.kind == ComponentKind::PermissionDeclaration
                    && (metadata(native, "nativePermissionPath")
                        != metadata(component, "nativePermissionPath")
                        || metadata(native, "mappingFidelity")
                            != metadata(component, "mappingFidelity")
                        || metadata(native, "mappingReason")
                            != metadata(component, "mappingReason"))
                {
                    return if metadata(native, "mappingFidelity") == Some("lossy") {
                        Err(super::conflict(
                            "Hermes permission mapping is unresolved and lossy",
                        ))
                    } else {
                        Err(invalid(
                            "Hermes permission metadata does not match native state",
                        ))
                    };
                }
                continue;
            }
            if !location.starts_with("config:") {
                continue;
            }
            if current_by_location.contains_key(location) {
                return Err(invalid(
                    "Hermes component identity does not match native state",
                ));
            }
            match component.kind {
                ComponentKind::PermissionDeclaration => {
                    let path = permission_path(component)?;
                    let path = path.join(".");
                    if location != format!("config:{path}") {
                        return Err(invalid(
                            "Hermes permission location does not match its native path",
                        ));
                    }
                    let (fidelity, reason) =
                        import::permission_mapping(&self.layout.version, &path)
                            .ok_or_else(|| invalid("Hermes permission path is invalid"))?;
                    if metadata(component, "mappingFidelity") != Some(fidelity)
                        || metadata(component, "mappingReason") != Some(reason)
                    {
                        return Err(invalid(
                            "Hermes permission metadata does not match its native path",
                        ));
                    }
                    if fidelity == "lossy" {
                        return Err(super::conflict(
                            "Hermes permission mapping is unresolved and lossy",
                        ));
                    }
                }
                ComponentKind::Plugin | ComponentKind::McpServer | ComponentKind::Hook => {
                    if metadata(component, "redacted").is_some()
                        || metadata(component, "secretReferenceNames").is_some()
                    {
                        return Err(invalid(
                            "Hermes new configuration cannot claim redaction metadata",
                        ));
                    }
                }
                _ => return Err(invalid("Hermes config component kind is invalid")),
            }
        }
        Ok(())
    }

    fn is_native_managed_bridge(&self, component: &ComponentRecord) -> bool {
        component.scope == ScopeRef::Global
            && component.kind == ComponentKind::McpServer
            && component.name == BRIDGE_SERVER_NAME
            && metadata(component, "profile") == Some(self.layout.profile.name.as_str())
            && metadata(component, "structuralLocation") == Some("config:mcp_servers.context-relay")
            && component.provenance.harness == Some(HarnessId::Hermes)
            && component.provenance.source.is_none()
            && component.archived
                == serde_json::from_str::<JsonValue>(&component.body_markdown)
                    .ok()
                    .and_then(|body| body.get("enabled").and_then(JsonValue::as_bool))
                    .is_some_and(|enabled| !enabled)
            && is_canonical_bridge_body(HarnessId::Hermes, &component.body_markdown, true)
    }

    fn render_config(
        &self,
        existing: &[u8],
        desired: &DesiredState,
    ) -> Result<Vec<u8>, ClientError> {
        let parsed = super::yaml::parse_config(existing)?;
        let current = self.project_current_config(&parsed)?;
        self.validate_config_authority(&current, desired)?;
        let current_by_location = current
            .iter()
            .filter_map(|component| {
                metadata(component, "structuralLocation")
                    .map(|location| (location.to_owned(), component))
            })
            .collect::<BTreeMap<_, _>>();
        let mut replacements = BTreeMap::<Vec<String>, Option<YamlValue>>::new();
        let mut enabled_plugins = yaml_string_list(
            resolve_yaml(&parsed.value, &["plugins", "enabled"]).and_then(YamlValue::as_sequence),
        )?;
        let mut disabled_plugins = yaml_string_list(
            resolve_yaml(&parsed.value, &["plugins", "disabled"]).and_then(YamlValue::as_sequence),
        )?;
        let mut desired_plugin_states = BTreeMap::<String, bool>::new();
        for component in desired
            .components
            .iter()
            .filter(|component| is_config_component(component))
        {
            let location = structural_location(component)?;
            let native = current_by_location.get(location).copied();
            if native.and_then(|current| metadata(current, "redacted")) == Some("true") {
                let unchanged = current_by_location.get(location).is_some_and(|current| {
                    current.body_markdown == component.body_markdown
                        && current.archived == component.archived
                });
                if unchanged {
                    continue;
                }
                let (root, name) = match component.kind {
                    ComponentKind::McpServer => (
                        "mcp_servers",
                        config_child_name(location, "config:mcp_servers.")?,
                    ),
                    ComponentKind::Hook if location.starts_with("config:hooks.") => {
                        ("hooks", config_child_name(location, "config:hooks.")?)
                    }
                    _ => {
                        return Err(invalid("Redacted Hermes configuration cannot be rendered"));
                    }
                };
                let native = native.ok_or_else(|| {
                    invalid("Redacted Hermes configuration is not bound to native state")
                })?;
                let current_body = serde_json::from_str::<JsonValue>(&native.body_markdown)
                    .map_err(|_| invalid("Native Hermes reviewed projection is invalid"))?;
                let mut desired_body = serde_json::from_str::<JsonValue>(&component.body_markdown)
                    .map_err(|_| invalid("Hermes component body must be an object"))?;
                if component.archived {
                    desired_body
                        .as_object_mut()
                        .ok_or_else(|| invalid("Hermes component body must be an object"))?
                        .insert("enabled".into(), JsonValue::Bool(false));
                }
                collect_redacted_scalar_edits(
                    Some(&current_body),
                    Some(&desired_body),
                    &mut vec![root.into(), name.into()],
                    &mut replacements,
                )?;
                continue;
            }
            super::yaml::scan_text_secret(
                component.body_markdown.as_bytes(),
                "profile:config.yaml",
            )?;
            match component.kind {
                ComponentKind::PermissionDeclaration => {
                    let path = permission_path(component)?;
                    let replacement = json_to_yaml(&component.body_markdown)?;
                    let native_path = path.join(".");
                    let fidelity = native
                        .and_then(|current| metadata(current, "mappingFidelity"))
                        .or_else(|| {
                            import::permission_mapping(&self.layout.version, &native_path)
                                .map(|(fidelity, _)| fidelity)
                        })
                        .ok_or_else(|| invalid("Hermes permission path is invalid"))?;
                    if fidelity == "lossy" {
                        let unchanged = current_by_location.get(location).is_some_and(|current| {
                            current.body_markdown == component.body_markdown
                                && current.archived == component.archived
                        });
                        if !unchanged {
                            return Err(super::conflict(
                                "Hermes permission mapping is unresolved and lossy",
                            ));
                        }
                        continue;
                    }
                    replacements.insert(path, (!component.archived).then_some(replacement));
                }
                ComponentKind::Plugin => {
                    let name = plugin_name_from_location(location)?;
                    let enabled = !component.archived;
                    if desired_plugin_states
                        .insert(name.to_owned(), enabled)
                        .is_some_and(|previous| previous != enabled)
                    {
                        return Err(invalid("Hermes plugin state is repeated"));
                    }
                }
                ComponentKind::McpServer => {
                    let name = config_child_name(location, "config:mcp_servers.")?;
                    let desired_value = json_to_yaml(&component.body_markdown)?;
                    let replacement = merge_reviewed_mapping(
                        resolve_yaml(&parsed.value, &["mcp_servers", name]),
                        &desired_value,
                        &[
                            "command",
                            "args",
                            "url",
                            "timeout",
                            "connect_timeout",
                            "idle_timeout_seconds",
                            "max_lifetime_seconds",
                            "enabled",
                            "supports_parallel_tool_calls",
                            "tools",
                        ],
                        component.archived,
                    )?;
                    replacements.insert(vec!["mcp_servers".into(), name.into()], Some(replacement));
                }
                ComponentKind::Hook if location.starts_with("config:hooks.") => {
                    let name = config_child_name(location, "config:hooks.")?;
                    let desired_value = json_to_yaml(&component.body_markdown)?;
                    let mut replacement = merge_reviewed_mapping(
                        resolve_yaml(&parsed.value, &["hooks", name]),
                        &desired_value,
                        &[],
                        component.archived,
                    )?;
                    if component.archived {
                        set_mapping_bool(&mut replacement, "enabled", false)?;
                    }
                    replacements.insert(vec!["hooks".into(), name.into()], Some(replacement));
                }
                _ => {}
            }
        }
        let mut plugin_changed = false;
        let mut append_enabled = Vec::new();
        let mut append_disabled = Vec::new();
        for (name, enabled) in desired_plugin_states {
            let already_enabled = enabled_plugins
                .iter()
                .filter(|value| *value == &name)
                .count();
            let already_disabled = disabled_plugins
                .iter()
                .filter(|value| *value == &name)
                .count();
            if (enabled && already_enabled == 1 && already_disabled == 0)
                || (!enabled && already_disabled == 1 && already_enabled == 0)
            {
                continue;
            }
            enabled_plugins.retain(|value| value != &name);
            disabled_plugins.retain(|value| value != &name);
            if enabled {
                append_enabled.push(name);
            } else {
                append_disabled.push(name);
            }
            plugin_changed = true;
        }
        enabled_plugins.extend(append_enabled);
        disabled_plugins.extend(append_disabled);
        if plugin_changed {
            let enabled = (!enabled_plugins.is_empty()).then(|| {
                YamlValue::Sequence(enabled_plugins.into_iter().map(YamlValue::String).collect())
            });
            let disabled = (!disabled_plugins.is_empty()).then(|| {
                YamlValue::Sequence(
                    disabled_plugins
                        .into_iter()
                        .map(YamlValue::String)
                        .collect(),
                )
            });
            if resolve_yaml(&parsed.value, &["plugins"]).is_some() {
                replacements.insert(vec!["plugins".into(), "enabled".into()], enabled);
                replacements.insert(vec!["plugins".into(), "disabled".into()], disabled);
            } else {
                let mut plugins = serde_yaml_ng::Mapping::new();
                if let Some(enabled) = enabled {
                    plugins.insert(YamlValue::String("enabled".into()), enabled);
                }
                if let Some(disabled) = disabled {
                    plugins.insert(YamlValue::String("disabled".into()), disabled);
                }
                replacements.insert(vec!["plugins".into()], Some(YamlValue::Mapping(plugins)));
            }
        }
        normalize_missing_root_replacements(&parsed.value, &mut replacements, "mcp_servers");
        normalize_missing_root_replacements(&parsed.value, &mut replacements, "hooks");
        super::yaml::patch_owned_paths(&parsed, &replacements)
    }

    fn approved_regular_file(
        &self,
        path: &Path,
        snapshot: &context_relay_native_runner::NativeSnapshot,
        bytes: Vec<u8>,
        mut metadata: context_relay_native_runner::NativeMetadata,
    ) -> Result<Option<ApprovedMutation>, ClientError> {
        if matches!(snapshot.state(), NativeState::RegularFile { bytes: current, .. } if current == &bytes)
        {
            return Ok(None);
        }
        let expected = self.gateway_reserved_state(path, snapshot.state())?;
        let (
            NativeState::RegularFile {
                metadata: current_metadata,
                ..
            },
            NativeState::RegularFile {
                metadata: reserved_metadata,
                ..
            },
        ) = (snapshot.state(), &expected)
        else {
            return Err(invalid("Hermes native state is not a regular file"));
        };
        if metadata == *current_metadata {
            metadata.clone_from(reserved_metadata);
        } else if metadata != *reserved_metadata {
            return Err(invalid(
                "Hermes native metadata does not match the gateway reservation",
            ));
        }
        Ok(Some(self.approved_state(
            path,
            &expected.fingerprint(),
            NativeState::regular_file(bytes, metadata),
        )?))
    }

    fn gateway_reserved_state(
        &self,
        path: &Path,
        state: &NativeState,
    ) -> Result<NativeState, ClientError> {
        if path.parent() != Some(self.layout.profile.hermes_home.as_path()) {
            return Ok(state.clone());
        }
        let lock = OsNativeFileSystem::new()
            .snapshot(&self.layout.profile.hermes_home.join("gateway.lock"))
            .map_err(|_| invalid("Hermes gateway lock cannot be safely inspected"))?;
        if matches!(lock.state(), NativeState::RegularFile { .. }) {
            return Ok(state.clone());
        }
        let NativeState::RegularFile { bytes, metadata } = state else {
            return Err(invalid(
                "Hermes profile-root creation requires an existing gateway lock",
            ));
        };
        let metadata = metadata
            .for_absent_sibling_creation(lock.state())
            .map_err(|_| invalid("Hermes gateway lock reservation changed"))?;
        Ok(NativeState::regular_file(bytes.clone(), metadata))
    }

    fn approved_state(
        &self,
        path: &Path,
        expected: &[u8; 32],
        intended: NativeState,
    ) -> Result<ApprovedMutation, ClientError> {
        Ok(ApprovedMutation {
            target: wire_path(path),
            kind: MutationKind::Payload,
            content: intended
                .encode_v1()
                .map_err(|_| invalid("Hermes native state is not representable"))?,
            expected: RestorableStateFingerprint(Sha256Digest(*expected)),
            intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
        })
    }

    fn markdown_path(&self, component: &ComponentRecord) -> Result<PathBuf, ClientError> {
        let location = structural_location(component)?;
        let path = if location == "profile:SOUL.md"
            && component.kind == ComponentKind::Rule
            && matches!(component.scope, ScopeRef::Global)
        {
            self.layout.profile.hermes_home.join("SOUL.md")
        } else if let Some(relative) = location.strip_prefix("profile:skills/") {
            if component.kind != ComponentKind::Skill || !relative.ends_with("/SKILL.md") {
                return Err(invalid("Hermes skill location is invalid"));
            }
            safe_relative(relative)?;
            self.layout
                .profile
                .hermes_home
                .join("skills")
                .join(relative)
        } else if let Some(relative) = location.strip_prefix("project:") {
            if !matches!(
                component.scope,
                ScopeRef::Project {
                    project_id
                } if project_id == self.project_id
            ) || !matches!(
                component.kind,
                ComponentKind::Instruction | ComponentKind::Rule
            ) || !(relative.ends_with("/.hermes.md")
                || relative.ends_with("/HERMES.md")
                || matches!(relative, ".hermes.md" | "HERMES.md"))
            {
                return Err(invalid("Hermes project Markdown location is invalid"));
            }
            safe_relative(relative)?;
            self.layout.project_root.join(relative)
        } else {
            return Err(invalid("Hermes Markdown location is invalid"));
        };
        Ok(path)
    }

    fn validate_gateway_hook_pair(
        &self,
        manifest: &ComponentRecord,
        handler: Option<&ComponentRecord>,
    ) -> Result<(), ClientError> {
        self.validate_component(manifest)?;
        if manifest.kind != ComponentKind::Hook
            || !structural_location(manifest)?.ends_with("/HOOK.yaml")
            || metadata(manifest, "gatewayHook") != Some("true")
        {
            return Err(invalid("Hermes gateway hook manifest is invalid"));
        }
        if let Some(handler) = handler {
            self.validate_component(handler)?;
            if handler.kind != ComponentKind::Hook
                || metadata(handler, "gatewayHook") != Some("true")
                || !structural_location(handler)?.ends_with("/handler.py")
                || structural_location(handler)?.strip_suffix("/handler.py")
                    != structural_location(manifest)?.strip_suffix("/HOOK.yaml")
            {
                return Err(invalid("Hermes gateway hook handler is invalid"));
            }
        }
        Ok(())
    }

    fn gateway_hook_path(&self, component: &ComponentRecord) -> Result<PathBuf, ClientError> {
        let relative = structural_location(component)?
            .strip_prefix("profile:")
            .ok_or_else(|| invalid("Hermes gateway hook location is invalid"))?;
        safe_relative(relative)?;
        if !relative.starts_with("hooks/")
            || !(relative.ends_with("/HOOK.yaml") || relative.ends_with("/handler.py"))
        {
            return Err(invalid("Hermes gateway hook location is invalid"));
        }
        Ok(self.layout.profile.hermes_home.join(relative))
    }

    fn reviewed_permission_paths(&self) -> Result<BTreeSet<String>, ClientError> {
        let bytes = read_regular(
            &self.layout.profile.hermes_home.join("config.yaml"),
            "Hermes config must be a regular file",
        )?;
        let parsed = super::yaml::parse_config(&bytes)?;
        Ok(import::project_reviewed_config(
            &parsed,
            &self.layout.profile.name,
            &self.layout.version,
        )?
        .into_iter()
        .filter(|component| component.kind == ComponentKind::PermissionDeclaration)
        .filter_map(|component| metadata(&component, "nativePermissionPath").map(str::to_owned))
        .collect())
    }
}

impl NativeMemoryAdapter for HermesAdapter {
    fn native_memory_capabilities(&self) -> Result<NativeMemoryCapabilities, ClientError> {
        let memory_root = self.layout.profile.hermes_home.join("memories");
        let sources = vec![
            native_memory_source(
                HarnessId::Hermes,
                &self.layout.version,
                ScopeRef::Global,
                NativeMemoryDocumentKind::Agent,
                wire_path(&memory_root.join("MEMORY.md")),
            )?,
            native_memory_source(
                HarnessId::Hermes,
                &self.layout.version,
                ScopeRef::Global,
                NativeMemoryDocumentKind::UserProfile,
                wire_path(&memory_root.join("USER.md")),
            )?,
        ];
        if self.require_apply_supported().is_err() {
            let capabilities = NativeMemoryCapabilities {
                disable: NativeMemoryDisable::WatchOnly,
                sources,
            };
            capabilities.validate()?;
            return Ok(capabilities);
        }

        let path = self.layout.profile.hermes_home.join("config.yaml");
        let snapshot = match OsNativeFileSystem::new().snapshot(&path) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                return Ok(NativeMemoryCapabilities {
                    disable: NativeMemoryDisable::WatchOnly,
                    sources,
                });
            }
        };
        let NativeState::RegularFile { bytes, metadata } = snapshot.state() else {
            return Ok(NativeMemoryCapabilities {
                disable: NativeMemoryDisable::WatchOnly,
                sources,
            });
        };
        let parsed = match super::yaml::parse_config(bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                return Ok(NativeMemoryCapabilities {
                    disable: NativeMemoryDisable::WatchOnly,
                    sources,
                });
            }
        };
        let memory = resolve_yaml(&parsed.value, &["memory"]);
        let supported_shape = memory.is_none_or(|value| {
            value.as_mapping().is_some_and(|mapping| {
                ["memory_enabled", "user_profile_enabled"]
                    .iter()
                    .all(|key| {
                        mapping
                            .get(YamlValue::String((*key).to_owned()))
                            .is_none_or(|value| value.as_bool().is_some())
                    })
            })
        });
        if !supported_shape {
            let capabilities = NativeMemoryCapabilities {
                disable: NativeMemoryDisable::WatchOnly,
                sources,
            };
            capabilities.validate()?;
            return Ok(capabilities);
        }
        let already_disabled = memory.is_some_and(|value| {
            value.as_mapping().is_some_and(|mapping| {
                ["memory_enabled", "user_profile_enabled"]
                    .iter()
                    .all(|key| {
                        mapping
                            .get(YamlValue::String((*key).to_owned()))
                            .and_then(YamlValue::as_bool)
                            == Some(false)
                    })
            })
        });
        let mutations = if already_disabled {
            vec![]
        } else {
            let mut replacements = BTreeMap::<Vec<String>, Option<YamlValue>>::new();
            let rendered = if memory.is_none() {
                let mut mapping = serde_yaml_ng::Mapping::new();
                mapping.insert(
                    YamlValue::String("memory_enabled".to_owned()),
                    YamlValue::Bool(false),
                );
                mapping.insert(
                    YamlValue::String("user_profile_enabled".to_owned()),
                    YamlValue::Bool(false),
                );
                replacements.insert(vec!["memory".to_owned()], Some(YamlValue::Mapping(mapping)));
                match super::yaml::patch_owned_paths(&parsed, &replacements) {
                    Ok(rendered) => rendered,
                    Err(_) => {
                        return Ok(NativeMemoryCapabilities {
                            disable: NativeMemoryDisable::WatchOnly,
                            sources,
                        });
                    }
                }
            } else {
                let mut scalar_replacements = BTreeMap::new();
                for key in ["memory_enabled", "user_profile_enabled"] {
                    let key_path = vec!["memory".to_owned(), key.to_owned()];
                    if resolve_yaml(&parsed.value, &["memory", key]).is_some() {
                        scalar_replacements.insert(key_path, false);
                    } else {
                        replacements.insert(key_path, Some(YamlValue::Bool(false)));
                    }
                }
                let scalar_rendered =
                    match super::yaml::patch_owned_boolean_scalars(&parsed, &scalar_replacements) {
                        Ok(rendered) => rendered,
                        Err(_) => {
                            return Ok(NativeMemoryCapabilities {
                                disable: NativeMemoryDisable::WatchOnly,
                                sources,
                            });
                        }
                    };
                if replacements.is_empty() {
                    scalar_rendered
                } else {
                    let reparsed = match super::yaml::parse_config(&scalar_rendered) {
                        Ok(reparsed) => reparsed,
                        Err(_) => {
                            return Ok(NativeMemoryCapabilities {
                                disable: NativeMemoryDisable::WatchOnly,
                                sources,
                            });
                        }
                    };
                    match super::yaml::patch_owned_paths(&reparsed, &replacements) {
                        Ok(rendered) => rendered,
                        Err(_) => {
                            return Ok(NativeMemoryCapabilities {
                                disable: NativeMemoryDisable::WatchOnly,
                                sources,
                            });
                        }
                    }
                }
            };
            let intended = NativeState::regular_file(rendered, metadata.clone());
            vec![self.approved_state(&path, snapshot.fingerprint(), intended)?]
        };
        let capabilities = NativeMemoryCapabilities {
            disable: NativeMemoryDisable::Supported(mutations),
            sources,
        };
        capabilities.validate()?;
        Ok(capabilities)
    }
}

pub(super) fn render_managed_markdown(
    existing: &[u8],
    desired_body: &str,
    archived: bool,
) -> Result<Vec<u8>, ClientError> {
    if desired_body.contains(MANAGED_START) || desired_body.contains(MANAGED_END) {
        return Err(invalid("Hermes desired body contains a managed marker"));
    }
    super::yaml::scan_text_secret(desired_body.as_bytes(), "managed:markdown")?;
    let text =
        std::str::from_utf8(existing).map_err(|_| invalid("Hermes Markdown is not valid UTF-8"))?;
    let newline = line_ending(text)?;
    let starts = text.match_indices(MANAGED_START).collect::<Vec<_>>();
    let ends = text.match_indices(MANAGED_END).collect::<Vec<_>>();
    if starts.is_empty() && ends.is_empty() {
        if archived || existing == desired_body.as_bytes() {
            return Ok(existing.to_vec());
        }
        let mut rendered = existing.to_vec();
        if !rendered.is_empty() && !rendered.ends_with(newline.as_bytes()) {
            rendered.extend_from_slice(newline.as_bytes());
        }
        rendered.extend_from_slice(managed_block(desired_body, newline).as_bytes());
        return Ok(rendered);
    }
    if starts.len() != 1 || ends.len() != 1 || starts[0].0 >= ends[0].0 {
        return Err(invalid("Hermes managed Markdown markers are malformed"));
    }
    let start = line_start(text, starts[0].0);
    let start_marker_end = starts[0].0 + MANAGED_START.len();
    let end_line_start = line_start(text, ends[0].0);
    let end_marker_end = ends[0].0 + MANAGED_END.len();
    let end = if text[end_marker_end..].starts_with("\r\n") {
        end_marker_end + 2
    } else if text[end_marker_end..].starts_with('\n') {
        end_marker_end + 1
    } else {
        end_marker_end
    };
    let start_terminated =
        text[start_marker_end..].starts_with("\r\n") || text[start_marker_end..].starts_with('\n');
    let end_terminated = end_marker_end == text.len()
        || text[end_marker_end..].starts_with("\r\n")
        || text[end_marker_end..].starts_with('\n');
    if !text[start..starts[0].0].trim().is_empty()
        || !start_terminated
        || !text[end_line_start..ends[0].0].trim().is_empty()
        || !end_terminated
        || !text[ends[0].0 + MANAGED_END.len()..end].trim().is_empty()
    {
        return Err(invalid("Hermes managed Markdown markers are malformed"));
    }
    let mut rendered = existing[..start].to_vec();
    if !archived {
        rendered.extend_from_slice(managed_block(desired_body, newline).as_bytes());
    }
    rendered.extend_from_slice(&existing[end..]);
    Ok(rendered)
}

pub(super) fn validate_managed_markdown(existing: &[u8]) -> Result<(), ClientError> {
    let text =
        std::str::from_utf8(existing).map_err(|_| invalid("Hermes Markdown is not valid UTF-8"))?;
    let _ = line_ending(text)?;
    let starts = text.match_indices(MANAGED_START).collect::<Vec<_>>();
    let ends = text.match_indices(MANAGED_END).collect::<Vec<_>>();
    if starts.is_empty() && ends.is_empty() {
        return Ok(());
    }
    if starts.len() != 1 || ends.len() != 1 || starts[0].0 >= ends[0].0 {
        return Err(invalid("Hermes managed Markdown markers are malformed"));
    }
    let start = line_start(text, starts[0].0);
    let start_marker_end = starts[0].0 + MANAGED_START.len();
    let end_line_start = line_start(text, ends[0].0);
    let end_marker_end = ends[0].0 + MANAGED_END.len();
    let end = if text[end_marker_end..].starts_with("\r\n") {
        end_marker_end + 2
    } else if text[end_marker_end..].starts_with('\n') {
        end_marker_end + 1
    } else {
        end_marker_end
    };
    let start_terminated =
        text[start_marker_end..].starts_with("\r\n") || text[start_marker_end..].starts_with('\n');
    let end_terminated = end_marker_end == text.len()
        || text[end_marker_end..].starts_with("\r\n")
        || text[end_marker_end..].starts_with('\n');
    if !text[start..starts[0].0].trim().is_empty()
        || !start_terminated
        || !text[end_line_start..ends[0].0].trim().is_empty()
        || !end_terminated
        || !text[ends[0].0 + MANAGED_END.len()..end].trim().is_empty()
    {
        return Err(invalid("Hermes managed Markdown markers are malformed"));
    }
    Ok(())
}

fn managed_block(body: &str, newline: &str) -> String {
    let normalized = body.replace("\r\n", "\n");
    let normalized = normalized.trim_end_matches('\n').replace('\n', newline);
    format!("{MANAGED_START}{newline}{normalized}{newline}{MANAGED_END}{newline}")
}

fn line_ending(text: &str) -> Result<&'static str, ClientError> {
    let mut lf = false;
    let mut crlf = false;
    for (index, byte) in text.as_bytes().iter().enumerate() {
        if *byte == b'\n' {
            if index > 0 && text.as_bytes()[index - 1] == b'\r' {
                crlf = true;
            } else {
                lf = true;
            }
        }
    }
    if lf && crlf {
        return Err(invalid("Hermes Markdown mixes line-ending conventions"));
    }
    Ok(if crlf { "\r\n" } else { "\n" })
}

fn line_start(text: &str, offset: usize) -> usize {
    text[..offset].rfind('\n').map_or(0, |index| index + 1)
}

fn is_config_component(component: &ComponentRecord) -> bool {
    metadata(component, "structuralLocation").is_some_and(|location| {
        location.starts_with("config:")
            && matches!(
                component.kind,
                ComponentKind::PermissionDeclaration
                    | ComponentKind::Plugin
                    | ComponentKind::McpServer
                    | ComponentKind::Hook
            )
    })
}

fn is_gateway_hook_component(component: &ComponentRecord) -> bool {
    component.kind == ComponentKind::Hook
        && metadata(component, "gatewayHook") == Some("true")
        && metadata(component, "structuralLocation")
            .is_some_and(|location| location.starts_with("profile:hooks/"))
}

fn structural_location(component: &ComponentRecord) -> Result<&str, ClientError> {
    metadata(component, "structuralLocation")
        .ok_or_else(|| invalid("Hermes component structural location is missing"))
}

fn metadata<'a>(component: &'a ComponentRecord, key: &str) -> Option<&'a str> {
    component
        .metadata
        .iter()
        .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
}

fn permission_path(component: &ComponentRecord) -> Result<Vec<String>, ClientError> {
    let path = metadata(component, "nativePermissionPath")
        .ok_or_else(|| invalid("Hermes permission path is missing"))?;
    let parts = path.split('.').map(str::to_owned).collect::<Vec<_>>();
    if !matches!(
        parts.as_slice(),
        [root] if root == "approvals" || root == "command_allowlist"
    ) && !matches!(parts.as_slice(), [root, _] if root == "approvals")
    {
        return Err(invalid("Hermes permission path is invalid"));
    }
    Ok(parts)
}

fn plugin_name_from_location(location: &str) -> Result<&str, ClientError> {
    location
        .strip_prefix("config:plugins.enabled.")
        .or_else(|| location.strip_prefix("config:plugins.disabled."))
        .filter(|name| safe_name(name))
        .ok_or_else(|| invalid("Hermes plugin state location is invalid"))
}

fn config_child_name<'a>(location: &'a str, prefix: &str) -> Result<&'a str, ClientError> {
    location
        .strip_prefix(prefix)
        .filter(|name| safe_name(name))
        .ok_or_else(|| invalid("Hermes config component location is invalid"))
}

fn safe_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && !matches!(name, "." | "..")
}

fn safe_relative(relative: &str) -> Result<(), ClientError> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component.as_os_str().to_str().is_none_or(|part| {
                    part.contains(['/', '\\']) || part.chars().any(char::is_control)
                })
        })
    {
        return Err(invalid("Hermes relative path is unsafe"));
    }
    Ok(())
}

fn json_to_yaml(body: &str) -> Result<YamlValue, ClientError> {
    let json: JsonValue =
        serde_json::from_str(body).map_err(|_| invalid("Hermes component body is invalid"))?;
    serde_yaml_ng::to_value(json).map_err(|_| invalid("Hermes component body is invalid"))
}

fn resolve_yaml<'a>(mut value: &'a YamlValue, path: &[&str]) -> Option<&'a YamlValue> {
    for part in path {
        value = value
            .as_mapping()?
            .get(YamlValue::String((*part).to_owned()))?;
    }
    Some(value)
}

fn yaml_string_list(values: Option<&Vec<YamlValue>>) -> Result<Vec<String>, ClientError> {
    let values = values
        .into_iter()
        .flatten()
        .map(|value| {
            value
                .as_str()
                .filter(|name| safe_name(name))
                .map(str::to_owned)
                .ok_or_else(|| invalid("Hermes plugin state is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut unique = BTreeSet::new();
    if values.iter().any(|value| !unique.insert(value)) {
        return Err(invalid("Hermes plugin state is repeated"));
    }
    Ok(values)
}

fn merge_reviewed_mapping(
    current: Option<&YamlValue>,
    desired: &YamlValue,
    reviewed_keys: &[&str],
    archived: bool,
) -> Result<YamlValue, ClientError> {
    let desired = desired
        .as_mapping()
        .ok_or_else(|| invalid("Hermes component body must be an object"))?;
    let mut merged = current
        .and_then(YamlValue::as_mapping)
        .cloned()
        .unwrap_or_default();
    let keys = if reviewed_keys.is_empty() {
        desired
            .keys()
            .filter_map(YamlValue::as_str)
            .collect::<Vec<_>>()
    } else {
        reviewed_keys.to_vec()
    };
    for key in keys {
        let yaml_key = YamlValue::String(key.to_owned());
        if let Some(value) = desired.get(&yaml_key) {
            merged.insert(yaml_key, value.clone());
        } else {
            merged.remove(&yaml_key);
        }
    }
    if archived {
        merged.insert(YamlValue::String("enabled".into()), YamlValue::Bool(false));
    }
    Ok(YamlValue::Mapping(merged))
}

fn collect_redacted_scalar_edits(
    current: Option<&JsonValue>,
    desired: Option<&JsonValue>,
    path: &mut Vec<String>,
    replacements: &mut BTreeMap<Vec<String>, Option<YamlValue>>,
) -> Result<(), ClientError> {
    if current == desired {
        return Ok(());
    }
    match (current, desired) {
        (Some(JsonValue::Object(current)), Some(JsonValue::Object(desired))) => {
            let keys = current
                .keys()
                .chain(desired.keys())
                .collect::<BTreeSet<_>>();
            for key in keys {
                path.push(key.clone());
                collect_redacted_scalar_edits(
                    current.get(key),
                    desired.get(key),
                    path,
                    replacements,
                )?;
                path.pop();
            }
            Ok(())
        }
        (Some(JsonValue::Object(current)), None) => {
            for (key, value) in current {
                path.push(key.clone());
                collect_redacted_scalar_edits(Some(value), None, path, replacements)?;
                path.pop();
            }
            Ok(())
        }
        (None, Some(JsonValue::Object(_)))
        | (Some(JsonValue::Object(_)), Some(_))
        | (Some(_), Some(JsonValue::Object(_)))
        | (Some(JsonValue::Array(_)), _)
        | (_, Some(JsonValue::Array(_))) => Err(invalid(
            "Redacted Hermes collection changes cannot be rendered safely",
        )),
        (Some(_), None) => {
            replacements.insert(path.clone(), None);
            Ok(())
        }
        (None, Some(_)) => Err(invalid(
            "Redacted Hermes configuration cannot add unreviewed scalar leaves",
        )),
        (Some(_), Some(value)) => {
            let value = serde_yaml_ng::to_value(value)
                .map_err(|_| invalid("Hermes reviewed scalar is invalid"))?;
            if matches!(value, YamlValue::Mapping(_) | YamlValue::Sequence(_)) {
                return Err(invalid(
                    "Redacted Hermes collection changes cannot be rendered safely",
                ));
            }
            replacements.insert(path.clone(), Some(value));
            Ok(())
        }
        (None, None) => Ok(()),
    }
}

fn set_mapping_bool(value: &mut YamlValue, key: &str, enabled: bool) -> Result<(), ClientError> {
    value
        .as_mapping_mut()
        .ok_or_else(|| invalid("Hermes component body must be an object"))?
        .insert(YamlValue::String(key.into()), YamlValue::Bool(enabled));
    Ok(())
}

fn normalize_missing_root_replacements(
    current: &YamlValue,
    replacements: &mut BTreeMap<Vec<String>, Option<YamlValue>>,
    root: &str,
) {
    if resolve_yaml(current, &[root]).is_some() {
        return;
    }
    let children = replacements
        .keys()
        .filter(|path| path.len() == 2 && path[0] == root)
        .cloned()
        .collect::<Vec<_>>();
    if children.is_empty() {
        return;
    }
    let mut mapping = serde_yaml_ng::Mapping::new();
    for path in children {
        if let Some(Some(value)) = replacements.remove(&path) {
            mapping.insert(YamlValue::String(path[1].clone()), value);
        }
    }
    replacements.insert(vec![root.into()], Some(YamlValue::Mapping(mapping)));
}

fn rendered_file(path: PathBuf, bytes: &[u8]) -> RenderedFile {
    RenderedFile {
        path: wire_path(&path),
        bytes_sha256: Sha256Digest(Sha256::digest(bytes).into()),
        byte_length: bytes.len() as u64,
    }
}

fn read_regular(path: &Path, message: &'static str) -> Result<Vec<u8>, ClientError> {
    read_optional_regular(path)?.ok_or_else(|| invalid(message))
}

fn read_optional_regular(path: &Path) -> Result<Option<Vec<u8>>, ClientError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid("Hermes native file cannot be inspected")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid("Hermes native target is not a regular file"));
    }
    std::fs::read(path)
        .map(Some)
        .map_err(|_| invalid("Hermes native file cannot be read"))
}

fn scope_key(scope: &ScopeRef) -> String {
    match scope {
        ScopeRef::Global => "global".into(),
        ScopeRef::Project { project_id } => format!("project:{project_id}"),
    }
}

fn valid_nonpermission_target(target: &str, profile: &str) -> bool {
    let parts = target.split('|').collect::<Vec<_>>();
    parts.len() >= 3
        && matches!(
            parts[0],
            "hermes-config" | "hermes-markdown" | "hermes-memory" | "hermes-gateway-hook"
        )
        && parts[1] == profile
        && !parts.iter().any(|part| part.is_empty())
}

fn is_passive_change_target(target: &str) -> bool {
    target.starts_with("hermes-markdown|") || target.starts_with("hermes-memory|")
}
