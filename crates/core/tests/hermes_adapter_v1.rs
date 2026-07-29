use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use context_relay_core::hermes::{
    HermesAdapter, HermesExecutableKind, HermesLayout, HermesMemoryKind, HermesProfile,
};
use context_relay_protocol::{
    CapabilityLevel, ComponentKind, ComponentRecord, DeviceId, ErrorCode, HarnessAdapter,
    HarnessId, HybridLogicalClock, ImportRequest, InstallationMethod, NativeScope, ProbeContext,
    ProjectId,
};
use serde_json::{Map, Value};

const PROJECT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Fixture {
    root: PathBuf,
    adapter: HermesAdapter,
    layout: HermesLayout,
    project_id: ProjectId,
    default_home: PathBuf,
    profiles_root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fixture(source: &str) -> Fixture {
    let source: Value = serde_json::from_str(source).unwrap();
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "context-relay-hermes-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
    let default_home = root.join("hermes home");
    let profiles_root = default_home.join("profiles");
    let project_root = root.join("project with spaces");
    let working_directory = project_root.join("service");
    let profile = source["profile"].as_object().unwrap();
    let files = profile["files"].as_object().unwrap();
    materialize_profile(&default_home, profile, files);
    materialize_profile(&profiles_root.join("coder"), profile, files);
    materialize_profile(&profiles_root.join("writer"), profile, files);
    materialize(&project_root, source["project"].as_object().unwrap());
    fs::create_dir_all(&working_directory).unwrap();

    // Keep the operational canaries in place so import tests prove they are excluded.
    for profile_root in [
        &default_home,
        &profiles_root.join("coder"),
        &profiles_root.join("writer"),
    ] {
        assert!(profile_root.join("gateway.pid").is_file());
        assert!(profile_root.join("gateway_state.json").is_file());
    }

    let executable = root.join("hermes");
    fs::write(&executable, b"\x7fELFfixture hermes executable").unwrap();
    let project_id = ProjectId::from_str(PROJECT_ID).unwrap();
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let layout = HermesLayout {
        executable,
        executable_kind: HermesExecutableKind::Native,
        version: source["version"].as_str().unwrap().to_owned(),
        installation_method: InstallationMethod::PackageManager,
        default_hermes_home: default_home.clone(),
        profile: HermesProfile {
            name: "coder".to_owned(),
            hermes_home: profiles_root.join("coder"),
        },
        project_root,
        working_directory,
    };
    let adapter = HermesAdapter::from_layout(
        layout.clone(),
        project_id,
        device_id,
        HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
    )
    .unwrap();
    Fixture {
        root,
        adapter,
        layout,
        project_id,
        default_home,
        profiles_root,
    }
}

fn materialize_profile(root: &Path, profile: &Map<String, Value>, files: &Map<String, Value>) {
    materialize(root, files);
    fs::write(
        root.join("config.yaml"),
        profile["configYaml"].as_str().unwrap(),
    )
    .unwrap();
}

fn materialize(root: &Path, files: &Map<String, Value>) {
    for (relative, body) in files {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body.as_str().unwrap()).unwrap();
    }
}

fn profile_layout(
    fixture: &Fixture,
    name: &str,
    version: &str,
    kind: HermesExecutableKind,
) -> HermesLayout {
    HermesLayout {
        executable: fixture.layout.executable.clone(),
        executable_kind: kind,
        version: version.to_owned(),
        installation_method: fixture.layout.installation_method,
        default_hermes_home: fixture.default_home.clone(),
        profile: HermesProfile {
            name: name.to_owned(),
            hermes_home: if name == "default" {
                fixture.default_home.clone()
            } else {
                fixture.profiles_root.join(name)
            },
        },
        project_root: fixture.layout.project_root.clone(),
        working_directory: fixture.layout.working_directory.clone(),
    }
}

fn probe(
    adapter: &HermesAdapter,
    requested_profile: Option<&str>,
) -> context_relay_protocol::ProbeReport {
    adapter
        .probe(&ProbeContext {
            harness: HarnessId::Hermes,
            requested_profile: requested_profile.map(str::to_owned),
        })
        .unwrap()
}

fn import_everything(
    fixture: &Fixture,
    include_disabled: bool,
) -> context_relay_protocol::ImportedState {
    match fixture.adapter.import(&ImportRequest {
        scopes: vec![
            NativeScope::Global,
            NativeScope::Project {
                project_id: fixture.project_id,
                root: fixture.adapter.project_root_wire(),
            },
        ],
        include_disabled,
    }) {
        Ok(imported) => imported,
        Err(error) => {
            let diagnostic = format!("{error:?}");
            assert!(
                !diagnostic.contains("must-not-import"),
                "Hermes import error exposed a secret canary"
            );
            panic!("Hermes import unexpectedly failed with {:?}", error.code);
        }
    }
}

fn metadata<'a>(component: &'a ComponentRecord, key: &str) -> Option<&'a str> {
    component
        .metadata
        .iter()
        .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
}

fn global_import_error(fixture: &Fixture) -> context_relay_protocol::ClientError {
    fixture
        .adapter
        .import(&ImportRequest {
            scopes: vec![NativeScope::Global],
            include_disabled: true,
        })
        .unwrap_err()
}

fn install_non_execution_sentinels(fixture: &Fixture) -> Vec<PathBuf> {
    let profile = &fixture.layout.profile.hermes_home;
    let mcp = fixture.root.join("mcp-ran");
    let plugin = fixture.root.join("plugin-ran");
    let hook = fixture.root.join("hook-ran");
    let config = fs::read_to_string(profile.join("config.yaml"))
        .unwrap()
        .replace(
            "command: node",
            &format!("command: \"touch {}\"", mcp.display()),
        );
    fs::write(profile.join("config.yaml"), config).unwrap();
    fs::write(
        profile.join("plugins/reviewer/plugin.py"),
        format!(
            "from pathlib import Path\nPath({:?}).touch()\n",
            plugin.to_string_lossy()
        ),
    )
    .unwrap();
    fs::write(
        profile.join("hooks/audit/handler.py"),
        format!(
            "from pathlib import Path\nPath({:?}).touch()\n",
            hook.to_string_lossy()
        ),
    )
    .unwrap();
    vec![mcp, plugin, hook]
}

#[test]
fn supported_release_fixtures_bind_one_named_profile() {
    for source in [
        include_str!("fixtures/hermes-0.18.2.json"),
        include_str!("fixtures/hermes-0.18.1.json"),
    ] {
        let fixture = fixture(source);
        let report = probe(&fixture.adapter, Some("coder"));
        assert_eq!(report.capability, CapabilityLevel::Full);
        assert_eq!(report.active_profile.as_deref(), Some("coder"));
        assert_eq!(
            report.policy_conflicts,
            vec![
                "approval_mode_not_portable".to_owned(),
                "deny_pattern_not_portable".to_owned(),
                "permanent_allowlist_not_portable".to_owned(),
            ]
        );
        assert_eq!(
            report.config_roots,
            vec![
                fixture.adapter.profile_home_wire(),
                fixture.adapter.project_root_wire()
            ]
        );
    }
}

#[test]
fn supported_releases_import_every_reviewed_component_kind() {
    for source in [
        include_str!("fixtures/hermes-0.18.2.json"),
        include_str!("fixtures/hermes-0.18.1.json"),
    ] {
        let fixture = fixture(source);
        let imported = import_everything(&fixture, true);
        for kind in [
            ComponentKind::Instruction,
            ComponentKind::Rule,
            ComponentKind::Skill,
            ComponentKind::Plugin,
            ComponentKind::McpServer,
            ComponentKind::Hook,
            ComponentKind::PermissionDeclaration,
        ] {
            assert!(
                imported
                    .components
                    .iter()
                    .any(|component| component.kind == kind),
                "missing {kind:?}"
            );
        }
        for name in ["reviewer", "legacy"] {
            assert!(imported.components.iter().any(|component| {
                component.kind == ComponentKind::Plugin && component.name == name
            }));
        }
        for name in ["docs", "local"] {
            assert!(imported.components.iter().any(|component| {
                component.kind == ComponentKind::McpServer && component.name == name
            }));
        }
        for (kind, name, location) in [
            (ComponentKind::Hook, "shell", "config:hooks.shell"),
            (
                ComponentKind::Hook,
                "audit",
                "profile:hooks/audit/HOOK.yaml",
            ),
            (
                ComponentKind::Hook,
                "audit/handler.py",
                "profile:hooks/audit/handler.py",
            ),
            (
                ComponentKind::Skill,
                "review",
                "profile:skills/review/SKILL.md",
            ),
        ] {
            assert!(imported.components.iter().any(|component| {
                component.kind == kind
                    && component.name == name
                    && metadata(component, "structuralLocation") == Some(location)
            }));
        }
        let permission_reasons = imported
            .components
            .iter()
            .filter(|component| component.kind == ComponentKind::PermissionDeclaration)
            .filter_map(|component| metadata(component, "mappingReason"))
            .collect::<std::collections::BTreeSet<_>>();
        assert!(permission_reasons.contains("approval_mode_not_portable"));
        assert!(permission_reasons.contains("deny_pattern_not_portable"));
        assert!(permission_reasons.contains("permanent_allowlist_not_portable"));
        for component in &imported.components {
            assert_eq!(metadata(component, "profile"), Some("coder"));
            assert!(metadata(component, "structuralLocation").is_some());
            assert!(metadata(component, "nativeFormat").is_some());
        }
    }
}

#[test]
fn import_serialization_contains_no_secret_or_operational_canary() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let imported = import_everything(&fixture, true);
    let memories = fixture.adapter.import_native_memory().unwrap();
    let serialized =
        format!("{}|{memories:?}", serde_json::to_string(&imported).unwrap()).to_ascii_lowercase();
    for excluded in [
        "must-not-import",
        "openrouter_api_key",
        "authorization",
        ".env",
        "auth.json",
        "sessions",
        "state.db",
        "gateway.pid",
        "gateway_state.json",
        "channels",
        "logs",
    ] {
        assert!(
            !serialized.contains(excluded),
            "serialized Hermes import exposed {excluded}"
        );
    }
}

#[test]
fn secret_bearing_yaml_fields_are_removed_before_component_creation() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let imported = import_everything(&fixture, true);
    let serialized = serde_json::to_string(&imported).unwrap();
    for secret in [
        "must-not-import-yaml-header",
        "must-not-import-yaml-env",
        "must-not-import-provider-key",
    ] {
        assert!(!serialized.contains(secret));
    }
    let docs = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::McpServer && component.name == "docs")
        .unwrap();
    assert_eq!(metadata(docs, "redacted"), Some("true"));
    assert_eq!(metadata(docs, "secretReferenceNames"), Some("HEADER_TOKEN"));
    assert!(!docs.body_markdown.contains("headers"));
    let local = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::McpServer && component.name == "local")
        .unwrap();
    assert_eq!(metadata(local, "redacted"), Some("true"));
    assert_eq!(metadata(local, "secretReferenceNames"), Some("DOCS_TOKEN"));
    assert!(!local.body_markdown.contains("env"));
}

#[test]
fn embedded_secret_text_is_removed_from_mcp_and_hook_components() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        r#"mcp_servers:
  authorization:
    command: "curl -H 'Authorization: Bearer must-not-import-mcp-authorization'"
    enabled: true
  basic:
    args:
      - "--header Basic must-not-import-mcp-basic"
    enabled: true
  private_key:
    command: "loader --value prefix-----BEGIN PRIVATE KEY-----must-not-import-mcp-private"
    enabled: true
  token:
    args:
      - "--token=prefix:ghp_must-not-import-mcp-token"
    enabled: true
  credential_url:
    url: "proxy=https://must-not-import-user:must-not-import-password@example.com/mcp"
    enabled: true
hooks:
  scalar_guard:
    enabled: true
    preflight: "runner --header 'Authorization: Bearer must-not-import-hook-authorization'"
    fallback: "runner --header Basic must-not-import-hook-basic"
    loader: "loader prefix-----BEGIN OPENSSH PRIVATE KEY-----must-not-import-hook-private"
    notifier: "runner --token=prefix:github_pat_must-not-import-hook-token"
    callback: "proxy=https://must-not-import-hook-user:must-not-import-hook-password@example.com/callback"
"#,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let serialized = serde_json::to_string(&imported).unwrap();
    assert!(
        !serialized.contains("must-not-import"),
        "serialized Hermes import exposed an embedded scalar canary"
    );

    for name in [
        "authorization",
        "basic",
        "private_key",
        "token",
        "credential_url",
    ] {
        let component = imported
            .components
            .iter()
            .find(|component| component.kind == ComponentKind::McpServer && component.name == name)
            .unwrap();
        assert_eq!(metadata(component, "redacted"), Some("true"));
        assert!(
            !component.body_markdown.contains("Authorization")
                && !component.body_markdown.contains("Bearer")
                && !component.body_markdown.contains("Basic")
                && !component.body_markdown.contains("PRIVATE KEY")
                && !component.body_markdown.contains("ghp_")
                && !component.body_markdown.contains('@'),
            "MCP component retained secret-like scalar text"
        );
    }

    let hook = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::Hook && component.name == "scalar_guard")
        .unwrap();
    assert_eq!(metadata(hook, "redacted"), Some("true"));
    assert_eq!(hook.body_markdown, r#"{"enabled":true}"#);
}

#[test]
fn nested_auth_structures_are_removed_from_mcp_and_hook_components() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        r#"mcp_servers:
  nested_auth:
    command: safe-runner
    tools:
      prompts:
        safe: safe-prompt
        oauth:
          access_token: must-not-import-mcp-access
          refresh_token: must-not-import-mcp-refresh
          client_secret: must-not-import-mcp-client
        authorization_code:
          code: must-not-import-mcp-code
        credentials:
          value: must-not-import-mcp-credential
        access_token: must-not-import-mcp-leaf-access
        refresh_token: must-not-import-mcp-leaf-refresh
        client_secret: must-not-import-mcp-leaf-client
    enabled: true
hooks:
  nested_auth:
    enabled: true
    settings:
      mode: audited
      oauth:
        access_token: must-not-import-hook-access
        refresh_token: must-not-import-hook-refresh
        client_secret: must-not-import-hook-client
      auth:
        code: must-not-import-hook-auth
      authorization_code:
        code: must-not-import-hook-code
      credentials:
        value: must-not-import-hook-credential
      access_token: must-not-import-hook-leaf-access
      refresh_token: must-not-import-hook-leaf-refresh
      client_secret: must-not-import-hook-leaf-client
"#,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let serialized = serde_json::to_string(&imported).unwrap();
    assert!(
        !serialized.contains("must-not-import"),
        "serialized Hermes import exposed a nested credential canary"
    );

    let mcp = imported
        .components
        .iter()
        .find(|component| {
            component.kind == ComponentKind::McpServer && component.name == "nested_auth"
        })
        .unwrap();
    assert_eq!(metadata(mcp, "redacted"), Some("true"));
    assert_eq!(
        mcp.body_markdown,
        r#"{"command":"safe-runner","enabled":true,"tools":{"prompts":{"safe":"safe-prompt"}}}"#
    );

    let hook = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::Hook && component.name == "nested_auth")
        .unwrap();
    assert_eq!(metadata(hook, "redacted"), Some("true"));
    assert_eq!(
        hook.body_markdown,
        r#"{"enabled":true,"settings":{"mode":"audited"}}"#
    );
}

#[test]
fn nested_exact_mcp_placeholders_are_sorted_deduplicated_and_propagated() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        r#"mcp_servers:
  nested_placeholders:
    command:
      oauth:
        access_token: ${COMMAND_TOKEN}
        duplicate: ${SHARED_TOKEN}
        prefixed: prefix-${PREFIXED_TOKEN}
    args:
      credentials:
        value: ${ARGS_TOKEN}
        duplicate: ${SHARED_TOKEN}
        lowercase: ${lowercase_token}
    url:
      auth:
        value: ${URL_TOKEN}
    timeout:
      authorization_code:
        value: ${TIMEOUT_TOKEN}
    connect_timeout:
      oauth2:
        value: ${CONNECT_TIMEOUT_TOKEN}
    idle_timeout_seconds:
      authentication:
        value: ${IDLE_TIMEOUT_TOKEN}
    max_lifetime_seconds:
      credential:
        value: ${MAX_LIFETIME_TOKEN}
    enabled:
      authorization:
        value: ${ENABLED_TOKEN}
    supports_parallel_tool_calls:
      credentials:
        value: ${PARALLEL_TOKEN}
    tools:
      include:
        oauth:
          access_token: ${TOOLS_INCLUDE_TOKEN}
      exclude:
        auth:
          value: ${TOOLS_EXCLUDE_TOKEN}
      prompts:
        authorization_code:
          value: ${TOOLS_PROMPTS_TOKEN}
      resources:
        credentials:
          value: ${TOOLS_RESOURCES_TOKEN}
"#,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let component = imported
        .components
        .iter()
        .find(|component| {
            component.kind == ComponentKind::McpServer && component.name == "nested_placeholders"
        })
        .unwrap();

    assert_eq!(metadata(component, "redacted"), Some("true"));
    assert_eq!(
        metadata(component, "secretReferenceNames"),
        Some(
            "ARGS_TOKEN,COMMAND_TOKEN,CONNECT_TIMEOUT_TOKEN,ENABLED_TOKEN,IDLE_TIMEOUT_TOKEN,\
MAX_LIFETIME_TOKEN,PARALLEL_TOKEN,SHARED_TOKEN,TIMEOUT_TOKEN,TOOLS_EXCLUDE_TOKEN,\
TOOLS_INCLUDE_TOKEN,TOOLS_PROMPTS_TOKEN,TOOLS_RESOURCES_TOKEN,URL_TOKEN"
        )
    );
    assert!(
        !component.body_markdown.contains("${")
            && !component.body_markdown.contains("oauth")
            && !component.body_markdown.contains("auth")
            && !component.body_markdown.contains("credential")
            && !component.body_markdown.contains("authorization")
    );
    assert!(
        !metadata(component, "secretReferenceNames")
            .unwrap()
            .contains("PREFIXED_TOKEN")
            && !metadata(component, "secretReferenceNames")
                .unwrap()
                .contains("lowercase_token"),
        "non-exact placeholder forms entered MCP metadata"
    );
}

#[test]
fn soul_and_nearest_project_context_have_exact_precedence() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let imported = import_everything(&fixture, true);
    let soul = imported
        .components
        .iter()
        .find(|component| metadata(component, "contextRole") == Some("soul"))
        .unwrap();
    assert_eq!(soul.name, "SOUL.md");
    assert_eq!(metadata(soul, "precedenceIndex"), Some("0"));
    assert_eq!(
        metadata(soul, "structuralLocation"),
        Some("profile:SOUL.md")
    );
    assert_eq!(metadata(soul, "profile"), Some("coder"));

    let project = imported
        .components
        .iter()
        .filter(|component| metadata(component, "contextRole") == Some("project"))
        .collect::<Vec<_>>();
    assert_eq!(project.len(), 1);
    assert_eq!(project[0].name, ".hermes.md");
    assert_eq!(metadata(project[0], "precedenceIndex"), Some("1"));
    assert_eq!(
        metadata(project[0], "structuralLocation"),
        Some("project:service/.hermes.md")
    );
    assert_eq!(metadata(project[0], "profile"), Some("coder"));
    assert!(
        project[0]
            .body_markdown
            .contains("Preserve wire contracts.")
    );
    assert!(!project[0].body_markdown.contains("Fallback context."));
    assert!(!project[0].body_markdown.contains("Root context."));
}

#[test]
fn memory_documents_remain_typed_and_separate() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let memories = fixture.adapter.import_native_memory().unwrap();
    assert_eq!(memories.len(), 2);
    assert_eq!(memories[0].kind, HermesMemoryKind::Agent);
    assert_eq!(memories[1].kind, HermesMemoryKind::User);
    assert_ne!(memories[0].body_markdown, memories[1].body_markdown);
    assert_ne!(memories[0].source_digest, memories[1].source_digest);
    let imported = import_everything(&fixture, true);
    assert!(imported.components.iter().all(|component| {
        !component.body_markdown.contains("Hermes-owned prefix.")
            && !component
                .body_markdown
                .contains("User prefers concise output.")
    }));
}

#[test]
fn skills_plugins_and_hooks_are_allowlist_walks() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let sentinels = install_non_execution_sentinels(&fixture);
    let imported = import_everything(&fixture, true);
    let serialized = serde_json::to_string(&imported).unwrap();
    assert!(serialized.contains("Review the diff."));
    assert!(serialized.contains("Nested review guidance."));
    assert!(serialized.contains("Review changes."));
    assert!(serialized.contains("profile:hooks/audit/handler.py"));
    assert!(serialized.contains("Path("));
    assert!(!serialized.contains("plugin.py"));
    assert!(!serialized.contains("requirements.txt"));
    assert!(!serialized.contains("ignored-hook.txt"));
    for sentinel in sentinels {
        assert!(!sentinel.exists(), "{} was executed", sentinel.display());
    }
}

#[test]
fn malformed_yaml_and_unsafe_topology_fail_closed_without_values() {
    let cases = [
        "approvals:\n  mode: smart\n  mode: must-not-import-duplicate\n",
        "approvals: !must-not-import-tag\n  mode: smart\n",
        "unknown: &outside\n  mode: must-not-import-alias\napprovals: *outside\n",
        "approvals:\n  <<: {mode: must-not-import-merge}\n",
        "approvals:\n  ? [not, string]\n  : must-not-import-key\n",
        "approvals:\n  nested:\n    a:\n      b:\n        c:\n          d:\n            e:\n              f:\n                g:\n                  h:\n                    i:\n                      j:\n                        k:\n                          l:\n                            m:\n                              n:\n                                o:\n                                  p:\n                                    q:\n                                      r:\n                                        s:\n                                          t:\n                                            u:\n                                              v:\n                                                w:\n                                                  x:\n                                                    y:\n                                                      z:\n                                                        aa:\n                                                          bb:\n                                                            cc:\n                                                              dd:\n                                                                ee:\n                                                                  ff: must-not-import-depth\n",
    ];
    for yaml in cases {
        let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
        fs::write(fixture.layout.profile.hermes_home.join("config.yaml"), yaml).unwrap();
        let rendered = format!("{:?}", global_import_error(&fixture));
        assert!(!rendered.contains("must-not-import"));
    }

    let collection_fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let collection = (0..257)
        .map(|index| format!("  key{index}: value\n"))
        .collect::<String>();
    fs::write(
        collection_fixture
            .layout
            .profile
            .hermes_home
            .join("config.yaml"),
        format!("approvals:\n{collection}"),
    )
    .unwrap();
    assert!(!format!("{:?}", global_import_error(&collection_fixture)).contains("value"));

    let markdown_fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        markdown_fixture.layout.profile.hermes_home.join("SOUL.md"),
        "-----BEGIN PRIVATE KEY-----\nmust-not-import-markdown\n",
    )
    .unwrap();
    assert!(!format!("{:?}", global_import_error(&markdown_fixture)).contains("must-not-import"));

    #[cfg(unix)]
    {
        let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
        let outside = fixture.root.join("outside-skill");
        fs::write(&outside, "must-not-import-symlink").unwrap();
        let target = fixture
            .layout
            .profile
            .hermes_home
            .join("skills/review/SKILL.md");
        fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink(outside, target).unwrap();
        assert!(!format!("{:?}", global_import_error(&fixture)).contains("must-not-import"));
    }
}

#[test]
fn disabled_components_respect_include_disabled() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let enabled = import_everything(&fixture, false);
    assert!(!enabled.components.iter().any(|component| {
        (component.kind == ComponentKind::Plugin && component.name == "legacy")
            || (component.kind == ComponentKind::McpServer && component.name == "old")
            || (component.kind == ComponentKind::Hook && component.name == "disabled")
    }));
    let all = import_everything(&fixture, true);
    for (kind, name) in [
        (ComponentKind::Plugin, "legacy"),
        (ComponentKind::McpServer, "old"),
        (ComponentKind::Hook, "disabled"),
    ] {
        let component = all
            .components
            .iter()
            .find(|component| component.kind == kind && component.name == name)
            .unwrap();
        assert!(
            component.archived || metadata(component, "enabled") == Some("false"),
            "{kind:?} {name} was not marked disabled"
        );
    }
}

#[test]
fn default_and_named_profiles_are_distinct_explicit_targets() {
    let _env = ENV_LOCK.lock().unwrap();
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let discovered = HermesAdapter::discover_profiles(&fixture.default_home).unwrap();
    assert_eq!(
        discovered
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        vec!["default", "coder", "writer"]
    );
    assert_ne!(discovered[0].hermes_home, discovered[1].hermes_home);
    assert_ne!(discovered[1].hermes_home, discovered[2].hermes_home);
    assert_ne!(discovered[0].hermes_home, discovered[2].hermes_home);
    for profile in discovered {
        let adapter = HermesAdapter::from_layout(
            profile_layout(
                &fixture,
                &profile.name,
                &fixture.layout.version,
                HermesExecutableKind::Native,
            ),
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap();
        assert_eq!(
            adapter.profile_home_wire().display.as_deref(),
            profile.hermes_home.to_str()
        );
    }
}

#[test]
fn unknown_profile_is_rejected_without_fallback_or_creation() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let default_before = fs::read(fixture.default_home.join("config.yaml")).unwrap();
    let coder_before = fs::read(fixture.profiles_root.join("coder/config.yaml")).unwrap();
    let error = HermesAdapter::from_layout(
        profile_layout(
            &fixture,
            "missing",
            &fixture.layout.version,
            HermesExecutableKind::Native,
        ),
        fixture.project_id,
        DeviceId::from_str(DEVICE_ID).unwrap(),
        HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    assert!(!fixture.profiles_root.join("missing").exists());
    assert_eq!(
        fs::read(fixture.default_home.join("config.yaml")).unwrap(),
        default_before
    );
    assert_eq!(
        fs::read(fixture.profiles_root.join("coder/config.yaml")).unwrap(),
        coder_before
    );
}

#[test]
fn invalid_nested_symlinked_and_case_colliding_profiles_are_ignored() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    for name in [
        "-invalid",
        "UPPER",
        "too.long.profile",
        "a".repeat(65).as_str(),
    ] {
        fs::create_dir_all(fixture.profiles_root.join(name)).unwrap();
    }
    fs::create_dir_all(fixture.profiles_root.join("coder/child")).unwrap();
    fs::create_dir_all(fixture.profiles_root.join("Coder")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        fixture.profiles_root.join("writer"),
        fixture.profiles_root.join("linked"),
    )
    .unwrap();
    #[cfg(windows)]
    let _ = std::os::windows::fs::symlink_dir(
        &fixture.profiles_root.join("writer"),
        fixture.profiles_root.join("linked"),
    );
    let discovered = HermesAdapter::discover_profiles(&fixture.default_home).unwrap();
    let has_distinct_case_collision = fs::read_dir(&fixture.profiles_root)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| entry.file_name() == "Coder");
    assert_eq!(
        discovered
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        if has_distinct_case_collision {
            vec!["default", "writer"]
        } else {
            vec!["default", "coder", "writer"]
        }
    );
}

#[test]
fn adapter_cannot_be_redirected_after_construction() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let default_canary = fixture.default_home.join("do-not-read");
    let writer_canary = fixture.profiles_root.join("writer/do-not-read");
    fs::write(&default_canary, "default canary").unwrap();
    fs::write(&writer_canary, "writer canary").unwrap();
    for requested in ["writer", "default"] {
        let error = fixture
            .adapter
            .probe(&ProbeContext {
                harness: HarnessId::Hermes,
                requested_profile: Some(requested.to_owned()),
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }
    assert_eq!(
        fs::read_to_string(default_canary).unwrap(),
        "default canary"
    );
    assert_eq!(fs::read_to_string(writer_canary).unwrap(), "writer canary");
}

#[test]
fn working_directory_must_stay_inside_project_root() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let mut outside = fixture.layout.clone();
    outside.working_directory = fixture.root.clone();
    assert_eq!(
        HermesAdapter::from_layout(
            outside,
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap_err()
        .code,
        ErrorCode::InvalidRequest
    );
    let mut unresolved = fixture.layout.clone();
    unresolved.project_root = fixture.root.join("does-not-exist");
    assert_eq!(
        HermesAdapter::from_layout(
            unresolved,
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
}

#[test]
fn unknown_versions_and_wrappers_are_import_only() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let mut variants = vec![
        ("9.9.9", HermesExecutableKind::Native, "hermes"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes-script"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes.cmd"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes.bat"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes.ps1"),
    ];
    for (version, kind, executable_name) in variants.drain(..) {
        let mut layout = profile_layout(&fixture, "coder", version, kind);
        layout.executable = fixture.root.join(executable_name);
        fs::write(
            &layout.executable,
            if executable_name == "hermes-script" {
                &b"#!/bin/sh\necho 0.18.2\n"[..]
            } else {
                &b"wrapper"[..]
            },
        )
        .unwrap();
        let adapter = HermesAdapter::from_layout(
            layout,
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap();
        assert_eq!(
            probe(&adapter, Some("coder")).capability,
            CapabilityLevel::ImportOnly
        );
        assert_eq!(
            adapter
                .render(&context_relay_protocol::DesiredState {
                    components: vec![],
                    scopes: vec![]
                })
                .unwrap_err()
                .code,
            ErrorCode::HarnessUnsupported
        );
    }
}

#[test]
fn from_layout_reclassifies_wrapper_bytes_claimed_as_native() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let mut layout = profile_layout(
        &fixture,
        "coder",
        &fixture.layout.version,
        HermesExecutableKind::Native,
    );
    layout.executable = fixture.root.join("claimed-native-wrapper");
    fs::write(&layout.executable, b"#!/bin/sh\necho 0.18.2\n").unwrap();

    let adapter = HermesAdapter::from_layout(
        layout,
        fixture.project_id,
        DeviceId::from_str(DEVICE_ID).unwrap(),
        HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
    )
    .unwrap();

    assert_eq!(
        probe(&adapter, Some("coder")).capability,
        CapabilityLevel::ImportOnly
    );
}

#[cfg(windows)]
#[test]
fn windows_junction_profile_paths_are_rejected() {
    fn junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg(format!(
                "mklink /J \"{}\" \"{}\"",
                link.display(),
                target.display()
            ))
            .status()
            .unwrap();
        assert!(status.success());
    }

    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let default_junction = fixture.root.join("default-junction");
    junction(&default_junction, &fixture.default_home);
    assert_eq!(
        HermesAdapter::discover_profiles(&default_junction)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    fs::remove_dir(&default_junction).unwrap();

    let profiles_target = fixture.root.join("profiles-target");
    fs::rename(&fixture.profiles_root, &profiles_target).unwrap();
    junction(&fixture.profiles_root, &profiles_target);
    assert_eq!(
        HermesAdapter::discover_profiles(&fixture.default_home)
            .unwrap()
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        vec!["default"]
    );
    fs::remove_dir(&fixture.profiles_root).unwrap();
    fs::rename(&profiles_target, &fixture.profiles_root).unwrap();

    let candidate_junction = fixture.profiles_root.join("fake");
    junction(&candidate_junction, &fixture.profiles_root.join("writer"));
    assert_eq!(
        HermesAdapter::discover_profiles(&fixture.default_home)
            .unwrap()
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        vec!["default", "coder", "writer"]
    );
}
