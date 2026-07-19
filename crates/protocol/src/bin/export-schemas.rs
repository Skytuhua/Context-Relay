use std::{env, fs, path::PathBuf};

use context_relay_protocol::{
    DECIMAL_U64_SCHEMA_PATTERN, MAX_BATCH_OPERATIONS, MAX_CIPHERTEXT_BYTES, MAX_EXTENSION_ITEMS,
    MAX_EXTENSION_KEY_BYTES, MAX_EXTENSION_TEXT_BYTES, MAX_MARKDOWN_BYTES, MAX_TITLE_BYTES,
    MCP_TOOL_NAMES, mcp_schema,
};
use serde_json::{Value, json};

fn main() {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("schemas"));
    fs::create_dir_all(&output).expect("schema directory");
    for name in MCP_TOOL_NAMES {
        let schema = mcp_schema(name).expect("known MCP tool");
        write(&output.join(format!("{name}-input-v1.json")), &schema.input);
        write(
            &output.join(format!("{name}-output-v1.json")),
            &schema.output,
        );
    }
    write(
        &output.join("context-relay-package-v1.json"),
        &package_schema(),
    );
    write(
        &output.join("context-relay-export-v1.json"),
        &export_schema(),
    );
}

fn write(path: &PathBuf, value: &Value) {
    let mut data = serde_json::to_string_pretty(value).expect("schema serializes");
    data.push('\n');
    fs::write(path, data).expect("schema writes");
}

fn root(properties: Value, required: Vec<&str>) -> Value {
    json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":properties,"required":required,"additionalProperties":false})
}

fn uuid() -> Value {
    json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})
}
fn digest() -> Value {
    json!({"type":"string","pattern":"^[0-9a-f]{64}$"})
}
fn required_text(max: usize) -> Value {
    json!({"type":"string","pattern":r"[\s\S]*\S[\s\S]*","maxLength":max,"x-utf8-maxBytes":max})
}
fn base64url(max_bytes: usize) -> Value {
    json!({
        "type":"string",
        "pattern":"^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$",
        "maxLength":(max_bytes * 4).div_ceil(3)
    })
}
fn decimal_u64() -> Value {
    json!({
        "type":"string",
        "pattern":DECIMAL_U64_SCHEMA_PATTERN
    })
}
fn hlc() -> Value {
    json!({"type":"object","properties":{"physicalMs":decimal_u64(),"logical":{"type":"integer","minimum":0,"maximum":4294967295u64},"node":uuid()},"required":["physicalMs","logical","node"],"additionalProperties":false})
}
fn provenance() -> Value {
    json!({"type":"object","properties":{"originDevice":uuid(),"harness":{"oneOf":[{"type":"null"},{"enum":["claude_code","codex","hermes"]}]},"source":{"oneOf":[{"type":"null"},{"type":"object","properties":{"source":{"const":"record"},"recordId":uuid()},"required":["source","recordId"],"additionalProperties":false},{"type":"object","properties":{"source":{"const":"package"},"packageId":uuid()},"required":["source","packageId"],"additionalProperties":false}]},"createdHlc":hlc()},"required":["originDevice","harness","source","createdHlc"],"additionalProperties":false})
}
fn scope() -> Value {
    json!({"oneOf":[{"type":"object","properties":{"scope":{"const":"global"}},"required":["scope"],"additionalProperties":false},{"type":"object","properties":{"scope":{"const":"project"},"projectId":uuid()},"required":["scope","projectId"],"additionalProperties":false}]})
}
fn dependency() -> Value {
    json!({"type":"object","properties":{"name":required_text(MAX_TITLE_BYTES),"version":required_text(MAX_TITLE_BYTES),"digest":digest(),"immutableSourceRef":required_text(MAX_MARKDOWN_BYTES)},"required":["name","version","digest","immutableSourceRef"],"additionalProperties":false})
}
fn dependencies() -> Value {
    json!({"type":"array","maxItems":MAX_BATCH_OPERATIONS,"items":dependency()})
}

fn component(kind: &str, extra: Value, mut required: Vec<&str>) -> Value {
    let mut properties = json!({"kind":{"const":kind},"id":uuid(),"scope":scope()})
        .as_object()
        .expect("object")
        .clone();
    properties.extend(extra.as_object().expect("component properties").clone());
    required.splice(0..0, ["kind", "id", "scope"]);
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}

fn extension_key() -> Value {
    let forbidden = [
        "password",
        "secret",
        "token",
        "cookie",
        "privatekey",
        "credential",
        "executable",
        "binary",
        "script",
        "shell",
        "command",
        "hook",
        "code",
    ]
    .map(|role| {
        let pattern = role
            .chars()
            .map(|character| {
                format!(
                    "[{}{}]",
                    character.to_ascii_lowercase(),
                    character.to_ascii_uppercase()
                )
            })
            .collect::<Vec<_>>()
            .join("[._-]*");
        json!({"pattern":pattern})
    });
    json!({
        "type":"string",
        "minLength":1,
        "maxLength":MAX_EXTENSION_KEY_BYTES,
        "x-utf8-maxBytes":MAX_EXTENSION_KEY_BYTES,
        "pattern":r"^[A-Za-z0-9._-]+$",
        "not":{"anyOf":forbidden}
    })
}

fn extension_text() -> Value {
    json!({
        "type":"string",
        "maxLength":MAX_EXTENSION_TEXT_BYTES,
        "x-utf8-maxBytes":MAX_EXTENSION_TEXT_BYTES,
        "not":{"anyOf":[
            {"pattern":r"[\u0000-\u001F\u007F-\u009F]"},
            {"pattern":r"-----[bB][eE][gG][iI][nN][^\r\n]*[pP][rR][iI][vV][aA][tT][eE] [kK][eE][yY]-----"}
        ]}
    })
}

fn extension_data() -> Value {
    json!({
        "type":"object",
        "maxProperties":MAX_EXTENSION_ITEMS,
        "propertyNames":extension_key(),
        "additionalProperties":extension_text()
    })
}

fn extension_namespace() -> Value {
    json!({
        "type":"string",
        "pattern":r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$",
        "maxLength":255,
        "x-utf8-maxBytes":255
    })
}

fn namespaced_extension() -> Value {
    json!({
        "type":"object",
        "properties":{"data":extension_data()},
        "required":["data"],
        "additionalProperties":false
    })
}

fn package_schema() -> Value {
    let components = json!({"type":"array","minItems":1,"maxItems":MAX_BATCH_OPERATIONS,"items":{"oneOf":[
        component("instruction",json!({"title":required_text(MAX_TITLE_BYTES),"bodyMarkdown":required_text(MAX_MARKDOWN_BYTES)}),vec!["title","bodyMarkdown"]),
        component("rule",json!({"title":required_text(MAX_TITLE_BYTES),"bodyMarkdown":required_text(MAX_MARKDOWN_BYTES)}),vec!["title","bodyMarkdown"]),
        component("skill",json!({"name":required_text(MAX_TITLE_BYTES),"bodyMarkdown":required_text(MAX_MARKDOWN_BYTES),"dependencies":dependencies()}),vec!["name","bodyMarkdown","dependencies"]),
        component("plugin",json!({"name":required_text(MAX_TITLE_BYTES),"dependencies":dependencies()}),vec!["name","dependencies"]),
        component("mcp_server",json!({"serverName":required_text(MAX_TITLE_BYTES),"package":dependency()}),vec!["serverName","package"]),
        component("hook",json!({"event":required_text(MAX_TITLE_BYTES),"componentId":uuid()}),vec!["event","componentId"]),
        component("permission_declaration",json!({"permissions":{"type":"array","minItems":1,"maxItems":MAX_BATCH_OPERATIONS,"uniqueItems":true,"items":required_text(MAX_TITLE_BYTES)},"approvalClass":{"enum":["passive","active"]}}),vec!["permissions","approvalClass"])
    ]}});
    let secret = json!({"type":"object","properties":{"id":uuid(),"name":required_text(MAX_TITLE_BYTES),"provider":required_text(MAX_TITLE_BYTES),"requiredOnDevice":{"type":"boolean"}},"required":["id","name","provider","requiredOnDevice"],"additionalProperties":false});
    root(
        json!({"format":{"const":"context-relay.package.v1"},"packageId":uuid(),"components":components,"secretRefs":{"type":"array","maxItems":MAX_BATCH_OPERATIONS,"items":secret},"harnessTargets":{"type":"array","minItems":1,"maxItems":3,"uniqueItems":true,"items":{"enum":["claude_code","codex","hermes"]}},"extensions":{"type":"object","maxProperties":MAX_BATCH_OPERATIONS,"propertyNames":extension_namespace(),"additionalProperties":namespaced_extension()}}),
        vec![
            "format",
            "packageId",
            "components",
            "secretRefs",
            "harnessTargets",
        ],
    )
}

fn export_schema() -> Value {
    root(
        json!({"format":{"const":"context-relay.export.v1"},"exportId":uuid(),"workspaceId":uuid(),"createdHlc":hlc(),"records":{"type":"array","maxItems":MAX_BATCH_OPERATIONS,"items":{"type":"object","properties":{"recordId":uuid(),"recordKind":{"enum":["memory","memory_candidate","task","secret_ref","instruction","component","project"]},"revision":uuid(),"tombstone":{"type":"boolean"},"provenance":provenance(),"encryptedPayload":base64url(MAX_CIPHERTEXT_BYTES)},"required":["recordId","recordKind","revision","tombstone","provenance","encryptedPayload"],"additionalProperties":false}},"operationOrder":{"type":"array","maxItems":MAX_BATCH_OPERATIONS,"uniqueItems":true,"items":uuid()}}),
        vec![
            "format",
            "exportId",
            "workspaceId",
            "createdHlc",
            "records",
            "operationOrder",
        ],
    )
}
