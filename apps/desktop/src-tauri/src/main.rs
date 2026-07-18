use context_relay_protocol::{PROTOCOL_VERSION, ProtocolVersion};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationInfo {
    application_version: &'static str,
    protocol_version: ProtocolVersion,
}

#[tauri::command]
fn application_info() -> ApplicationInfo {
    ApplicationInfo {
        application_version: env!("CARGO_PKG_VERSION"),
        protocol_version: PROTOCOL_VERSION,
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![application_info])
        .run(tauri::generate_context!())
        .expect("Context Relay desktop shell should run");
}
