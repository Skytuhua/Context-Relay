use context_relay_core::health_descriptor;

fn main() {
    let health = health_descriptor();
    println!(
        "Context Relay daemon shell ({}, protocol {})",
        health.status, health.protocol_version
    );
}
