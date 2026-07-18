use context_relay_protocol::PROTOCOL_VERSION;

fn main() {
    println!(
        "Context Relay MCP shell (protocol {}.{})",
        PROTOCOL_VERSION.major, PROTOCOL_VERSION.minor
    );
}
