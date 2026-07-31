use context_relay_context_mcp::{parse_harness, run_stdio};

#[tokio::main]
async fn main() {
    let Some(harness) = parse_harness(std::env::args_os()) else {
        eprintln!("Context Relay MCP requires one supported harness binding");
        std::process::exit(2);
    };
    if let Err(error) = run_stdio(harness).await {
        eprintln!("Context Relay MCP stopped: {}", error.redacted_message());
        std::process::exit(1);
    }
}
