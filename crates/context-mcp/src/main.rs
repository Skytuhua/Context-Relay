use std::io::Write as _;

use context_relay_context_mcp::{Invocation, parse_invocation, run_hook_stdio, run_stdio};

#[tokio::main]
async fn main() {
    let Some(invocation) = parse_invocation(std::env::args_os()) else {
        eprintln!("Context Relay MCP requires one supported harness binding");
        std::process::exit(2);
    };
    match invocation {
        Invocation::Mcp { harness } => {
            if let Err(error) = run_stdio(harness).await {
                eprintln!("Context Relay MCP stopped: {}", error.redacted_message());
                std::process::exit(1);
            }
        }
        Invocation::Hook { harness, event } => match run_hook_stdio(harness, event).await {
            Ok(output) => {
                if std::io::stdout().write_all(output.as_bytes()).is_err() {
                    eprintln!("Context Relay hook stopped: The local service is unavailable");
                    std::process::exit(1);
                }
            }
            Err(error) => {
                eprintln!("Context Relay hook stopped: {}", error.redacted_message());
                std::process::exit(1);
            }
        },
    }
}
