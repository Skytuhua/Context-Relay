use context_relay_contextd::{Daemon, DaemonConfig, DaemonError};

const FAILURE_DIAGNOSTIC: &str = "Context Relay daemon could not run";

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{}", diagnostic(&error));
        std::process::exit(1);
    }
}

async fn run() -> Result<(), DaemonError> {
    let daemon = Daemon::start(DaemonConfig::production()?).await?;
    let handle = daemon.handle();
    let mut owner = tokio::spawn(daemon.run());

    tokio::select! {
        result = &mut owner => joined(result),
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|_| DaemonError::Transport)?;
            let _ = handle.shutdown().await;
            joined(owner.await)
        }
    }
}

fn joined(
    result: Result<Result<(), DaemonError>, tokio::task::JoinError>,
) -> Result<(), DaemonError> {
    result.map_err(|_| DaemonError::Transport)?
}

fn diagnostic(_: &DaemonError) -> &'static str {
    FAILURE_DIAGNOSTIC
}

#[cfg(test)]
mod tests {
    use context_relay_contextd::DaemonError;

    use super::diagnostic;

    #[test]
    fn every_daemon_failure_has_one_fixed_redacted_diagnostic() {
        for error in [
            DaemonError::AlreadyRunning,
            DaemonError::Startup,
            DaemonError::Transport,
        ] {
            assert_eq!(diagnostic(&error), "Context Relay daemon could not run");
        }
    }
}
