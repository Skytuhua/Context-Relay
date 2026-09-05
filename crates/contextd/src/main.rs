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
    match parse_command(std::env::args_os().skip(1))? {
        CommandMode::Shutdown => return shutdown().await,
        CommandMode::Run => {}
    }
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

#[derive(Debug, Eq, PartialEq)]
enum CommandMode {
    Run,
    Shutdown,
}

fn parse_command(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<CommandMode, DaemonError> {
    let mut args = args.into_iter();
    match (args.next(), args.next()) {
        (None, None) => Ok(CommandMode::Run),
        (Some(arg), None) if arg == "--shutdown" => Ok(CommandMode::Shutdown),
        _ => Err(DaemonError::Startup),
    }
}

#[cfg(windows)]
async fn shutdown() -> Result<(), DaemonError> {
    context_relay_local_ipc::shutdown_running_daemon()
        .await
        .map_err(|_| DaemonError::Transport)
}

#[cfg(not(windows))]
async fn shutdown() -> Result<(), DaemonError> {
    Err(DaemonError::Transport)
}

#[cfg(test)]
mod tests {
    use context_relay_contextd::DaemonError;

    use super::{CommandMode, diagnostic, parse_command};

    #[test]
    fn no_arguments_preserve_daemon_mode() {
        assert_eq!(parse_command([]).unwrap(), CommandMode::Run);
    }

    #[test]
    fn shutdown_is_an_explicit_mode_and_extra_arguments_fail_closed() {
        assert_eq!(
            parse_command(["--shutdown".into()]).unwrap(),
            CommandMode::Shutdown
        );
        for args in [
            vec!["--unknown"],
            vec!["--shutdown", "extra"],
            vec!["extra", "--shutdown"],
        ] {
            assert!(parse_command(args.into_iter().map(Into::into)).is_err());
        }
    }

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
