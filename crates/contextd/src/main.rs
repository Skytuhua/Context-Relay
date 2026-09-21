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
        CommandMode::VerifyPackagedSearch => return verify_packaged_search(),
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
    VerifyPackagedSearch,
}

fn parse_command(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<CommandMode, DaemonError> {
    let mut args = args.into_iter();
    match (args.next(), args.next()) {
        (None, None) => Ok(CommandMode::Run),
        (Some(arg), None) if arg == "--shutdown" => Ok(CommandMode::Shutdown),
        (Some(arg), None) if arg == "--verify-packaged-search" => {
            Ok(CommandMode::VerifyPackagedSearch)
        }
        _ => Err(DaemonError::Startup),
    }
}

#[cfg(target_os = "macos")]
fn verify_packaged_search() -> Result<(), DaemonError> {
    use context_relay_core::search::{EmbeddingPurpose, PinnedModelEmbedder};
    // Packaging invokes this explicit mode before any daemon, vault or IPC startup.
    let executable = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| DaemonError::Startup)?;
    let macos = executable.parent().ok_or(DaemonError::Startup)?;
    let contents = macos.parent().ok_or(DaemonError::Startup)?;
    if macos.file_name().is_none_or(|name| name != "MacOS")
        || contents.file_name().is_none_or(|name| name != "Contents")
    {
        return Err(DaemonError::Startup);
    }
    let mut model = PinnedModelEmbedder::load_packaged(&contents.join("Resources/search"))
        .map_err(|_| DaemonError::Startup)?;
    let query = model
        .embed(EmbeddingPurpose::Query, "car repair")
        .map_err(|_| DaemonError::Startup)?;
    let relevant = model
        .embed(
            EmbeddingPurpose::Passage,
            "How to repair an automobile engine",
        )
        .map_err(|_| DaemonError::Startup)?;
    let unrelated = model
        .embed(EmbeddingPurpose::Passage, "How to bake sourdough bread")
        .map_err(|_| DaemonError::Startup)?;
    let similarity = |passage: &context_relay_core::search::Embedding384| -> f64 {
        query
            .as_slice()
            .iter()
            .zip(passage.as_slice())
            .map(|(left, right)| f64::from(*left) * f64::from(*right))
            .sum()
    };
    if similarity(&relevant) <= similarity(&unrelated) {
        return Err(DaemonError::Startup);
    }
    println!("verified packaged search");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn verify_packaged_search() -> Result<(), DaemonError> {
    Err(DaemonError::Startup)
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
    fn packaged_search_verification_is_explicit_and_rejects_arguments() {
        let mode = parse_command(["--verify-packaged-search".into()]).unwrap();
        assert_eq!(format!("{mode:?}"), "VerifyPackagedSearch");
        assert!(parse_command(["--verify-packaged-search".into(), "extra".into()]).is_err());
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
