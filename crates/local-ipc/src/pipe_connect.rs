use std::{io, time::Duration};

use tokio::time::{Instant, sleep_until};

const PIPE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PIPE_RETRY_INTERVAL: Duration = Duration::from_millis(50);

// A Windows listener publishes the next instance when it accepts the current
// one. Only ERROR_PIPE_BUSY is transient here: missing/denied endpoints must
// retain their original error and must not trigger a second daemon launch.
// This retries opening a handle, never an authenticated request or mutation.
pub(super) async fn open_pipe_with<T>(
    mut open: impl FnMut() -> io::Result<T>,
    busy_code: i32,
) -> io::Result<T> {
    let deadline = Instant::now() + PIPE_CONNECT_TIMEOUT;
    loop {
        match open() {
            Ok(stream) => return Ok(stream),
            Err(error) if error.raw_os_error() == Some(busy_code) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(error);
                }
                sleep_until((now + PIPE_RETRY_INTERVAL).min(deadline)).await;
                if Instant::now() >= deadline {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};
    use tokio::time::Instant;

    use super::open_pipe_with;

    const PIPE_BUSY: i32 = 231;

    #[tokio::test(start_paused = true)]
    async fn busy_pipe_retries_until_a_listener_instance_is_available() {
        let start = Instant::now();
        let mut attempts = 0;
        let result = open_pipe_with(
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(io::Error::from_raw_os_error(PIPE_BUSY))
                } else {
                    Ok("connected")
                }
            },
            PIPE_BUSY,
        )
        .await;
        assert_eq!(result.unwrap(), "connected");
        assert_eq!(attempts, 3);
        assert_eq!(start.elapsed(), Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn permanently_busy_pipe_has_one_five_second_deadline() {
        let start = Instant::now();
        let mut attempts = 0;
        let error = open_pipe_with::<()>(
            || {
                attempts += 1;
                Err(io::Error::from_raw_os_error(PIPE_BUSY))
            },
            PIPE_BUSY,
        )
        .await
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(PIPE_BUSY));
        assert_eq!(start.elapsed(), Duration::from_secs(5));
        assert_eq!(attempts, 100, "no busy loop or post-deadline open");
    }

    #[tokio::test(start_paused = true)]
    async fn absent_and_denied_endpoints_are_not_retried() {
        for code in [2, 3, 5] {
            let start = Instant::now();
            let mut attempts = 0;
            let error = open_pipe_with::<()>(
                || {
                    attempts += 1;
                    Err(io::Error::from_raw_os_error(code))
                },
                PIPE_BUSY,
            )
            .await
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(code));
            assert_eq!(attempts, 1);
            assert_eq!(start.elapsed(), Duration::ZERO);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_terminal_error_after_busy_stops_the_retry_loop() {
        let mut attempts = 0;
        let error = open_pipe_with::<()>(
            || {
                attempts += 1;
                Err(io::Error::from_raw_os_error(if attempts == 1 {
                    PIPE_BUSY
                } else {
                    5 // ERROR_ACCESS_DENIED
                }))
            },
            PIPE_BUSY,
        )
        .await
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(5));
        assert_eq!(attempts, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_a_pending_connection_stops_all_retries() {
        let mut attempts = 0;
        let result = tokio::time::timeout(
            Duration::from_millis(75),
            open_pipe_with::<()>(
                || {
                    attempts += 1;
                    Err(io::Error::from_raw_os_error(PIPE_BUSY))
                },
                PIPE_BUSY,
            ),
        )
        .await;
        assert!(result.is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(attempts, 2, "no detached retries after caller cancellation");
    }

    #[tokio::test(start_paused = true)]
    async fn successful_open_is_immediate_and_never_replayed() {
        let start = Instant::now();
        let mut attempts = 0;
        let result = open_pipe_with(
            || {
                attempts += 1;
                Ok(42)
            },
            PIPE_BUSY,
        )
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts, 1);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }
}
