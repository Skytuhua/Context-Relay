//! Loopback OAuth callback receiver. Run outside the ordered vault worker.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use context_relay_core::auth::{
    HostedIdentity, HostedSessionOwner, LoginAttempt, LoginCancellation, LoginError, LoginExchange,
    PendingLogin,
};
use reqwest::Url;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub struct LoopbackLogin {
    listener: TcpListener,
    pending: PendingLogin,
    deadline: tokio::time::Instant,
}

/// Owns the listener and session attempt together. Dropping it withdraws the
/// attempt immediately and schedules blocking credential cleanup on the runtime.
pub struct DaemonLogin {
    owner: Arc<HostedSessionOwner>,
    listener: Option<LoopbackLogin>,
    attempt: Option<LoginAttempt>,
    cancellation: Option<LoginCancellation>,
    runtime: tokio::runtime::Handle,
}

impl DaemonLogin {
    pub async fn begin(project: &str, owner: Arc<HostedSessionOwner>) -> Result<Self, LoginError> {
        let listener = LoopbackLogin::bind(project).await?;
        let runtime = tokio::runtime::Handle::current();
        let cancellation = LoginCancellation::default();
        let mut flow = Self {
            owner: owner.clone(),
            listener: Some(listener),
            attempt: None,
            cancellation: Some(cancellation.clone()),
            runtime,
        };
        let attempt =
            tokio::task::spawn_blocking(move || owner.begin_login_cancellable(cancellation))
                .await
                .map_err(|_| LoginError::Unavailable)??;
        flow.attempt = Some(attempt);
        Ok(flow)
    }

    /// Open this URL only after begin succeeds; it contains no verifier or tokens.
    pub fn authorization_url(&self) -> Result<Url, LoginError> {
        self.listener
            .as_ref()
            .map(LoopbackLogin::authorization_url)
            .ok_or(LoginError::Canceled)
    }

    pub async fn wait(mut self) -> Result<HostedIdentity, LoginError> {
        let exchange = self
            .listener
            .take()
            .ok_or(LoginError::Canceled)?
            .wait()
            .await?;
        let attempt = self.attempt.take().ok_or(LoginError::Canceled)?;
        let owner = self.owner.clone();
        let result = tokio::task::spawn_blocking(move || {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| LoginError::Unavailable)?
                .as_secs();
            owner.complete_login(attempt, exchange, now)
        })
        .await
        .map_err(|_| LoginError::Unavailable)?;
        if result.is_ok() {
            self.cancellation = None;
        }
        result
    }

    /// Returns only after the owner has processed cancellation and local cleanup.
    pub async fn cancel(mut self) -> Result<(), LoginError> {
        self.listener = None;
        let cancellation = self.cancellation.take().ok_or(LoginError::Canceled)?;
        cancellation.cancel();
        let owner = self.owner.clone();
        tokio::task::spawn_blocking(move || owner.cancel_attempt(cancellation))
            .await
            .map_err(|_| LoginError::Unavailable)?
    }
}

impl Drop for DaemonLogin {
    fn drop(&mut self) {
        if let Some(cancellation) = self.cancellation.take() {
            cancellation.cancel();
            let owner = self.owner.clone();
            self.runtime.spawn_blocking(move || {
                let _ = owner.cancel_attempt(cancellation);
            });
        }
    }
}

impl LoopbackLogin {
    pub async fn bind(project: &str) -> Result<Self, LoginError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| LoginError::Unavailable)?;
        let address = listener.local_addr().map_err(|_| LoginError::Unavailable)?;
        Ok(Self {
            listener,
            pending: PendingLogin::new(project, address, Instant::now())?,
            deadline: tokio::time::Instant::now() + Duration::from_secs(300),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, LoginError> {
        self.listener
            .local_addr()
            .map_err(|_| LoginError::Unavailable)
    }

    pub fn authorization_url(&self) -> Url {
        self.pending.authorization_url()
    }

    /// Dropping or aborting this future closes the listener and discards the verifier.
    pub async fn wait(mut self) -> Result<LoginExchange, LoginError> {
        let deadline = self.deadline;
        tokio::time::timeout_at(deadline, async {
            let address = self.local_addr()?;
            // Bound invalid traffic as well as total lifetime and each socket read.
            for _ in 0..128 {
                let (mut stream, _) = self
                    .listener
                    .accept()
                    .await
                    .map_err(|_| LoginError::Unavailable)?;
                let target =
                    tokio::time::timeout(Duration::from_secs(2), read_target(&mut stream, address))
                        .await;
                let result = match target {
                    Ok(Ok(target)) => Url::parse(&format!("http://{address}{target}"))
                        .map_err(|_| LoginError::Callback)
                        .and_then(|url| self.pending.take_callback(&url, Instant::now())),
                    _ => Err(LoginError::Callback),
                };
                let terminal = result.is_ok()
                    || matches!(result, Err(LoginError::Denied | LoginError::Expired));
                // A disconnected browser must not discard a valid exchange.
                let _ =
                    tokio::time::timeout(Duration::from_secs(2), respond(&mut stream, terminal))
                        .await;
                if terminal {
                    return result;
                }
            }
            Err(LoginError::Unavailable)
        })
        .await
        .map_err(|_| LoginError::Expired)?
    }
}

async fn read_target(stream: &mut TcpStream, address: SocketAddr) -> Result<String, LoginError> {
    let mut bytes = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0_u8; 1024];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| LoginError::Callback)?;
        if read == 0 || bytes.len() + read > 8192 {
            return Err(LoginError::Callback);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            if end + 4 != bytes.len() || !bytes.is_ascii() {
                return Err(LoginError::Callback);
            }
            let request = std::str::from_utf8(&bytes[..end]).map_err(|_| LoginError::Callback)?;
            let mut lines = request.split("\r\n");
            let mut first = lines.next().ok_or(LoginError::Callback)?.split(' ');
            if first.next() != Some("GET") {
                return Err(LoginError::Callback);
            }
            let target = first.next().ok_or(LoginError::Callback)?;
            if !target.starts_with('/')
                || target.len() > 4096
                || !target.bytes().all(|b| b.is_ascii_graphic())
                || first.next() != Some("HTTP/1.1")
                || first.next().is_some()
            {
                return Err(LoginError::Callback);
            }
            let mut host = None;
            let mut length = None;
            for line in lines {
                let (name, value) = line.split_once(':').ok_or(LoginError::Callback)?;
                if name.is_empty()
                    || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_graphic() || b == b' ' || b == b'\t')
                {
                    return Err(LoginError::Callback);
                }
                let value = value.trim();
                match name.to_ascii_lowercase().as_str() {
                    "host" if host.is_none() => host = Some(value),
                    "content-length" if length.is_none() && value == "0" => length = Some(value),
                    "host" | "content-length" | "transfer-encoding" => {
                        return Err(LoginError::Callback);
                    }
                    _ => {}
                }
            }
            if host != Some(address.to_string().as_str()) {
                return Err(LoginError::Callback);
            }
            return Ok(target.to_owned());
        }
    }
}

async fn respond(stream: &mut TcpStream, accepted: bool) -> std::io::Result<()> {
    let status = if accepted {
        "200 OK"
    } else {
        "400 Bad Request"
    };
    let body = "Continue in Context Relay.";
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}
