//! Loopback OAuth callback receiver. Run outside the ordered vault worker.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use context_relay_core::auth::{LoginError, LoginExchange, PendingLogin};
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
