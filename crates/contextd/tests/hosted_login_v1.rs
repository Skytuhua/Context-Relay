use std::time::Duration;

use context_relay_contextd::hosted_login::LoopbackLogin;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

async fn send(address: std::net::SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(6), stream.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

#[tokio::test]
async fn listener_rejects_untrusted_http_then_accepts_its_callback_once() {
    let listener = LoopbackLogin::bind("https://example.supabase.co")
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    assert!(address.ip().is_loopback());
    let auth = listener.authorization_url();
    let redirect = auth
        .query_pairs()
        .find(|(key, _)| key == "redirect_to")
        .unwrap()
        .1
        .into_owned();
    let redirect = auth.join(&redirect).unwrap();
    let target = format!(
        "{}?{}&code=synthetic-code",
        redirect.path(),
        redirect.query().unwrap()
    );
    let worker = tokio::spawn(listener.wait());
    // An idle connection must time out, allowing subsequent callbacks through.
    let _idle = TcpStream::connect(address).await.unwrap();
    for request in [
        format!("GET {target} HTTP/1.1\r\nHost: attacker.example\r\n\r\n"),
        format!("POST {target} HTTP/1.1\r\nHost: {address}\r\nContent-Length: 0\r\n\r\n"),
        format!("GET {target} HTTP/1.1\r\nHost: {address}\r\nHost: {address}\r\n\r\n"),
        format!("GET {target} HTTP/1.1\r\nHost: {address}\r\nTransfer-Encoding: chunked\r\n\r\n"),
    ] {
        assert!(send(address, &request).await.starts_with("HTTP/1.1 400"));
    }
    let mut oversized = TcpStream::connect(address).await.unwrap();
    oversized
        .write_all(
            format!(
                "GET {target} HTTP/1.1\r\nHost: {address}\r\nX-Large: {}\r\n\r\n",
                "a".repeat(8192)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut rejected = String::new();
    let read = tokio::time::timeout(
        Duration::from_secs(6),
        oversized.read_to_string(&mut rejected),
    )
    .await
    .unwrap();
    assert!(
        read.is_ok()
            || read
                .as_ref()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
    );
    assert!(!rejected.starts_with("HTTP/1.1 200"));
    let response = send(
        address,
        &format!("GET {target} HTTP/1.1\r\nHost: {address}\r\n\r\n"),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("Cache-Control: no-store"));
    assert!(!response.contains("synthetic-code"));
    let exchange = worker.await.unwrap().unwrap();
    assert!(!format!("{exchange:?}").contains("synthetic-code"));
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn aborting_login_closes_the_listener() {
    let listener = LoopbackLogin::bind("https://example.supabase.co")
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let worker = tokio::spawn(listener.wait());
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test(start_paused = true)]
async fn unused_login_expires_and_closes_the_listener() {
    let listener = LoopbackLogin::bind("https://example.supabase.co")
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let worker = tokio::spawn(listener.wait());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(300)).await;
    assert_eq!(
        worker.await.unwrap().unwrap_err(),
        context_relay_core::auth::LoginError::Expired
    );
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn provider_denial_finishes_without_exposing_provider_details() {
    let listener = LoopbackLogin::bind("https://example.supabase.co")
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let auth = listener.authorization_url();
    let redirect = auth
        .query_pairs()
        .find(|(key, _)| key == "redirect_to")
        .unwrap()
        .1
        .into_owned();
    let redirect = auth.join(&redirect).unwrap();
    let target = format!(
        "{}?{}&error=access_denied&error_description=private-detail",
        redirect.path(),
        redirect.query().unwrap()
    );
    let worker = tokio::spawn(listener.wait());
    let response = send(
        address,
        &format!("GET {target} HTTP/1.1\r\nHost: {address}\r\n\r\n"),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(!response.contains("private-detail"));
    assert_eq!(
        worker.await.unwrap().unwrap_err(),
        context_relay_core::auth::LoginError::Denied
    );
    assert!(TcpStream::connect(address).await.is_err());
}
