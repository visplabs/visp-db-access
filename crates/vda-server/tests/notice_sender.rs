#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The notice sender against local listeners: what it sends, what it
//! refuses, and that it stops reading and waiting where it says it does.
//!
//! The TLS tests make a throwaway certificate with the `openssl` command and
//! are skipped where it is not installed. No key is kept in the repository.
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::rustls::{
    self,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
};
use vda_server::notices::send::{Failure, Sender};

const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";

/// Read one request: the head, and the body that `content-length` announces.
async fn read_request<S: AsyncReadExt + Unpin>(stream: &mut S) -> Option<String> {
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        seen.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&seen).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end]
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")?
                        .parse::<usize>()
                        .ok()
                })
                .unwrap_or(0);
            if seen.len() >= end + 4 + length {
                return Some(text);
            }
        }
    }
}
/// A plain listener that records each request and answers with `answer`.
/// With `answer` empty it accepts, reads, and never answers.
async fn plain(answer: Vec<u8>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let (record, answer) = (record.clone(), answer.clone());
            tokio::spawn(async move {
                if let Some(request) = read_request(&mut stream).await {
                    record.lock().unwrap().push(request);
                }
                if answer.is_empty() {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    return;
                }
                let _ = stream.write_all(&answer).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, seen)
}
/// A self-signed certificate for `names`, or `None` without `openssl`.
fn certificate(names: &str) -> Option<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("notice-cert-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let (key, cert) = (dir.join("key.pem"), dir.join("cert.pem"));
    let made = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
        ])
        .args(["-nodes", "-days", "2", "-subj", "/CN=notice-test"])
        .arg("-addext")
        .arg(format!("subjectAltName={names}"))
        // A certificate that may sign others is refused as a server's own.
        .args(["-addext", "basicConstraints=critical,CA:FALSE"])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output();
    let ready = matches!(&made, Ok(output) if output.status.success());
    let pair = ready.then(|| {
        (
            CertificateDer::from_pem_file(&cert).unwrap(),
            PrivateKeyDer::from_pem_file(&key).unwrap(),
        )
    });
    let _ = std::fs::remove_dir_all(&dir);
    if pair.is_none() {
        eprintln!("skipped: the openssl command is not available");
    }
    pair
}
/// A TLS listener with the given certificate that answers 200.
async fn tls(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (u16, Arc<Mutex<Vec<String>>>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, record) = (acceptor.clone(), record.clone());
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                if let Some(request) = read_request(&mut stream).await {
                    record.lock().unwrap().push(request);
                }
                let _ = stream.write_all(OK).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, seen)
}
fn trusting(cert: &CertificateDer<'static>) -> Sender {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    Sender::with_roots(roots, true).unwrap()
}

#[tokio::test]
async fn a_notice_is_one_post_with_the_given_headers_and_body() {
    let (port, seen) = plain(OK.to_vec()).await;
    let sender = Sender::new(true).unwrap();
    let headers = [
        ("x-visp-gate-event", "approval.created".to_owned()),
        ("x-visp-gate-signature", "sha256=abc".to_owned()),
    ];
    let status = sender
        .send(
            &format!("http://127.0.0.1:{port}/hook/one?team=a"),
            &headers,
            br#"{"version":1}"#.to_vec(),
        )
        .await;
    assert_eq!(status, Ok(200));
    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    let request = requests[0].to_ascii_lowercase();
    assert!(
        request.starts_with("post /hook/one?team=a http/1.1\r\n"),
        "{request}"
    );
    for line in [
        format!("host: 127.0.0.1:{port}\r\n"),
        "content-type: application/json\r\n".into(),
        "content-length: 13\r\n".into(),
        "user-agent: visp-gate-notices/1\r\n".into(),
        "connection: close\r\n".into(),
        "x-visp-gate-event: approval.created\r\n".into(),
        "x-visp-gate-signature: sha256=abc\r\n".into(),
    ] {
        assert!(request.contains(&line), "{line:?} in {request}");
    }
    assert!(request.ends_with("\r\n\r\n{\"version\":1}"), "{request}");
    // Nothing identifies the gateway's version or host, and no cookie or
    // authorization header is ever added.
    for absent in ["cookie", "authorization", "referer", "x-forwarded"] {
        assert!(!request.contains(absent), "{absent}");
    }
}

#[tokio::test]
async fn only_a_2xx_answer_is_a_delivery_and_a_redirect_is_not_followed() {
    let (elsewhere, elsewhere_seen) = plain(OK.to_vec()).await;
    let sender = Sender::new(true).unwrap();
    for (status, reason) in [
        (301, "Moved Permanently"),
        (302, "Found"),
        (307, "Temporary Redirect"),
        (308, "Permanent Redirect"),
        (400, "Bad Request"),
        (404, "Not Found"),
        (429, "Too Many Requests"),
        (500, "Internal Server Error"),
        (503, "Service Unavailable"),
    ] {
        let answer = format!(
            "HTTP/1.1 {status} {reason}\r\nlocation: http://127.0.0.1:{elsewhere}/taken\r\n\
             content-length: 0\r\nconnection: close\r\n\r\n"
        );
        let (port, seen) = plain(answer.into_bytes()).await;
        let outcome = sender
            .send(
                &format!("http://127.0.0.1:{port}/hook"),
                &[],
                b"{}".to_vec(),
            )
            .await;
        assert_eq!(outcome, Err(Failure::Http(status)));
        assert_eq!(seen.lock().unwrap().len(), 1, "{status}: sent once");
    }
    assert_eq!(
        elsewhere_seen.lock().unwrap().len(),
        0,
        "no redirect was followed"
    );
    for status in [200, 201, 202, 204] {
        let answer =
            format!("HTTP/1.1 {status} Fine\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        let (port, _) = plain(answer.into_bytes()).await;
        let outcome = sender
            .send(
                &format!("http://127.0.0.1:{port}/hook"),
                &[],
                b"{}".to_vec(),
            )
            .await;
        assert_eq!(outcome, Ok(status));
    }
}

#[tokio::test]
async fn a_large_or_endless_answer_is_not_read_and_a_silent_receiver_is_given_up() {
    // A two-megabyte body: the status is taken, the rest is not waited for.
    let mut large = b"HTTP/1.1 200 OK\r\ncontent-length: 2097152\r\n\r\n".to_vec();
    large.extend(std::iter::repeat_n(b'x', 2 * 1024 * 1024));
    let (port, _) = plain(large).await;
    let sender = Sender::new(true)
        .unwrap()
        .with_timeouts(Duration::from_millis(500), Duration::from_secs(2));
    let started = Instant::now();
    let outcome = sender
        .send(
            &format!("http://127.0.0.1:{port}/hook"),
            &[],
            b"{}".to_vec(),
        )
        .await;
    assert_eq!(outcome, Ok(200));
    assert!(started.elapsed() < Duration::from_secs(2));

    // A body that never ends: the headers arrive, the body trickles forever.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_request(&mut stream).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
            .await;
        loop {
            if stream.write_all(b"1\r\nx\r\n").await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    let sender = sender.with_timeouts(Duration::from_millis(300), Duration::from_millis(600));
    let started = Instant::now();
    let outcome = sender
        .send(
            &format!("http://127.0.0.1:{port}/hook"),
            &[],
            b"{}".to_vec(),
        )
        .await;
    assert_eq!(outcome, Err(Failure::Timeout));
    assert!(started.elapsed() < Duration::from_secs(2));

    // A receiver that accepts and says nothing.
    let (port, _) = plain(Vec::new()).await;
    let started = Instant::now();
    let outcome = sender
        .send(
            &format!("http://127.0.0.1:{port}/hook"),
            &[],
            b"{}".to_vec(),
        )
        .await;
    assert_eq!(outcome, Err(Failure::Timeout));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn an_answer_that_is_not_http_or_has_a_huge_head_is_a_protocol_failure() {
    let sender = Sender::new(true).unwrap();
    let mut huge = b"HTTP/1.1 200 OK\r\nx-padding: ".to_vec();
    huge.extend(std::iter::repeat_n(b'a', 64 * 1024));
    huge.extend_from_slice(b"\r\ncontent-length: 0\r\n\r\n");
    for answer in [b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(), huge] {
        let (port, _) = plain(answer).await;
        let outcome = sender
            .send(
                &format!("http://127.0.0.1:{port}/hook"),
                &[],
                b"{}".to_vec(),
            )
            .await;
        assert_eq!(outcome, Err(Failure::Protocol));
    }
    // Nothing listens there.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let outcome = sender
        .send(
            &format!("http://127.0.0.1:{port}/hook"),
            &[],
            b"{}".to_vec(),
        )
        .await;
    assert_eq!(outcome, Err(Failure::Connect));
}

#[tokio::test]
async fn without_local_development_nothing_on_this_machine_is_reached() {
    let (port, seen) = plain(OK.to_vec()).await;
    let sender = Sender::new(false).unwrap();
    for (url, expected) in [
        (format!("http://127.0.0.1:{port}/hook"), Failure::InvalidUrl),
        (format!("http://localhost:{port}/hook"), Failure::InvalidUrl),
        (
            format!("https://127.0.0.1:{port}/hook"),
            Failure::InvalidUrl,
        ),
        (format!("https://[::1]:{port}/hook"), Failure::InvalidUrl),
        (
            format!("https://2130706433:{port}/hook"),
            Failure::InvalidUrl,
        ),
        (
            format!("https://[::ffff:127.0.0.1]:{port}/hook"),
            Failure::InvalidUrl,
        ),
        // A name is resolved, and its addresses are checked before a connection.
        (
            format!("https://localhost:{port}/hook"),
            Failure::NotDeliverable,
        ),
        // A name that cannot resolve gets the same answer as one that
        // resolves to this machine: the class does not tell them apart.
        (
            format!("https://{}.example:{port}/hook", "x".repeat(70)),
            Failure::NotDeliverable,
        ),
    ] {
        let outcome = sender.send(&url, &[], b"{}".to_vec()).await;
        assert_eq!(outcome, Err(expected), "{url}");
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        seen.lock().unwrap().len(),
        0,
        "no request reached the listener"
    );
}

#[tokio::test]
async fn tls_is_checked_against_the_trusted_roots_and_the_name() {
    let Some((cert, key)) = certificate("DNS:localhost,IP:127.0.0.1") else {
        return;
    };
    let (port, seen) = tls(cert.clone(), key).await;
    let body = br#"{"event":"notice.test"}"#.to_vec();
    // Trusted, and the name matches: by name and by address.
    let sender = trusting(&cert);
    for host in ["localhost", "127.0.0.1"] {
        let outcome = sender
            .send(&format!("https://{host}:{port}/hook"), &[], body.clone())
            .await;
        assert_eq!(outcome, Ok(200), "{host}");
    }
    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /hook HTTP/1.1\r\n"));
    assert!(requests[0]
        .to_ascii_lowercase()
        .contains(&format!("host: localhost:{port}\r\n")));
    assert!(requests[0].ends_with(r#"{"event":"notice.test"}"#));
    // The built-in public roots do not trust it: no request is sent.
    let public = Sender::new(true).unwrap();
    let outcome = public
        .send(&format!("https://localhost:{port}/hook"), &[], body.clone())
        .await;
    assert_eq!(outcome, Err(Failure::Tls));
    // Trusted, but for another name.
    let Some((other, other_key)) = certificate("DNS:other.example") else {
        return;
    };
    let (other_port, other_seen) = tls(other.clone(), other_key).await;
    let outcome = trusting(&other)
        .send(
            &format!("https://localhost:{other_port}/hook"),
            &[],
            body.clone(),
        )
        .await;
    assert_eq!(outcome, Err(Failure::Tls));
    // A TLS address on a plain listener, and the reverse, fail and send nothing readable.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_port = listener.local_addr().unwrap().port();
    let plain_seen = Arc::new(Mutex::new(Vec::new()));
    let record = plain_seen.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = stream.write_all(OK).await;
        let mut sent = Vec::new();
        let _ = stream.read_to_end(&mut sent).await;
        record
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(&sent).into_owned());
    });
    let outcome = sender
        .send(
            &format!("https://127.0.0.1:{plain_port}/hook"),
            &[],
            body.clone(),
        )
        .await;
    assert_eq!(outcome, Err(Failure::Tls));
    let outcome = sender
        .send(&format!("http://127.0.0.1:{port}/hook"), &[], body)
        .await;
    assert!(matches!(outcome, Err(Failure::Protocol)), "{outcome:?}");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(seen.lock().unwrap().len(), 2);
    assert_eq!(other_seen.lock().unwrap().len(), 0);
    assert!(plain_seen
        .lock()
        .unwrap()
        .iter()
        .all(|request| !request.contains("notice.test")));
}
