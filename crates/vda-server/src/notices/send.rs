//! The one outbound HTTP request the gateway makes for a notice.
//!
//! The address comes from an administrator, so the sender must not be usable
//! to reach anything inside the network. It takes `https` only (plain `http`
//! only to loopback in local development), resolves the name once, refuses
//! the delivery unless every address it got is public, and then connects to
//! an address it checked, so a second DNS answer cannot move the request. It
//! follows no redirect, reads no proxy from the environment, and gives up
//! after ten seconds. It reads the status line and at most a few kilobytes
//! of the answer, and keeps none of it.
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, pki_types::ServerName};
use vda_core::network::webhook_ip_allowed;

/// How much of a response is read before the connection is dropped.
const RESPONSE_LIMIT: usize = 4096;
/// The longest address that is accepted.
const URL_LIMIT: usize = 2048;
const USER_AGENT: &str = "vda-notices/1";

/// Why a delivery did not succeed. Only the class is kept and shown: never a
/// part of the address, of a response, or of an error text from the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The stored address or secret cannot be used.
    Config,
    InvalidUrl,
    /// The host name does not resolve, or resolves to an address a notice
    /// may not go to. One class for both, on purpose: telling them apart
    /// would tell which names exist inside the network.
    NotDeliverable,
    Connect,
    Tls,
    Timeout,
    /// The answer was not HTTP, or too large to read.
    Protocol,
    /// The receiver answered with a status that is not 2xx. A redirect is
    /// one of these: it is not followed.
    Http(u16),
}
impl Failure {
    /// The short text stored in `notices.last_error` and shown in the console.
    pub fn class(self) -> String {
        match self {
            Failure::Config => "config".into(),
            Failure::InvalidUrl => "invalid_url".into(),
            Failure::NotDeliverable => "not_deliverable".into(),
            Failure::Connect => "connect".into(),
            Failure::Tls => "tls".into(),
            Failure::Timeout => "timeout".into(),
            Failure::Protocol => "protocol".into(),
            Failure::Http(status) => format!("http_{status}"),
        }
    }
    /// The HTTP status, when the receiver gave one.
    pub fn status(self) -> Option<u16> {
        match self {
            Failure::Http(status) => Some(status),
            _ => None,
        }
    }
}

/// A webhook address that passed the checks that need no network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    https: bool,
    host: url::Host<String>,
    port: u16,
    /// The `Host` header: the host, and the port when it is not the default.
    authority: String,
    /// The path and the query.
    path: String,
}
impl Target {
    /// Parse and check an address. The message of an error is safe to show
    /// to the administrator who typed the address.
    pub fn parse(raw: &str, allow_private: bool) -> Result<Self, &'static str> {
        if raw.len() > URL_LIMIT {
            return Err("The address is too long");
        }
        // The parser drops tabs and line breaks and trims spaces. An address
        // that has them is not what its author sees, so it is refused.
        if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("The address must not contain spaces or control characters");
        }
        let url = url::Url::parse(raw).map_err(|_| "The address is not a valid URL")?;
        let https = match url.scheme() {
            "https" => true,
            "http" if allow_private => false,
            _ => return Err("The address must start with https://"),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err("The address must not contain a user name or a password");
        }
        if url.fragment().is_some() {
            return Err("The address must not contain a fragment");
        }
        let host = url.host().ok_or("The address has no host")?.to_owned();
        let literal = match &host {
            url::Host::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            url::Host::Ipv6(ip) => Some(IpAddr::V6(*ip)),
            url::Host::Domain(_) => None,
        };
        // A name is checked when it is resolved, for every delivery.
        if let Some(ip) = literal {
            if !address_allowed(ip, https, allow_private) {
                return Err("A notice cannot be sent to this address");
            }
        }
        let port = url
            .port_or_known_default()
            .ok_or("The address has no port")?;
        let name = url.host_str().ok_or("The address has no host")?;
        let authority = match url.port() {
            Some(port) => format!("{name}:{port}"),
            None => name.to_owned(),
        };
        let path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        Ok(Self {
            https,
            host,
            port,
            authority,
            path,
        })
    }
    /// The host, as shown to administrators in place of the address.
    pub fn host(&self) -> String {
        self.host.to_string()
    }
}
/// Whether a notice may go to this address over this scheme.
fn address_allowed(ip: IpAddr, https: bool, allow_private: bool) -> bool {
    let loopback = match ip {
        IpAddr::V4(v) => v.is_loopback(),
        IpAddr::V6(v) => v.is_loopback() || v.to_ipv4_mapped().is_some_and(|v| v.is_loopback()),
    };
    // Plain HTTP exists for a receiver on the developer's own machine.
    webhook_ip_allowed(ip, allow_private) && (https || loopback)
}

/// Sends notices. Cheap to clone; holds no connection between requests.
#[derive(Clone)]
pub struct Sender {
    tls: Arc<rustls::ClientConfig>,
    allow_private: bool,
    connect_timeout: Duration,
    total_timeout: Duration,
}
impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sender")
            .field("allow_private", &self.allow_private)
            .finish_non_exhaustive()
    }
}
impl Sender {
    /// A sender that trusts the public certificate authorities built into
    /// the binary. It reads no trust store, proxy or key log from the
    /// environment.
    pub fn new(allow_private: bool) -> Result<Self, rustls::Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(roots, allow_private)
    }
    /// A sender that trusts exactly `roots`.
    pub fn with_roots(
        roots: rustls::RootCertStore,
        allow_private: bool,
    ) -> Result<Self, rustls::Error> {
        // The provider is named: two are compiled into the build, and the
        // process-wide default must not decide which one signs a handshake.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: Arc::new(tls),
            allow_private,
            connect_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(10),
        })
    }
    /// Shorter limits, for tests.
    pub fn with_timeouts(mut self, connect: Duration, total: Duration) -> Self {
        self.connect_timeout = connect;
        self.total_timeout = total;
        self
    }
    /// Whether private addresses are allowed (local development).
    pub fn allow_private(&self) -> bool {
        self.allow_private
    }
    /// POST `body` as JSON to `url`. `Ok` is the 2xx status.
    pub async fn send(
        &self,
        url: &str,
        headers: &[(&'static str, String)],
        body: Vec<u8>,
    ) -> Result<u16, Failure> {
        match tokio::time::timeout(self.total_timeout, self.exchange(url, headers, body)).await {
            Ok(outcome) => outcome,
            Err(_) => Err(Failure::Timeout),
        }
    }
    async fn exchange(
        &self,
        url: &str,
        headers: &[(&'static str, String)],
        body: Vec<u8>,
    ) -> Result<u16, Failure> {
        let target = Target::parse(url, self.allow_private).map_err(|_| Failure::InvalidUrl)?;
        let addresses = self.resolve(&target).await?;
        let stream = tokio::time::timeout(self.connect_timeout, connect(&addresses))
            .await
            .map_err(|_| Failure::Timeout)??;
        let status = if target.https {
            let name = match &target.host {
                url::Host::Domain(name) => {
                    ServerName::try_from(name.clone()).map_err(|_| Failure::InvalidUrl)?
                }
                url::Host::Ipv4(ip) => ServerName::IpAddress(IpAddr::V4(*ip).into()),
                url::Host::Ipv6(ip) => ServerName::IpAddress(IpAddr::V6(*ip).into()),
            };
            let stream = tokio_rustls::TlsConnector::from(self.tls.clone())
                .connect(name, stream)
                .await
                .map_err(|_| Failure::Tls)?;
            post(TokioIo::new(stream), &target, headers, body).await?
        } else {
            post(TokioIo::new(stream), &target, headers, body).await?
        };
        if (200..300).contains(&status) {
            Ok(status)
        } else {
            Err(Failure::Http(status))
        }
    }
    /// Resolve the host once and check every address of the answer. One
    /// address that is not allowed refuses the delivery: a name that points
    /// at both a public and an internal address is not trusted for either.
    async fn resolve(&self, target: &Target) -> Result<Vec<SocketAddr>, Failure> {
        let addresses: Vec<SocketAddr> = match &target.host {
            url::Host::Ipv4(ip) => vec![SocketAddr::new(IpAddr::V4(*ip), target.port)],
            url::Host::Ipv6(ip) => vec![SocketAddr::new(IpAddr::V6(*ip), target.port)],
            url::Host::Domain(name) => tokio::time::timeout(
                self.connect_timeout,
                tokio::net::lookup_host((name.as_str(), target.port)),
            )
            .await
            .map_err(|_| Failure::NotDeliverable)?
            .map_err(|_| Failure::NotDeliverable)?
            .collect(),
        };
        // No answer and a refused answer are the same failure to the caller.
        let refused = addresses
            .iter()
            .any(|address| !address_allowed(address.ip(), target.https, self.allow_private));
        if addresses.is_empty() || refused {
            return Err(Failure::NotDeliverable);
        }
        Ok(addresses)
    }
}
/// Connect to the first checked address that answers. The name is not
/// resolved again: these are the addresses that were checked.
async fn connect(addresses: &[SocketAddr]) -> Result<TcpStream, Failure> {
    for address in addresses.iter().take(4) {
        if let Ok(stream) = TcpStream::connect(address).await {
            // A small request and a small answer: do not wait to batch them.
            let _ = stream.set_nodelay(true);
            return Ok(stream);
        }
    }
    Err(Failure::Connect)
}
/// Ends the task that drives a connection when the request is over, however
/// it ends.
struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
/// Send one POST on an open connection and return the status of the answer.
async fn post<I>(
    io: I,
    target: &Target,
    headers: &[(&'static str, String)],
    body: Vec<u8>,
) -> Result<u16, Failure>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        // Also the limit of the response head.
        .max_buf_size(16 * 1024)
        .handshake::<I, Full<Bytes>>(io)
        .await
        .map_err(|_| Failure::Protocol)?;
    let _driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(target.path.as_str())
        .header(hyper::header::HOST, target.authority.as_str())
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::USER_AGENT, USER_AGENT)
        .header(hyper::header::CONNECTION, "close");
    for (name, value) in headers {
        request = request.header(*name, value.as_str());
    }
    let request = request
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| Failure::InvalidUrl)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| Failure::Protocol)?;
    let status = response.status().as_u16();
    // Let a small answer finish, so the receiver sees a clean close; the
    // content is dropped as it arrives.
    let mut body = response.into_body();
    let mut read = 0usize;
    while read < RESPONSE_LIMIT {
        match body.frame().await {
            Some(Ok(frame)) => read += frame.data_ref().map_or(0, Bytes::len),
            _ => break,
        }
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_must_be_https_without_credentials() {
        let ok = Target::parse("https://hooks.example/services/T0/B0/x?y=1", false);
        assert_eq!(
            ok.as_ref()
                .map(|t| (t.https, t.port, t.authority.as_str(), t.path.as_str())),
            Ok((true, 443, "hooks.example", "/services/T0/B0/x?y=1"))
        );
        assert_eq!(ok.map(|t| t.host()), Ok("hooks.example".to_owned()));
        let port = Target::parse("https://hooks.example:8443", false);
        assert_eq!(
            port.as_ref()
                .map(|t| (t.port, t.authority.as_str(), t.path.as_str())),
            Ok((8443, "hooks.example:8443", "/"))
        );
        for refused in [
            // Schemes.
            "http://hooks.example/x",
            "ftp://hooks.example/x",
            "file:///etc/passwd",
            "gopher://hooks.example/x",
            "javascript:alert(1)",
            "data:text/plain,x",
            "//hooks.example/x",
            "hooks.example/x",
            "",
            // Credentials in the address.
            "https://user@hooks.example/x",
            "https://user:pass@hooks.example/x",
            "https://:pass@hooks.example/x",
            // No host, a fragment, spaces and control characters.
            "https://",
            "https://hooks.example/x#frag",
            "https://hooks.example/a b",
            " https://hooks.example/x",
            "https://hooks.example/x\n",
            "https://hooks.exa\tmple/x",
            "https://hooks.example/\u{0}",
        ] {
            assert!(Target::parse(refused, false).is_err(), "{refused:?}");
        }
        assert!(Target::parse(&format!("https://h.example/{}", "a".repeat(2048)), false).is_err());
    }

    #[test]
    fn an_address_that_is_an_ip_is_checked_in_every_spelling() {
        for refused in [
            "https://127.0.0.1/x",
            "https://10.0.0.5/x",
            "https://172.16.0.1/x",
            "https://192.168.1.1/x",
            "https://100.64.0.1/x",
            "https://169.254.169.254/latest/meta-data/",
            "https://0.0.0.0/x",
            // The forms a URL parser reads as an IPv4 address.
            "https://2130706433/x",
            "https://0x7f000001/x",
            "https://0x7f.1/x",
            "https://017700000001/x",
            "https://0177.0.0.1/x",
            "https://127.1/x",
            "https://10.1/x",
            "https://0xa9fea9fe/x",
            "https://3232235777/x",
            "https://1.1.1.1.:443@127.0.0.1/x",
            // IPv6, plain and with an IPv4 address inside.
            "https://[::1]/x",
            "https://[::]/x",
            "https://[fe80::1]/x",
            "https://[fc00::1]/x",
            "https://[fd00:ec2::254]/x",
            "https://[::ffff:127.0.0.1]/x",
            "https://[::ffff:7f00:1]/x",
            "https://[::ffff:10.0.0.1]/x",
            "https://[::ffff:169.254.169.254]/x",
            "https://[::127.0.0.1]/x",
            "https://[64:ff9b::7f00:1]/x",
            "https://[2002:7f00:1::]/x",
            "https://[::ffff:0:127.0.0.1]/x",
            "https://[::ffff:0:7f00:1]/x",
            "https://[::ffff:0:a9fe:a9fe]/x",
            "https://[::ffff:0:10.0.0.1]/x",
            "https://[2001:10::1]/x",
            "https://[2001:20::1]/x",
            "https://[2001:2::1]/x",
            "https://[3fff::1]/x",
            "https://[5f00::1]/x",
            "https://[::1:0:0:1]/x",
            "https://[1::1]/x",
            "https://[fe00::1]/x",
            "https://[64:ff9b:0:1::7f00:1]/x",
            "https://168.63.129.16/x",
            "https://192.88.99.1/x",
        ] {
            assert!(Target::parse(refused, false).is_err(), "{refused}");
        }
        for public in [
            "https://1.1.1.1/x",
            "https://[2606:4700:4700::1111]/x",
            "https://16843009/x",
        ] {
            assert!(Target::parse(public, false).is_ok(), "{public}");
        }
        // The parser, not this code, decides what the host is: the checked
        // host is the host that is connected to.
        let slash = Target::parse("https://1.1.1.1\\@127.0.0.1/x", false);
        assert_eq!(slash.map(|t| t.host()), Ok("1.1.1.1".to_owned()));
    }

    #[test]
    fn plain_http_is_for_loopback_in_local_development_only() {
        assert!(Target::parse("http://127.0.0.1:9000/hook", false).is_err());
        let local = Target::parse("http://127.0.0.1:9000/hook", true);
        assert_eq!(
            local
                .as_ref()
                .map(|t| (t.https, t.port, t.authority.as_str())),
            Ok((false, 9000, "127.0.0.1:9000"))
        );
        assert!(Target::parse("http://[::1]:9000/hook", true).is_ok());
        // Not loopback: refused over plain HTTP also in local development.
        assert!(Target::parse("http://10.0.0.5/hook", true).is_err());
        assert!(Target::parse("http://1.1.1.1/hook", true).is_err());
        // Private addresses are allowed over TLS in local development, the
        // metadata address never.
        assert!(Target::parse("https://10.0.0.5/hook", true).is_ok());
        assert!(Target::parse("https://169.254.169.254/hook", true).is_err());
        assert!(Target::parse("http://169.254.169.254/hook", true).is_err());
    }

    #[test]
    fn a_failure_is_named_by_its_class_only() {
        assert_eq!(Failure::Http(500).class(), "http_500");
        assert_eq!(Failure::Http(302).status(), Some(302));
        assert_eq!(Failure::NotDeliverable.class(), "not_deliverable");
        assert_eq!(Failure::Tls.status(), None);
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_loopback_is_refused_before_any_connection() {
        let Ok(sender) = Sender::new(false) else {
            return;
        };
        assert_eq!(
            sender
                .send("https://localhost:9/hook", &[], Vec::new())
                .await,
            Err(Failure::NotDeliverable)
        );
        assert_eq!(
            sender
                .send("http://localhost:9/hook", &[], Vec::new())
                .await,
            Err(Failure::InvalidUrl)
        );
    }
}
