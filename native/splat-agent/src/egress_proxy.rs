// Hostname egress for one lease: a CONNECT proxy the daemon runs outside the lease.
//
// The kernel allow-list speaks in IPv4 address and port, and a lease cannot resolve a name. So a
// tool that needs `pypi.org` had no way to say so: its addresses rotate, and a pinned address is
// stale by the time it is written down. The daemon therefore listens on one loopback port per
// lease, the lease's connect allow-list holds exactly that port, and every connection is judged
// here by name. The map is keyed by cgroup, so one lease dialling another's port is refused by the
// hook that was already there - nothing in the BPF program changes for this.
//
// What is checked, and what is not, is docs/EGRESS-PROXY.md. The short form: the CONNECT name, the
// address it resolves to, and the SNI in the ClientHello. Not the Host header inside TLS.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

/// Below Linux's default ephemeral range (32768-60999), so an outbound connection of the guest's
/// own never lands on a port a lease's proxy is about to ask for.
pub const DEFAULT_PORT_START: u16 = 28000;

/// A receipt names every host a lease reached, in full. A cap is what makes "in full" true: past
/// it a new host is refused and counted, so the list is never silently cut short.
pub const MAX_HOSTS_PER_LEASE: usize = 64;

/// Connections one lease's proxy holds at once. Every one is a descriptor of the daemon's, which
/// all leases share, so a lease that opens sockets in a loop must run out of its own allowance
/// before it can run the daemon out of descriptors.
const MAX_CONNECTIONS_PER_LEASE: usize = 128;

/// Refusals listed by reason in the unsigned EXIT frame. The signed count has no such limit.
const MAX_REFUSALS_LISTED: usize = 32;
const MAX_REQUEST_BYTES: usize = 4096;
/// One TLS record: five bytes of header and at most 2^14 of body.
const MAX_HELLO_BYTES: usize = 5 + 16384;
const HANDSHAKE_PATIENCE: Duration = Duration::from_secs(10);
const ECH_EXTENSION: u16 = 0xfe0d;

/// One policy entry: an exact name, or every name below a suffix, on one port.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostRule {
    /// Lower-case ASCII, no trailing dot. For a wildcard, the part after `*.`.
    name: String,
    wildcard: bool,
    port: u16,
}

impl HostRule {
    /// `name`, `name:port`, `*.suffix` or `*.suffix:port`. The port defaults to 443. Anything else
    /// is an error, never a skipped entry: a rule the proxy cannot hold is a rule nobody enforces.
    pub fn parse(entry: &str) -> std::result::Result<Self, String> {
        let (host, port) = match entry.rsplit_once(':') {
            Some((host, port)) => {
                let port: u16 = port.parse().ok().filter(|p| *p != 0)
                    .ok_or_else(|| format!("egress host {entry:?} has no port from 1 to 65535"))?;
                (host, port)
            }
            None => (entry, 443),
        };
        let (name, wildcard) = match host.strip_prefix("*.") {
            Some(suffix) => (suffix, true),
            None => (host, false),
        };
        if !is_hostname(name) {
            return Err(format!(
                "egress host {entry:?} is not a lower-case DNS name, optionally led by '*.' and followed by ':port'"
            ));
        }
        Ok(Self { name: name.to_string(), wildcard, port })
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        if port != self.port {
            return false;
        }
        if !self.wildcard {
            return host == self.name;
        }
        // Whole labels below the suffix, never the suffix itself and never a name that merely ends
        // in the same letters: `*.example.com` must not admit `example.com` or `badexample.com`.
        host.strip_suffix(self.name.as_str()).is_some_and(|rest| rest.len() > 1 && rest.ends_with('.'))
    }

    /// Whether everything `inner` admits, this rule admits too.
    fn covers(&self, inner: &HostRule) -> bool {
        if !inner.wildcard {
            return self.matches(&inner.name, inner.port);
        }
        self.wildcard && self.port == inner.port
            && (inner.name == self.name || self.matches(&inner.name, inner.port))
    }
}

impl std::fmt::Display for HostRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}:{}", if self.wildcard { "*." } else { "" }, self.name, self.port)
    }
}

/// A DNS name as the proxy will hold it: letters, digits and hyphens in dot-separated labels, at
/// least two labels, and not an address. An address is refused because the whole point of this
/// path is a name the receipt can state; pinned addresses have their own, older, vocabulary.
fn is_hostname(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.parse::<std::net::IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty() && label.len() <= 63
                && !label.starts_with('-') && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        // An all-digit last label is how `1.2.3.4` and its odd spellings (`1.2.3`, `0x7f.1`) reach
        // a resolver as an address. No public suffix is numeric.
        && name.rsplit('.').next().is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
}

pub fn parse_rules(entries: &[String]) -> std::result::Result<Vec<HostRule>, String> {
    entries.iter().map(|entry| HostRule::parse(entry)).collect()
}

/// The first of `asked` that `allowed` does not cover, if any.
pub fn first_outside<'a>(allowed: &[HostRule], asked: &'a [HostRule]) -> Option<&'a HostRule> {
    asked.iter().find(|rule| !allowed.iter().any(|ceiling| ceiling.covers(rule)))
}

/// Globally routable IPv4 only. A name that resolves anywhere else - loopback, the guest's own
/// addresses, the Windows host across the WSL NAT, a cloud metadata service, another lease's
/// proxy - is refused, because a hostname rule was never consent to reach those.
fn is_public(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    !(addr.is_unspecified() || addr.is_loopback() || addr.is_private() || addr.is_link_local()
        || addr.is_broadcast() || addr.is_multicast() || addr.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64)   // 100.64.0.0/10, carrier-grade NAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24, protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18)   // 198.18.0.0/15, benchmarking
        || o[0] >= 240)                            // 240.0.0.0/4, reserved
}

#[derive(Default)]
struct Carried {
    hosts: BTreeSet<String>,
    refused: u64,
    refusals: Vec<String>,
}

/// What a lease's proxy did, for the receipt.
#[derive(Debug, PartialEq, Eq)]
pub struct EgressRecord {
    /// Every `host:port` carried, sorted.
    pub hosts: Vec<String>,
    pub refused: u64,
    /// `target: reason` for the first refusals; unsigned, for a person to read.
    pub refusals: Vec<String>,
}

/// One lease's listener. Dropping it closes the listener and every connection it carries.
pub struct LeaseProxy {
    port: u16,
    state: Arc<Mutex<Carried>>,
    accept: JoinHandle<()>,
}

impl LeaseProxy {
    /// Binds the first free loopback port in `start..start+count` and serves `rules` on it.
    ///
    /// The kernel is the pool: a port is taken exactly while a listener holds it, so there is no
    /// table here to drift from the truth, and a port a lease squatted is skipped, not shared.
    pub async fn start(start: u16, count: u16, rules: Vec<HostRule>) -> Result<Self> {
        Self::start_with(start, count, rules, Dialer::default()).await
    }

    async fn start_with(start: u16, count: u16, rules: Vec<HostRule>, dialer: Dialer) -> Result<Self> {
        let mut bound = None;
        for port in start..start.saturating_add(count) {
            if let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                bound = Some((listener, port));
                break;
            }
        }
        let Some((listener, port)) = bound else {
            bail!("no free egress proxy port in {start}..{}", start.saturating_add(count));
        };
        let state = Arc::new(Mutex::new(Carried::default()));
        let shared = Arc::new(Shared { rules, dialer, state: state.clone() });
        let accept = tokio::spawn(async move {
            // Owned by this task, so aborting it aborts every connection with it.
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            // Out of descriptors, most likely. Wait, or this loop spins on the error.
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        };
                        if connections.len() >= MAX_CONNECTIONS_PER_LEASE {
                            shared.refuse("", "this lease has too many connections open");
                            continue; // Dropping the stream closes it.
                        }
                        let shared = shared.clone();
                        connections.spawn(async move { shared.serve(stream).await });
                    }
                    Some(_) = connections.join_next() => {}
                }
            }
        });
        Ok(Self { port, state, accept })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// `http://127.0.0.1:<port>`, the value of the lease's proxy variables.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Stops the proxy and returns what it did. Called once the workload is gone, so nothing the
    /// lease could still do is missing from the answer.
    pub fn finish(self) -> EgressRecord {
        self.accept.abort();
        let mut carried = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        EgressRecord {
            hosts: std::mem::take(&mut carried.hosts).into_iter().collect(),
            refused: carried.refused,
            refusals: std::mem::take(&mut carried.refusals),
        }
    }
}

impl Drop for LeaseProxy {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// How the proxy reaches the outside. Production resolves and filters; a test pins one address,
/// because the filter rightly refuses the loopback listeners a test can stand up.
#[derive(Clone, Default)]
struct Dialer {
    #[cfg(test)]
    fixed: Option<SocketAddr>,
}

impl Dialer {
    async fn connect(&self, host: &str, port: u16) -> std::result::Result<TcpStream, &'static str> {
        #[cfg(test)]
        if let Some(addr) = self.fixed {
            return TcpStream::connect(addr).await.map_err(|_| "the host could not be reached");
        }
        let resolved = tokio::net::lookup_host((host, port)).await.map_err(|_| "the name did not resolve")?;
        let mut public = Vec::new();
        for addr in resolved {
            match addr {
                // One non-public answer refuses the name outright. Trying the next address would
                // let a record set mixing a public and a private address choose per attempt.
                SocketAddr::V4(v4) if !is_public(*v4.ip()) => return Err("the name resolves to a non-public address"),
                SocketAddr::V4(_) => public.push(addr),
                SocketAddr::V6(_) => {}
            }
        }
        if public.is_empty() {
            return Err("the name has no IPv4 address");
        }
        for addr in public {
            // The address that was judged is the address that is dialled: no second lookup.
            if let Ok(stream) = TcpStream::connect(addr).await {
                return Ok(stream);
            }
        }
        Err("the host could not be reached")
    }
}

struct Shared {
    rules: Vec<HostRule>,
    dialer: Dialer,
    state: Arc<Mutex<Carried>>,
}

impl Shared {
    fn refuse(&self, target: &str, reason: &str) {
        let mut carried = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        carried.refused += 1;
        if carried.refusals.len() < MAX_REFUSALS_LISTED {
            // The target is the lease's own bytes: bounded and stripped before it is written down.
            let shown: String = target.chars().filter(|c| c.is_ascii_graphic()).take(80).collect();
            carried.refusals.push(format!("{shown}: {reason}"));
        }
    }

    /// Records `target` as carried, unless that would take the lease past its cap.
    fn admit(&self, target: &str) -> bool {
        let mut carried = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if carried.hosts.contains(target) {
            return true;
        }
        if carried.hosts.len() >= MAX_HOSTS_PER_LEASE {
            return false;
        }
        carried.hosts.insert(target.to_string())
    }

    async fn serve(&self, mut client: TcpStream) {
        let (target, outcome) = match tokio::time::timeout(HANDSHAKE_PATIENCE, self.open(&mut client)).await {
            Ok(Ok(tunnel)) => {
                let (mut upstream, hello) = tunnel;
                // Only now is anything forwarded: the ClientHello that was held back, then both ways.
                if upstream.write_all(&hello).await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
                return;
            }
            Ok(Err(refusal)) => refusal,
            Err(_) => (String::new(), Refusal::plain("the handshake did not complete in time")),
        };
        self.refuse(&target, outcome.reason);
        if outcome.answer {
            let reply = format!(
                "HTTP/1.1 {}\r\nX-Splat-Refused: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                outcome.status, outcome.reason
            );
            let _ = client.write_all(reply.as_bytes()).await;
        }
    }

    /// Everything that must hold before a byte is forwarded. Returns the upstream connection and
    /// the ClientHello read from the tool, or the target as far as it was learned and why not.
    async fn open(&self, client: &mut TcpStream) -> std::result::Result<(TcpStream, Vec<u8>), (String, Refusal)> {
        let head = read_head(client).await.map_err(|reason| (String::new(), Refusal::http("400 Bad Request", reason)))?;
        let (host, port) = parse_connect(&head).map_err(|refusal| (String::new(), refusal))?;
        let target = format!("{host}:{port}");
        let fail = |refusal: Refusal| (target.clone(), refusal);

        if !self.rules.iter().any(|rule| rule.matches(&host, port)) {
            return Err(fail(Refusal::http("403 Forbidden", "the host is not in this lease's egress policy")));
        }
        let upstream = self.dialer.connect(&host, port).await
            .map_err(|reason| fail(Refusal::http("502 Bad Gateway", reason)))?;
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await
            .map_err(|_| fail(Refusal::plain("the tool closed the connection")))?;

        let hello = read_client_hello(client).await.map_err(|reason| fail(Refusal::plain(reason)))?;
        match client_hello_sni(&hello) {
            Ok(Some(sni)) if sni.eq_ignore_ascii_case(&host) => {}
            Ok(Some(_)) => return Err(fail(Refusal::plain("the TLS server name is not the host that was asked for"))),
            Ok(None) => return Err(fail(Refusal::plain("the TLS ClientHello names no server"))),
            Err(reason) => return Err(fail(Refusal::plain(reason))),
        }
        if !self.admit(&target) {
            return Err(fail(Refusal::plain("this lease has reached its limit of distinct hosts")));
        }
        Ok((upstream, hello))
    }
}

struct Refusal {
    status: &'static str,
    reason: &'static str,
    /// False once `200` has been sent: the tool is speaking TLS by then and the only honest reply
    /// left is to close.
    answer: bool,
}

impl Refusal {
    fn http(status: &'static str, reason: &'static str) -> Self {
        Self { status, reason, answer: true }
    }
    fn plain(reason: &'static str) -> Self {
        Self { status: "", reason, answer: false }
    }
}

async fn read_head(client: &mut TcpStream) -> std::result::Result<Vec<u8>, &'static str> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    // A byte at a time, so nothing past the blank line is consumed: what follows it is the tool's
    // ClientHello, and that has to arrive at `read_client_hello` whole.
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == MAX_REQUEST_BYTES {
            return Err("the request is too long");
        }
        match client.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return Err("the request ended early"),
        }
    }
    Ok(head)
}

/// The host and port of a `CONNECT host:port HTTP/1.x` request, the host lower-cased.
fn parse_connect(head: &[u8]) -> std::result::Result<(String, u16), Refusal> {
    let bad = || Refusal::http("400 Bad Request", "the request is not a CONNECT this proxy understands");
    let text = std::str::from_utf8(head).map_err(|_| bad())?;
    let mut parts = text.lines().next().ok_or_else(bad)?.split(' ');
    let (method, authority, version) = (parts.next(), parts.next(), parts.next());
    if parts.next().is_some() {
        return Err(bad());
    }
    match method {
        Some("CONNECT") => {}
        Some(other) if !other.is_empty() => {
            return Err(Refusal::http("405 Method Not Allowed", "this proxy carries CONNECT only"))
        }
        _ => return Err(bad()),
    }
    if !version.is_some_and(|v| v == "HTTP/1.1" || v == "HTTP/1.0") {
        return Err(bad());
    }
    let (host, port) = authority.and_then(|a| a.rsplit_once(':')).ok_or_else(bad)?;
    let port: u16 = port.parse().ok().filter(|p| *p != 0).ok_or_else(bad)?;
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if !is_hostname(&host) {
        return Err(Refusal::http("403 Forbidden", "the target is not a DNS name"));
    }
    Ok((host, port))
}

async fn read_client_hello(client: &mut TcpStream) -> std::result::Result<Vec<u8>, &'static str> {
    let mut hello = vec![0u8; 5];
    client.read_exact(&mut hello).await.map_err(|_| "the tool sent no TLS ClientHello")?;
    // Handshake record, TLS major version 3.
    if hello[0] != 22 || hello[1] != 3 {
        return Err("the tool did not start TLS");
    }
    let length = u16::from_be_bytes([hello[3], hello[4]]) as usize;
    if length == 0 || 5 + length > MAX_HELLO_BYTES {
        return Err("the TLS record has an impossible length");
    }
    hello.resize(5 + length, 0);
    client.read_exact(&mut hello[5..]).await.map_err(|_| "the TLS ClientHello ended early")?;
    Ok(hello)
}

/// The server name in a ClientHello that fits one record, or why it cannot be trusted to have one.
///
/// A ClientHello split across records is refused, not reassembled: no mainstream client does it
/// to a hello this small, and a parser that stitches records is a parser that can be made to
/// disagree with the server about where the name is.
fn client_hello_sni(record: &[u8]) -> std::result::Result<Option<String>, &'static str> {
    const MALFORMED: &str = "the TLS ClientHello is malformed";
    let mut body = Reader(record.get(5..).ok_or(MALFORMED)?);
    if body.u8()? != 1 {
        return Err("the first TLS message is not a ClientHello");
    }
    let length = body.u24()?;
    let mut hello = Reader(body.take(length).map_err(|_| "the TLS ClientHello spans more than one record")?);
    hello.take(2 + 32)?; // legacy_version, random
    let session = hello.u8()? as usize;
    hello.take(session)?;
    let suites = hello.u16()? as usize;
    hello.take(suites)?;
    let compression = hello.u8()? as usize;
    hello.take(compression)?;
    if hello.0.is_empty() {
        return Ok(None);
    }
    let extensions = hello.u16()? as usize;
    let mut extensions = Reader(hello.take(extensions)?);
    let mut name = None;
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        let length = extensions.u16()? as usize;
        let mut data = Reader(extensions.take(length)?);
        if kind == ECH_EXTENSION {
            // With an encrypted hello the name out here is a decoy by design.
            return Err("the TLS ClientHello carries Encrypted Client Hello");
        }
        if kind == 0 {
            if name.is_some() {
                return Err(MALFORMED);
            }
            let list = data.u16()? as usize;
            let mut list = Reader(data.take(list)?);
            if list.u8()? != 0 {
                return Err(MALFORMED);
            }
            let length = list.u16()? as usize;
            let bytes = list.take(length)?;
            // A second name in the list is one this proxy would not have judged.
            if !list.0.is_empty() {
                return Err(MALFORMED);
            }
            name = Some(std::str::from_utf8(bytes).map_err(|_| MALFORMED)?.to_string());
        }
    }
    Ok(name)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> std::result::Result<&'a [u8], &'static str> {
        if self.0.len() < n {
            return Err("the TLS ClientHello is malformed");
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> std::result::Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> std::result::Result<u16, &'static str> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> std::result::Result<usize, &'static str> {
        let b = self.take(3)?;
        Ok((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(entry: &str) -> HostRule {
        HostRule::parse(entry).unwrap()
    }

    /// A ClientHello record carrying `extensions` verbatim.
    fn hello_with(extensions: &[u8]) -> Vec<u8> {
        let mut hello = vec![3, 3];
        hello.extend([7u8; 32]);
        hello.push(0); // session id
        hello.extend([0, 2, 0x13, 0x01]); // one cipher suite
        hello.extend([1, 0]); // null compression
        hello.extend((extensions.len() as u16).to_be_bytes());
        hello.extend(extensions);
        let mut record = vec![22, 3, 1];
        record.extend(((hello.len() + 4) as u16).to_be_bytes());
        record.push(1);
        record.extend(&(hello.len() as u32).to_be_bytes()[1..]);
        record.extend(hello);
        record
    }

    fn sni_extension(name: &str) -> Vec<u8> {
        let mut ext = vec![0, 0];
        ext.extend(((name.len() + 5) as u16).to_be_bytes());
        ext.extend(((name.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend((name.len() as u16).to_be_bytes());
        ext.extend(name.as_bytes());
        ext
    }

    #[test]
    fn a_rule_is_a_name_with_an_optional_wildcard_and_port_and_nothing_else() {
        assert_eq!(rule("pypi.org").to_string(), "pypi.org:443");
        assert_eq!(rule("*.githubusercontent.com:8443").to_string(), "*.githubusercontent.com:8443");
        for bad in ["", "localhost", "Pypi.org", "pypi.org:0", "pypi.org:70000", "pypi.org:", "*.com.", "a..b",
            "-a.com", "a-.com", "*", "*.", "a.*.com", "**.a.com", "1.2.3.4", "1.2.3.4:443", "0x7f.1", "a.b/c",
            "a.b c", "[::1]:443", "::1", "exa\u{0441}mple.com"] {
            assert!(HostRule::parse(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_wildcard_admits_whole_labels_below_its_suffix_and_never_the_suffix_itself() {
        let wild = rule("*.example.com");
        assert!(wild.matches("a.example.com", 443));
        assert!(wild.matches("a.b.example.com", 443));
        assert!(!wild.matches("example.com", 443), "the suffix itself");
        assert!(!wild.matches("badexample.com", 443), "a name that only ends in the same letters");
        assert!(!wild.matches(".example.com", 443));
        assert!(!wild.matches("a.example.com", 80), "another port");
        assert!(!wild.matches("a.example.com.evil.net", 443));
        let exact = rule("example.com");
        assert!(exact.matches("example.com", 443));
        assert!(!exact.matches("a.example.com", 443));
    }

    #[test]
    fn a_request_must_sit_inside_the_operators_rules() {
        let operator = [rule("pypi.org"), rule("*.pythonhosted.org"), rule("git.example.com:22")];
        let inside = [rule("pypi.org"), rule("files.pythonhosted.org"), rule("*.pythonhosted.org"),
            rule("*.cdn.pythonhosted.org"), rule("git.example.com:22")];
        assert_eq!(first_outside(&operator, &inside), None);
        for outside in ["pypi.org:80", "*.pypi.org", "pythonhosted.org", "*.evil.net", "git.example.com", "evil.net"] {
            let asked = [rule(outside)];
            assert_eq!(first_outside(&operator, &asked), Some(&asked[0]), "{outside} was let through");
        }
        assert!(first_outside(&[], &[rule("pypi.org")]).is_some(), "an empty policy admits nothing");
    }

    #[test]
    fn only_globally_routable_addresses_are_dialled() {
        for private in ["127.0.0.1", "127.8.8.8", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            "169.254.169.254", "100.64.0.1", "100.127.255.255", "0.0.0.0", "0.1.2.3", "224.0.0.1",
            "255.255.255.255", "240.0.0.1", "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.19.255.255",
            "198.51.100.1", "203.0.113.1"] {
            assert!(!is_public(private.parse().unwrap()), "{private} was called public");
        }
        for public in ["1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.0", "172.15.0.1", "172.32.0.1",
            "198.17.0.1", "198.20.0.1", "151.101.0.223"] {
            assert!(is_public(public.parse().unwrap()), "{public} was called non-public");
        }
    }

    #[test]
    fn connect_is_the_only_request_and_its_target_must_be_a_name() {
        let ok = |line: &str| parse_connect(format!("{line}\r\nHost: x\r\n\r\n").as_bytes()).map_err(|r| r.status);
        assert_eq!(ok("CONNECT PyPI.org:443 HTTP/1.1"), Ok(("pypi.org".into(), 443)));
        assert_eq!(ok("CONNECT pypi.org.:443 HTTP/1.0"), Ok(("pypi.org".into(), 443)), "one trailing dot");
        assert_eq!(ok("GET http://pypi.org/ HTTP/1.1"), Err("405 Method Not Allowed"));
        assert_eq!(ok("CONNECT 1.1.1.1:443 HTTP/1.1"), Err("403 Forbidden"));
        assert_eq!(ok("CONNECT [::1]:443 HTTP/1.1"), Err("403 Forbidden"));
        assert_eq!(ok("CONNECT localhost:443 HTTP/1.1"), Err("403 Forbidden"));
        for bad in ["CONNECT pypi.org HTTP/1.1", "CONNECT pypi.org:0 HTTP/1.1", "CONNECT pypi.org:443",
            "CONNECT pypi.org:443 HTTP/2", "CONNECT pypi.org:443 HTTP/1.1 x", "CONNECT  pypi.org:443 HTTP/1.1", ""] {
            assert_eq!(ok(bad), Err("400 Bad Request"), "{bad:?}");
        }
    }

    #[test]
    fn the_server_name_is_read_from_a_client_hello_and_a_doubtful_hello_is_refused() {
        assert_eq!(client_hello_sni(&hello_with(&sni_extension("pypi.org"))), Ok(Some("pypi.org".into())));
        assert_eq!(client_hello_sni(&hello_with(&[])), Ok(None));
        // An unrelated extension before the name is skipped, not mistaken for it.
        let mut padded = vec![0, 10, 0, 2, 0, 0];
        padded.extend(sni_extension("pypi.org"));
        assert_eq!(client_hello_sni(&hello_with(&padded)), Ok(Some("pypi.org".into())));

        let mut ech = sni_extension("public.example");
        ech.extend([0xfe, 0x0d, 0, 1, 0]);
        assert_eq!(client_hello_sni(&hello_with(&ech)), Err("the TLS ClientHello carries Encrypted Client Hello"));

        let mut twice = sni_extension("pypi.org");
        twice.extend(sni_extension("evil.net"));
        assert!(client_hello_sni(&hello_with(&twice)).is_err(), "two server_name extensions");

        // Two names in one list: the second is one the proxy never judged.
        let two_names = [0, 0, 0, 13, 0, 11, 0, 0, 3, b'a', b'.', b'b', 0, 0, 2, b'c', b'd'];
        assert!(client_hello_sni(&hello_with(&two_names)).is_err());

        let whole = hello_with(&sni_extension("pypi.org"));
        for cut in 5..whole.len() {
            assert!(client_hello_sni(&whole[..cut]).is_err(), "a hello cut at {cut} bytes was read");
        }
        let mut server_hello = whole.clone();
        server_hello[5] = 2;
        assert!(client_hello_sni(&server_hello).is_err());
    }

    /// An upstream that answers every connection with what it was sent, upper-cased.
    async fn shouting_upstream() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 32768];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 || stream.write_all(&buf[..n].to_ascii_uppercase()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    async fn proxy_for(rules: &[&str], upstream: SocketAddr) -> LeaseProxy {
        let rules = rules.iter().map(|r| rule(r)).collect();
        LeaseProxy::start_with(DEFAULT_PORT_START, 256, rules, Dialer { fixed: Some(upstream) }).await.unwrap()
    }

    /// Sends a CONNECT, and returns the status line with the stream still open.
    async fn connect(proxy: &LeaseProxy, authority: &str) -> (String, TcpStream) {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).await.unwrap();
        stream.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1, "the proxy closed before answering");
            head.push(byte[0]);
        }
        (String::from_utf8(head).unwrap().lines().next().unwrap().to_string(), stream)
    }

    async fn closed(stream: TcpStream) -> bool {
        closed_within(stream, 5000).await
    }

    async fn closed_within(mut stream: TcpStream, millis: u64) -> bool {
        let mut buf = [0u8; 1];
        matches!(tokio::time::timeout(Duration::from_millis(millis), stream.read(&mut buf)).await, Ok(Ok(0)) | Ok(Err(_)))
    }

    #[tokio::test]
    async fn an_allowed_host_is_carried_and_named_in_the_record() {
        let proxy = proxy_for(&["pypi.org", "*.pythonhosted.org"], shouting_upstream().await).await;
        let (status, mut stream) = connect(&proxy, "Files.PythonHosted.org:443").await;
        assert_eq!(status, "HTTP/1.1 200 Connection Established");
        let hello = hello_with(&sni_extension("files.pythonhosted.org"));
        stream.write_all(&hello).await.unwrap();
        // The held-back ClientHello reaches the upstream first and whole, then bytes flow both ways.
        let mut echoed = vec![0u8; hello.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, hello.to_ascii_uppercase());
        stream.write_all(b"after the hello").await.unwrap();
        let mut reply = [0u8; 15];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"AFTER THE HELLO");
        drop(stream);

        assert_eq!(proxy.finish(), EgressRecord { hosts: vec!["files.pythonhosted.org:443".into()], refused: 0, refusals: vec![] });
    }

    #[tokio::test]
    async fn a_host_outside_the_policy_is_refused_and_counted_and_never_reaches_the_upstream() {
        let proxy = proxy_for(&["pypi.org"], shouting_upstream().await).await;
        let (status, _) = connect(&proxy, "evil.net:443").await;
        assert_eq!(status, "HTTP/1.1 403 Forbidden");
        let (status, _) = connect(&proxy, "pypi.org:80").await;
        assert_eq!(status, "HTTP/1.1 403 Forbidden", "the right name on another port");
        let (status, _) = connect(&proxy, "127.0.0.1:443").await;
        assert_eq!(status, "HTTP/1.1 403 Forbidden");

        let record = proxy.finish();
        assert_eq!((record.hosts.len(), record.refused), (0, 3));
        assert_eq!(record.refusals[0], "evil.net:443: the host is not in this lease's egress policy");
    }

    #[tokio::test]
    async fn a_tunnel_whose_tls_names_another_host_or_is_not_tls_is_closed_before_a_byte_is_forwarded() {
        let proxy = proxy_for(&["pypi.org"], shouting_upstream().await).await;

        let (_, mut fronted) = connect(&proxy, "pypi.org:443").await;
        fronted.write_all(&hello_with(&sni_extension("evil.net"))).await.unwrap();
        assert!(closed(fronted).await, "a ClientHello for another name was forwarded");

        let (_, mut nameless) = connect(&proxy, "pypi.org:443").await;
        nameless.write_all(&hello_with(&[])).await.unwrap();
        assert!(closed(nameless).await);

        let (_, mut plaintext) = connect(&proxy, "pypi.org:443").await;
        plaintext.write_all(b"GET / HTTP/1.1\r\nHost: evil.net\r\n\r\n").await.unwrap();
        assert!(closed(plaintext).await, "plaintext was forwarded through a CONNECT tunnel");

        let record = proxy.finish();
        assert_eq!((record.hosts.len(), record.refused), (0, 3), "{:?}", record.refusals);
    }

    #[tokio::test]
    async fn the_sixty_fifth_distinct_host_is_refused_so_the_record_is_never_cut_short() {
        let proxy = proxy_for(&["*.example.com"], shouting_upstream().await).await;
        for n in 0..=MAX_HOSTS_PER_LEASE {
            let host = format!("h{n}.example.com");
            let (_, mut stream) = connect(&proxy, &format!("{host}:443")).await;
            let hello = hello_with(&sni_extension(&host));
            stream.write_all(&hello).await.unwrap();
            if n < MAX_HOSTS_PER_LEASE {
                let mut echoed = vec![0u8; hello.len()];
                stream.read_exact(&mut echoed).await.unwrap();
            } else {
                assert!(closed(stream).await, "host {n} was carried past the cap");
            }
        }
        // A host already in the record is still carried: the cap is on distinct hosts.
        let (_, mut again) = connect(&proxy, "h0.example.com:443").await;
        let hello = hello_with(&sni_extension("h0.example.com"));
        again.write_all(&hello).await.unwrap();
        let mut echoed = vec![0u8; hello.len()];
        again.read_exact(&mut echoed).await.unwrap();

        let record = proxy.finish();
        assert_eq!((record.hosts.len(), record.refused), (MAX_HOSTS_PER_LEASE, 1));
    }

    #[tokio::test]
    async fn a_lease_cannot_hold_more_connections_than_its_allowance() {
        let proxy = proxy_for(&["pypi.org"], shouting_upstream().await).await;
        // Idle connections: each sits in the handshake wait, holding a slot.
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS_PER_LEASE {
            held.push(TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).await.unwrap());
        }
        // Accepting is asynchronous; the one past the allowance is closed once the others are counted.
        let mut refused = false;
        for _ in 0..50 {
            if closed_within(TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).await.unwrap(), 100).await {
                refused = true;
                break;
            }
        }
        assert!(refused, "a connection past the allowance was held open");
        // Giving slots back makes room again: the cap is on what is open, not on what was ever opened.
        held.clear();
        let mut carried = false;
        for _ in 0..50 {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).await.unwrap();
            stream.write_all(b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n").await.unwrap();
            let mut status = [0u8; 12];
            if stream.read_exact(&mut status).await.is_ok() && &status == b"HTTP/1.1 200" {
                carried = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(carried, "the proxy never accepted again after its connections closed");
        assert!(proxy.finish().refused >= 1);
    }

    #[tokio::test]
    async fn each_lease_gets_its_own_port_and_a_finished_lease_gives_its_port_back() {
        // A range of this test's own, so the other tests' proxies cannot take from it.
        let (start, count) = (DEFAULT_PORT_START + 300, 2);
        let first = LeaseProxy::start(start, count, vec![]).await.unwrap();
        let second = LeaseProxy::start(start, count, vec![]).await.unwrap();
        assert_ne!(first.port(), second.port());
        assert_eq!(first.url(), format!("http://127.0.0.1:{}", first.port()));
        assert!(LeaseProxy::start(start, count, vec![]).await.is_err(), "a third lease got a port from a pool of two");

        let (freed, open) = (first.port(), TcpStream::connect((Ipv4Addr::LOCALHOST, first.port())).await.unwrap());
        first.finish();
        assert!(closed(open).await, "a connection outlived its lease's proxy");
        // The listener is closed by an aborted task, which the runtime gets to on its own schedule.
        let mut reused = None;
        for _ in 0..50 {
            if let Ok(proxy) = LeaseProxy::start(start, count, vec![]).await {
                reused = Some(proxy);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(reused.expect("the freed port was never reusable").port(), freed);
        drop(second);
    }
}
