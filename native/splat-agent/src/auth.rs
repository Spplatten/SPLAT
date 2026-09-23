// Peer authentication for the leased-execution RPC.
//
// The daemon runs as root and its EXECUTE_TOOL request names a command to run. Before this module
// existed, the only thing standing between any process in the guest and root execution was the
// ability to open a TCP connection to 127.0.0.1 - which is to say, nothing. Reachability was being
// treated as authority.
//
// The token is a shared secret in a root-owned 0600 file, and since protocol 3 it never crosses the
// wire: this daemon proves it holds the token by answering a caller's nonce, and every request proves
// it back over both nonces, its place on the connection and its own bytes. What that buys, precisely:
//
//   * A non-root process in the guest cannot read the file. Nor can it learn the token by taking the
//     port while this daemon is down, as protocol 2 allowed: a caller sends such a listener a nonce
//     and nothing else, and any proof it does see is good for one request on one connection.
//   * A process already running as root in the guest can read the file - and could equally load its
//     own BPF programs or write the cgroup tree directly. A token cannot defend against a principal
//     that already outranks the thing protecting it, and pretending otherwise would be the same
//     class of claim this daemon has spent several commits retiring.
//   * On the Windows side the bridge reads the token through `wsl.exe -u root`, so any Windows
//     process running as that user can obtain it. Closing that requires a transport that carries
//     peer identity (AF_VSOCK with a guest-side allow-list, or SO_PEERCRED over AF_UNIX); it is
//     the wire-contract work, not this.
//   * The frames this daemon sends after the handshake prove themselves too, when the caller asked
//     for it in its HELLO (2026-09-23; roadmap 2.6). Each travels in a PROVEN wrapper whose proof
//     covers both nonces, the frame's number on the connection and its exact bytes - the request
//     proof's shape, in the other direction - and the CHALLENGE that agreed to it is proven under a
//     label of its own, so the agreement cannot be stripped off in transit. A caller that did not
//     ask, which is every bridge older than that date, is answered unwrapped as before. On loopback
//     nothing sits between the two ends of a connection; this is what makes the protocol symmetric
//     before anything leaves the host.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{info, warn};

/// Length of a generated token in bytes; rendered as 64 lowercase hex characters.
const TOKEN_BYTES: usize = 32;

/// Bytes in a handshake nonce, and in a proof, which is SHA-256's output: 64 hex digits on the wire.
pub const NONCE_BYTES: usize = 32;

// Distinct labels, so no proof can be passed off as another kind.
const DAEMON_LABEL: &[u8] = b"splat-agent/3 daemon";
/// The daemon's handshake proof on a connection whose frames it will prove: a CHALLENGE that agreed
/// to prove frames verifies only under this label, so dropping `framesProven` from it in transit
/// leaves a proof the caller refuses rather than a quieter connection.
const DAEMON_FRAMES_LABEL: &[u8] = b"splat-agent/3 daemon+frames";
const REQUEST_LABEL: &[u8] = b"splat-agent/3 request";
const FRAME_LABEL: &[u8] = b"splat-agent/3 frame";

/// The two nonces that name one connection's handshake, and whether the daemon's frames on it are
/// proven. Every request on it is proven over both nonces; so is every frame back, when asked.
pub struct Session {
    pub client_nonce: [u8; NONCE_BYTES],
    pub server_nonce: [u8; NONCE_BYTES],
    pub prove_frames: bool,
}

pub struct PeerAuth {
    token: String,
}

impl PeerAuth {
    /// Loads the token at `path`, creating it if absent.
    ///
    /// Fails rather than falling back to "no authentication". A daemon that cannot establish who is
    /// allowed to talk to it has no business accepting a request to run a command as root, and the
    /// alternative - an unauthenticated mode reachable by default - is exactly the shape that made
    /// this a P1.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let token = fs::read_to_string(path)
                .with_context(|| format!("read auth token {}", path.display()))?
                .trim()
                .to_string();

            if token.is_empty() {
                bail!("auth token file {} is empty", path.display());
            }

            Self::warn_if_world_readable(path);
            info!("Peer authentication token loaded from {}", path.display());
            return Ok(Self { token });
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create auth token directory {}", parent.display()))?;
            // 0700: the directory listing alone should not be a hint to an unprivileged prober.
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }

        let token = Self::generate()?;

        // Created 0600 by mode() on the open, not chmod'd afterwards: a create-then-chmod leaves a
        // window in which the secret is readable by anyone who happened to be watching the path.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create auth token {}", path.display()))?;
        file.write_all(token.as_bytes())
            .with_context(|| format!("write auth token {}", path.display()))?;

        info!("Generated a new peer authentication token at {}", path.display());
        Ok(Self { token })
    }

    /// For tests and for a caller that supplies its own secret out of band.
    #[allow(dead_code)]
    pub fn from_token(token: impl Into<String>) -> Self {
        Self { token: token.into() }
    }

    fn generate() -> Result<String> {
        Ok(hex(&random_bytes::<TOKEN_BYTES>()?))
    }

    fn warn_if_world_readable(path: &Path) {
        if let Ok(md) = fs::metadata(path) {
            let mode = md.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                warn!(
                    "Auth token {} is mode {mode:o}; anything but 0600 means an unprivileged \
                     process in this guest can read it and issue leases.",
                    path.display()
                );
            }
        }
    }

    /// This daemon's answer to a HELLO: proof that it holds the token, over the caller's nonce and its
    /// own. A caller checks it before sending anything else, which is what keeps it from handing a
    /// request - or, under protocol 2, the token itself - to whatever took this daemon's port.
    ///
    /// Under a label of its own when this connection's frames will be proven, so a CHALLENGE that
    /// agreed to that cannot be passed off as one that did not.
    pub fn daemon_proof(
        &self,
        client_nonce: &[u8; NONCE_BYTES],
        server_nonce: &[u8; NONCE_BYTES],
        proves_frames: bool,
    ) -> [u8; NONCE_BYTES] {
        let mut mac = self.mac();
        mac.update(if proves_frames { DAEMON_FRAMES_LABEL } else { DAEMON_LABEL });
        mac.update(&[0]);
        mac.update(client_nonce);
        mac.update(server_nonce);
        let mut proof = [0u8; NONCE_BYTES];
        proof.copy_from_slice(&mac.finalize().into_bytes());
        proof
    }

    /// Whether `proof` is this token's proof of `request`, as the `sequence`-th request on the
    /// connection these nonces opened.
    ///
    /// Checked in fixed time. A comparison that stops at the first differing byte lets a local caller
    /// time its way to a valid proof a byte at a time, and a local caller is who this check stops.
    pub fn verifies(
        &self,
        client_nonce: &[u8; NONCE_BYTES],
        server_nonce: &[u8; NONCE_BYTES],
        sequence: u64,
        request: &[u8],
        proof: &[u8],
    ) -> bool {
        self.request_mac(client_nonce, server_nonce, sequence, request)
            .verify_slice(proof)
            .is_ok()
    }

    /// This daemon's proof of one frame it sends: over both nonces, the frame's number on the
    /// connection and its exact bytes, so a captured frame is good for one place on one connection
    /// and a replayed or reordered one is refused by the bridge. The request proof's shape, sent the
    /// other way, under its own label.
    pub fn frame_proof(
        &self,
        client_nonce: &[u8; NONCE_BYTES],
        server_nonce: &[u8; NONCE_BYTES],
        sequence: u64,
        frame: &[u8],
    ) -> [u8; NONCE_BYTES] {
        let mut mac = self.mac();
        mac.update(FRAME_LABEL);
        mac.update(&[0]);
        mac.update(client_nonce);
        mac.update(server_nonce);
        mac.update(&sequence.to_be_bytes());
        mac.update(frame);
        let mut proof = [0u8; NONCE_BYTES];
        proof.copy_from_slice(&mac.finalize().into_bytes());
        proof
    }

    /// The proof a caller holding this token makes. The daemon only ever checks one, so only the tests
    /// make one here.
    #[cfg(test)]
    pub fn request_proof(
        &self,
        client_nonce: &[u8; NONCE_BYTES],
        server_nonce: &[u8; NONCE_BYTES],
        sequence: u64,
        request: &[u8],
    ) -> [u8; NONCE_BYTES] {
        let mut proof = [0u8; NONCE_BYTES];
        proof.copy_from_slice(&self.request_mac(client_nonce, server_nonce, sequence, request).finalize().into_bytes());
        proof
    }

    fn request_mac(
        &self,
        client_nonce: &[u8; NONCE_BYTES],
        server_nonce: &[u8; NONCE_BYTES],
        sequence: u64,
        request: &[u8],
    ) -> Hmac<Sha256> {
        let mut mac = self.mac();
        mac.update(REQUEST_LABEL);
        mac.update(&[0]);
        mac.update(client_nonce);
        mac.update(server_nonce);
        mac.update(&sequence.to_be_bytes());
        mac.update(request);
        mac
    }

    fn mac(&self) -> Hmac<Sha256> {
        <Hmac<Sha256> as Mac>::new_from_slice(self.token.as_bytes()).expect("HMAC takes a key of any length")
    }

    /// Only the tests read this back; the daemon never logs or echoes the secret itself.
    #[allow(dead_code)]
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// Bytes from the kernel's CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    // read_exact on an opened handle, NOT fs::read. /dev/urandom is a character device with no EOF, so
    // fs::read never returns - it just grows its buffer until the box gives out. Caught by the test
    // suite hanging at exactly the two tests that generate a token.
    let mut file = fs::File::open("/dev/urandom").context("open /dev/urandom")?;
    let mut bytes = [0u8; N];
    file.read_exact(&mut bytes).context("read entropy")?;
    Ok(bytes)
}

/// Lowercase hex, the way tokens, nonces and proofs are written.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A nonce or proof from exactly 64 hex digits, or None. Strict, because a lenient parser - Rust's own
/// accepts a leading `+` - is a second way to spell the same bytes.
pub fn from_hex(text: &str) -> Option<[u8; NONCE_BYTES]> {
    let digits = text.as_bytes();
    if digits.len() != NONCE_BYTES * 2 {
        return None;
    }

    let mut bytes = [0u8; NONCE_BYTES];
    for (byte, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(bytes)
}

fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Computed independently with Python's hmac module on 2026-09-14, and asserted by the bridge's
    // WslAgentSessionTests too, so the two sides cannot drift apart while each agrees with itself.
    const VECTOR_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const VECTOR_REQUEST: &[u8] = br#"{"type":"HEALTH_CHECK"}"#;

    fn vector_nonces() -> ([u8; NONCE_BYTES], [u8; NONCE_BYTES]) {
        let mut client = [0u8; NONCE_BYTES];
        let mut server = [0u8; NONCE_BYTES];
        for i in 0..NONCE_BYTES {
            client[i] = i as u8;
            server[i] = (NONCE_BYTES + i) as u8;
        }
        (client, server)
    }

    #[test]
    fn the_proofs_match_the_vector_the_bridge_is_tested_against() {
        let auth = PeerAuth::from_token(VECTOR_TOKEN);
        let (client, server) = vector_nonces();

        assert_eq!(
            hex(&auth.daemon_proof(&client, &server, false)),
            "52265f2b72fe6c7801c6ffadbd9745a0a69bb165d31d71f31007e81f1c01ea7d"
        );
        assert_eq!(
            hex(&auth.daemon_proof(&client, &server, true)),
            "c1fb43f8ecb070c29c61eb34189d0917d3c0738dd7f120920c9607fc71661d3d"
        );
        assert_eq!(
            hex(&auth.request_proof(&client, &server, 0, VECTOR_REQUEST)),
            "835749efc2b9219f33027ab8571edebb135df57a55b6a0fbc79e1cc68c42c5aa"
        );
        assert_eq!(
            hex(&auth.request_proof(&client, &server, 1, VECTOR_REQUEST)),
            "2bb2251468dd196a6a88d2684c95beacdf2954864d0555e0143a124c30ca755d"
        );
    }

    /// The frame vectors, asserted by WslAgentSessionTests too. Computed independently with Python's
    /// hmac module on 2026-09-23.
    #[test]
    fn the_frame_proofs_match_the_vector_the_bridge_is_tested_against() {
        let auth = PeerAuth::from_token(VECTOR_TOKEN);
        let (client, server) = vector_nonces();
        let frame = br#"{"type":"EXIT","exitCode":0}"#;

        assert_eq!(
            hex(&auth.frame_proof(&client, &server, 0, frame)),
            "a8105556e4245abee3c9221c484065cef75ada4422251d572ee802ddae1f08f4"
        );
        assert_eq!(
            hex(&auth.frame_proof(&client, &server, 1, frame)),
            "1787bcf29e2992298a87cfa606ff26f6afe6e496f61b95f42f3ff8e4baf6f3bf"
        );
    }

    /// A frame's proof, a request's proof and the two handshake proofs are four different things,
    /// and none stands in for another: the labels are what keep a captured value in its place.
    #[test]
    fn no_proof_of_one_kind_passes_as_another() {
        let auth = PeerAuth::from_token(VECTOR_TOKEN);
        let (client, server) = vector_nonces();
        let bytes = VECTOR_REQUEST;

        let frame = auth.frame_proof(&client, &server, 0, bytes);
        let request = auth.request_proof(&client, &server, 0, bytes);
        assert_ne!(frame, request, "the same bytes at the same place, proven as a frame and as a request");
        assert_ne!(auth.daemon_proof(&client, &server, false), auth.daemon_proof(&client, &server, true));
        assert_ne!(auth.frame_proof(&client, &server, 1, bytes), frame, "a frame proof names its place");
        assert_ne!(auth.frame_proof(&server, &client, 0, bytes), frame, "and its connection");
    }

    #[test]
    fn a_proof_holds_for_one_request_on_one_connection_and_nowhere_else() {
        let auth = PeerAuth::from_token(VECTOR_TOKEN);
        let (client, server) = vector_nonces();
        let proof = auth.request_proof(&client, &server, 0, VECTOR_REQUEST);

        assert!(auth.verifies(&client, &server, 0, VECTOR_REQUEST, &proof));
        assert!(!auth.verifies(&client, &server, 1, VECTOR_REQUEST, &proof), "replayed later on the connection");
        assert!(!auth.verifies(&server, &client, 0, VECTOR_REQUEST, &proof), "on a connection with other nonces");
        assert!(!auth.verifies(&client, &server, 0, br#"{"type":"EXECUTE_TOOL"}"#, &proof), "over another request");
        assert!(!auth.verifies(&client, &server, 0, VECTOR_REQUEST, &proof[..31]), "cut short");
        assert!(
            !PeerAuth::from_token("b".repeat(64)).verifies(&client, &server, 0, VECTOR_REQUEST, &proof),
            "under another token"
        );
    }

    #[test]
    fn hex_is_read_strictly() {
        let bytes = [0xab_u8; NONCE_BYTES];
        assert_eq!(from_hex(&hex(&bytes)), Some(bytes));
        assert_eq!(from_hex(&"AB".repeat(NONCE_BYTES)), Some(bytes));
        assert_eq!(from_hex(&"ab".repeat(NONCE_BYTES - 1)), None, "too short");
        assert_eq!(from_hex(&format!("+b{}", "ab".repeat(NONCE_BYTES - 1))), None, "a sign is not a digit");
        assert_eq!(from_hex(&"zz".repeat(NONCE_BYTES)), None);
    }

    #[test]
    fn a_generated_token_is_created_private_and_reloaded_verbatim() {
        let dir = std::env::temp_dir().join(format!("splat_auth_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("agent.token");

        let created = PeerAuth::load_or_create(&path).expect("create");
        assert_eq!(created.token().len(), TOKEN_BYTES * 2);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "a token any guest user can read is not a credential"
        );

        let reloaded = PeerAuth::load_or_create(&path).expect("reload");
        assert_eq!(reloaded.token(), created.token());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_generated_tokens_differ() {
        let dir = std::env::temp_dir().join(format!("splat_auth2_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let a = PeerAuth::load_or_create(&dir.join("a.token")).unwrap();
        let b = PeerAuth::load_or_create(&dir.join("b.token")).unwrap();
        assert_ne!(a.token(), b.token());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_token_file_is_refused_rather_than_treated_as_no_auth() {
        let dir = std::env::temp_dir().join(format!("splat_auth3_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.token");
        fs::write(&path, "   \n").unwrap();

        assert!(PeerAuth::load_or_create(&path).is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
