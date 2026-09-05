// Peer authentication for the leased-execution RPC.
//
// The daemon runs as root and its EXECUTE_TOOL request names a command to run. Before this module
// existed, the only thing standing between any process in the guest and root execution was the
// ability to open a TCP connection to 127.0.0.1 - which is to say, nothing. Reachability was being
// treated as authority.
//
// The token is a shared secret in a root-owned 0600 file. What that buys, precisely:
//
//   * A non-root process in the guest cannot read the file, so it cannot issue or widen a lease.
//     That is the threat the audit named, and it is closed.
//   * A process already running as root in the guest can read the file - and could equally load its
//     own BPF programs or write the cgroup tree directly. A token cannot defend against a principal
//     that already outranks the thing protecting it, and pretending otherwise would be the same
//     class of claim this daemon has spent several commits retiring.
//   * On the Windows side the bridge reads the token through `wsl.exe -u root`, so any Windows
//     process running as that user can obtain it. Closing that requires a transport that carries
//     peer identity (AF_VSOCK with a guest-side allow-list, or SO_PEERCRED over AF_UNIX); it is
//     the wire-contract work, not this.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{bail, Context, Result};
use tracing::{info, warn};

/// Length of a generated token in bytes; rendered as 64 lowercase hex characters.
const TOKEN_BYTES: usize = 32;

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
        // read_exact on an opened handle, NOT fs::read. /dev/urandom is a character device with no
        // EOF, so fs::read never returns - it just grows its buffer until the box gives out. Caught
        // by the test suite hanging at exactly the two tests that generate a token.
        let mut file = fs::File::open("/dev/urandom").context("open /dev/urandom")?;
        let mut bytes = [0u8; TOKEN_BYTES];
        file.read_exact(&mut bytes)
            .context("read entropy for a new auth token")?;

        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
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

    /// Whether `presented` is the token, compared without an early return.
    ///
    /// `==` on a String stops at the first differing byte. Over a loopback socket a local process
    /// can time that well enough to recover the secret byte by byte, and a local process is exactly
    /// the caller this check exists to stop.
    pub fn accepts(&self, presented: Option<&str>) -> bool {
        match presented {
            Some(p) => constant_time_eq(p.as_bytes(), self.token.as_bytes()),
            None => false,
        }
    }

    /// Only the tests read this back; the daemon never logs or echoes the secret itself.
    #[allow(dead_code)]
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// Length-independent equality. Differing lengths are rejected up front - the length of a
/// fixed-format token is not a secret - and equal-length inputs are compared in full.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // read_volatile stops the optimiser turning the accumulate back into an early exit.
    unsafe { std::ptr::read_volatile(&diff) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_matching_token_is_accepted_and_anything_else_is_not() {
        let auth = PeerAuth::from_token("a".repeat(64));

        assert!(auth.accepts(Some(&"a".repeat(64))));
        assert!(!auth.accepts(Some(&"b".repeat(64))));
        assert!(!auth.accepts(Some("")), "an empty token is not a token");
        assert!(!auth.accepts(None), "a request that omits the field is unauthenticated");
    }

    #[test]
    fn a_prefix_of_the_token_is_not_accepted() {
        // The shape a length-only or early-exit comparison would let through.
        let auth = PeerAuth::from_token("deadbeef");
        assert!(!auth.accepts(Some("dead")));
        assert!(!auth.accepts(Some("deadbeef0")));
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
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
        assert!(reloaded.accepts(Some(created.token())));

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
