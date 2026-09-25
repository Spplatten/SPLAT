// The guest's own signature over what a lease did (roadmap 2.5).
//
// Until now the kernel-enforced path had the WEAKEST receipt of anything this product produces. A
// Windows mission seals MISSION_RUN_FACTS into a chained ledger and exports a bundle a stranger can
// verify; a Linux lease - the half where the refusals are made by the kernel rather than by SPLAT
// asking nicely - reported its outcome over a socket to a host that then wrote down whatever it
// liked. Nothing the guest said was bound to the guest having said it. That is backwards: the
// stronger the enforcement, the more the receipt should be worth.
//
// So the daemon signs. The key is generated in the guest, lives root-owned 0600 beside the auth
// token, and never leaves; the host records the public half and the signature. What this proves is
// narrow and worth stating exactly: that the outcome text came from a process holding this guest's
// private key. It does NOT prove the guest is honest - root in the guest can sign a lie, which is
// the boundary the substrate already has and does not pretend to close. What it does close is the
// gap between the guest saying something and the record claiming it: an edit made on the Windows
// side, or by anything between, no longer verifies.
//
// RSA-2048 with PKCS#1 v1.5 over SHA-256, and NOT the Ed25519 roadmap 2.5 named. The reason is the
// verifier, not the primitive: every run-record bundle already ships verify_proofs.py and
// verify_proofs.ps1, which check the operator's RSA signature with nothing but their standard
// libraries - "one modular exponentiation and a comparison". Ed25519 has no .NET BCL support and no
// standard-library path in either script, so choosing it would mean hand-rolled curve arithmetic in
// Python, PowerShell and C# for a stranger to trust, to verify a signature made by a crate. Reusing
// the primitive the bundle already verifies means this signature costs the reader nothing new.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{bail, Context, Result};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Where the lease signing key lives unless `--outcome-key` says otherwise. Beside the auth token,
/// under the same root-owned 0700 directory, for the same reason: an unprivileged process in the
/// guest that could read either one could impersonate the daemon.
pub const DEFAULT_KEY_PATH: &str = "/etc/splat/outcome.key";

/// 2048 rather than 3072 or 4096: the signature rides in every EXIT frame and is verified by a
/// Python script doing modular exponentiation by hand, on machines that are not this one.
const KEY_BITS: usize = 2048;

pub struct OutcomeSigner {
    signing_key: SigningKey<Sha256>,
    /// PKCS#1 RSAPublicKey DER - the exact encoding verify_proofs.py's der_rsa_public_key() parses.
    public_der: Vec<u8>,
    key_id: String,
}

impl OutcomeSigner {
    /// Loads the key at `path`, generating one if absent. Returns `None` rather than failing when
    /// the key cannot be established, because a daemon that cannot sign must still contain: the
    /// EXIT frame then carries no signature and the record says the outcome is unsigned, which is
    /// the same honesty the run-record bundle already practises for a missing operator key.
    pub fn load_or_create(path: &Path) -> Option<Self> {
        match Self::try_load_or_create(path) {
            Ok(signer) => {
                info!(
                    "Lease outcomes are signed with the guest key at {} (key id {})",
                    path.display(),
                    &signer.key_id[..16]
                );
                Some(signer)
            }
            Err(e) => {
                warn!(
                    "Lease outcomes will be UNSIGNED: {} could not be established ({e:#}). \
                     Containment is unaffected; what a lease reports simply cannot be bound to this guest.",
                    path.display()
                );
                None
            }
        }
    }

    fn try_load_or_create(path: &Path) -> Result<Self> {
        let key = if path.exists() {
            Self::warn_if_world_readable(path);
            let pem = fs::read_to_string(path)
                .with_context(|| format!("read outcome key {}", path.display()))?;
            RsaPrivateKey::from_pkcs1_pem(pem.trim())
                .with_context(|| format!("parse outcome key {}", path.display()))?
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create outcome key directory {}", parent.display()))?;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }

            let mut rng = rand::thread_rng();
            let key = RsaPrivateKey::new(&mut rng, KEY_BITS).context("generate outcome key")?;
            let pem = key
                .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                .context("encode outcome key")?;

            // 0600 at creation, never a create-then-chmod: the window in between is exactly long
            // enough for something watching the path to read a key that signs this guest's answers.
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("create outcome key {}", path.display()))?;
            file.write_all(pem.as_bytes())
                .with_context(|| format!("write outcome key {}", path.display()))?;

            info!("Generated a new lease outcome signing key at {}", path.display());
            key
        };

        let public_der = key
            .to_public_key()
            .to_pkcs1_der()
            .context("encode outcome public key")?
            .as_bytes()
            .to_vec();

        if public_der.is_empty() {
            bail!("the outcome public key encoded to nothing");
        }

        let key_id = hex(&Sha256::digest(&public_der));

        Ok(Self {
            signing_key: SigningKey::<Sha256>::new(key),
            public_der,
            key_id,
        })
    }

    /// SHA-256 of the public key DER, hex. What a record names so two bundles can be told apart,
    /// and what `doctor` prints so an operator can see which guest is signing.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The public half, base64 of PKCS#1 RSAPublicKey DER: what the verifier needs and all it needs.
    pub fn public_key_base64(&self) -> String {
        base64(&self.public_der)
    }

    /// Base64 of the PKCS#1 v1.5 signature over the canonical outcome's UTF-8 bytes.
    pub fn sign(&self, canonical: &str) -> String {
        base64(&self.signing_key.sign(canonical.as_bytes()).to_bytes())
    }

    fn warn_if_world_readable(path: &Path) {
        if let Ok(md) = fs::metadata(path) {
            let mode = md.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                warn!(
                    "Outcome key {} is mode {mode:o}; anything but 0600 means an unprivileged \
                     process in this guest can sign outcomes as this daemon.",
                    path.display()
                );
            }
        }
    }
}

/// The exact bytes that get signed.
///
/// Pipe-delimited and ordered rather than JSON, because three independent implementations have to
/// rebuild these bytes identically - the daemon, the C# bridge, and two verifier scripts - and
/// canonical JSON is a specification people get subtly wrong (key order, number formatting,
/// whitespace, unicode escaping). A fixed field order with escaped separators has one reading.
///
/// Every field is something the GUEST observed. Nothing the host asked for appears here unless the
/// guest read it back, because a signature over the host's own request would prove only that the
/// host can repeat itself.
#[allow(clippy::too_many_arguments)]
pub fn canonical_outcome(
    mission_id: &str,
    cgroup_id: u64,
    enforcing: bool,
    workload_uid: u32,
    exit_code: i32,
    violations_counted: Option<u64>,
    violations_reported: u64,
    violations_dropped: u64,
    workspace: Option<&str>,
    workspace_removed: Option<bool>,
) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("splat-lease-outcome/1");
    field(&mut out, "mission", mission_id);
    field(&mut out, "cgroup", &cgroup_id.to_string());
    field(&mut out, "enforcing", if enforcing { "true" } else { "false" });
    field(&mut out, "uid", &workload_uid.to_string());
    field(&mut out, "exit", &exit_code.to_string());
    // "unknown" and "0" are different answers, and the signature has to cover which one was given.
    field(
        &mut out,
        "counted",
        &violations_counted.map_or_else(|| "unknown".to_string(), |n| n.to_string()),
    );
    field(&mut out, "reported", &violations_reported.to_string());
    field(&mut out, "dropped", &violations_dropped.to_string());
    field(&mut out, "workspace", workspace.unwrap_or(""));
    field(
        &mut out,
        "workspaceRemoved",
        &workspace_removed.map_or_else(|| "n/a".to_string(), |b| b.to_string()),
    );
    out
}

fn field(out: &mut String, key: &str, value: &str) {
    out.push('|');
    out.push_str(key);
    out.push('=');
    // A workspace path may hold either of these; without escaping, a crafted path could forge a
    // field boundary and move a value into another field's place.
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\p"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TABLE[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn the_canonical_form_is_fixed_and_escapes_its_separators() {
        let text = canonical_outcome(
            "m-1", 4021, true, 65534, 0, Some(2), 2, 0, Some("/var/lib/splat/missions/m-1"), Some(true),
        );
        assert_eq!(
            text,
            "splat-lease-outcome/1|mission=m-1|cgroup=4021|enforcing=true|uid=65534|exit=0\
             |counted=2|reported=2|dropped=0|workspace=/var/lib/splat/missions/m-1|workspaceRemoved=true"
        );

        // A path holding a separator cannot forge a field boundary.
        let hostile = canonical_outcome("m|2", 1, false, 0, -1, None, 0, 0, Some("/a|b\\c"), None);
        assert!(hostile.contains("mission=m\\p2"), "{hostile}");
        assert!(hostile.contains("workspace=/a\\pb\\\\c"), "{hostile}");
        assert!(hostile.contains("counted=unknown"), "{hostile}");
        assert!(hostile.contains("workspaceRemoved=n/a"), "{hostile}");
    }

    #[test]
    fn a_signature_verifies_under_the_public_key_and_fails_on_an_edited_outcome() {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let dir = std::env::temp_dir().join(format!("splat-outcome-{}", std::process::id()));
        let path = dir.join("outcome.key");
        let _ = fs::remove_dir_all(&dir);

        let signer = OutcomeSigner::load_or_create(&path).expect("a key should be creatable in temp");
        let text = canonical_outcome("m-1", 7, true, 65534, 0, Some(1), 1, 0, None, None);
        let signature = signer.sign(&text);

        // Decoded the way the shipped verifier decodes it: PKCS#1 DER public key, base64 signature.
        let der = decode_base64(&signer.public_key_base64());
        let verifying = VerifyingKey::<Sha256>::new(
            rsa::RsaPublicKey::from_pkcs1_der(&der).expect("public key round-trips"),
        );
        let bytes = decode_base64(&signature);
        let sig = rsa::pkcs1v15::Signature::try_from(bytes.as_slice()).expect("signature parses");

        verifying.verify(text.as_bytes(), &sig).expect("the outcome verifies");

        let edited = text.replace("exit=0", "exit=1");
        assert!(
            verifying.verify(edited.as_bytes(), &sig).is_err(),
            "an outcome edited after signing must not verify"
        );

        // The key is reused rather than regenerated, or every restart would orphan its own records.
        let again = OutcomeSigner::load_or_create(&path).expect("the key reloads");
        assert_eq!(again.key_id(), signer.key_id());

        let _ = fs::remove_dir_all(&dir);
    }

    fn decode_base64(text: &str) -> Vec<u8> {
        const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for ch in text.bytes().filter(|b| *b != b'=') {
            let value = TABLE.iter().position(|c| *c == ch).expect("base64 alphabet") as u32;
            buffer = (buffer << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buffer >> bits) as u8);
            }
        }
        out
    }
}
