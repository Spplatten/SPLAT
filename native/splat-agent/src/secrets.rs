//! A separate root-only local channel supplies one bounded secret for one exact session/request.
//! TCP frames contain an opaque, single-use grant; they never contain the secret payload.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::auth::{self, Session};
use crate::identities::{IdentityPool, LeaseIdentity};
use crate::secret_memory::{LockedInput, SecretBytes, MAX_SECRET_BYTES};

const MAX_HEADER_BYTES: usize = 65536;
const MAX_GRANTS: usize = 64;
const MAX_TTL_SECONDS: u64 = 60;
const IO_BUDGET: Duration = Duration::from_secs(5);
type SessionKey = [u8; 64];

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Deposit {
    pub client_nonce: String,
    pub server_nonce: String,
    pub request: Value,
    pub ttl_seconds: u64,
    pub secret_length: usize,
}

struct Grant {
    session: SessionKey,
    request_hash: [u8; 32],
    expires: Instant,
    bytes: SecretBytes,
}

#[derive(Default)]
struct State {
    sessions: HashSet<SessionKey>,
    grants: HashMap<String, Grant>,
}

#[derive(Clone)]
pub struct Broker {
    state: Arc<Mutex<State>>,
    identities: IdentityPool,
    recovery: Option<crate::secret_recovery::Registry>,
}

pub struct SessionGuard {
    broker: Broker,
    key: SessionKey,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.broker.state.lock() {
            state.sessions.remove(&self.key);
            state.grants.retain(|_, grant| grant.session != self.key);
        }
    }
}

pub struct StepSecret {
    pub stdin: Option<File>,
    pub identity: LeaseIdentity,
    pub workspace: Option<PathBuf>,
    cleanup: Option<StepCleanup>,
    resident: Option<LockedInput>,
    request_digest: [u8; 32],
    recovery: Option<crate::secret_recovery::Registry>,
    record: Option<PathBuf>,
}

struct StepCleanup {
    cgroup_path: PathBuf,
    cgroup_id: u64,
    manager: crate::lease::LeaseManager,
    jail: Option<Arc<crate::jail::JailPlan>>,
    paths: Vec<PathBuf>,
}

impl StepSecret {
    pub fn register_workspace(&mut self, path: &Path) -> Result<()> {
        self.workspace = Some(path.to_owned());
        if let Some(registry) = &self.recovery {
            self.record = Some(registry.register(path, self.identity.id())?);
        }
        Ok(())
    }

    pub fn receipt(&self, step_id: &str, outcome: &str) -> String {
        serde_json::json!({"type":"splat-secret-step/1", "stepId":step_id,
            "requestSha256":auth::hex(&self.request_digest), "outcomeCanonical":outcome,
            "secretStdinClosed":true, "environmentMode":"explicit", "processOutput":"discarded"}).to_string()
    }

    pub fn arm_cleanup(&mut self, cgroup: &crate::cgroup::EphemeralCgroup,
        manager: crate::lease::LeaseManager, jail: Option<Arc<crate::jail::JailPlan>>) {
        let paths = jail.as_ref().map_or_else(Vec::new, |jail| jail.cleanup_paths());
        self.cleanup = Some(StepCleanup { cgroup_path: cgroup.path.clone(),
            cgroup_id: cgroup.cgroup_id, manager, jail, paths });
    }

    pub fn finish(&mut self) -> Result<()> {
        self.stdin.take();
        if let Some(cleanup) = &mut self.cleanup {
            crate::cgroup::EphemeralCgroup::kill_tree(&cleanup.cgroup_path)?;
            cleanup.jail.take();
            for path in &cleanup.paths {
                match std::fs::symlink_metadata(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => bail!("secret step scratch cleanup is incomplete"),
                }
            }
        }
        self.resident.take();
        Ok(())
    }
}

impl Drop for StepSecret {
    fn drop(&mut self) {
        // Runs on every early return too, including failed socket writes and task cancellation.
        // A held Arc prevents scratch teardown before descendants have actually been drained.
        let drained = self.cleanup.as_ref().is_none_or(|cleanup|
            crate::cgroup::EphemeralCgroup::kill_tree(&cleanup.cgroup_path).is_ok());
        if !drained {
            self.identity.mark_spawned();
            if let Some(resident) = self.resident.take() { std::mem::forget(resident); }
            if let Some(jail) = self.cleanup.as_mut().and_then(|cleanup| cleanup.jail.take()) {
                std::mem::forget(jail); // Startup orphan recovery owns it after an unsuccessful drain.
            }
            return;
        }
        if let Some(cleanup) = &self.cleanup { cleanup.manager.revoke_lease(cleanup.cgroup_id); }
        let scratch_removed = self.finish().is_ok();
        let workspace_removed = self.workspace.as_ref().is_none_or(|path| crate::workspace::remove(path));
        if scratch_removed && workspace_removed {
            if let Some(record) = &self.record {
                if std::fs::remove_file(record).is_err() {
                    tracing::warn!("A payload-free secret recovery record remains for startup cleanup");
                }
            }
            self.identity.release_after_drain();
        }
        else { self.identity.mark_spawned(); }
    }
}

fn session_key(session: &Session) -> SessionKey {
    let mut key = [0; 64];
    key[..32].copy_from_slice(&session.client_nonce);
    key[32..].copy_from_slice(&session.server_nonce);
    key
}

fn nonce(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) { bail!("invalid session nonce"); }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() { *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?; }
    Ok(result)
}

fn request_hash(request: &Value) -> Result<[u8; 32]> {
    let mut request = request.clone();
    let fields = request.as_object_mut().ok_or_else(|| anyhow::anyhow!("request must be an object"))?;
    fields.remove("secretGrant");
    // serde_json's default map orders keys. Hash the parsed request, including argv, environment,
    // destination, duration and limits: changing any of them invalidates the grant.
    Ok(Sha256::digest(serde_json::to_vec(&request)?).into())
}

fn validate_request(request: &Value) -> Result<()> {
    if request.get("type").and_then(Value::as_str) != Some("EXECUTE_TOOL")
        || request.get("protocolVersion").and_then(Value::as_u64) != Some(3)
        || request.get("ephemeralWorkspace").and_then(Value::as_bool) != Some(true)
        || !matches!(request.get("leaseDurationSeconds").and_then(Value::as_u64), Some(5..=300)) {
        bail!("secret grants require a bounded, disposable protocol-3 execution request");
    }
    for field in ["missionId", "stepId"] {
        let id = request.get(field).and_then(Value::as_str).unwrap_or("");
        if id.is_empty() || id.len() > 128 || id == "." || id == ".."
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
            bail!("secret grants require explicit safe mission and step identifiers");
        }
    }
    let command = request.get("command").and_then(Value::as_str).unwrap_or("");
    let working_directory = request.get("workingDirectory").and_then(Value::as_str).unwrap_or("");
    if !Path::new(command).is_absolute() || command.contains('\0')
        || !Path::new(working_directory).is_absolute() || working_directory.contains('\0')
        || request.get("allowNetwork").and_then(Value::as_bool).is_none()
        || crate::string_list(request, "argv").is_none_or(|values| values.iter().any(|value| value.contains('\0')))
        || crate::string_list(request, "allowedExecPaths").is_none_or(|values|
            !values.iter().any(|value| value == command) || values.iter().any(|value| !Path::new(value).is_absolute() || value.contains('\0'))) {
        bail!("secret grant execution and network policy must be explicit and well formed");
    }
    if crate::string_list(request, "allowedEgressIps").is_none_or(|values|
        values.iter().any(|value| value.parse::<std::net::Ipv4Addr>().is_err()))
        || request.get("allowedEgressPorts").and_then(Value::as_array).is_none_or(|values|
            values.iter().any(|value| !matches!(value.as_u64(), Some(1..=65535)))) {
        bail!("secret grant destinations must be explicit IPv4 addresses and valid ports");
    }
    crate::execution::environment(request)?;
    Ok(())
}

impl Broker {
    pub fn new(identities: IdentityPool) -> Self {
        Self { state: Arc::new(Mutex::new(State::default())), identities, recovery: None }
    }

    pub fn with_recovery(mut self, registry: crate::secret_recovery::Registry) -> Self {
        self.recovery = Some(registry);
        self
    }

    pub fn register(&self, session: &Session) -> Result<SessionGuard> {
        let key = session_key(session);
        let mut state = self.state.lock().map_err(|_| anyhow::anyhow!("secret broker unavailable"))?;
        if !state.sessions.insert(key) { bail!("duplicate session"); }
        Ok(SessionGuard { broker: self.clone(), key })
    }

    fn deposit(&self, header: Deposit, bytes: SecretBytes, now: Instant) -> Result<String> {
        if header.secret_length == 0 || header.secret_length > MAX_SECRET_BYTES
            || bytes.as_slice().len() != header.secret_length || header.ttl_seconds == 0
            || header.ttl_seconds > MAX_TTL_SECONDS || header.request.get("secretGrant").is_some() {
            bail!("invalid secret grant bounds");
        }
        validate_request(&header.request)?;
        let session = session_key(&Session { client_nonce: nonce(&header.client_nonce)?,
            server_nonce: nonce(&header.server_nonce)?, prove_frames: true });
        let hash = request_hash(&header.request)?;
        let mut state = self.state.lock().map_err(|_| anyhow::anyhow!("secret broker unavailable"))?;
        state.grants.retain(|_, grant| grant.expires > now);
        if !state.sessions.contains(&session) { bail!("secret grant session is unavailable"); }
        if state.grants.len() >= MAX_GRANTS { bail!("secret grant capacity exhausted"); }
        let id = auth::hex(&auth::random_bytes::<32>()?);
        if state.grants.contains_key(&id) { bail!("secret grant identifier collision"); }
        state.grants.insert(id.clone(), Grant { session, request_hash: hash,
            expires: now + Duration::from_secs(header.ttl_seconds), bytes });
        Ok(id)
    }

    pub fn take(&self, session: &Session, request: &Value, now: Instant) -> Result<StepSecret> {
        validate_request(request)?;
        let id = request.get("secretGrant").and_then(Value::as_str).unwrap_or("");
        let hash = request_hash(request)?;
        let mut state = self.state.lock().map_err(|_| anyhow::anyhow!("secret broker unavailable"))?;
        state.grants.retain(|_, grant| grant.expires > now);
        let valid = state.grants.get(id).is_some_and(|grant|
            grant.session == session_key(session) && grant.request_hash == hash);
        if !valid { bail!("secret grant is unavailable for this session and request"); }
        let identity = self.identities.acquire()?;
        let grant = state.grants.remove(id).expect("validated while holding the lock");
        drop(state);
        let (stdin, resident) = grant.bytes.stdin_file()?;
        // The locked pending copy is wiped now. Only the anonymous sealed stdin descriptor remains.
        drop(grant);
        Ok(StepSecret { stdin: Some(stdin), identity, workspace: None, cleanup: None,
            resident: Some(resident), request_digest: hash, recovery: self.recovery.clone(), record: None })
    }

    fn expire(&self) {
        if let Ok(mut state) = self.state.lock() { state.grants.retain(|_, grant| grant.expires > Instant::now()); }
    }
}

fn private_parent(path: &Path) -> Result<()> {
    let parent = path.parent().filter(|p| p.is_absolute()).ok_or_else(|| anyhow::anyhow!("secret socket needs an absolute path"))?;
    let metadata = std::fs::symlink_metadata(parent).context("read secret socket parent")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 || parent.canonicalize()? != parent {
        bail!("secret socket parent must be a canonical root-owned private directory (0700)");
    }
    Ok(())
}

fn root_peer(fd: std::os::fd::RawFd) -> Result<()> {
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, peer.as_mut_ptr().cast(), &mut length) };
    if rc != 0 || length as usize != std::mem::size_of::<libc::ucred>() || unsafe { peer.assume_init().uid } != 0 {
        bail!("secret delivery requires the local root service principal");
    }
    Ok(())
}

pub fn bind(path: &Path) -> Result<UnixListener> {
    if unsafe { libc::geteuid() } != 0 { bail!("secret delivery requires a root daemon"); }
    private_parent(path)?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() || metadata.uid() != 0 { bail!("refusing to replace a non-service secret socket path"); }
        match std::os::unix::net::UnixStream::connect(path) {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => std::fs::remove_file(path)?,
            _ => bail!("secret socket is already in use or its state is unknown"),
        }
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub async fn serve(listener: UnixListener, broker: Broker) {
    let slots = Arc::new(tokio::sync::Semaphore::new(8));
    let mut sweep = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = sweep.tick() => broker.expire(),
            incoming = listener.accept() => {
                let (stream, _) = match incoming {
                    Ok(connection) => connection,
                    Err(_) => {
                        tracing::error!("Secret broker accept failed; retrying");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(slot) = slots.clone().try_acquire_owned() else { continue; };
                let broker = broker.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    // A malformed request never echoes its header or payload, even in an error.
                    let _ = tokio::time::timeout(IO_BUDGET, receive(stream, broker)).await;
                });
            }
        }
    }
}

async fn receive(mut stream: UnixStream, broker: Broker) -> Result<()> {
    root_peer(stream.as_raw_fd())?;
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_HEADER_BYTES { bail!("secret metadata frame exceeds its limit"); }
    let mut header = vec![0; length];
    stream.read_exact(&mut header).await?;
    let header: Deposit = serde_json::from_slice(&header).context("invalid secret metadata")?;
    if header.secret_length == 0 || header.secret_length > MAX_SECRET_BYTES { bail!("secret input exceeds its limit"); }
    let mut bytes = SecretBytes::new(header.secret_length)?;
    stream.read_exact(bytes.as_mut_slice()).await?;
    let mut tail = SecretBytes::new(1)?;
    if stream.read(tail.as_mut_slice()).await? != 0 { bail!("trailing secret input refused"); }
    let id = broker.deposit(header, bytes, Instant::now())?;
    let response = serde_json::to_vec(&serde_json::json!({"secretGrant":id}))?;
    stream.write_all(&response).await?;
    stream.shutdown().await?;
    Ok(())
}

/// CLI issuer: public binding metadata comes from a file, secret bytes only from stdin.
pub fn submit(socket: &Path, metadata: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 { bail!("secret issuance requires the local root service principal"); }
    private_parent(socket)?;
    let mut public = Vec::new();
    File::open(metadata).context("read secret binding metadata")?
        .take(MAX_HEADER_BYTES as u64 + 1).read_to_end(&mut public)?;
    if public.len() > MAX_HEADER_BYTES { bail!("secret metadata exceeds its limit"); }
    let mut header: Deposit = serde_json::from_slice(&public)?;
    let mut bytes = SecretBytes::new(MAX_SECRET_BYTES + 1)?;
    let mut length = 0;
    let mut input = std::io::stdin().lock();
    while length < bytes.as_slice().len() {
        let read = input.read(&mut bytes.as_mut_slice()[length..])?;
        if read == 0 { break; }
        length += read;
    }
    if length == 0 || length > MAX_SECRET_BYTES { bail!("secret stdin must contain 1..4096 bytes"); }
    header.secret_length = length;
    validate_request(&header.request)?;
    let public = serde_json::to_vec(&header)?;
    if public.len() > MAX_HEADER_BYTES { bail!("secret metadata exceeds its limit"); }
    let mut stream = std::os::unix::net::UnixStream::connect(socket)?;
    root_peer(stream.as_raw_fd())?;
    stream.set_read_timeout(Some(IO_BUDGET))?;
    stream.set_write_timeout(Some(IO_BUDGET))?;
    stream.write_all(&(public.len() as u32).to_be_bytes())?;
    stream.write_all(&public)?;
    stream.write_all(&bytes.as_slice()[..length])?;
    drop(bytes);
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    std::io::Read::by_ref(&mut stream).take(1025).read_to_end(&mut response)?;
    if response.len() > 1024 { bail!("invalid secret grant acknowledgement"); }
    let ack: Value = serde_json::from_slice(&response).context("secret broker refused the grant")?;
    let id = ack.get("secretGrant").and_then(Value::as_str).unwrap_or("");
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) { bail!("invalid secret grant acknowledgement"); }
    println!("{}", serde_json::json!({"secretGrant": id}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session(value: u8) -> Session { Session { client_nonce: [value; 32], server_nonce: [value + 1; 32], prove_frames: true } }
    fn request() -> Value { json!({"type":"EXECUTE_TOOL", "protocolVersion":3, "missionId":"mission-1", "stepId":"publish-1",
        "ephemeralWorkspace":true, "leaseDurationSeconds":30, "command":"/usr/bin/python3", "argv":["-I", "step.py"],
        "workingDirectory":"/var/lib/splat/missions/mission-1", "allowedExecPaths":["/usr/bin/python3"], "allowNetwork":true,
        "allowedEgressIps":["192.0.2.7"], "allowedEgressPorts":[443]}) }
    fn deposit(broker: &Broker, session: &Session, now: Instant) -> String {
        let mut bytes = SecretBytes::new(16).unwrap();
        bytes.as_mut_slice().copy_from_slice(b"synthetic-secret");
        broker.deposit(Deposit { client_nonce: auth::hex(&session.client_nonce), server_nonce: auth::hex(&session.server_nonce),
            request: request(), ttl_seconds: 30, secret_length: 16 }, bytes, now).unwrap()
    }

    #[test]
    fn grant_is_bound_to_session_step_command_arguments_and_destinations() {
        let broker = Broker::new(IdentityPool::for_test(2));
        let session = session(1);
        let _guard = broker.register(&session).unwrap();
        let now = Instant::now();
        let id = deposit(&broker, &session, now);
        let mut approved = request(); approved["secretGrant"] = json!(id);
        let other = super::tests::session(5);
        assert!(broker.take(&other, &approved, now).is_err());
        for (field, value) in [("stepId", json!("other")), ("missionId", json!("other")),
            ("command", json!("/bin/sh")), ("argv", json!(["different"])),
            ("allowedEgressIps", json!(["192.0.2.8"])), ("allowedEgressPorts", json!([80])),
            ("leaseDurationSeconds", json!(60)), ("environment", json!({"SPLAT_PARAM_X":"changed"}))] {
            let mut changed = approved.clone(); changed[field] = value;
            assert!(broker.take(&session, &changed, now).is_err(), "{field}");
        }
        assert!(broker.take(&session, &approved, now).is_ok());
        assert!(broker.take(&session, &approved, now).is_err());
    }

    #[test]
    fn expiry_and_session_end_destroy_pending_grants() {
        let broker = Broker::new(IdentityPool::for_test(2));
        let session = session(1);
        let guard = broker.register(&session).unwrap();
        let now = Instant::now();
        let mut approved = request(); approved["secretGrant"] = json!(deposit(&broker, &session, now));
        assert!(broker.take(&session, &approved, now + Duration::from_secs(30)).is_err());
        approved["secretGrant"] = json!(deposit(&broker, &session, now));
        drop(guard);
        assert!(broker.take(&session, &approved, now).is_err());
        assert!(broker.state.lock().unwrap().grants.is_empty());
    }

    #[test]
    fn concurrent_consumers_cannot_reuse_a_grant() {
        let broker = Broker::new(IdentityPool::for_test(2));
        let session = session(1);
        let _guard = broker.register(&session).unwrap();
        let now = Instant::now();
        let mut approved = request(); approved["secretGrant"] = json!(deposit(&broker, &session, now));
        let results = std::thread::scope(|scope| {
            let first = scope.spawn(|| broker.take(&session, &approved, now));
            let second = scope.spawn(|| broker.take(&session, &approved, now));
            [first.join().unwrap().is_ok(), second.join().unwrap().is_ok()]
        });
        assert_eq!(results.into_iter().filter(|ok| *ok).count(), 1);
    }

    #[test]
    fn receipt_commits_the_approved_request_without_fingerprinting_the_secret() {
        let broker = Broker::new(IdentityPool::for_test(1));
        let session = session(1);
        let _guard = broker.register(&session).unwrap();
        let now = Instant::now();
        let mut approved = request(); approved["secretGrant"] = json!(deposit(&broker, &session, now));
        let secret = broker.take(&session, &approved, now).unwrap();
        let receipt = secret.receipt("publish-1", "guest outcome");
        let fields: Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(fields["requestSha256"], json!(auth::hex(&request_hash(&request()).unwrap())));
        assert_eq!(fields["stepId"], "publish-1");
        assert_eq!(fields["outcomeCanonical"], "guest outcome");
        assert!(!receipt.contains("synthetic-secret"));
        assert!(!receipt.contains(&auth::hex(&Sha256::digest(b"synthetic-secret"))));
    }

    #[test]
    fn grants_are_bounded_and_a_full_identity_pool_does_not_consume_one() {
        let identities = IdentityPool::for_test(1);
        let held = identities.acquire().unwrap();
        let broker = Broker::new(identities);
        let session = session(1);
        let _guard = broker.register(&session).unwrap();
        let now = Instant::now();
        let mut approved = request(); approved["secretGrant"] = json!(deposit(&broker, &session, now));
        assert!(broker.take(&session, &approved, now).is_err());
        drop(held);
        assert!(broker.take(&session, &approved, now).is_ok());
        for _ in 0..MAX_GRANTS { deposit(&broker, &session, now); }
        let header = Deposit { client_nonce: auth::hex(&session.client_nonce), server_nonce: auth::hex(&session.server_nonce),
            request: request(), ttl_seconds: 30, secret_length: 1 };
        assert!(broker.deposit(header, SecretBytes::new(1).unwrap(), now).is_err());
    }

    #[test]
    fn metadata_rejects_unsafe_lifetimes_unbound_steps_and_unknown_fields() {
        for (field, value) in [("ephemeralWorkspace", json!(false)), ("leaseDurationSeconds", json!(301)),
            ("leaseDurationSeconds", json!(0)), ("missionId", json!("../escape")),
            ("stepId", json!("")), ("protocolVersion", json!(2)), ("type", json!("HEALTH_CHECK"))] {
            let mut invalid = request(); invalid[field] = value;
            assert!(validate_request(&invalid).is_err(), "{field}");
        }
        for (field, value) in [("allowedEgressPorts", json!([4294967376u64])), ("allowedEgressIps", json!(["host.example"])),
            ("argv", json!(["a\0b"])), ("allowNetwork", json!(null)), ("allowedExecPaths", json!([]))] {
            let mut invalid = request(); invalid[field] = value;
            assert!(validate_request(&invalid).is_err(), "{field}");
        }
        assert!(serde_json::from_value::<Deposit>(json!({"clientNonce":"00", "serverNonce":"00",
            "request":request(), "ttlSeconds":1, "secretLength":1, "secret":"refused"})).is_err());
        assert!(nonce(&"é".repeat(32)).is_err());
        let broker = Broker::new(IdentityPool::for_test(1));
        let session = session(1);
        let _guard = broker.register(&session).unwrap();
        for ttl_seconds in [0, 61, u64::MAX] {
            let header = Deposit { client_nonce: auth::hex(&session.client_nonce), server_nonce: auth::hex(&session.server_nonce),
                request: request(), ttl_seconds, secret_length: 1 };
            assert!(broker.deposit(header, SecretBytes::new(1).unwrap(), Instant::now()).is_err());
        }
    }

    #[test]
    fn dropping_a_prelaunch_secret_removes_its_workspace_and_releases_its_identity() {
        let pool = IdentityPool::for_test(1);
        let broker = Broker::new(pool.clone());
        let session = session(1);
        let _guard = broker.register(&session).unwrap();
        let now = Instant::now();
        let mut approved = request(); approved["secretGrant"] = json!(deposit(&broker, &session, now));
        let mut secret = broker.take(&session, &approved, now).unwrap();
        let path = std::env::temp_dir().join(format!("splat-secret-prelaunch-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("synthetic"), "synthetic-only").unwrap();
        secret.workspace = Some(path.clone());
        drop(secret);
        assert!(!path.exists());
        assert!(pool.acquire().is_ok());
    }

    #[tokio::test]
    #[ignore = "root component proof; no daemon service or BPF changes"]
    async fn root_secret_broker_accepts_binary_input_and_refuses_truncation_and_trailing_bytes() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let broker = Broker::new(IdentityPool::for_test(2));
        let session = session(1);
        let _guard = broker.register(&session).unwrap();
        for (payload, expected) in [(b"a\0bc".as_slice(), true), (b"abc".as_slice(), false), (b"abcde".as_slice(), false)] {
            let (mut client, server) = UnixStream::pair().unwrap();
            let receiver = tokio::spawn(receive(server, broker.clone()));
            let header = serde_json::to_vec(&Deposit { client_nonce: auth::hex(&session.client_nonce),
                server_nonce: auth::hex(&session.server_nonce), request: request(), ttl_seconds: 30, secret_length: 4 }).unwrap();
            client.write_u32(header.len() as u32).await.unwrap();
            client.write_all(&header).await.unwrap();
            client.write_all(payload).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response).await;
            assert_eq!(receiver.await.unwrap().is_ok(), expected);
            if expected {
                let mut approved = request();
                approved["secretGrant"] = serde_json::from_slice::<Value>(&response).unwrap()["secretGrant"].clone();
                let mut secret = broker.take(&session, &approved, Instant::now()).unwrap();
                let mut received = Vec::new();
                secret.stdin.as_mut().unwrap().read_to_end(&mut received).unwrap();
                assert_eq!(received, payload);
            } else { assert!(response.is_empty()); }
        }
    }

    #[tokio::test]
    #[ignore = "root component proof; no daemon service or BPF changes"]
    async fn root_secret_upload_cancellation_releases_locked_pages_without_issuing_a_grant() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let locked = || std::fs::read_to_string("/proc/self/status").unwrap().lines()
            .find_map(|line| line.strip_prefix("VmLck:").map(|value| value.split_whitespace().next().unwrap().parse::<u64>().unwrap())).unwrap();
        let before = locked();
        let broker = Broker::new(IdentityPool::for_test(1));
        let session = session(1);
        let _guard = broker.register(&session).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let receiver = tokio::spawn(receive(server, broker.clone()));
        let header = serde_json::to_vec(&Deposit { client_nonce: auth::hex(&session.client_nonce),
            server_nonce: auth::hex(&session.server_nonce), request: request(), ttl_seconds: 30, secret_length: 100 }).unwrap();
        client.write_u32(header.len() as u32).await.unwrap();
        client.write_all(&header).await.unwrap();
        client.write_all(b"x").await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while locked() == before { tokio::task::yield_now().await; }
        }).await.unwrap();
        receiver.abort();
        assert!(receiver.await.unwrap_err().is_cancelled());
        assert_eq!(locked(), before);
        assert!(broker.state.lock().unwrap().grants.is_empty());
    }

    #[tokio::test]
    #[ignore = "root component proof; touches only a temporary socket and an unprivileged test child"]
    async fn root_secret_broker_rejects_nonroot_peers_even_when_socket_permissions_are_relaxed() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let directory = std::env::temp_dir().join(format!("splat-secret-peer-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("input.sock");
        let listener = bind(&path).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o711)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let mut command = tokio::process::Command::new("/usr/bin/python3");
        command.args(["-I", "-c", r#"
import socket, sys
stream = socket.socket(socket.AF_UNIX)
stream.connect(sys.argv[1])
try:
    stream.sendall(b'\x00\x00\x00\x00')
    assert not stream.recv(1)
except (ConnectionResetError, BrokenPipeError):
    pass
"#]).arg(&path).kill_on_drop(true);
        unsafe { command.pre_exec(|| crate::drop_privileges(65534, 65534)); }
        let mut child = command.spawn().unwrap();
        let (stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await.unwrap().unwrap();
        let result = receive(stream, Broker::new(IdentityPool::for_test(1))).await;
        assert!(result.unwrap_err().to_string().contains("root service principal"));
        assert!(child.wait().await.unwrap().success());
        drop(listener);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
