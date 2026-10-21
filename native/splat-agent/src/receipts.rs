//! A bounded, private cache of bound lease outcomes. A cache miss never proves non-execution.
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ENTRIES: usize = 1024;
const MAX_RECORD_BYTES: usize = 32768;
const RETENTION_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    mission: String,
    context: String,
    policy: String,
    created: u64,
    lease: Option<Value>,
    outcome: Option<Value>,
}

struct State {
    root: PathBuf,
    _lock: File,
    records: HashMap<String, Record>,
}

#[derive(Clone)]
pub struct Store(Arc<Mutex<State>>);

fn key(mission: &str) -> String { format!("{:x}", Sha256::digest(mission.as_bytes())) }
fn now() -> Result<u64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()) }

fn private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file() && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o077 == 0 && metadata.nlink() == 1, "receipt file is not private");
    Ok(file)
}

impl State {
    fn path(&self, id: &str) -> PathBuf { self.root.join(format!("{id}.json")) }

    fn write(&self, id: &str, record: &Record) -> Result<()> {
        let bytes = serde_json::to_vec(record)?;
        ensure!(bytes.len() <= MAX_RECORD_BYTES, "receipt exceeds cache record limit");
        let temp = self.root.join(format!(".pending-{}", rand::random::<u64>()));
        let result = (|| {
            let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temp, self.path(id))?;
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() { let _ = fs::remove_file(temp); }
        result
    }

    fn remove(&mut self, id: &str) -> Result<()> {
        fs::remove_file(self.path(id))?;
        self.records.remove(id);
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    fn prune(&mut self, timestamp: u64) -> Result<()> {
        let expired: Vec<_> = self.records.iter().filter(|(_, r)| timestamp.saturating_sub(r.created) >= RETENTION_SECONDS)
            .map(|(id, _)| id.clone()).collect();
        for id in expired { self.remove(&id)?; }
        Ok(())
    }
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        if !root.exists() { fs::DirBuilder::new().recursive(true).mode(0o700).create(root)?; }
        let metadata = fs::symlink_metadata(root)?;
        ensure!(metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0, "receipt directory must be private and owned by the daemon");
        let lock_path = root.join(".lock");
        let lock = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&lock_path)?;
        private_file(&lock_path)?;
        ensure!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another daemon owns this receipt cache");
        let mut state = State { root: root.to_owned(), _lock: lock, records: HashMap::new() };
        for entry in fs::read_dir(root)? {
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).context("invalid receipt filename")?;
            if name == ".lock" { continue; }
            if name.starts_with(".pending-") {
                private_file(&path)?;
                fs::remove_file(path)?;
                continue;
            }
            ensure!(name.is_ascii() && name.len() == 69 && name.ends_with(".json")
                && name[..64].bytes().all(|b| b.is_ascii_hexdigit()), "unexpected receipt cache file");
            let mut bytes = Vec::new();
            private_file(&path)?.take((MAX_RECORD_BYTES + 1) as u64).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= MAX_RECORD_BYTES, "oversized receipt cache file");
            let record: Record = serde_json::from_slice(&bytes)?;
            ensure!(key(&record.mission) == name[..64], "receipt filename does not match its mission");
            ensure!(state.records.len() < MAX_ENTRIES, "receipt cache exceeds its entry limit");
            state.records.insert(key(&record.mission), record);
        }
        state.prune(now()?)?;
        Ok(Self(Arc::new(Mutex::new(state))))
    }

    pub fn reserve(&self, mission: &str, context: &str, policy: &str) -> Result<()> {
        ensure!(!mission.is_empty() && mission.len() <= 128 && context.len() <= 8192
            && (policy == "none" || policy.len() == 64), "invalid receipt identity");
        let mut state = self.0.lock().map_err(|_| anyhow::anyhow!("receipt cache poisoned"))?;
        let timestamp = now()?;
        state.prune(timestamp)?;
        let id = key(mission);
        ensure!(!state.records.contains_key(&id) && !state.path(&id).exists(), "bound mission already admitted; use receipt lookup");
        if state.records.len() >= MAX_ENTRIES {
            let oldest = state.records.iter().filter(|(_, r)| r.outcome.is_some())
                .min_by_key(|(_, r)| r.created).map(|(id, _)| id.clone());
            let Some(oldest) = oldest else { bail!("receipt cache has no completed entry to retire"); };
            state.remove(&oldest)?;
        }
        let record = Record { mission: mission.into(), context: context.into(), policy: policy.into(),
            created: timestamp, lease: None, outcome: None };
        state.write(&id, &record)?;
        state.records.insert(id, record);
        Ok(())
    }

    pub fn finish(&self, mission: &str, context: &str, lease: &Value, outcome: &Value) -> Result<()> {
        let mut state = self.0.lock().map_err(|_| anyhow::anyhow!("receipt cache poisoned"))?;
        let id = key(mission);
        let record = state.records.get(&id).context("receipt admission is missing")?;
        ensure!(record.context == context && record.outcome.is_none(), "receipt identity or completion mismatch");
        let record = Record { lease: Some(lease.clone()), outcome: Some(outcome.clone()), ..record.clone() };
        // Persist the signed terminal outcome before attempting delivery on a possibly dead connection.
        state.write(&id, &record)?;
        state.records.insert(id, record);
        Ok(())
    }

    pub fn lookup(&self, mission: &str, context: &str, policy: &str) -> Result<Value> {
        let state = self.0.lock().map_err(|_| anyhow::anyhow!("receipt cache poisoned"))?;
        let unavailable = serde_json::json!({"type":"RECEIPT_RESPONSE", "status":"unavailable"});
        let Some(record) = state.records.get(&key(mission)) else { return Ok(unavailable); };
        if record.context != context || record.policy != policy || now()?.saturating_sub(record.created) >= RETENTION_SECONDS {
            return Ok(unavailable);
        }
        Ok(match (&record.lease, &record.outcome) {
            (Some(lease), Some(outcome)) => serde_json::json!({"type":"RECEIPT_RESPONSE", "status":"complete",
                "lease":lease, "outcome":outcome}),
            _ => serde_json::json!({"type":"RECEIPT_RESPONSE", "status":"pending"}),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self { Self(std::env::temp_dir().join(format!("splat-receipts-{}-{}", std::process::id(), rand::random::<u64>()))) }
    }
    impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

    #[test]
    fn lookup_survives_restart_but_cannot_cross_context_or_policy() {
        let directory = Directory::new();
        let store = Store::open(&directory.0).unwrap();
        store.reserve("mission", "caller-a", "none").unwrap();
        assert_eq!(store.lookup("mission", "caller-a", "none").unwrap()["status"], "pending");
        assert!(store.reserve("mission", "caller-b", "none").is_err());
        store.finish("mission", "caller-a", &serde_json::json!({"type":"LEASE"}), &serde_json::json!({"type":"EXIT"})).unwrap();
        assert!(Store::open(&directory.0).is_err());
        drop(store);
        let store = Store::open(&directory.0).unwrap();
        assert_eq!(store.lookup("mission", "caller-a", "none").unwrap()["status"], "complete");
        assert_eq!(store.lookup("mission", "caller-b", "none").unwrap()["status"], "unavailable");
        assert_eq!(store.lookup("mission", "caller-a", &"a".repeat(64)).unwrap()["status"], "unavailable");
        assert_eq!(store.lookup("missing", "caller-a", "none").unwrap()["status"], "unavailable");
    }

    #[test]
    fn cache_misses_and_expiry_never_claim_that_execution_did_not_start() {
        let directory = Directory::new();
        let store = Store::open(&directory.0).unwrap();
        store.reserve("mission", "caller", "none").unwrap();
        let mut state = store.0.lock().unwrap();
        state.records.get_mut(&key("mission")).unwrap().created = 0;
        drop(state);
        assert_eq!(store.lookup("mission", "caller", "none").unwrap()["status"], "unavailable");
    }

    #[test]
    fn a_symlink_or_foreign_file_refuses_cache_startup() {
        let directory = Directory::new();
        let store = Store::open(&directory.0).unwrap();
        drop(store);
        std::os::unix::fs::symlink("/etc/passwd", directory.0.join(format!("{}.json", "a".repeat(64)))).unwrap();
        assert!(Store::open(&directory.0).is_err());
    }

    #[test]
    fn capacity_does_not_evict_pending_work_and_oversize_completion_stays_unresolved() {
        let directory = Directory::new();
        let store = Store::open(&directory.0).unwrap();
        store.reserve("mission", "caller", "none").unwrap();
        assert!(store.finish("mission", "caller", &serde_json::json!({}),
            &serde_json::json!({"oversized": "x".repeat(MAX_RECORD_BYTES)})).is_err());
        assert_eq!(store.lookup("mission", "caller", "none").unwrap()["status"], "pending");
        {
            let mut state = store.0.lock().unwrap();
            let pending = state.records[&key("mission")].clone();
            for i in 1..MAX_ENTRIES {
                state.records.insert(key(&i.to_string()), Record { mission: i.to_string(), ..pending.clone() });
            }
        }
        assert!(store.reserve("new", "caller", "none").is_err());
        store.finish("mission", "caller", &serde_json::json!({}), &serde_json::json!({})).unwrap();
        store.reserve("new", "caller", "none").unwrap();
        assert_eq!(store.lookup("mission", "caller", "none").unwrap()["status"], "unavailable");
        assert_eq!(store.lookup("new", "caller", "none").unwrap()["status"], "pending");
    }
}
