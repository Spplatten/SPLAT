//! Pending grants are bounded, locked, excluded from dumps/fork, and wiped before unmapping.

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::ptr::NonNull;

pub const MAX_SECRET_BYTES: usize = 4096;

pub struct SecretBytes {
    pointer: NonNull<u8>,
    length: usize,
}

// Ownership is exclusive. The broker moves this buffer between tasks behind a mutex; it never
// exposes a shared mutable view and never dereferences its DONTFORK mapping in the fork child.
unsafe impl Send for SecretBytes {}

pub struct LockedInput {
    pointer: NonNull<u8>,
    length: usize,
}

unsafe impl Send for LockedInput {}

impl Drop for LockedInput {
    fn drop(&mut self) {
        unsafe {
            libc::munlock(self.pointer.as_ptr().cast(), self.length);
            libc::munmap(self.pointer.as_ptr().cast(), self.length);
        }
    }
}

impl SecretBytes {
    pub fn new(length: usize) -> io::Result<Self> {
        if length == 0 || length > MAX_SECRET_BYTES + 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "secret input size is invalid"));
        }
        unsafe {
            let raw = libc::mmap(std::ptr::null_mut(), length, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
            if raw == libc::MAP_FAILED { return Err(io::Error::last_os_error()); }
            let bytes = Self { pointer: NonNull::new_unchecked(raw.cast()), length };
            if libc::mlock(raw, length) != 0
                || libc::madvise(raw, length, libc::MADV_DONTDUMP) != 0
                || libc::madvise(raw, length, libc::MADV_DONTFORK) != 0 {
                return Err(io::Error::last_os_error()); // Drop also cleans partially prepared memory.
            }
            Ok(bytes)
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.length) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.length) }
    }

    pub fn stdin_file(&self) -> io::Result<(File, LockedInput)> {
        let fd = unsafe { libc::memfd_create(c"splat-step-input".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        let mut file = unsafe { File::from_raw_fd(fd) };
        // The inherited descriptor remains readable, but a workload cannot reopen it through
        // /proc, including a sibling with the same legacy UID. Secret steps additionally use
        // distinct UIDs to prevent same-user ptrace/process-memory access after the read.
        if unsafe { libc::fchmod(fd, 0) } != 0 { return Err(io::Error::last_os_error()); }
        file.write_all(self.as_slice())?;
        file.seek(SeekFrom::Start(0))?;
        let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // Keep the sealed backing pages resident until the whole cgroup is gone, including
        // after the pending buffer has been wiped. The child inherits only fd 0, not this map.
        let raw = unsafe { libc::mmap(std::ptr::null_mut(), self.length, libc::PROT_READ,
            libc::MAP_SHARED, fd, 0) };
        if raw == libc::MAP_FAILED { return Err(io::Error::last_os_error()); }
        let locked = LockedInput { pointer: unsafe { NonNull::new_unchecked(raw.cast()) }, length: self.length };
        if unsafe { libc::mlock(raw, self.length) } != 0
            || unsafe { libc::madvise(raw, self.length, libc::MADV_DONTDUMP) } != 0
            || unsafe { libc::madvise(raw, self.length, libc::MADV_DONTFORK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((file, locked))
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        unsafe {
            // Volatile writes keep destruction from being optimized away as a dead store.
            for index in 0..self.length { std::ptr::write_volatile(self.pointer.as_ptr().add(index), 0); }
            libc::munlock(self.pointer.as_ptr().cast(), self.length);
            libc::munmap(self.pointer.as_ptr().cast(), self.length);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn secret_input_is_anonymous_sealed_and_not_reopenable_by_mode() {
        let mut bytes = SecretBytes::new(16).unwrap();
        bytes.as_mut_slice().copy_from_slice(b"synthetic-secret");
        let (mut file, _locked) = bytes.stdin_file().unwrap();
        drop(bytes);
        let mut answer = Vec::new();
        file.read_to_end(&mut answer).unwrap();
        assert_eq!(answer, b"synthetic-secret");
        assert!(file.write_all(b"tamper").is_err());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0);
        assert_ne!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
        let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let address = _locked.pointer.as_ptr() as usize;
        let mut matching = false;
        let mut flags = None;
        for line in maps.lines() {
            if let Some(range) = line.split_whitespace().next().and_then(|word| word.split_once('-')) {
                if let (Ok(start), Ok(end)) = (usize::from_str_radix(range.0, 16), usize::from_str_radix(range.1, 16)) {
                    matching = (start..end).contains(&address);
                }
            }
            if matching && line.starts_with("VmFlags:") { flags = Some(line); break; }
        }
        let flags: Vec<_> = flags.expect("resident input mapping").split_whitespace().collect();
        for flag in ["lo", "dc", "dd"] { assert!(flags.contains(&flag), "missing {flag}"); }
    }
}
