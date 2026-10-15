# Aya instead of libbpf-rs: for future planning

**Decision, 2026-10-11: not now.** The daemon stays on `libbpf-rs` through roadmap 5.2 and 2.4. Aya
gets a time-boxed trial when the daemon is packaged for Linux hosts, priority 5 in
the daemon product plan (moved out of the repository on 2026-10-14), because packaging is where its advantage lies.
This page is a plan. Nothing in it is built.

## The daemon today

- **Kernel half.** [`lease_lsm.bpf.c`](../native/splat-agent/src/bpf/lease_lsm.bpf.c): 422 lines of C on
  four LSM hooks (`bprm_check_security`, `file_open`, `socket_connect`, `socket_sendmsg`), compiled by
  clang through `libbpf-cargo` in [`build.rs`](../native/splat-agent/build.rs).
- **User half.** `libbpf-rs` 0.24, about 36 call sites across `main.rs`, `pinning.rs` and `jail.rs`.
  Pinning is what keeps the hooks in force after the daemon dies (`pin_ids_after_sigkill` in
  [`daemon-probe.json`](../native/splat-agent/evidence/daemon-probe.json)).
- **Packaging cost.** libbpf brings libelf, zlib and zstd. The `portable` feature in
  [`Cargo.toml`](../native/splat-agent/Cargo.toml) links them statically, and
  [`publish-splat-mcp.ps1`](../packaging/publish-splat-mcp.ps1) refuses a daemon that links them
  dynamically. The daemon still links glibc, so provisioning requires glibc 2.39 or newer in the guest.
- **Proof.** The root probe recorded on 2026-10-06 (74 checks, PASS) is bound to the SHA-256 of the C
  source.

## What Aya would give

- **A pure-Rust loader.** No libelf, zlib or zstd. Possibly a fully static binary with no glibc
  minimum in the guest, which would simplify every Linux host the daemon is licensed onto. Unverified
  until built.
- **One language.** Kernel and user halves could share types, so the byte-level contracts in
  [SCHEMA.md](SCHEMA.md) are kept by the compiler rather than by hand.

## What it would cost

1. **A rewrite of the enforcement core.** The C program becomes Rust, and the loader call sites change
   with it. It is not a library swap.
2. **A new proof.** A new source binding, and all 74 checks re-run under root, which is the
   operator's to run.
3. **The toolchain.** Aya's kernel-side programs have historically needed nightly Rust and
   `bpf-linker`. Whether that still holds was not verified on 2026-10-11; check it before planning around
   it. A nightly compiler in a security product's build is a reproducibility risk.
4. **The reference loader.** libbpf is the kernel developers' own loader. Aya reimplements the same
   BTF and CO-RE handling in Rust.
5. **Timing.** Any loader change collides with work in the same crate and resets that work's proof.

## The trial, when it is time

1. **Loader only, first.** Keep the C program, so the proof stays bound to the same source, and
   replace only the `libbpf-rs` loader with Aya. Whether Aya loads a clang-compiled `lsm/` object
   cleanly is the first thing to test.
2. **Build it fully static** and confirm it links no C libraries and needs no glibc minimum.
3. **Run the same root probe.**

Switch only if all three hold: all 74 checks pass, the binary needs no C libraries or glibc minimum,
and pinning survives a SIGKILL of the daemon as it does today. Rewriting the kernel program in Rust is
a separate decision after that, with its own proof.

## Sources

- [bpf-linker on docs.rs](https://docs.rs/crate/bpf-linker/latest)
- [Aya's LSM program type (mirror of the commit)](https://git.mirrors.dragonos.org.cn/DragonOS-Community/aya/commit/76e8e72fe17b4f7f54cadf8344dc47cf3340d6ce?lang=mn-MN)
- [Aya map and program pinning (mirror of the commit)](https://git.mirrors.dragonos.org.cn/DragonOS-Community/aya/commit/9426f36?lang=cs-CZ)
- [Gentoo bpf-linker changelog](https://packages.gentoo.org/packages/dev-util/bpf-linker/changelog)
- [libbpf API: link and map pinning](https://libbpf.readthedocs.io/en/v1.5.0/api.html)
