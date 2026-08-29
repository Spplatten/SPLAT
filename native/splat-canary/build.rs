// Compiles src/bpf/lease_lsm.bpf.c with clang and generates the Rust skeleton the loader
// includes at build time. Requires clang and a vmlinux.h (produced by setup-guest.sh from
// /sys/kernel/btf/vmlinux). If vmlinux.h is missing this build fails loudly on purpose —
// no BTF means no CO-RE, which is exactly the kernel-feasibility gate the README describes.

use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/lease_lsm.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"))
        .join("lease_lsm.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        // vmlinux.h lives next to the .bpf.c; -g keeps BTF for CO-RE relocations.
        .clang_args(["-I", "src/bpf", "-g", "-O2"])
        .build_and_generate(&out)
        .expect("bpf skeleton build failed (is clang installed and src/bpf/vmlinux.h present?)");

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=src/bpf/vmlinux.h");
}
