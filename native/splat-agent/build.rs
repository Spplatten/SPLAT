use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bpf_src = "src/bpf/lease_lsm.bpf.c";
    let skel_out = out_dir.join("lease_lsm.skel.rs");

    println!("cargo:rerun-if-changed={bpf_src}");

    libbpf_cargo::SkeletonBuilder::new()
        .source(bpf_src)
        // -mcpu=v3: the sequence counter is a fetching atomic (__sync_fetch_and_add whose result is
        // used), which the generic BPF ISA cannot express; v3 needs kernel 5.12 or later, and the
        // hooks already need 5.7.
        .clang_args(["-I", "src/bpf", "-g", "-O2", "-mcpu=v3"])
        .build_and_generate(&skel_out)
        .expect("failed to compile BPF-LSM program and generate skeleton");
}