use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bpf_src = "src/bpf/lease_lsm.bpf.c";
    let skel_out = out_dir.join("lease_lsm.skel.rs");

    println!("cargo:rerun-if-changed={bpf_src}");

    libbpf_cargo::SkeletonBuilder::new()
        .source(bpf_src)
        .clang_args(["-I", "src/bpf", "-g", "-O2"])
        .build_and_generate(&skel_out)
        .expect("failed to compile BPF-LSM program and generate skeleton");
}