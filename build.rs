use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/darwin_shim.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let obj_path = out_dir.join("darwin_shim.o");
    let lib_path = out_dir.join("libdarwin_shim.a");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let clang_arch = match target_arch.as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => other,
    };

    let status = Command::new("clang")
        .args([
            "-O2",
            "-Wall",
            "-Wextra",
            "-arch",
            clang_arch,
            "-mmacosx-version-min=12.0",
            "-c",
            "src/darwin_shim.c",
            "-o",
        ])
        .arg(&obj_path)
        .status()
        .expect("failed to invoke clang");
    assert!(status.success(), "clang failed to compile darwin_shim.c");

    let ar_status = Command::new("ar")
        .args(["crs"])
        .arg(&lib_path)
        .arg(&obj_path)
        .status()
        .expect("failed to invoke ar");
    assert!(ar_status.success(), "ar failed to archive libdarwin_shim.a");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=darwin_shim");
}
