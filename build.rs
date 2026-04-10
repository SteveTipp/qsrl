use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=LIBOQS_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    if env::var_os("CARGO_FEATURE_LIBOQS_BACKEND").is_none() {
        return;
    }

    if let Some(root) = env::var_os("LIBOQS_DIR") {
        let root = PathBuf::from(root);
        let lib_dir = root.join("lib");
        let lib64_dir = root.join("lib64");

        println!("cargo:rustc-link-lib=oqs");
        if lib_dir.exists() {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
        }
        if lib64_dir.exists() {
            println!("cargo:rustc-link-search=native={}", lib64_dir.display());
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib64_dir.display());
        }
        probe_openssl();
        return;
    }

    pkg_config::Config::new()
        .statik(true)
        .atleast_version("0.15.0")
        .probe("liboqs")
        .expect("liboqs-backend requires liboqs >= 0.15.0 via pkg-config or LIBOQS_DIR");
    probe_openssl();
}

fn probe_openssl() {
    pkg_config::Config::new()
        .statik(true)
        .probe("openssl")
        .expect("liboqs-backend could not locate OpenSSL via pkg-config");
}
