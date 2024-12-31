use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let c_file = Path::new("third_party/wireguard-linux/contrib/embeddable-wg-library/wireguard.c");
    let target_dir = Path::new(&out_dir).join("wireguard");
    std::fs::create_dir_all(&target_dir).unwrap();
    println!("cargo:rerun-if-changed={}", c_file.display());
    cc::Build::new()
        .file(c_file)
        .include("third_party/wireguard-linux/contrib/embeddable-wg-library")
        .out_dir(target_dir)
        .compile("libwireguard.a");
    println!("cargo:rustc-link-lib=static=wireguard");
}
