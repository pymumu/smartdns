
use std::env;

fn link_smartdns_lib() {
    let curr_source_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let smartdns_src_dir = format!("{}/../../src", curr_source_dir);
    let smartdns_lib_file = format!("{}/libsmartdns-test.a", smartdns_src_dir);

    /*
    to run tests, please run the following command:
    make test-prepare
    */
    if std::path::Path::new(&smartdns_lib_file).exists() && !cfg!(feature = "build-release") {
        println!("cargo:rerun-if-changed={}", smartdns_lib_file);
        println!("cargo:rustc-link-lib=static=smartdns-test");
        println!("cargo:rustc-link-lib=ssl");
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-search=native={}", smartdns_src_dir);
        println!("cargo:warning=link smartdns-test library");
    }
}

fn main() {
    link_smartdns_lib();
}
