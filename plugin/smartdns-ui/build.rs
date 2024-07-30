use std::env;
use std::path::PathBuf;
use std::collections::HashSet;

#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

fn link_smartdns_lib() {
    let curr_source_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let smartdns_src_dir = format!("{}/../../src", curr_source_dir);
    let smartdns_lib_file = format!("{}/libsmartdns-test.a", smartdns_src_dir);

    let ignored_macros = IgnoreMacros(
        vec![
            "IPPORT_RESERVED".into(),
        ]
        .into_iter()
        .collect(),
    );

    let bindings = bindgen::Builder::default()
        .header(format!("{}/smartdns.h", smartdns_src_dir))
        .clang_arg(format!("-I{}/include", smartdns_src_dir))
        .parse_callbacks(Box::new(ignored_macros))
        .blocklist_file("/usr/include/.*")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("smartdns_bindings.rs"))
        .expect("Couldn't write bindings!");
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
    }
}

fn main() {
    link_smartdns_lib();
}
