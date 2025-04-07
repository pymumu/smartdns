use std::collections::HashSet;
use std::env;
use std::path::PathBuf;

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

fn get_git_commit_version() {
    let result = std::process::Command::new("git")
        .args(&["describe", "--tags", "--always", "--dirty"])
        .output();

    let git_version = match result {
        Ok(output) => output.stdout,
        Err(_) => Vec::new(),
    };

    let git_version = String::from_utf8(git_version).expect("Invalid UTF-8 sequence");
    println!("cargo:rustc-env=GIT_VERSION={}", git_version.trim());
}

fn link_smartdns_lib() {
    let curr_source_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let smartdns_src_dir = format!("{}/../../src", curr_source_dir);
    let smartdns_inc_dir = format!("{}/include", smartdns_src_dir);
    let smartdns_lib_file = format!("{}/libsmartdns-test.a", smartdns_src_dir);

    let cc = env::var("RUSTC_LINKER")
        .unwrap_or_else(|_| env::var("CC").unwrap_or_else(|_| "cc".to_string()));

    let sysroot_output = std::process::Command::new(&cc)
        .arg("--print-sysroot")
        .output();
    let mut sysroot = None;
    if let Ok(output) = sysroot_output {
        if output.status.success() {
            let path = String::from_utf8(output.stdout).unwrap();
            sysroot = Some(path.trim().to_string());
        }
    }

    let ignored_macros = IgnoreMacros(vec!["IPPORT_RESERVED".into()].into_iter().collect());

    let mut bindings_builder =
        bindgen::Builder::default().header(format!("{}/smartdns/smartdns.h", smartdns_inc_dir));
    if let Some(sysroot) = sysroot {
        bindings_builder = bindings_builder.clang_arg(format!("--sysroot={}", sysroot));
    }
    let bindings = bindings_builder
        .clang_arg(format!("-I{}/include", smartdns_src_dir))
        .parse_callbacks(Box::new(ignored_macros))
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
    get_git_commit_version();
    link_smartdns_lib();
}
