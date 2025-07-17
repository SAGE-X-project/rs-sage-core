//! Build script for generating C bindings

use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rerun-if-changed=src/");

    // Generate C header file location info
    let _out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:warning=C headers are in include/sage_crypto.h");

    // For FFI builds
    #[cfg(feature = "ffi")]
    {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libsage_crypto_core.so");
    }
}
