//! Build script for generating C bindings

use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rerun-if-changed=src/");

    // Generate C header file location info
    let _out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:warning=C headers are in include/sage_crypto.h");

    // Platform-specific linker flags for FFI
    #[cfg(feature = "ffi")]
    {
        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        
        match target_os.as_str() {
            "linux" => {
                // Linux supports -soname option
                println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libsage_crypto_core.so");
            }
            "macos" => {
                // macOS uses -install_name instead of -soname
                println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libsage_crypto_core.dylib");
            }
            _ => {
                // Other platforms - no special linker flags needed
            }
        }
    }
}
