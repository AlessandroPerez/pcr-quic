use std::env;
use std::path::PathBuf;

fn main() {
    let quiche_path = env::var("QUICHE_PATH")
        .unwrap_or_else(|_| "../quiche".to_string());
    
    let crypto_shim_path = format!("{}/quiche/src/crypto/pcr_shim/crypto_shim.c", quiche_path);
    let boringssl_include = format!("{}/quiche/deps/boringssl/include", quiche_path);
    let boringssl_lib = format!("{}/quiche/deps/boringssl/build", quiche_path);
    
    // Check if files exist
    if !std::path::Path::new(&crypto_shim_path).exists() {
        eprintln!("Warning: crypto_shim.c not found at {}", crypto_shim_path);
        eprintln!("Set QUICHE_PATH environment variable to point to quiche repository");
        eprintln!("Example: export QUICHE_PATH=/path/to/quiche");
        eprintln!("\nSkipping C compilation - FFI functions will not be available");
        return;
    }
    
    if !std::path::Path::new(&boringssl_include).exists() {
        eprintln!("Warning: BoringSSL headers not found at {}", boringssl_include);
        eprintln!("Make sure quiche's BoringSSL is built: cd {} && cargo build", quiche_path);
        eprintln!("\nSkipping C compilation - FFI functions will not be available");
        return;
    }
    
    println!("cargo:rerun-if-changed={}", crypto_shim_path);
    println!("cargo:rerun-if-env-changed=QUICHE_PATH");
    
    // Compile C shim
    cc::Build::new()
        .file(&crypto_shim_path)
        .include(&boringssl_include)
        .warnings(false)  // Suppress warnings from external code
        .compile("pcr_shim");
    
    // Link BoringSSL
    println!("cargo:rustc-link-search=native={}", boringssl_lib);
    println!("cargo:rustc-link-lib=static=crypto");
    
    // Link liboqs (required for oqs-boringssl variant)
    let liboqs_path = env::var("LIBOQS_PATH")
        .unwrap_or_else(|_| format!("{}/build/lib", 
            env::var("HOME").unwrap() + "/Documents/liboqs-for-boringssl"));
    
    if std::path::Path::new(&format!("{}/liboqs.a", liboqs_path)).exists() {
        println!("cargo:rustc-link-search=native={}", liboqs_path);
        println!("cargo:rustc-link-lib=static=oqs");
        println!("cargo:info=Linked against liboqs");
    }
    
    // Link required system libraries
    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=dl");
    }
    
    println!("cargo:info=PCR-QUIC C shim compiled successfully");
}
