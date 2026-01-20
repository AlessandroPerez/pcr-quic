//! PCR-QUIC BoringSSL FFI bindings
//!
//! Low-level FFI declarations for the PCR-QUIC crypto shim.
//! These functions are implemented in C (crypto_shim.c) and link against BoringSSL.

use std::os::raw::c_int;

// ============================================================================
// FFI Declarations
// ============================================================================

extern "C" {
    /// HKDF-SHA256 (Extract + Expand)
    pub fn pcr_hkdf_sha256(
        out: *mut u8,
        out_len: usize,
        ikm: *const u8,
        ikm_len: usize,
        salt: *const u8,
        salt_len: usize,
        info: *const u8,
        info_len: usize,
    ) -> c_int;

    /// HKDF-SHA256 Extract phase only
    pub fn pcr_hkdf_extract_sha256(
        prk: *mut u8,
        salt: *const u8,
        salt_len: usize,
        ikm: *const u8,
        ikm_len: usize,
    ) -> c_int;

    /// HKDF-SHA256 Expand phase only
    pub fn pcr_hkdf_expand_sha256(
        out: *mut u8,
        out_len: usize,
        prk: *const u8,
        prk_len: usize,
        info: *const u8,
        info_len: usize,
    ) -> c_int;

    /// SHA-256 direct hash (faster than HKDF)
    pub fn pcr_sha256(
        out: *mut u8,
        input: *const u8,
        input_len: usize,
    ) -> c_int;

    /// SHA-256 of two concatenated inputs
    pub fn pcr_sha256_two(
        out: *mut u8,
        in1: *const u8,
        in1_len: usize,
        in2: *const u8,
        in2_len: usize,
    ) -> c_int;

    /// AES-256-GCM authenticated encryption (seal)
    pub fn pcr_aes256gcm_seal(
        out: *mut u8,
        out_len: *mut usize,
        key: *const u8,
        nonce: *const u8,
        ad: *const u8,
        ad_len: usize,
        input: *const u8,
        input_len: usize,
    ) -> c_int;

    /// AES-256-GCM authenticated decryption (open)
    pub fn pcr_aes256gcm_open(
        out: *mut u8,
        out_len: *mut usize,
        key: *const u8,
        nonce: *const u8,
        ad: *const u8,
        ad_len: usize,
        input: *const u8,
        input_len: usize,
    ) -> c_int;

    /// X25519 keypair generation
    pub fn pcr_x25519_keypair(
        public_key: *mut u8,
        private_key: *mut u8,
    ) -> c_int;

    /// X25519 ECDH shared secret derivation
    pub fn pcr_x25519_derive(
        shared_secret: *mut u8,
        private_key: *const u8,
        peer_public: *const u8,
    ) -> c_int;

    /// Hybrid KEM (X25519 + ML-KEM-768) keypair generation
    pub fn pcr_hybrid_kem_keypair(
        public_key: *mut u8,
        secret_key: *mut u8,
    ) -> c_int;

    /// Hybrid KEM encapsulation
    pub fn pcr_hybrid_kem_encaps(
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    ) -> c_int;

    /// Hybrid KEM decapsulation
    pub fn pcr_hybrid_kem_decaps(
        shared_secret: *mut u8,
        ciphertext: *const u8,
        secret_key: *const u8,
    ) -> c_int;

    /// Securely zero memory
    pub fn pcr_secure_zero(ptr: *mut u8, len: usize);

    /// Generate cryptographically secure random bytes
    pub fn pcr_random_bytes(out: *mut u8, len: usize) -> c_int;

    // ========================================================================
    // AES-256-GCM Context-based API (Cached Key Schedule)
    // ========================================================================

    /// Create new AES-GCM context with cached key schedule
    pub fn pcr_aes256gcm_ctx_new(key: *const u8) -> *mut std::ffi::c_void;

    /// Free AES-GCM context
    pub fn pcr_aes256gcm_ctx_free(ctx: *mut std::ffi::c_void);

    /// AES-GCM seal with cached context (fast path)
    pub fn pcr_aes256gcm_seal_ctx(
        ctx: *mut std::ffi::c_void,
        out: *mut u8,
        out_len: *mut usize,
        nonce: *const u8,
        ad: *const u8,
        ad_len: usize,
        input: *const u8,
        input_len: usize,
    ) -> c_int;

    /// AES-GCM open with cached context (fast path)
    pub fn pcr_aes256gcm_open_ctx(
        ctx: *mut std::ffi::c_void,
        out: *mut u8,
        out_len: *mut usize,
        nonce: *const u8,
        ad: *const u8,
        ad_len: usize,
        input: *const u8,
        input_len: usize,
    ) -> c_int;

    /// AES-GCM in-place seal with separate tag output (fastest path)
    /// Uses BoringSSL's scatter-gather API to avoid all data copies
    pub fn pcr_aes256gcm_seal_in_place(
        ctx: *mut std::ffi::c_void,
        data: *mut u8,
        data_len: usize,
        nonce: *const u8,
        ad: *const u8,
        ad_len: usize,
        out_tag: *mut u8,
        out_tag_len: *mut usize,
    ) -> c_int;
}
