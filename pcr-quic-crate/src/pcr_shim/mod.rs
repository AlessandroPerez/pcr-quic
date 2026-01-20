//! PCR-QUIC Crypto Shim - Rust FFI bindings
//!
//! This module provides safe Rust wrappers around the C crypto shim functions
//! for the PCR-QUIC double ratchet protocol.
//!
//! # Security Properties
//!
//! - Forward Secrecy (FS): Per-packet nonce ratchet ensures past packets cannot
//!   be decrypted if current state is compromised.
//! - Post-Compromise Security (PCS): Epoch rekey via hybrid KEM allows recovery
//!   from state compromise.
//! - Precise Key Deletion: Keys are zeroized after use via `pcr_secure_zero`.
//!
//! # Module Structure
//!
//! - `bssl`: Low-level FFI declarations for BoringSSL crypto primitives
//! - Safe wrapper functions in this module

use std::ptr;

use crate::{PcrError, Result};

// ============================================================================
// Submodules
// ============================================================================

/// Low-level FFI bindings to BoringSSL via the C crypto shim
pub mod bssl;

// ============================================================================
// Constants (matching crypto_shim.h)
// ============================================================================

pub const AES256_KEY_LEN: usize = 32;
pub const AES256_GCM_IV_LEN: usize = 12;
pub const AES256_GCM_TAG_LEN: usize = 16;
pub const HKDF_SHA256_HASH_LEN: usize = 32;

pub const X25519_PUBLIC_KEY_LEN: usize = 32;
pub const X25519_PRIVATE_KEY_LEN: usize = 32;
pub const X25519_SHARED_SECRET_LEN: usize = 32;

pub const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
pub const MLKEM768_SECRET_KEY_LEN: usize = 2400;
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
pub const MLKEM768_SHARED_SECRET_LEN: usize = 32;

pub const HYBRID_PUBLIC_KEY_LEN: usize = X25519_PUBLIC_KEY_LEN + MLKEM768_PUBLIC_KEY_LEN;
pub const HYBRID_SECRET_KEY_LEN: usize = X25519_PRIVATE_KEY_LEN + MLKEM768_SECRET_KEY_LEN;
pub const HYBRID_CIPHERTEXT_LEN: usize = X25519_PUBLIC_KEY_LEN + MLKEM768_CIPHERTEXT_LEN;
pub const HYBRID_SHARED_SECRET_LEN: usize = 32;

// ============================================================================
// Safe Rust Wrappers
// ============================================================================

/// HKDF-SHA256 key derivation (Extract + Expand)
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt (use empty slice for default)
/// * `info` - Optional context/application info
/// * `out_len` - Number of bytes to derive
///
/// # Returns
/// Derived key material of length `out_len`
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>> {
    let mut out = vec![0u8; out_len];

    let salt_ptr = if salt.is_empty() {
        ptr::null()
    } else {
        salt.as_ptr()
    };

    let info_ptr = if info.is_empty() {
        ptr::null()
    } else {
        info.as_ptr()
    };

    let rc = unsafe {
        bssl::pcr_hkdf_sha256(
            out.as_mut_ptr(),
            out_len,
            ikm.as_ptr(),
            ikm.len(),
            salt_ptr,
            salt.len(),
            info_ptr,
            info.len(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(out)
}

/// HKDF-SHA256 Extract phase only
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt
///
/// # Returns
/// 32-byte pseudorandom key (PRK)
pub fn hkdf_extract_sha256(ikm: &[u8], salt: &[u8]) -> Result<[u8; HKDF_SHA256_HASH_LEN]> {
    let mut prk = [0u8; HKDF_SHA256_HASH_LEN];

    let salt_ptr = if salt.is_empty() {
        ptr::null()
    } else {
        salt.as_ptr()
    };

    let rc = unsafe {
        bssl::pcr_hkdf_extract_sha256(
            prk.as_mut_ptr(),
            salt_ptr,
            salt.len(),
            ikm.as_ptr(),
            ikm.len(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(prk)
}

/// HKDF-SHA256 Expand phase only
///
/// # Arguments
/// * `prk` - Pseudorandom key from Extract phase
/// * `info` - Optional context info
/// * `out_len` - Number of bytes to derive
///
/// # Returns
/// Derived key material of length `out_len`
pub fn hkdf_expand_sha256(prk: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; out_len];

    let info_ptr = if info.is_empty() {
        ptr::null()
    } else {
        info.as_ptr()
    };

    let rc = unsafe {
        bssl::pcr_hkdf_expand_sha256(
            out.as_mut_ptr(),
            out_len,
            prk.as_ptr(),
            prk.len(),
            info_ptr,
            info.len(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(out)
}

/// HKDF-SHA256 into a fixed-size array (no allocation)
///
/// This is an optimized version that writes directly into a provided buffer.
#[inline]
pub fn hkdf_sha256_into<const N: usize>(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out: &mut [u8; N],
) -> Result<()> {
    let salt_ptr = if salt.is_empty() {
        ptr::null()
    } else {
        salt.as_ptr()
    };

    let info_ptr = if info.is_empty() {
        ptr::null()
    } else {
        info.as_ptr()
    };

    let rc = unsafe {
        bssl::pcr_hkdf_sha256(
            out.as_mut_ptr(),
            N,
            ikm.as_ptr(),
            ikm.len(),
            salt_ptr,
            salt.len(),
            info_ptr,
            info.len(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(())
}

/// HKDF-SHA256 Expand phase into fixed buffer (no allocation)
#[inline]
pub fn hkdf_expand_sha256_into<const N: usize>(
    prk: &[u8],
    info: &[u8],
    out: &mut [u8; N],
) -> Result<()> {
    let info_ptr = if info.is_empty() {
        ptr::null()
    } else {
        info.as_ptr()
    };

    let rc = unsafe {
        bssl::pcr_hkdf_expand_sha256(
            out.as_mut_ptr(),
            N,
            prk.as_ptr(),
            prk.len(),
            info_ptr,
            info.len(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(())
}

/// SHA-256 direct hash (faster than HKDF for ratchet derivation)
#[inline]
pub fn sha256(input: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let rc = unsafe {
        bssl::pcr_sha256(
            out.as_mut_ptr(),
            input.as_ptr(),
            input.len(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(out)
}

/// SHA-256 of two concatenated inputs (no allocation)
#[inline]
pub fn sha256_two(in1: &[u8], in2: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    
    let in1_ptr = if in1.is_empty() { ptr::null() } else { in1.as_ptr() };
    let in2_ptr = if in2.is_empty() { ptr::null() } else { in2.as_ptr() };
    
    let rc = unsafe {
        bssl::pcr_sha256_two(
            out.as_mut_ptr(),
            in1_ptr,
            in1.len(),
            in2_ptr,
            in2.len(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(out)
}

/// AES-256-GCM authenticated encryption
///
/// # Arguments
/// * `key` - 32-byte AES key
/// * `nonce` - 12-byte nonce/IV
/// * `ad` - Additional authenticated data
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Ciphertext with appended authentication tag (plaintext.len() + 16 bytes)
pub fn aes256gcm_seal(
    key: &[u8; AES256_KEY_LEN],
    nonce: &[u8; AES256_GCM_IV_LEN],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut out = vec![0u8; plaintext.len() + AES256_GCM_TAG_LEN];
    let mut out_len: usize = 0;

    let ad_ptr = if ad.is_empty() { ptr::null() } else { ad.as_ptr() };
    let in_ptr = if plaintext.is_empty() {
        ptr::null()
    } else {
        plaintext.as_ptr()
    };

    let rc = unsafe {
        bssl::pcr_aes256gcm_seal(
            out.as_mut_ptr(),
            &mut out_len,
            key.as_ptr(),
            nonce.as_ptr(),
            ad_ptr,
            ad.len(),
            in_ptr,
            plaintext.len(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    out.truncate(out_len);
    Ok(out)
}

/// AES-256-GCM authenticated encryption (in-place, no allocation)
///
/// Encrypts plaintext in-place and appends the authentication tag.
/// The output buffer must be at least plaintext.len() + 16 bytes.
///
/// # Arguments
/// * `key` - 32-byte AES key
/// * `nonce` - 12-byte nonce/IV
/// * `ad` - Additional authenticated data
/// * `buf` - Buffer containing plaintext, will be overwritten with ciphertext + tag
/// * `plaintext_len` - Length of plaintext in buffer
///
/// # Returns
/// Length of ciphertext (plaintext_len + 16)
#[inline]
pub fn aes256gcm_seal_in_place(
    key: &[u8; AES256_KEY_LEN],
    nonce: &[u8; AES256_GCM_IV_LEN],
    ad: &[u8],
    buf: &mut [u8],
    plaintext_len: usize,
) -> Result<usize> {
    if buf.len() < plaintext_len + AES256_GCM_TAG_LEN {
        return Err(PcrError::CryptoFailed);
    }

    let mut out_len: usize = 0;
    let ad_ptr = if ad.is_empty() { ptr::null() } else { ad.as_ptr() };

    // Need to use separate input/output since BoringSSL may not support in-place
    // Create a temporary copy of the plaintext
    let mut temp_in = [0u8; 2048]; // Max QUIC packet size
    if plaintext_len > temp_in.len() {
        return Err(PcrError::CryptoFailed);
    }
    temp_in[..plaintext_len].copy_from_slice(&buf[..plaintext_len]);

    let rc = unsafe {
        bssl::pcr_aes256gcm_seal(
            buf.as_mut_ptr(),
            &mut out_len,
            key.as_ptr(),
            nonce.as_ptr(),
            ad_ptr,
            ad.len(),
            temp_in.as_ptr(),
            plaintext_len,
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(out_len)
}

/// AES-256-GCM authenticated decryption
///
/// # Arguments
/// * `key` - 32-byte AES key
/// * `nonce` - 12-byte nonce/IV
/// * `ad` - Additional authenticated data
/// * `ciphertext` - Ciphertext with appended tag (must be at least 16 bytes)
///
/// # Returns
/// Decrypted plaintext if authentication succeeds
pub fn aes256gcm_open(
    key: &[u8; AES256_KEY_LEN],
    nonce: &[u8; AES256_GCM_IV_LEN],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < AES256_GCM_TAG_LEN {
        return Err(PcrError::CryptoFailed);
    }

    let mut out = vec![0u8; ciphertext.len() - AES256_GCM_TAG_LEN];
    let mut out_len: usize = 0;

    let ad_ptr = if ad.is_empty() { ptr::null() } else { ad.as_ptr() };

    let rc = unsafe {
        bssl::pcr_aes256gcm_open(
            out.as_mut_ptr(),
            &mut out_len,
            key.as_ptr(),
            nonce.as_ptr(),
            ad_ptr,
            ad.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    out.truncate(out_len);
    Ok(out)
}

// ============================================================================
// AES-256-GCM Context (Cached Key Schedule) - OPTIMIZED PATH
// ============================================================================

/// AES-256-GCM encryption context with cached key schedule
///
/// This provides much faster encryption/decryption when using the same key
/// for multiple packets, as the AES key schedule is computed only once.
pub struct Aes256GcmCtx {
    ctx: *mut std::ffi::c_void,
}

// Safety: The context is thread-safe as it's only used for encryption
unsafe impl Send for Aes256GcmCtx {}
unsafe impl Sync for Aes256GcmCtx {}

impl Aes256GcmCtx {
    /// Create a new AES-GCM context with the given key
    ///
    /// The key schedule is computed once and cached for subsequent operations.
    pub fn new(key: &[u8; AES256_KEY_LEN]) -> Result<Self> {
        let ctx = unsafe { bssl::pcr_aes256gcm_ctx_new(key.as_ptr()) };
        if ctx.is_null() {
            return Err(PcrError::CryptoFailed);
        }
        Ok(Self { ctx })
    }

    /// Encrypt with cached key schedule (fast path)
    #[inline]
    pub fn seal(
        &self,
        nonce: &[u8; AES256_GCM_IV_LEN],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut out = vec![0u8; plaintext.len() + AES256_GCM_TAG_LEN];
        let mut out_len: usize = 0;

        let ad_ptr = if ad.is_empty() { ptr::null() } else { ad.as_ptr() };
        let in_ptr = if plaintext.is_empty() { ptr::null() } else { plaintext.as_ptr() };

        let rc = unsafe {
            bssl::pcr_aes256gcm_seal_ctx(
                self.ctx,
                out.as_mut_ptr(),
                &mut out_len,
                nonce.as_ptr(),
                ad_ptr,
                ad.len(),
                in_ptr,
                plaintext.len(),
            )
        };

        if rc != 1 {
            return Err(PcrError::CryptoFailed);
        }

        out.truncate(out_len);
        Ok(out)
    }

    /// Encrypt in-place with cached key schedule (fastest path)
    ///
    /// Uses BoringSSL's scatter-gather API for true in-place encryption.
    /// The tag is appended directly after the ciphertext.
    /// Buffer must have room for plaintext_len + 16 bytes (tag)
    ///
    /// Returns the total output length (ciphertext + tag)
    #[inline]
    pub fn seal_in_place(
        &self,
        nonce: &[u8; AES256_GCM_IV_LEN],
        ad: &[u8],
        buf: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize> {
        if buf.len() < plaintext_len + AES256_GCM_TAG_LEN {
            return Err(PcrError::CryptoFailed);
        }

        let ad_ptr = if ad.is_empty() { ptr::null() } else { ad.as_ptr() };
        let mut tag_len: usize = 0;

        // True in-place encryption: data is encrypted in-place, tag written at end
        let rc = unsafe {
            bssl::pcr_aes256gcm_seal_in_place(
                self.ctx,
                buf.as_mut_ptr(),
                plaintext_len,
                nonce.as_ptr(),
                ad_ptr,
                ad.len(),
                buf.as_mut_ptr().add(plaintext_len),  // Tag goes after ciphertext
                &mut tag_len,
            )
        };

        if rc != 1 {
            return Err(PcrError::CryptoFailed);
        }

        Ok(plaintext_len + tag_len)
    }

    /// Decrypt with cached key schedule (fast path)
    #[inline]
    pub fn open(
        &self,
        nonce: &[u8; AES256_GCM_IV_LEN],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < AES256_GCM_TAG_LEN {
            return Err(PcrError::CryptoFailed);
        }

        let mut out = vec![0u8; ciphertext.len() - AES256_GCM_TAG_LEN];
        let mut out_len: usize = 0;

        let ad_ptr = if ad.is_empty() { ptr::null() } else { ad.as_ptr() };

        let rc = unsafe {
            bssl::pcr_aes256gcm_open_ctx(
                self.ctx,
                out.as_mut_ptr(),
                &mut out_len,
                nonce.as_ptr(),
                ad_ptr,
                ad.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        };

        if rc != 1 {
            return Err(PcrError::CryptoFailed);
        }

        out.truncate(out_len);
        Ok(out)
    }
}

impl Drop for Aes256GcmCtx {
    fn drop(&mut self) {
        unsafe {
            bssl::pcr_aes256gcm_ctx_free(self.ctx);
        }
    }
}

/// X25519 keypair generation
///
/// # Returns
/// Tuple of (public_key, private_key)
pub fn x25519_keypair() -> Result<(
    [u8; X25519_PUBLIC_KEY_LEN],
    [u8; X25519_PRIVATE_KEY_LEN],
)> {
    let mut public_key = [0u8; X25519_PUBLIC_KEY_LEN];
    let mut private_key = [0u8; X25519_PRIVATE_KEY_LEN];

    let rc = unsafe { bssl::pcr_x25519_keypair(public_key.as_mut_ptr(), private_key.as_mut_ptr()) };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok((public_key, private_key))
}

/// X25519 ECDH shared secret derivation
///
/// # Arguments
/// * `private_key` - Our private key
/// * `peer_public` - Peer's public key
///
/// # Returns
/// 32-byte shared secret
pub fn x25519_derive(
    private_key: &[u8; X25519_PRIVATE_KEY_LEN],
    peer_public: &[u8; X25519_PUBLIC_KEY_LEN],
) -> Result<[u8; X25519_SHARED_SECRET_LEN]> {
    let mut shared_secret = [0u8; X25519_SHARED_SECRET_LEN];

    let rc = unsafe {
        bssl::pcr_x25519_derive(
            shared_secret.as_mut_ptr(),
            private_key.as_ptr(),
            peer_public.as_ptr(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(shared_secret)
}

/// Hybrid KEM (X25519 + ML-KEM-768) keypair generation
///
/// # Returns
/// Tuple of (public_key, secret_key) for hybrid KEM
pub fn hybrid_kem_keypair() -> Result<(
    Box<[u8; HYBRID_PUBLIC_KEY_LEN]>,
    Box<[u8; HYBRID_SECRET_KEY_LEN]>,
)> {
    let mut public_key = Box::new([0u8; HYBRID_PUBLIC_KEY_LEN]);
    let mut secret_key = Box::new([0u8; HYBRID_SECRET_KEY_LEN]);

    let rc = unsafe {
        bssl::pcr_hybrid_kem_keypair(public_key.as_mut_ptr(), secret_key.as_mut_ptr())
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok((public_key, secret_key))
}

/// Hybrid KEM encapsulation
///
/// Generates a shared secret and ciphertext for the given public key.
/// Used by the initiator of an epoch rekey.
///
/// # Arguments
/// * `public_key` - Recipient's hybrid public key
///
/// # Returns
/// Tuple of (ciphertext, shared_secret)
pub fn hybrid_kem_encaps(
    public_key: &[u8; HYBRID_PUBLIC_KEY_LEN],
) -> Result<(
    Box<[u8; HYBRID_CIPHERTEXT_LEN]>,
    [u8; HYBRID_SHARED_SECRET_LEN],
)> {
    let mut ciphertext = Box::new([0u8; HYBRID_CIPHERTEXT_LEN]);
    let mut shared_secret = [0u8; HYBRID_SHARED_SECRET_LEN];

    let rc = unsafe {
        bssl::pcr_hybrid_kem_encaps(
            ciphertext.as_mut_ptr(),
            shared_secret.as_mut_ptr(),
            public_key.as_ptr(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok((ciphertext, shared_secret))
}

/// Hybrid KEM decapsulation
///
/// Recovers the shared secret from ciphertext using our secret key.
/// Used by the responder of an epoch rekey.
///
/// # Arguments
/// * `ciphertext` - Ciphertext from encapsulation
/// * `secret_key` - Our hybrid secret key
///
/// # Returns
/// 32-byte shared secret
pub fn hybrid_kem_decaps(
    ciphertext: &[u8; HYBRID_CIPHERTEXT_LEN],
    secret_key: &[u8; HYBRID_SECRET_KEY_LEN],
) -> Result<[u8; HYBRID_SHARED_SECRET_LEN]> {
    let mut shared_secret = [0u8; HYBRID_SHARED_SECRET_LEN];

    let rc = unsafe {
        bssl::pcr_hybrid_kem_decaps(
            shared_secret.as_mut_ptr(),
            ciphertext.as_ptr(),
            secret_key.as_ptr(),
        )
    };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(shared_secret)
}

// ============================================================================
// Slice-based KEM wrappers for dynamic-sized keys
// ============================================================================

/// Hybrid KEM encapsulation with slice inputs
///
/// This is a convenience wrapper that accepts slices instead of fixed arrays.
/// Validates the public key length before calling the underlying function.
pub fn hybrid_kem_encaps_slice(public_key: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if public_key.len() != HYBRID_PUBLIC_KEY_LEN {
        return Err(PcrError::CryptoFailed);
    }

    let mut pk_arr = [0u8; HYBRID_PUBLIC_KEY_LEN];
    pk_arr.copy_from_slice(public_key);

    let (ct_box, ss) = hybrid_kem_encaps(&pk_arr)?;
    Ok((ct_box.to_vec(), ss))
}

/// Hybrid KEM decapsulation with slice inputs
///
/// This is a convenience wrapper that accepts slices instead of fixed arrays.
/// Validates lengths before calling the underlying function.
pub fn hybrid_kem_decaps_slice(ciphertext: &[u8], secret_key: &[u8]) -> Result<[u8; 32]> {
    if ciphertext.len() != HYBRID_CIPHERTEXT_LEN {
        return Err(PcrError::CryptoFailed);
    }
    if secret_key.len() != HYBRID_SECRET_KEY_LEN {
        return Err(PcrError::CryptoFailed);
    }

    let mut ct_arr = [0u8; HYBRID_CIPHERTEXT_LEN];
    ct_arr.copy_from_slice(ciphertext);

    let mut sk_arr = [0u8; HYBRID_SECRET_KEY_LEN];
    sk_arr.copy_from_slice(secret_key);

    hybrid_kem_decaps(&ct_arr, &sk_arr)
}

/// Securely zero memory
///
/// Zeroes memory in a way that won't be optimized out by the compiler.
/// Use this to erase sensitive key material.
pub fn secure_zero(data: &mut [u8]) {
    if !data.is_empty() {
        unsafe {
            bssl::pcr_secure_zero(data.as_mut_ptr(), data.len());
        }
    }
}

/// Generate cryptographically secure random bytes
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; len];

    let rc = unsafe { bssl::pcr_random_bytes(out.as_mut_ptr(), len) };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(out)
}

/// Fill buffer with cryptographically secure random bytes
pub fn random_bytes_into(out: &mut [u8]) -> Result<()> {
    if out.is_empty() {
        return Ok(());
    }

    let rc = unsafe { bssl::pcr_random_bytes(out.as_mut_ptr(), out.len()) };

    if rc != 1 {
        return Err(PcrError::CryptoFailed);
    }

    Ok(())
}

// ============================================================================
// Zeroize on Drop wrapper for sensitive data
// ============================================================================

/// A wrapper that securely zeros memory on drop.
/// Use this for storing sensitive cryptographic material.
pub struct SecretBytes<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Clone for SecretBytes<N> {
    fn clone(&self) -> Self {
        Self { data: self.data }
    }
}

impl<const N: usize> SecretBytes<N> {
    /// Create a new SecretBytes with zeroed contents
    pub fn new() -> Self {
        Self { data: [0u8; N] }
    }

    /// Create SecretBytes from an existing array
    pub fn from_array(data: [u8; N]) -> Self {
        Self { data }
    }

    /// Get a reference to the underlying data
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.data
    }

    /// Get a mutable reference to the underlying data
    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }
}

impl<const N: usize> Default for SecretBytes<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        secure_zero(&mut self.data);
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> AsMut<[u8]> for SecretBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_hkdf_sha256() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let result = hkdf_sha256(ikm, salt, info, 32);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_hkdf_extract_expand() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let prk = hkdf_extract_sha256(ikm, salt).unwrap();
        assert_eq!(prk.len(), 32);

        let okm = hkdf_expand_sha256(&prk, info, 64).unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_aes256gcm_round_trip() {
        let key = [0x42u8; AES256_KEY_LEN];
        let nonce = [0x01u8; AES256_GCM_IV_LEN];
        let ad = b"additional data";
        let plaintext = b"hello world, this is a test message!";

        let ciphertext = aes256gcm_seal(&key, &nonce, ad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + AES256_GCM_TAG_LEN);

        let decrypted = aes256gcm_open(&key, &nonce, ad, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes256gcm_auth_failure() {
        let key = [0x42u8; AES256_KEY_LEN];
        let nonce = [0x01u8; AES256_GCM_IV_LEN];
        let ad = b"additional data";
        let plaintext = b"hello world";

        let mut ciphertext = aes256gcm_seal(&key, &nonce, ad, plaintext).unwrap();

        // Corrupt the ciphertext
        ciphertext[0] ^= 0xff;

        let result = aes256gcm_open(&key, &nonce, ad, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_x25519_key_exchange() {
        let (alice_pk, alice_sk) = x25519_keypair().unwrap();
        let (bob_pk, bob_sk) = x25519_keypair().unwrap();

        let alice_ss = x25519_derive(&alice_sk, &bob_pk).unwrap();
        let bob_ss = x25519_derive(&bob_sk, &alice_pk).unwrap();

        assert_eq!(alice_ss, bob_ss);
    }

    #[test]
    fn test_hybrid_kem_round_trip() {
        let (public_key, secret_key) = hybrid_kem_keypair().unwrap();

        let (ciphertext, encaps_ss) = hybrid_kem_encaps(&public_key).unwrap();
        let decaps_ss = hybrid_kem_decaps(&ciphertext, &secret_key).unwrap();

        assert_eq!(encaps_ss, decaps_ss);
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different with overwhelming probability
    }

    #[test]
    fn test_secret_bytes_zeroize() {
        let secret = SecretBytes::<32>::from_array([0xffu8; 32]);
        assert_eq!(secret.as_bytes(), &[0xffu8; 32]);
        drop(secret);
        // Note: We can't easily verify the memory is zeroed after drop,
        // but the secure_zero function is called.
    }
}
