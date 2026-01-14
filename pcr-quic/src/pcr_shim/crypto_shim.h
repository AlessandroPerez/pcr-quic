/*
 * PCR-QUIC Crypto Shim - BoringSSL wrapper for PCR-QUIC double ratchet
 *
 * This shim provides the cryptographic primitives needed for the PCR-QUIC
 * double ratchet protocol:
 *   - HKDF-SHA256 for key derivation
 *   - AES-256-GCM for authenticated encryption
 *   - Hybrid KEM (X25519 + ML-KEM-768) for epoch rekeying (§6.2)
 *
 * All functions return 1 on success, 0 on failure.
 */

#ifndef PCR_CRYPTO_SHIM_H
#define PCR_CRYPTO_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

#define PCR_AES256_KEY_LEN    32
#define PCR_AES256_GCM_IV_LEN 12
#define PCR_AES256_GCM_TAG_LEN 16
#define PCR_HKDF_SHA256_HASH_LEN 32
#define PCR_SHA256_HASH_LEN 32

/* X25519 constants */
#define PCR_X25519_PUBLIC_KEY_LEN  32
#define PCR_X25519_PRIVATE_KEY_LEN 32
#define PCR_X25519_SHARED_SECRET_LEN 32

/* ML-KEM-768 constants (from liboqs) */
#define PCR_MLKEM768_PUBLIC_KEY_LEN  1184
#define PCR_MLKEM768_SECRET_KEY_LEN  2400
#define PCR_MLKEM768_CIPHERTEXT_LEN  1088
#define PCR_MLKEM768_SHARED_SECRET_LEN 32

/* Hybrid KEM (X25519 + ML-KEM-768) combined sizes */
#define PCR_HYBRID_PUBLIC_KEY_LEN  (PCR_X25519_PUBLIC_KEY_LEN + PCR_MLKEM768_PUBLIC_KEY_LEN)
#define PCR_HYBRID_SECRET_KEY_LEN  (PCR_X25519_PRIVATE_KEY_LEN + PCR_MLKEM768_SECRET_KEY_LEN)
#define PCR_HYBRID_CIPHERTEXT_LEN  (PCR_X25519_PUBLIC_KEY_LEN + PCR_MLKEM768_CIPHERTEXT_LEN)
#define PCR_HYBRID_SHARED_SECRET_LEN 32  /* Combined via HKDF */

/* ============================================================================
 * HKDF-SHA256 Functions
 * ============================================================================ */

/**
 * pcr_hkdf_sha256 - HKDF Extract+Expand using SHA-256
 *
 * Performs HKDF as defined in RFC 5869 using SHA-256 as the hash function.
 * This is the primary key derivation function for PCR-QUIC.
 *
 * @param out:      Output buffer for derived key material
 * @param out_len:  Length of output to generate (max 255 * 32 bytes)
 * @param ikm:      Input keying material
 * @param ikm_len:  Length of IKM
 * @param salt:     Optional salt (can be NULL, will use zero-filled buffer)
 * @param salt_len: Length of salt (0 if salt is NULL)
 * @param info:     Optional context/application-specific info
 * @param info_len: Length of info
 *
 * @return 1 on success, 0 on failure
 */
int pcr_hkdf_sha256(
    uint8_t *out, size_t out_len,
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len);

/**
 * pcr_hkdf_extract_sha256 - HKDF Extract phase only
 *
 * Extracts a pseudorandom key (PRK) from the input keying material.
 *
 * @param prk:      Output buffer for PRK (must be 32 bytes)
 * @param salt:     Optional salt
 * @param salt_len: Length of salt
 * @param ikm:      Input keying material
 * @param ikm_len:  Length of IKM
 *
 * @return 1 on success, 0 on failure
 */
int pcr_hkdf_extract_sha256(
    uint8_t prk[PCR_HKDF_SHA256_HASH_LEN],
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len);

/**
 * pcr_hkdf_expand_sha256 - HKDF Expand phase only
 *
 * Expands a PRK into output keying material.
 *
 * @param out:      Output buffer
 * @param out_len:  Length of output to generate
 * @param prk:      Pseudorandom key from Extract phase
 * @param prk_len:  Length of PRK (should be 32 for SHA-256)
 * @param info:     Optional context info
 * @param info_len: Length of info
 *
 * @return 1 on success, 0 on failure
 */
int pcr_hkdf_expand_sha256(
    uint8_t *out, size_t out_len,
    const uint8_t *prk, size_t prk_len,
    const uint8_t *info, size_t info_len);

/**
 * pcr_sha256 - Direct SHA-256 hash (faster than HKDF for simple derivation)
 *
 * @param out:      Output buffer (must be 32 bytes)
 * @param in:       Input data
 * @param in_len:   Length of input
 *
 * @return 1 on success, 0 on failure
 */
int pcr_sha256(
    uint8_t out[PCR_SHA256_HASH_LEN],
    const uint8_t *in, size_t in_len);

/**
 * pcr_sha256_two - SHA-256 of concatenated inputs (avoids allocation)
 *
 * Computes SHA-256(in1 || in2)
 *
 * @param out:      Output buffer (must be 32 bytes)
 * @param in1:      First input
 * @param in1_len:  Length of first input
 * @param in2:      Second input
 * @param in2_len:  Length of second input
 *
 * @return 1 on success, 0 on failure
 */
int pcr_sha256_two(
    uint8_t out[PCR_SHA256_HASH_LEN],
    const uint8_t *in1, size_t in1_len,
    const uint8_t *in2, size_t in2_len);

/* ============================================================================
 * AES-256-GCM Functions
 * ============================================================================ */

/**
 * pcr_aes256gcm_seal - AES-256-GCM authenticated encryption
 *
 * Encrypts plaintext and produces ciphertext with authentication tag appended.
 *
 * @param out:      Output buffer (must have space for in_len + 16 bytes for tag)
 * @param out_len:  [out] Actual output length written
 * @param key:      32-byte AES-256 key
 * @param nonce:    12-byte nonce/IV
 * @param ad:       Additional authenticated data (can be NULL)
 * @param ad_len:   Length of AAD
 * @param in:       Plaintext to encrypt
 * @param in_len:   Length of plaintext
 *
 * @return 1 on success, 0 on failure
 */
int pcr_aes256gcm_seal(
    uint8_t *out, size_t *out_len,
    const uint8_t key[PCR_AES256_KEY_LEN],
    const uint8_t nonce[PCR_AES256_GCM_IV_LEN],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *in, size_t in_len);

/**
 * pcr_aes256gcm_open - AES-256-GCM authenticated decryption
 *
 * Decrypts ciphertext and verifies authentication tag.
 *
 * @param out:      Output buffer for plaintext (can be same as in for in-place)
 * @param out_len:  [out] Actual plaintext length written
 * @param key:      32-byte AES-256 key
 * @param nonce:    12-byte nonce/IV
 * @param ad:       Additional authenticated data (can be NULL)
 * @param ad_len:   Length of AAD
 * @param in:       Ciphertext with appended tag (in_len must include 16-byte tag)
 * @param in_len:   Length of ciphertext + tag
 *
 * @return 1 on success (tag verified), 0 on failure (authentication failed)
 */
int pcr_aes256gcm_open(
    uint8_t *out, size_t *out_len,
    const uint8_t key[PCR_AES256_KEY_LEN],
    const uint8_t nonce[PCR_AES256_GCM_IV_LEN],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *in, size_t in_len);

/* ============================================================================
 * X25519 ECDH Functions
 * ============================================================================ */

/**
 * pcr_x25519_keypair - Generate X25519 keypair
 *
 * @param public_key:  [out] 32-byte public key
 * @param private_key: [out] 32-byte private key
 *
 * @return 1 on success, 0 on failure
 */
int pcr_x25519_keypair(
    uint8_t public_key[PCR_X25519_PUBLIC_KEY_LEN],
    uint8_t private_key[PCR_X25519_PRIVATE_KEY_LEN]);

/**
 * pcr_x25519_derive - X25519 ECDH shared secret derivation
 *
 * @param shared_secret: [out] 32-byte shared secret
 * @param private_key:   Our 32-byte private key
 * @param peer_public:   Peer's 32-byte public key
 *
 * @return 1 on success, 0 on failure
 */
int pcr_x25519_derive(
    uint8_t shared_secret[PCR_X25519_SHARED_SECRET_LEN],
    const uint8_t private_key[PCR_X25519_PRIVATE_KEY_LEN],
    const uint8_t peer_public[PCR_X25519_PUBLIC_KEY_LEN]);

/* ============================================================================
 * Hybrid KEM Functions (X25519 + ML-KEM-768)
 * See §6.2 of the PCR-QUIC spec for epoch rekeying
 * ============================================================================ */

/**
 * pcr_hybrid_kem_keypair - Generate hybrid KEM keypair
 *
 * Generates both X25519 and ML-KEM-768 keypairs, concatenated.
 *
 * @param public_key:  [out] Combined public key (32 + 1184 bytes)
 * @param secret_key:  [out] Combined secret key (32 + 2400 bytes)
 *
 * @return 1 on success, 0 on failure
 */
int pcr_hybrid_kem_keypair(
    uint8_t public_key[PCR_HYBRID_PUBLIC_KEY_LEN],
    uint8_t secret_key[PCR_HYBRID_SECRET_KEY_LEN]);

/**
 * pcr_hybrid_kem_encaps - Hybrid KEM encapsulation
 *
 * Generates a shared secret and ciphertext using the recipient's public key.
 * Used by the initiator of an epoch rekey.
 *
 * @param ciphertext:     [out] Combined ciphertext (32 + 1088 bytes)
 * @param shared_secret:  [out] 32-byte shared secret (combined via HKDF)
 * @param public_key:     Recipient's combined public key
 *
 * @return 1 on success, 0 on failure
 */
int pcr_hybrid_kem_encaps(
    uint8_t ciphertext[PCR_HYBRID_CIPHERTEXT_LEN],
    uint8_t shared_secret[PCR_HYBRID_SHARED_SECRET_LEN],
    const uint8_t public_key[PCR_HYBRID_PUBLIC_KEY_LEN]);

/**
 * pcr_hybrid_kem_decaps - Hybrid KEM decapsulation
 *
 * Recovers the shared secret from ciphertext using our secret key.
 * Used by the responder of an epoch rekey.
 *
 * @param shared_secret:  [out] 32-byte shared secret (combined via HKDF)
 * @param ciphertext:     Combined ciphertext from encaps
 * @param secret_key:     Our combined secret key
 *
 * @return 1 on success, 0 on failure
 */
int pcr_hybrid_kem_decaps(
    uint8_t shared_secret[PCR_HYBRID_SHARED_SECRET_LEN],
    const uint8_t ciphertext[PCR_HYBRID_CIPHERTEXT_LEN],
    const uint8_t secret_key[PCR_HYBRID_SECRET_KEY_LEN]);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* Opaque AES-256-GCM context (caches key schedule for reuse) */
typedef struct pcr_aes256gcm_ctx pcr_aes256gcm_ctx_t;

/**
 * pcr_aes256gcm_ctx_new - Create new AES-GCM context with key schedule
 *
 * Caches the AES key schedule for faster subsequent seal/open operations.
 * Use this when encrypting/decrypting multiple packets with the same key.
 *
 * @param key: 32-byte AES-256 key
 *
 * @return Opaque context pointer, or NULL on failure
 */
pcr_aes256gcm_ctx_t *pcr_aes256gcm_ctx_new(const uint8_t key[PCR_AES256_KEY_LEN]);

/**
 * pcr_aes256gcm_ctx_free - Free AES-GCM context
 *
 * Securely zeroizes and frees the context.
 *
 * @param ctx: Context to free (can be NULL)
 */
void pcr_aes256gcm_ctx_free(pcr_aes256gcm_ctx_t *ctx);

/**
 * pcr_aes256gcm_seal_ctx - Encrypt with cached context (fast path)
 *
 * Same as pcr_aes256gcm_seal but uses cached key schedule.
 * Note: For in-place encryption, out can equal in.
 */
int pcr_aes256gcm_seal_ctx(
    pcr_aes256gcm_ctx_t *ctx,
    uint8_t *out, size_t *out_len,
    const uint8_t nonce[PCR_AES256_GCM_IV_LEN],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *in, size_t in_len);

/**
 * pcr_aes256gcm_seal_in_place - In-place encryption with separate tag output
 *
 * Encrypts data in-place and writes the authentication tag to a separate buffer.
 * This is the fastest path for encryption as it avoids all data copies.
 *
 * @param ctx:          Cached AES-GCM context
 * @param data:         Buffer containing plaintext, will be encrypted in-place
 * @param data_len:     Length of plaintext
 * @param nonce:        12-byte nonce
 * @param ad:           Additional authenticated data
 * @param ad_len:       Length of AAD
 * @param out_tag:      Output buffer for 16-byte auth tag
 * @param out_tag_len:  [out] Actual tag length written (always 16)
 *
 * @return 1 on success, 0 on failure
 */
int pcr_aes256gcm_seal_in_place(
    pcr_aes256gcm_ctx_t *ctx,
    uint8_t *data, size_t data_len,
    const uint8_t nonce[PCR_AES256_GCM_IV_LEN],
    const uint8_t *ad, size_t ad_len,
    uint8_t out_tag[PCR_AES256_GCM_TAG_LEN], size_t *out_tag_len);

/**
 * pcr_aes256gcm_open_ctx - Decrypt with cached context (fast path)
 *
 * Same as pcr_aes256gcm_open but uses cached key schedule.
 */
int pcr_aes256gcm_open_ctx(
    pcr_aes256gcm_ctx_t *ctx,
    uint8_t *out, size_t *out_len,
    const uint8_t nonce[PCR_AES256_GCM_IV_LEN],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *in, size_t in_len);

/**
 * pcr_secure_zero - Securely zero memory
 *
 * Zeros memory in a way that won't be optimized out by the compiler.
 * Use this to erase sensitive key material.
 *
 * @param ptr: Pointer to memory to zero
 * @param len: Number of bytes to zero
 */
void pcr_secure_zero(void *ptr, size_t len);

/**
 * pcr_random_bytes - Generate cryptographically secure random bytes
 *
 * @param out: Output buffer
 * @param len: Number of bytes to generate
 *
 * @return 1 on success, 0 on failure
 */
int pcr_random_bytes(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PCR_CRYPTO_SHIM_H */
