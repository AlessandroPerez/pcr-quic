/*
 * PCR-QUIC Crypto Shim - BoringSSL implementation
 *
 * Implementation of the cryptographic primitives for PCR-QUIC using BoringSSL.
 * This provides HKDF-SHA256 and AES-256-GCM operations needed for the
 * double ratchet protocol.
 */

#include "crypto_shim.h"

#include <string.h>

/* BoringSSL headers */
#include <openssl/hkdf.h>
#include <openssl/evp.h>
#include <openssl/aead.h>
#include <openssl/rand.h>
#include <openssl/curve25519.h>
#include <openssl/mem.h>

/* ============================================================================
 * HKDF-SHA256 Implementation
 * ============================================================================ */

int pcr_hkdf_sha256(
    uint8_t *out, size_t out_len,
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len)
{
    if (!out || !ikm) {
        return 0;
    }

    /* If salt is NULL, HKDF uses a zero-filled salt of hash length */
    return HKDF(out, out_len,
                EVP_sha256(),
                ikm, ikm_len,
                salt, salt_len,
                info, info_len);
}

int pcr_hkdf_extract_sha256(
    uint8_t prk[PCR_HKDF_SHA256_HASH_LEN],
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len)
{
    if (!prk || !ikm) {
        return 0;
    }

    size_t prk_len = PCR_HKDF_SHA256_HASH_LEN;
    return HKDF_extract(prk, &prk_len,
                        EVP_sha256(),
                        ikm, ikm_len,
                        salt, salt_len);
}

int pcr_hkdf_expand_sha256(
    uint8_t *out, size_t out_len,
    const uint8_t *prk, size_t prk_len,
    const uint8_t *info, size_t info_len)
{
    if (!out || !prk) {
        return 0;
    }

    return HKDF_expand(out, out_len,
                       EVP_sha256(),
                       prk, prk_len,
                       info, info_len);
}

/* ============================================================================
 * SHA-256 Direct Hash (faster than HKDF for simple derivation)
 * ============================================================================ */

int pcr_sha256(
    uint8_t out[PCR_HKDF_SHA256_HASH_LEN],
    const uint8_t *in, size_t in_len)
{
    if (!out || !in) {
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }

    int ret = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
        EVP_DigestUpdate(ctx, in, in_len) &&
        EVP_DigestFinal_ex(ctx, out, NULL)) {
        ret = 1;
    }

    EVP_MD_CTX_free(ctx);
    return ret;
}

int pcr_sha256_two(
    uint8_t out[PCR_HKDF_SHA256_HASH_LEN],
    const uint8_t *in1, size_t in1_len,
    const uint8_t *in2, size_t in2_len)
{
    if (!out) {
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }

    int ret = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
        (in1_len == 0 || EVP_DigestUpdate(ctx, in1, in1_len)) &&
        (in2_len == 0 || EVP_DigestUpdate(ctx, in2, in2_len)) &&
        EVP_DigestFinal_ex(ctx, out, NULL)) {
        ret = 1;
    }

    EVP_MD_CTX_free(ctx);
    return ret;
}

/* ============================================================================
 * AES-256-GCM Implementation
 * ============================================================================ */

int pcr_aes256gcm_seal(
    uint8_t *out, size_t *out_len,
    const uint8_t key[PCR_AES256_KEY_LEN],
    const uint8_t nonce[PCR_AES256_GCM_IV_LEN],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *in, size_t in_len)
{
    if (!out || !out_len || !key || !nonce) {
        return 0;
    }

    const EVP_AEAD *aead = EVP_aead_aes_256_gcm();
    EVP_AEAD_CTX ctx;
    int ret = 0;

    /* Initialize the AEAD context */
    if (!EVP_AEAD_CTX_init(&ctx, aead, key, PCR_AES256_KEY_LEN,
                           PCR_AES256_GCM_TAG_LEN, NULL)) {
        return 0;
    }

    /* Perform the seal operation */
    size_t max_out_len = in_len + PCR_AES256_GCM_TAG_LEN;
    if (!EVP_AEAD_CTX_seal(&ctx, out, out_len, max_out_len,
                           nonce, PCR_AES256_GCM_IV_LEN,
                           in, in_len,
                           ad, ad_len)) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_AEAD_CTX_cleanup(&ctx);
    return ret;
}

int pcr_aes256gcm_open(
    uint8_t *out, size_t *out_len,
    const uint8_t key[PCR_AES256_KEY_LEN],
    const uint8_t nonce[PCR_AES256_GCM_IV_LEN],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *in, size_t in_len)
{
    if (!out || !out_len || !key || !nonce || !in) {
        return 0;
    }

    /* Input must be at least the tag length */
    if (in_len < PCR_AES256_GCM_TAG_LEN) {
        return 0;
    }

    const EVP_AEAD *aead = EVP_aead_aes_256_gcm();
    EVP_AEAD_CTX ctx;
    int ret = 0;

    /* Initialize the AEAD context */
    if (!EVP_AEAD_CTX_init(&ctx, aead, key, PCR_AES256_KEY_LEN,
                           PCR_AES256_GCM_TAG_LEN, NULL)) {
        return 0;
    }

    /* Perform the open operation */
    size_t max_out_len = in_len - PCR_AES256_GCM_TAG_LEN;
    if (!EVP_AEAD_CTX_open(&ctx, out, out_len, max_out_len,
                           nonce, PCR_AES256_GCM_IV_LEN,
                           in, in_len,
                           ad, ad_len)) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_AEAD_CTX_cleanup(&ctx);
    return ret;
}

/* ============================================================================
 * AES-256-GCM Context-based Implementation (Cached Key Schedule)
 * ============================================================================ */

struct pcr_aes256gcm_ctx {
    EVP_AEAD_CTX ctx;
    int initialized;
};

pcr_aes256gcm_ctx_t *pcr_aes256gcm_ctx_new(const uint8_t key[PCR_AES256_KEY_LEN])
{
    if (!key) {
        return NULL;
    }

    pcr_aes256gcm_ctx_t *ctx = (pcr_aes256gcm_ctx_t *)malloc(sizeof(pcr_aes256gcm_ctx_t));
    if (!ctx) {
        return NULL;
    }

    const EVP_AEAD *aead = EVP_aead_aes_256_gcm();
    if (!EVP_AEAD_CTX_init(&ctx->ctx, aead, key, PCR_AES256_KEY_LEN,
                           PCR_AES256_GCM_TAG_LEN, NULL)) {
        free(ctx);
        return NULL;
    }

    ctx->initialized = 1;
    return ctx;
}

void pcr_aes256gcm_ctx_free(pcr_aes256gcm_ctx_t *ctx)
{
    if (ctx) {
        if (ctx->initialized) {
            EVP_AEAD_CTX_cleanup(&ctx->ctx);
        }
        OPENSSL_cleanse(ctx, sizeof(*ctx));
        free(ctx);
    }
}

int pcr_aes256gcm_seal_ctx(
    pcr_aes256gcm_ctx_t *ctx,
    uint8_t *out, size_t *out_len,
    const uint8_t nonce[PCR_AES256_GCM_IV_LEN],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *in, size_t in_len)
{
    if (!ctx || !ctx->initialized || !out || !out_len || !nonce) {
        return 0;
    }

    size_t max_out_len = in_len + PCR_AES256_GCM_TAG_LEN;
    if (!EVP_AEAD_CTX_seal(&ctx->ctx, out, out_len, max_out_len,
                           nonce, PCR_AES256_GCM_IV_LEN,
                           in, in_len,
                           ad, ad_len)) {
        return 0;
    }

    return 1;
}

int pcr_aes256gcm_seal_in_place(
    pcr_aes256gcm_ctx_t *ctx,
    uint8_t *data, size_t data_len,
    const uint8_t nonce[PCR_AES256_GCM_IV_LEN],
    const uint8_t *ad, size_t ad_len,
    uint8_t out_tag[PCR_AES256_GCM_TAG_LEN], size_t *out_tag_len)
{
    if (!ctx || !ctx->initialized || !data || !nonce || !out_tag || !out_tag_len) {
        return 0;
    }

    /* Use scatter-gather API: encrypt in-place, tag written separately */
    if (!EVP_AEAD_CTX_seal_scatter(&ctx->ctx,
                                    data,        /* ciphertext written here (in-place) */
                                    out_tag,     /* tag written here */
                                    out_tag_len,
                                    PCR_AES256_GCM_TAG_LEN,  /* max tag length */
                                    nonce, PCR_AES256_GCM_IV_LEN,
                                    data, data_len,  /* plaintext (same as output) */
                                    NULL, 0,     /* extra_in, extra_in_len */
                                    ad, ad_len)) {
        return 0;
    }

    return 1;
}

int pcr_aes256gcm_open_ctx(
    pcr_aes256gcm_ctx_t *ctx,
    uint8_t *out, size_t *out_len,
    const uint8_t nonce[PCR_AES256_GCM_IV_LEN],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *in, size_t in_len)
{
    if (!ctx || !ctx->initialized || !out || !out_len || !nonce || !in) {
        return 0;
    }

    if (in_len < PCR_AES256_GCM_TAG_LEN) {
        return 0;
    }

    size_t max_out_len = in_len - PCR_AES256_GCM_TAG_LEN;
    if (!EVP_AEAD_CTX_open(&ctx->ctx, out, out_len, max_out_len,
                           nonce, PCR_AES256_GCM_IV_LEN,
                           in, in_len,
                           ad, ad_len)) {
        return 0;
    }

    return 1;
}

/* ============================================================================
 * X25519 Implementation
 * ============================================================================ */

int pcr_x25519_keypair(
    uint8_t public_key[PCR_X25519_PUBLIC_KEY_LEN],
    uint8_t private_key[PCR_X25519_PRIVATE_KEY_LEN])
{
    if (!public_key || !private_key) {
        return 0;
    }

    /* Generate random private key */
    if (!RAND_bytes(private_key, PCR_X25519_PRIVATE_KEY_LEN)) {
        return 0;
    }

    /* Derive public key from private key */
    X25519_public_from_private(public_key, private_key);

    return 1;
}

int pcr_x25519_derive(
    uint8_t shared_secret[PCR_X25519_SHARED_SECRET_LEN],
    const uint8_t private_key[PCR_X25519_PRIVATE_KEY_LEN],
    const uint8_t peer_public[PCR_X25519_PUBLIC_KEY_LEN])
{
    if (!shared_secret || !private_key || !peer_public) {
        return 0;
    }

    return X25519(shared_secret, private_key, peer_public);
}

/* ============================================================================
 * Hybrid KEM Implementation (X25519 + ML-KEM-768)
 *
 * Note: ML-KEM-768 support requires liboqs. For now, we provide a stub
 * implementation that only uses X25519. The full hybrid implementation
 * will be enabled when OQS-BoringSSL is available.
 * ============================================================================ */

/* Forward declarations for ML-KEM-768 (from liboqs or OQS-BoringSSL) */
#if defined(PCR_USE_MLKEM768)
#include <oqs/oqs.h>

static int mlkem768_keypair(uint8_t *public_key, uint8_t *secret_key)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        return 0;
    }

    int ret = (OQS_KEM_keypair(kem, public_key, secret_key) == OQS_SUCCESS);
    OQS_KEM_free(kem);
    return ret;
}

static int mlkem768_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
                           const uint8_t *public_key)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        return 0;
    }

    int ret = (OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) == OQS_SUCCESS);
    OQS_KEM_free(kem);
    return ret;
}

static int mlkem768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext,
                           const uint8_t *secret_key)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        return 0;
    }

    int ret = (OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key) == OQS_SUCCESS);
    OQS_KEM_free(kem);
    return ret;
}
#endif /* PCR_USE_MLKEM768 */

int pcr_hybrid_kem_keypair(
    uint8_t public_key[PCR_HYBRID_PUBLIC_KEY_LEN],
    uint8_t secret_key[PCR_HYBRID_SECRET_KEY_LEN])
{
    if (!public_key || !secret_key) {
        return 0;
    }

    /* Generate X25519 keypair (first 32 bytes of each) */
    if (!pcr_x25519_keypair(public_key, secret_key)) {
        return 0;
    }

#if defined(PCR_USE_MLKEM768)
    /* Generate ML-KEM-768 keypair (remaining bytes) */
    if (!mlkem768_keypair(public_key + PCR_X25519_PUBLIC_KEY_LEN,
                          secret_key + PCR_X25519_PRIVATE_KEY_LEN)) {
        pcr_secure_zero(public_key, PCR_HYBRID_PUBLIC_KEY_LEN);
        pcr_secure_zero(secret_key, PCR_HYBRID_SECRET_KEY_LEN);
        return 0;
    }
#else
    /* Without ML-KEM-768, zero the remaining space as a placeholder */
    memset(public_key + PCR_X25519_PUBLIC_KEY_LEN, 0,
           PCR_MLKEM768_PUBLIC_KEY_LEN);
    memset(secret_key + PCR_X25519_PRIVATE_KEY_LEN, 0,
           PCR_MLKEM768_SECRET_KEY_LEN);
#endif

    return 1;
}

int pcr_hybrid_kem_encaps(
    uint8_t ciphertext[PCR_HYBRID_CIPHERTEXT_LEN],
    uint8_t shared_secret[PCR_HYBRID_SHARED_SECRET_LEN],
    const uint8_t public_key[PCR_HYBRID_PUBLIC_KEY_LEN])
{
    if (!ciphertext || !shared_secret || !public_key) {
        return 0;
    }

    uint8_t x25519_ss[PCR_X25519_SHARED_SECRET_LEN];
    uint8_t x25519_ephemeral_sk[PCR_X25519_PRIVATE_KEY_LEN];

    /* Generate ephemeral X25519 keypair and perform ECDH */
    if (!pcr_x25519_keypair(ciphertext, x25519_ephemeral_sk)) {
        return 0;
    }

    if (!pcr_x25519_derive(x25519_ss, x25519_ephemeral_sk, public_key)) {
        pcr_secure_zero(x25519_ephemeral_sk, sizeof(x25519_ephemeral_sk));
        return 0;
    }

    pcr_secure_zero(x25519_ephemeral_sk, sizeof(x25519_ephemeral_sk));

#if defined(PCR_USE_MLKEM768)
    uint8_t mlkem_ss[PCR_MLKEM768_SHARED_SECRET_LEN];

    /* ML-KEM-768 encapsulation */
    if (!mlkem768_encaps(ciphertext + PCR_X25519_PUBLIC_KEY_LEN,
                         mlkem_ss,
                         public_key + PCR_X25519_PUBLIC_KEY_LEN)) {
        pcr_secure_zero(x25519_ss, sizeof(x25519_ss));
        return 0;
    }

    /* Combine shared secrets using HKDF */
    /* IKM = X25519_SS || MLKEM_SS */
    uint8_t combined_ikm[PCR_X25519_SHARED_SECRET_LEN + PCR_MLKEM768_SHARED_SECRET_LEN];
    memcpy(combined_ikm, x25519_ss, PCR_X25519_SHARED_SECRET_LEN);
    memcpy(combined_ikm + PCR_X25519_SHARED_SECRET_LEN, mlkem_ss,
           PCR_MLKEM768_SHARED_SECRET_LEN);

    const uint8_t info[] = "pcr-quic hybrid kem";
    int ret = pcr_hkdf_sha256(shared_secret, PCR_HYBRID_SHARED_SECRET_LEN,
                              combined_ikm, sizeof(combined_ikm),
                              NULL, 0,
                              info, sizeof(info) - 1);

    pcr_secure_zero(x25519_ss, sizeof(x25519_ss));
    pcr_secure_zero(mlkem_ss, sizeof(mlkem_ss));
    pcr_secure_zero(combined_ikm, sizeof(combined_ikm));

    return ret;
#else
    /* Without ML-KEM-768, use X25519 shared secret directly via HKDF */
    memset(ciphertext + PCR_X25519_PUBLIC_KEY_LEN, 0, PCR_MLKEM768_CIPHERTEXT_LEN);

    const uint8_t info[] = "pcr-quic hybrid kem";
    int ret = pcr_hkdf_sha256(shared_secret, PCR_HYBRID_SHARED_SECRET_LEN,
                              x25519_ss, sizeof(x25519_ss),
                              NULL, 0,
                              info, sizeof(info) - 1);

    pcr_secure_zero(x25519_ss, sizeof(x25519_ss));
    return ret;
#endif
}

int pcr_hybrid_kem_decaps(
    uint8_t shared_secret[PCR_HYBRID_SHARED_SECRET_LEN],
    const uint8_t ciphertext[PCR_HYBRID_CIPHERTEXT_LEN],
    const uint8_t secret_key[PCR_HYBRID_SECRET_KEY_LEN])
{
    if (!shared_secret || !ciphertext || !secret_key) {
        return 0;
    }

    uint8_t x25519_ss[PCR_X25519_SHARED_SECRET_LEN];

    /* X25519 ECDH with ephemeral public key from ciphertext */
    if (!pcr_x25519_derive(x25519_ss, secret_key, ciphertext)) {
        return 0;
    }

#if defined(PCR_USE_MLKEM768)
    uint8_t mlkem_ss[PCR_MLKEM768_SHARED_SECRET_LEN];

    /* ML-KEM-768 decapsulation */
    if (!mlkem768_decaps(mlkem_ss,
                         ciphertext + PCR_X25519_PUBLIC_KEY_LEN,
                         secret_key + PCR_X25519_PRIVATE_KEY_LEN)) {
        pcr_secure_zero(x25519_ss, sizeof(x25519_ss));
        return 0;
    }

    /* Combine shared secrets using HKDF */
    uint8_t combined_ikm[PCR_X25519_SHARED_SECRET_LEN + PCR_MLKEM768_SHARED_SECRET_LEN];
    memcpy(combined_ikm, x25519_ss, PCR_X25519_SHARED_SECRET_LEN);
    memcpy(combined_ikm + PCR_X25519_SHARED_SECRET_LEN, mlkem_ss,
           PCR_MLKEM768_SHARED_SECRET_LEN);

    const uint8_t info[] = "pcr-quic hybrid kem";
    int ret = pcr_hkdf_sha256(shared_secret, PCR_HYBRID_SHARED_SECRET_LEN,
                              combined_ikm, sizeof(combined_ikm),
                              NULL, 0,
                              info, sizeof(info) - 1);

    pcr_secure_zero(x25519_ss, sizeof(x25519_ss));
    pcr_secure_zero(mlkem_ss, sizeof(mlkem_ss));
    pcr_secure_zero(combined_ikm, sizeof(combined_ikm));

    return ret;
#else
    /* Without ML-KEM-768, derive shared secret from X25519 only */
    const uint8_t info[] = "pcr-quic hybrid kem";
    int ret = pcr_hkdf_sha256(shared_secret, PCR_HYBRID_SHARED_SECRET_LEN,
                              x25519_ss, sizeof(x25519_ss),
                              NULL, 0,
                              info, sizeof(info) - 1);

    pcr_secure_zero(x25519_ss, sizeof(x25519_ss));
    return ret;
#endif
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

void pcr_secure_zero(void *ptr, size_t len)
{
    if (ptr) {
        OPENSSL_cleanse(ptr, len);
    }
}

int pcr_random_bytes(uint8_t *out, size_t len)
{
    if (!out) {
        return 0;
    }

    return RAND_bytes(out, len);
}
