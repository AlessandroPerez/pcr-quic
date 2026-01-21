# PCR-QUIC Integration Patches

This directory contains the patch file to apply PCR-QUIC modifications to upstream Cloudflare quiche.

## Files

- **quiche-pcr-integration.patch** - Main integration patch for PCR-QUIC
  - Adds `pcr-quic` feature flag to Cargo.toml
  - Integrates packet encryption/decryption hooks in lib.rs
  - Links pcr-quic-crate for double ratchet cryptography

## Usage

```bash
# 1. Clone vanilla quiche
git clone https://github.com/cloudflare/quiche.git
cd quiche
git checkout 70466076  # Tested commit

# 2. Copy to working directory and apply patch
cd /path/to/pcr-quic
cp -r /path/to/quiche ./quiche
patch -p0 < pcr-quiche/quiche-pcr-integration.patch

# 3. Build with PCR features
cd quiche
cargo build --release -p quiche_apps --features pcr-quic
```

## Patch Contents

The patch modifies two key files:

1. **quiche/Cargo.toml**: Adds PCR feature flags
   - `pcr-quic`: Enables PCR-QUIC integration
   - `pcr-quic-mlkem`: Adds ML-KEM-768 KEM support
   - `pcr-quic-debug`: Debug instrumentation (WARNING: logs keys)

2. **quiche/src/lib.rs**: Adds encryption/decryption hooks
   - Pre-encryption: Ratchets nonce, optionally rekeys
   - Encryption: Calls PCR instead of TLS 1.3 AEAD
   - Decryption: Verifies and decrypts PCR-protected packets

## Maintenance

To regenerate the patch after modifying the integrated quiche:

```bash
cd /home/ale/Documents
diff -u quiche/quiche/Cargo.toml pcr-quic/quiche/quiche/Cargo.toml > pcr-quic/pcr-quiche/quiche-pcr-integration.patch
diff -u quiche/quiche/src/lib.rs pcr-quic/quiche/quiche/src/lib.rs >> pcr-quic/pcr-quiche/quiche-pcr-integration.patch
```

## Tested Versions

- **Upstream quiche commit**: 70466076 (master, January 2026)
- **Rust version**: 1.82+
- **PCR-QUIC version**: 0.1.0
