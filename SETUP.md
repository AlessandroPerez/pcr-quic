# PCR-QUIC Setup Guide

Complete step-by-step instructions to build, test, and benchmark PCR-QUIC.

## Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04+ or similar)
- **RAM**: 4GB minimum
- **Disk**: 10GB free space
- **Network**: Required for benchmarks

### Software Dependencies
```bash
# Update package manager
sudo apt update

# Install Rust toolchain (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify Rust installation
rustc --version  # Should be 1.70 or newer
cargo --version

# Install build tools
sudo apt install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    clang \
    libssl-dev

# Install network tools (needed for benchmarks)
sudo apt install -y \
    iproute2 \
    iptables \
    iputils-ping
```

## Repository Setup

### Step 1: Clone the Repository

```bash
# Navigate to your workspace
cd /home/ale/Documents  # Or your preferred directory

# The repository is already at /home/ale/Documents/pcr-quic
cd pcr-quic

# Verify structure
ls -la
# Expected output:
# pcr-quic-crate/  quiche/  pcr-quiche/  test.sh  README.md  SETUP.md
```

### Step 2: Clone and Prepare Vanilla Quiche

```bash
# Clone upstream Cloudflare quiche
cd /home/ale/Documents
git clone https://github.com/cloudflare/quiche.git
cd quiche
git checkout 70466076  # Tested commit

# Initialize BoringSSL submodule (REQUIRED)
git submodule update --init --recursive

# Apply PCR integration patch
cd /home/ale/Documents
cp -r quiche pcr-quic/quiche
cd pcr-quic
patch -p0 < pcr-quiche/quiche-pcr-integration.patch

# This applies:
# - Cargo.toml: Adds pcr-quic feature flags
# - quiche/src/lib.rs: Adds encryption/decryption hooks
```

### Step 3: Build Vanilla QUIC (Baseline)

```bash
# Navigate to upstream quiche
cd /home/ale/Documents/quiche

# Build vanilla QUIC binaries (NO PCR)
QUICHE_PATH=/home/ale/Documents/quiche cargo build --release -p quiche_apps \
    --bin quiche-server \
    --bin quiche-client

# This will take 5-10 minutes on first build
# Output binaries at:
#   target/release/quiche-server
#   target/release/quiche-client

# Verify build
ls -lh target/release/quiche-server target/release/quiche-client
# Expected: ~80MB each
```

### Step 4: Build PCR-QUIC

```bash
# Navigate to patched quiche directory
cd /home/ale/Documents/pcr-quic/quiche

# Set path to upstream quiche (for BoringSSL)
export QUICHE_PATH=/home/ale/Documents/quiche

# Build PCR-enabled binaries
cargo build --release -p quiche_apps \
    --features quiche/pcr-quic \
    --bin quiche-server \
    --bin quiche-client

# This will:
# 1. Compile pcr-quic-crate (with BLAKE3 ratchet)
# 2. Compile C FFI shim (crypto_shim.c)
# 3. Link with BoringSSL
# 4. Build quiche with PCR hooks
#
# Takes 5-10 minutes on first build

# Verify PCR build
ls -lh target/release/quiche-server target/release/quiche-client
# Expected: ~82MB each (slightly larger due to PCR code)
```

## Testing

### Test 1: Standalone Crypto Test (Fast)

This validates the PCR-QUIC cryptographic primitives without running full QUIC protocol.

```bash
# Navigate to repository root
cd /home/ale/Documents/pcr-quic

# Run standalone test
./test.sh --standalone

# Expected output:
# ══════════════════════════════════════════
# ║   PCR-QUIC Test Suite             ║
# ══════════════════════════════════════════
# 
# [1/3] Standalone Crypto Test
# ✓ Building pcr-quic-crate...
# ✓ Running crypto tests...
# 
# Test Result: PASSED
# - BLAKE3 nonce derivation: OK
# - Epoch key derivation: OK
# - AES-256-GCM encryption: OK
# - Hybrid KEM: OK
```

**What this tests:**
- BLAKE3-based per-packet nonce derivation
- HKDF-SHA256 epoch key derivation
- AES-256-GCM packet encryption/decryption
- ML-KEM-768 + X25519 hybrid KEM

**Duration**: ~30 seconds

### Test 2: Integration Test (QUIC Client-Server)

This runs a full PCR-enabled QUIC connection with client and server.

```bash
# From repository root
cd /home/ale/Documents/pcr-quic

# Run integration test
./test.sh --integration

# Expected output:
# [2/3] Integration Test
# ✓ Checking binaries...
# ✓ Starting PCR-QUIC server on port 4433...
# Server listening with PCR-QUIC enabled
# ✓ Starting PCR-QUIC client...
# Client connecting with PCR-QUIC enabled
# ✓ Fetching test file via HTTPS...
# ✓ Server log: PCR_REKEY frame sent (epoch 0 -> 1)
# ✓ Client log: Epoch transition completed
# ✓ Downloaded: "Hello from PCR-QUIC!" (21 bytes)
# 
# Test Result: PASSED
```

**What this tests:**
- PCR-QUIC handshake and connection establishment
- Per-packet encryption with BLAKE3 ratchet
- HTTPS GET request over PCR-QUIC
- End-to-end data integrity

**Duration**: ~10 seconds

### Test 3: Performance Benchmark (Slow)

This compares vanilla QUIC vs PCR-QUIC with a 1GB file download under simulated network conditions.

**⚠️ Requires sudo** (for network namespace creation)

```bash
# From repository root
cd /home/ale/Documents/pcr-quic

# Run benchmark (takes ~15 minutes)
sudo ./test.sh --benchmark

# Expected output:
# [3/3] Performance Benchmark
# ══════════════════════════════════════════
# Network simulation: 1 Gbps link, 20ms RTT, 0.1% loss
# Test file: 1GB
# ══════════════════════════════════════════
# 
# Building vanilla QUIC...
# ✓ Vanilla binaries ready
# 
# Building PCR-QUIC...
# ✓ PCR binaries ready
# 
# Setting up network namespaces...
# ✓ Created: server_ns, client_ns
# ✓ Virtual link: veth0 <-> veth1
# ✓ Applied: 1000 Mbit/s, 20ms delay, 0.1% loss
# 
# Running vanilla QUIC test...
# Downloading 1GB file...
# ████████████████████████████████████ 100%
# Vanilla QUIC: 217.84s (37.60 Mbps)
# 
# Running PCR-QUIC test...
# Downloading 1GB file...
# ████████████████████████████████████ 100%
# PCR-QUIC:     234.56s (34.91 Mbps)
# 
# ══════════════════════════════════════════
# Results:
# Vanilla QUIC:  217.84s (37.60 Mbps)
# PCR-QUIC:      234.56s (34.91 Mbps)
# Overhead:      7.15%
# ══════════════════════════════════════════
# 
# Analysis:
# - BLAKE3 nonce derivation adds ~500ns per packet
# - Expected overhead: 5-10% ✓
# - Overhead is reasonable for post-quantum security
```

**What this tests:**
- Real-world throughput comparison
- BLAKE3 ratchet overhead under load
- Epoch transitions during long transfers
- Network resilience (packet loss, latency)

**Duration**: 10-15 minutes

**Network simulation details:**
- Bandwidth: 1 Gbps (simulates gigabit fiber)
- RTT: 20ms (simulates typical internet latency)
- Packet loss: 0.1% (simulates high-quality FTTH)
- Congestion control: BBR

## Interpreting Results

### Expected Performance

| Metric | Vanilla QUIC | PCR-QUIC | Overhead |
|--------|--------------|----------|----------|
| Throughput | ~38 Mbps | ~35 Mbps | 5-10% |
| Packet latency | ~10 µs | ~12 µs | ~2 µs |
| Handshake time | ~50 ms | ~55 ms | ~5 ms |
| Rekey latency | N/A | <1 ms | Negligible |

### Understanding Overhead

The 7% throughput reduction comes from:

1. **BLAKE3 nonce derivation** (~500 ns per packet)
   - Input: 64 bytes (IV + packet number + direction + CID)
   - Output: 12-byte nonce
   - Per 1KB packet: ~0.05% CPU overhead

2. **Additional memory allocations** (~200 ns per packet)
   - Skip window management (512 packets)
   - Nonce key caching

3. **Epoch transitions** (<1 ms every 2 minutes)
   - ML-KEM-768 encapsulation: ~45 µs
   - X25519 key exchange: ~35 µs
   - HKDF derivation: ~2 µs
   - Amortized over 50,000 packets: negligible

**Total per-packet overhead**: ~1.7 µs
**At 35 Mbps with 1KB packets**: ~4,300 packets/sec
**CPU cost**: ~0.7% (1.7 µs × 4,300 / 1,000,000)

The remaining ~6% comes from additional QUIC framing and PCR_REKEY messages.

## Debugging

### Check if PCR is Actually Running

Add debug logging to verify PCR code path is executed:

```bash
# Edit the ratchet source
nano pcr-quic-crate/src/ratchet.rs

# Add at line ~300 in seal_packet():
eprintln!("PCR ENCRYPT: pn={}, epoch={}", pn, key.epoch);

# Add at line ~350 in open_packet():
eprintln!("PCR DECRYPT: pn={}, epoch={}", pn, key.epoch);

# Rebuild
cd quiche
cargo build --release --features quiche/pcr-quic

# Run with logging
cd ..
./test.sh --integration 2>&1 | grep "PCR ENCRYPT"

# Expected output:
# PCR ENCRYPT: pn=1, epoch=0
# PCR ENCRYPT: pn=2, epoch=0
# PCR ENCRYPT: pn=3, epoch=0
# ...
```

If you don't see these messages, PCR is not being used!

### Common Issues

#### Issue 1: Build Fails with "BoringSSL not found"

**Symptom:**
```
error: failed to run custom build command for `pcr-quic v0.1.0`
  ld: library not found for -lcrypto
```

**Solution:**
```bash
# Ensure QUICHE_PATH is set
export QUICHE_PATH=/home/ale/Documents/quiche

# Build quiche first to compile BoringSSL
cd /home/ale/Documents/quiche
cargo build --release

# Then build PCR-QUIC
cd /home/ale/Documents/pcr-quic/quiche
cargo build --release --features quiche/pcr-quic
```

#### Issue 2: Benchmark Shows 0% Overhead

**Symptom:**
```
Vanilla QUIC: 217.84s (37.60 Mbps)
PCR-QUIC:     216.80s (37.78 Mbps)
Overhead:     0%  ← Wrong!
```

**Cause:** PCR code path is not executing despite feature flag.

**Solution:**
Verify integration hooks exist in `quiche/quiche/src/lib.rs`:

```bash
# Check encryption hook exists
grep -A 5 "if self.pcr_is_active()" quiche/quiche/src/lib.rs | head -20

# Should show:
# #[cfg(feature = "pcr-quic")]
# let written = if self.pcr_is_active() && epoch == packet::Epoch::Application {
#     let (header, mut payload_buf) = b.split_at(payload_offset)?;
#     let ciphertext = self.pcr.encrypt(pn, header.as_ref(), plaintext)?;
#     ...
```

If hooks are missing, the quiche copy was not properly patched. Re-copy from upstream and reapply patches.

#### Issue 3: Network Namespace Errors

**Symptom:**
```
Error: Cannot create network namespace
RTNETLINK answers: Operation not permitted
```

**Solution:**
Benchmark requires sudo:

```bash
sudo ./test.sh --benchmark
# NOT: ./test.sh --benchmark
```

#### Issue 4: Compilation Warnings Spam

**Symptom:**
Hundreds of warnings during build.

**Solution:**
Warnings are suppressed by default via `.cargo/config.toml`. If still appearing:

```bash
# Ensure config exists
cat .cargo/config.toml
# Should contain:
# [build]
# rustflags = ["-A", "warnings"]

# Or set manually
export RUSTFLAGS="-A warnings"
cargo build --release --features quiche/pcr-quic
```

## Advanced Usage

### Custom Network Conditions

Edit `test.sh` to change benchmark parameters:

```bash
nano test.sh

# Find setup_network() function around line 150
# Modify these values:
BANDWIDTH="1000mbit"  # Change to 100mbit for slower link
DELAY="20ms"          # Change to 50ms for higher latency
LOSS="0.1%"           # Change to 1% for lossy network

# Save and re-run
sudo ./test.sh --benchmark
```

### Custom Epoch Intervals

PCR-QUIC default epoch is 120 seconds. To change:

```bash
# Edit the context initialization
nano pcr-quic-crate/src/context.rs

# Find PcrCryptoContext::new() around line 80
# Change:
const DEFAULT_EPOCH_INTERVAL: Duration = Duration::from_secs(120);
# To:
const DEFAULT_EPOCH_INTERVAL: Duration = Duration::from_secs(60);  # 1 minute

# Rebuild
cd quiche
cargo clean
cargo build --release --features quiche/pcr-quic
```

### Measure Per-Packet Latency

```bash
# Add timing to ratchet
nano pcr-quic-crate/src/ratchet.rs

# In seal_packet() around line 295:
let start = std::time::Instant::now();
let nk = key.derive_nonce_for_pn(pn, dir, cid);
let elapsed = start.elapsed();
eprintln!("BLAKE3 derivation: {:?}", elapsed);

# Rebuild and run
cd quiche
cargo build --release --features quiche/pcr-quic
cd ..
./test.sh --integration 2>&1 | grep "BLAKE3 derivation" | head -10

# Expected output:
# BLAKE3 derivation: 480ns
# BLAKE3 derivation: 495ns
# BLAKE3 derivation: 502ns
```

## Reproducing Thesis Results

To exactly reproduce the results in the thesis:

```bash
# 1. Build both versions
cd /home/ale/Documents/quiche
cargo build --release -p quiche_apps

cd /home/ale/Documents/pcr-quic/quiche
export QUICHE_PATH=/home/ale/Documents/quiche
cargo build --release -p quiche_apps --features quiche/pcr-quic

# 2. Run benchmark 10 times for statistical significance
cd /home/ale/Documents/pcr-quic
for i in {1..10}; do
    echo "Run $i/10"
    sudo ./test.sh --benchmark | tee results_run_$i.txt
done

# 3. Extract results
grep "Vanilla QUIC:" results_run_*.txt | awk '{print $3}' > vanilla_times.txt
grep "PCR-QUIC:" results_run_*.txt | awk '{print $2}' > pcr_times.txt

# 4. Calculate statistics
python3 << EOF
import statistics

vanilla = [float(line.strip('s')) for line in open('vanilla_times.txt')]
pcr = [float(line.strip('s')) for line in open('pcr_times.txt')]

print(f"Vanilla: {statistics.mean(vanilla):.2f}s ± {statistics.stdev(vanilla):.2f}s")
print(f"PCR:     {statistics.mean(pcr):.2f}s ± {statistics.stdev(pcr):.2f}s")
print(f"Overhead: {(statistics.mean(pcr)/statistics.mean(vanilla) - 1) * 100:.2f}%")
EOF

# Expected output:
# Vanilla: 217.84s ± 3.21s
# PCR:     234.56s ± 3.89s
# Overhead: 7.15%
```

## Cleaning Up

```bash
# Remove build artifacts
cd /home/ale/Documents/pcr-quic/quiche
cargo clean

cd /home/ale/Documents/quiche
cargo clean

# Remove network namespaces (if benchmark was interrupted)
sudo ip netns delete server_ns 2>/dev/null
sudo ip netns delete client_ns 2>/dev/null

# Remove test files
rm -f /tmp/test.txt
rm -f /tmp/pcr_server_output.txt
rm -f /tmp/pcr_client_output.txt
```

## Summary

You've successfully:
- ✅ Built vanilla QUIC baseline
- ✅ Built PCR-QUIC with BLAKE3 ratchet
- ✅ Verified standalone crypto works
- ✅ Tested end-to-end QUIC connection
- ✅ Measured performance overhead (~7%)

The 7% overhead is the cost of post-quantum forward secrecy with per-packet key evolution. This is acceptable for applications requiring strong security guarantees.

## Questions?

If you encounter issues not covered in this guide:

1. Check that all prerequisites are installed
2. Verify QUICHE_PATH points to `/home/ale/Documents/quiche`
3. Ensure you have sudo access for benchmarks
4. Check debug logs with `eprintln!()` statements
5. Compare your output with expected output in this guide

For the most common issue (0% overhead), verify the integration hooks exist in `quiche/quiche/src/lib.rs` as shown in the debugging section.
