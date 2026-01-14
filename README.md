# PCR-QUIC: Per-Packet Cryptographic Ratcheting for QUIC

[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)

PCR-QUIC implements a double-ratchet mechanism for QUIC providing:
- **Forward Secrecy (FS)**: Per-packet nonce ratchet
- **Post-Compromise Security (PCS)**: KEM-based epoch rekeying
- **Precise Key Deletion**: Keys zeroized after use

## Repository Structure

```
pcr-quic/
├── benchmarks/            # Performance benchmarks
│   ├── ftth/              # FTTH network simulation tests
│   │   ├── setup_network.sh    # Network namespace setup (1 Gbps, 20ms RTT, 0.1% loss)
│   │   ├── run_tests.sh        # Automated test runner (baseline & PCR-QUIC)
│   │   ├── compare_results.sh  # Results comparison tool
│   │   └── results/            # Benchmark results (JSON format)
│   └── results/           # Aggregated benchmark results
├── README.md              # This file
└── .gitignore

External Dependencies:
├── quiche/                # Cloudflare's QUIC library (sibling directory)
│   └── quiche/src/pcr/    # PCR-QUIC implementation (integrated)
│       ├── ratchet.rs     # Per-packet symmetric ratchet (BLAKE3)
│       ├── keys.rs        # Epoch key derivation (HKDF-SHA256)
│       ├── context.rs     # Crypto context & epoch management
│       ├── integration.rs # quiche Connection integration
│       ├── frame.rs       # PCR_REKEY frame encoding/decoding
│       ├── params.rs      # Transport parameter negotiation
│       └── wiring.rs      # Packet protection hooks
```

**Note:** PCR-QUIC is currently implemented as a feature flag (`--features pcr-quic`) 
integrated directly into the quiche library, rather than as a standalone crate.

## Baseline Performance

Tested on simulated FTTH network (1 Gbps, 20ms RTT, 0.1% packet loss):

| Implementation | Throughput (Mbps) | Test Duration | File Size |
|----------------|-------------------|---------------|-----------|
| Stock QUIC     | 37.02            | 232s          | 1 GB      |
| PCR-QUIC       | TBD              | TBD           | 1 GB      |

Network configuration:
- Bandwidth: 1 Gbps
- RTT: 20ms (10ms each direction)
- Packet Loss: 0.1% (Bernoulli, applied to server→client data)
- Congestion Control: CUBIC
- Initial cwnd: 10 packets (RFC 9002 default)

## Quick Start

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install dependencies (Debian/Ubuntu)
sudo apt-get install build-essential cmake pkg-config libssl-dev jq

# For network namespace tests (Linux only)
sudo apt-get install iproute2 iptables bc
```

### Setup Quiche (Required for Benchmarks)

The benchmark scripts require Cloudflare's quiche to be cloned and built:

```bash
# Create a workspace directory
mkdir -p ~/pcr-quic-workspace
cd ~/pcr-quic-workspace

# Clone this repository
git clone https://github.com/yourusername/pcr-quic.git

# Clone quiche (required dependency) as a sibling directory
git clone --recursive https://github.com/cloudflare/quiche.git

# Build quiche
cd quiche
cargo build --release --bin quiche-server --bin quiche-client

# Create 1GB test file
mkdir -p apps/src/bin/root
dd if=/dev/zero of=apps/src/bin/root/1gb.bin bs=1M count=1024

# Verify build
ls -lh target/release/quiche-{server,client}

# Return to workspace
cd ..
```

**Directory Structure:**
```
~/pcr-quic-workspace/
├── pcr-quic/          # This repository
│   ├── benchmarks/
│   └── README.md
└── quiche/            # Cloudflare's quiche (sibling directory)
    ├── target/release/
    └── apps/
```

The benchmark scripts automatically find quiche in the sibling directory. For a custom location, set `QUICHE_PATH`:

```bash
export QUICHE_PATH=/your/custom/path/to/quiche
cd ~/pcr-quic-workspace/pcr-quic/benchmarks/ftth
./run_tests.sh baseline
```

### Building PCR-QUIC (Future)

```bash
# Build PCR-QUIC library (TODO: not yet extracted)
cd pcr-quic
cargo build --release

# Build with quiche integration
cd ../pcr-quic-quiche
cargo build --release
```

### Running Benchmarks

```bash
cd benchmarks/ftth

# Run baseline (stock QUIC) - requires quiche to be built first!
sudo ./run_tests.sh baseline

# Run PCR-QUIC tests (TODO: after integration)
sudo ./run_tests.sh pcr-quic

# Compare results
./compare_results.sh
```

## Reproducing Results

### Automated Testing (Recommended)

The easiest way to reproduce results:

```bash
# 1. Setup quiche (one-time setup - see Prerequisites above)
cd /home/ale/Documents
git clone --recursive https://github.com/cloudflare/quiche.git
cd quiche
cargo build --release --bin quiche-server --bin quiche-client
mkdir -p apps/src/bin/root
dd if=/dev/zero of=apps/src/bin/root/1gb.bin bs=1M count=1024

# 2. Run automated baseline tests (runs 3 iterations, calculates average)
cd /home/ale/Documents/pcr-quic/benchmarks/ftth
sudo ./run_tests.sh baseline

# 3. View results
./compare_results.sh
```

Expected result: ~37 Mbps average throughput for 1GB transfers

### Manual Testing

If you prefer to run tests manually:

```bash
# 1. Setup simulated FTTH network (requires root)
cd benchmarks/ftth
sudo ./setup_network.sh

# 2. In one terminal (server namespace)
cd /home/ale/Documents/quiche
sudo ip netns exec server ./target/release/quiche-server \
  --listen 10.0.0.1:4433 \
  --cert apps/src/bin/cert.crt \
  --key apps/src/bin/cert.key \
  --root apps/src/bin/root

# 3. In another terminal (client namespace)
sudo ip netns exec client ./target/release/quiche-client \
  --no-verify \
  https://10.0.0.1:4433/1gb.bin \
  --dump-responses /tmp/results

# 4. Calculate throughput
# Time the transfer and divide: (1GB * 8) / seconds = Mbps
```

### PCR-QUIC Test (TODO)

Once PCR-QUIC is integrated into quiche:

```bash
# Build quiche with PCR-QUIC feature
cd /home/ale/Documents/quiche
cargo build --release --features pcr-quic --bin quiche-server --bin quiche-client

# Run automated tests
cd /home/ale/Documents/pcr-quic/benchmarks/ftth
sudo ./run_tests.sh pcr-quic
```

## Architecture

### Core Library (`pcr-quic/`)

The core library is **implementation-agnostic** and provides:
- Cryptographic ratchet primitives
- Epoch key derivation
- Frame encoding/decoding
- No dependencies on specific QUIC implementations

### Quiche Adapter (`pcr-quic-quiche/`)

Integration layer for Cloudflare's quiche:
- Connection state management
- Packet protection hooks
- Transport parameter negotiation

This design allows PCR-QUIC to be adapted to other QUIC implementations (quinn, s2n-quic, msquic) by creating similar adapter crates.

## Testing

```bash
# Unit tests
cd pcr-quic
cargo test

# Integration tests
cd pcr-quic-quiche
cargo test --features integration-tests

# Benchmarks (requires network namespaces)
cd benchmarks/ftth
sudo ./run_all_tests.sh
```

## Performance Analysis

### With 0% Packet Loss
- Stock QUIC: ~135 Mbps
- Network fully saturates after slow start

### With 0.1% Packet Loss
- Stock QUIC: ~37 Mbps (27% of no-loss capacity)
- CUBIC congestion control responds conservatively to loss
- This is expected behavior per RFC 9002

### Expected PCR-QUIC Overhead
- Per-packet crypto operations: ~5-10% overhead
- Epoch rekeying: negligible (every 2 minutes)
- Memory: +64 bytes per direction for ratchet state

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Citation

If you use PCR-QUIC in academic work, please cite:

```bibtex
@inproceedings{pcr-quic-2026,
  title={PCR-QUIC: Per-Packet Cryptographic Ratcheting for QUIC},
  author={Alessandro Perez},
  year={2026}
}
```

## License

BSD-3-Clause - see [LICENSE](LICENSE)

## Acknowledgments

Based on [Cloudflare Quiche](https://github.com/cloudflare/quiche)
