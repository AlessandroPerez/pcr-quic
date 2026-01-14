# PCR-QUIC: Per-Packet Cryptographic Ratcheting for QUIC

[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)

PCR-QUIC implements a double-ratchet mechanism for QUIC providing:
- **Forward Secrecy (FS)**: Per-packet nonce ratchet
- **Post-Compromise Security (PCS)**: KEM-based epoch rekeying
- **Precise Key Deletion**: Keys zeroized after use

## Repository Structure

```
pcr-quic/
├── pcr-quic/              # Core PCR-QUIC library (standalone)
│   ├── src/
│   │   ├── ratchet.rs     # Symmetric ratchet implementation
│   │   ├── keys.rs        # Epoch key derivation
│   │   ├── context.rs     # Epoch management
│   │   ├── params.rs      # Transport parameters
│   │   └── frame.rs       # Frame encoding/decoding
│   └── Cargo.toml
├── pcr-quic-quiche/       # Quiche integration adapter
│   ├── src/
│   │   └── integration.rs
│   └── Cargo.toml
├── benchmarks/            # Performance benchmarks
│   ├── ftth/              # FTTH network simulation tests
│   │   ├── setup.sh       # Network namespace setup
│   │   └── run_tests.sh   # Automated test runner
│   └── results/           # Benchmark results
└── README.md
```

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
sudo apt-get install build-essential cmake pkg-config

# For network namespace tests (Linux only)
sudo apt-get install iproute2 iptables bc
```

### Building

```bash
# Build PCR-QUIC library
cd pcr-quic
cargo build --release

# Build with quiche integration
cd ../pcr-quic-quiche
cargo build --release
```

### Running Benchmarks

```bash
cd benchmarks/ftth

# Run baseline (stock QUIC)
./run_tests.sh baseline

# Run PCR-QUIC tests
./run_tests.sh pcr-quic

# Compare results
./compare_results.sh
```

## Reproducing Results

### 1. Baseline Stock QUIC Test

```bash
# Setup simulated FTTH network (requires root)
cd benchmarks/ftth
sudo ./setup_network.sh

# Run stock quiche server/client
cd /path/to/quiche
cargo build --release --bin quiche-server --bin quiche-client

# In one terminal (server namespace)
sudo ip netns exec server ./target/release/quiche-server \
  --listen 10.0.0.1:4433 \
  --cert apps/src/bin/cert.crt \
  --key apps/src/bin/cert.key \
  --root apps/src/bin/root

# In another terminal (client namespace)
sudo ip netns exec client ./target/release/quiche-client \
  --no-verify \
  https://10.0.0.1:4433/1gb.bin \
  --dump-responses /tmp/results
```

Expected result: ~37 Mbps throughput for 1GB transfer

### 2. PCR-QUIC Test

```bash
# Build quiche with PCR-QUIC feature
cd /path/to/quiche
cargo build --release --features pcr-quic --bin quiche-server --bin quiche-client

# Run with same network setup
# (same commands as above)
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
  author={Your Name},
  year={2026}
}
```

## License

BSD-3-Clause - see [LICENSE](LICENSE)

## Acknowledgments

Based on [Cloudflare Quiche](https://github.com/cloudflare/quiche)
