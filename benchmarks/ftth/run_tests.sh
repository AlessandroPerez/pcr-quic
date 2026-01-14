#!/bin/bash
# Automated benchmark runner for PCR-QUIC vs Stock QUIC
# Usage: ./run_tests.sh [baseline|pcr-quic|both]

set -e

# Default quiche path: assumes quiche is cloned as sibling directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
QUICHE_PATH="${QUICHE_PATH:-$(cd "$REPO_ROOT/../quiche" 2>/dev/null && pwd || echo "")}"

# Validate quiche path
if [ -z "$QUICHE_PATH" ] || [ ! -d "$QUICHE_PATH" ]; then
    echo "ERROR: quiche directory not found!"
    echo "Expected location: $REPO_ROOT/../quiche"
    echo "Or set QUICHE_PATH environment variable: export QUICHE_PATH=/path/to/quiche"
    exit 1
fi

RESULTS_DIR="$SCRIPT_DIR/results"
TEST_FILE_SIZE="1073741824"  # 1 GB
NUM_RUNS=3
ROOT_DIR="$QUICHE_PATH/apps/src/bin/root"
CERT_PATH="$QUICHE_PATH/apps/src/bin/cert.crt"
KEY_PATH="$QUICHE_PATH/apps/src/bin/cert.key"

# Simple logging without color codes (to avoid bc errors)
log_info() {
    echo "[INFO] $1"
}

log_warn() {
    echo "[WARN] $1"
}

log_error() {
    echo "[ERROR] $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (sudo)"
    exit 1
fi

# Create results directory
mkdir -p "$RESULTS_DIR"
mkdir -p /tmp/pcr_quic_test

# Create 1GB test file if it doesn't exist
if [ ! -f "$ROOT_DIR/1gb.bin" ]; then
    log_info "Creating 1GB test file..."
    mkdir -p "$ROOT_DIR"
    dd if=/dev/zero of="$ROOT_DIR/1gb.bin" bs=1M count=1024 2>/dev/null
fi

# Setup network
log_info "Setting up network namespaces..."
./setup_network.sh

run_test() {
    local test_name=$1
    local features=$2
    local run_number=$3
    
    log_info "Running test: $test_name (run $run_number/$NUM_RUNS)"
    
    # Build quiche
    cd "$QUICHE_PATH"
    if [ -z "$features" ]; then
        log_info "Building stock quiche..."
        cargo build --release --bin quiche-server --bin quiche-client 2>&1 | grep -E "(Finished|error)" || true
    else
        log_info "Building quiche with features: $features..."
        cargo build --release --features "$features" --bin quiche-server --bin quiche-client 2>&1 | grep -E "(Finished|error)" || true
    fi
    
    # Clean previous test file
    rm -f /tmp/pcr_quic_test/1gb.bin
    
    # Start server in background
    log_info "Starting server..."
    ip netns exec server "$QUICHE_PATH/target/release/quiche-server" \
        --listen 10.0.0.1:4433 \
        --cert "$CERT_PATH" \
        --key "$KEY_PATH" \
        --root "$ROOT_DIR" \
        >/dev/null 2>&1 &
    
    SERVER_PID=$!
    sleep 2
    
    # Run client and measure
    log_info "Starting download..."
    START=$(date +%s)
    
    ip netns exec client "$QUICHE_PATH/target/release/quiche-client" \
        --no-verify \
        https://10.0.0.1:4433/1gb.bin \
        --dump-responses /tmp/pcr_quic_test \
        2>&1 | tee /tmp/client_output.log || true
    
    END=$(date +%s)
    
    # Kill server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    
    # Calculate results
    ELAPSED=$((END - START))
    SIZE=$(stat -c%s /tmp/pcr_quic_test/1gb.bin 2>/dev/null || echo 0)
    
    if [ "$SIZE" -gt 0 ]; then
        MBPS=$(echo "scale=2; ($SIZE * 8) / ($ELAPSED * 1000000)" | bc)
        log_info "Test complete: ${MBPS} Mbps (${ELAPSED}s, ${SIZE} bytes)"
        
        # Save results
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        RESULT_FILE="$RESULTS_DIR/${test_name}_run${run_number}_${TIMESTAMP}.json"
        cat > "$RESULT_FILE" <<EOF
{
  "test_name": "$test_name",
  "run_number": $run_number,
  "timestamp": "$(date -Iseconds)",
  "duration_seconds": $ELAPSED,
  "bytes_transferred": $SIZE,
  "throughput_mbps": $MBPS,
  "features": "$features",
  "network": {
    "bandwidth": "1 Gbps",
    "rtt_ms": 20,
    "packet_loss": "0.1%"
  }
}
EOF
        
        echo "$MBPS"
    else
        log_error "Download failed - no data received"
        echo "0"
    fi
}

# Run baseline tests
if [ "$1" == "baseline" ] || [ "$1" == "both" ] || [ -z "$1" ]; then
    log_info "=== Running Baseline (Stock QUIC) Tests ==="
    BASELINE_RESULTS=()
    for i in $(seq 1 $NUM_RUNS); do
        result=$(run_test "baseline" "" "$i")
        BASELINE_RESULTS+=("$result")
    done
    
    # Calculate average
    TOTAL=0
    for result in "${BASELINE_RESULTS[@]}"; do
        TOTAL=$(echo "$TOTAL + $result" | bc)
    done
    AVG=$(echo "scale=2; $TOTAL / ${#BASELINE_RESULTS[@]}" | bc)
    log_info "Baseline average: ${AVG} Mbps"
fi

# Run PCR-QUIC tests
if [ "$1" == "pcr-quic" ] || [ "$1" == "both" ]; then
    log_info "=== Running PCR-QUIC Tests ==="
    PCR_RESULTS=()
    for i in $(seq 1 $NUM_RUNS); do
        result=$(run_test "pcr-quic" "pcr-quic" "$i")
        PCR_RESULTS+=("$result")
    done
    
    # Calculate average
    TOTAL=0
    for result in "${PCR_RESULTS[@]}"; do
        TOTAL=$(echo "$TOTAL + $result" | bc)
    done
    AVG=$(echo "scale=2; $TOTAL / ${#PCR_RESULTS[@]}" | bc)
    log_info "PCR-QUIC average: ${AVG} Mbps"
fi

log_info "All tests complete. Results saved to: $RESULTS_DIR"
log_info "To compare results, run: ./compare_results.sh"
