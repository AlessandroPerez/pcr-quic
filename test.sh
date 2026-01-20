#!/bin/bash
# Unified test script for PCR-QUIC
# Usage: 
#   ./test.sh                    # Run all tests
#   ./test.sh --standalone       # Test standalone crypto crate only
#   ./test.sh --integration      # Test quiche integration only
#   ./test.sh --benchmark        # Run 1GB download benchmark

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
QUICHE_VANILLA="${QUICHE_PATH:-/home/ale/Documents/quiche}"
QUICHE_PCR="$SCRIPT_DIR/pcr-quiche"

# Suppress warnings during compilation
export RUSTFLAGS="-A warnings"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parse arguments
RUN_STANDALONE=false
RUN_INTEGRATION=false
RUN_BENCHMARK=false

if [ $# -eq 0 ]; then
    RUN_STANDALONE=true
    RUN_INTEGRATION=true
else
    for arg in "$@"; do
        case $arg in
            --standalone) RUN_STANDALONE=true ;;
            --integration) RUN_INTEGRATION=true ;;
            --benchmark) RUN_BENCHMARK=true ;;
            --all) RUN_STANDALONE=true; RUN_INTEGRATION=true; RUN_BENCHMARK=true ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  (no args)         Run standalone + integration tests"
                echo "  --standalone      Test standalone crypto crate only"
                echo "  --integration     Test quiche integration only"
                echo "  --benchmark       Run 1GB download benchmark"
                echo "  --all             Run all tests including benchmark"
                echo "  -h, --help        Show this help message"
                exit 0
                ;;
            *)
                echo "Unknown option: $arg"
                echo "Run with -h for help"
                exit 1
                ;;
        esac
    done
fi

# ============================================================================
# Test 1: Standalone Crypto Test
# ============================================================================
test_standalone() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Test 1: Standalone Crypto Crate${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo

    if [ ! -d "$QUICHE_PCR" ]; then
        echo -e "${RED}❌ Error: pcr-quiche not found at $QUICHE_PCR${NC}"
        echo "This should be the PCR-integrated quiche in the pcr-quic repo"
        return 1
    fi

    echo "QUICHE_PCR: $QUICHE_PCR"
    
    cd "$SCRIPT_DIR/examples"
    
    echo "Building basic_ratchet example..."
    cargo build --example basic_ratchet --quiet
    
    echo "Running basic_ratchet test..."
    cargo run --example basic_ratchet --quiet
    
    echo -e "${GREEN}✅ Standalone crypto test PASSED${NC}"
    echo
}

# ============================================================================
# Test 2: Integration Test
# ============================================================================
test_integration() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Test 2: Quiche Integration${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo

    SERVER_BIN="$QUICHE_PCR/target/release/quiche-server"
    CLIENT_BIN="$QUICHE_PCR/target/release/quiche-client"

    if [ ! -f "$SERVER_BIN" ] || [ ! -f "$CLIENT_BIN" ]; then
        echo -e "${YELLOW}⚠️  Binaries not found. Building with PCR-QUIC...${NC}"
        cd "$QUICHE_PCR"
        cargo build --release -p quiche_apps --features quiche/pcr-quic \
            --bin quiche-server --bin quiche-client --quiet
    fi

    echo "✅ Binaries ready"
    
    # Generate test certificates
    echo "Generating test certificates..."
    openssl req -x509 -newkey rsa:2048 -keyout /tmp/pcr_key.pem \
        -out /tmp/pcr_cert.pem -days 365 -nodes -subj "/CN=localhost" \
        2>/dev/null
    
    # Create test file
    echo "Hello from PCR-QUIC!" > /tmp/test.txt
    
    # Start server
    echo "Starting server..."
    "$SERVER_BIN" --listen 127.0.0.1:4433 \
        --cert /tmp/pcr_cert.pem --key /tmp/pcr_key.pem \
        --root /tmp > /tmp/pcr_server.log 2>&1 &
    SERVER_PID=$!
    sleep 2
    
    # Run client
    echo "Running client..."
    if "$CLIENT_BIN" --no-verify https://127.0.0.1:4433/test.txt \
        > /tmp/pcr_client_output.txt 2>&1; then
        
        if grep -q "Hello from PCR-QUIC!" /tmp/pcr_client_output.txt; then
            echo -e "${GREEN}✅ Integration test PASSED${NC}"
            INTEGRATION_SUCCESS=true
        else
            echo -e "${RED}❌ Client didn't receive correct data${NC}"
            INTEGRATION_SUCCESS=false
        fi
    else
        echo -e "${RED}❌ Client failed${NC}"
        cat /tmp/pcr_client_output.txt
        INTEGRATION_SUCCESS=false
    fi
    
    # Cleanup
    kill $SERVER_PID 2>/dev/null || true
    rm -f /tmp/pcr_*.pem /tmp/test.txt /tmp/pcr_*.log /tmp/pcr_client_output.txt
    
    echo
    [ "$INTEGRATION_SUCCESS" = true ] || return 1
}

# ============================================================================
# Test 3: Network Benchmark
# ============================================================================
test_benchmark() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Test 3: 1GB Download Benchmark${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo

    TEST_FILE="/tmp/test_1gb.bin"
    RESULTS_DIR="/tmp/quic_benchmark_results"
    VANILLA_SERVER="$QUICHE_VANILLA/target/release/quiche-server"
    VANILLA_CLIENT="$QUICHE_VANILLA/target/release/quiche-client"
    PCR_SERVER="$QUICHE_PCR/target/release/quiche-server"
    PCR_CLIENT="$QUICHE_PCR/target/release/quiche-client"

    # Create test file if needed
    if [ ! -f "$TEST_FILE" ]; then
        echo "Creating 1GB test file..."
        dd if=/dev/urandom of="$TEST_FILE" bs=1M count=1024 status=progress
    fi

    # Check if network namespaces are set up
    if ! sudo ip netns list 2>/dev/null | grep -q "server"; then
        echo -e "${YELLOW}Setting up network namespaces...${NC}"
        if [ -f "$QUICHE_VANILLA/quiche/examples/setup_netns_ftth_combined.sh" ]; then
            sudo "$QUICHE_VANILLA/quiche/examples/setup_netns_ftth_combined.sh"
        else
            echo -e "${RED}❌ Network setup script not found${NC}"
            return 1
        fi
    fi

    mkdir -p "$RESULTS_DIR"
    
    echo "Network: 1 Gbps, 20ms RTT, 0.1% loss"
    echo "Test file: 1GB"
    echo

    # Function to run one test
    run_test() {
        local variant=$1
        local server_bin=$2
        local client_bin=$3
        local log_prefix="${RESULTS_DIR}/${variant}"
        
        echo -e "${YELLOW}Testing ${variant}...${NC}"
        
        # Start server
        sudo ip netns exec server "$server_bin" \
            --listen 10.0.0.1:4433 \
            --cert "$QUICHE_VANILLA/apps/src/bin/cert.crt" \
            --key "$QUICHE_VANILLA/apps/src/bin/cert.key" \
            --root /tmp > "${log_prefix}_server.log" 2>&1 &
        
        local server_pid=$!
        sleep 2
        
        # Run client and measure time
        local start_time=$(date +%s.%N)
        
        sudo ip netns exec client "$client_bin" \
            --no-verify https://10.0.0.1:4433/test_1gb.bin \
            > "${log_prefix}_client.log" 2>&1
        
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc)
        
        # Stop server
        sudo kill $server_pid 2>/dev/null || true
        sleep 1
        
        # Calculate throughput
        local throughput_mbps=$(echo "scale=2; 8192 / $duration" | bc)
        
        echo "  Duration: ${duration}s"
        echo "  Throughput: ${throughput_mbps} Mbps"
        echo
        
        echo "${duration}" > "${RESULTS_DIR}/${variant}_time.txt"
    }

    # Build vanilla version (no PCR)
    echo "Building vanilla QUIC..."
    cd "$QUICHE_VANILLA"
    cargo build --release -p quiche_apps \
        --bin quiche-server --bin quiche-client --quiet
    
    run_test "vanilla" "$VANILLA_SERVER" "$VANILLA_CLIENT"
    
    # Build PCR version
    echo "Building PCR-QUIC..."
    cd "$QUICHE_PCR"
    cargo build --release -p quiche_apps --features quiche/pcr-quic \
        --bin quiche-server --bin quiche-client --quiet
    
    run_test "pcr" "$PCR_SERVER" "$PCR_CLIENT"
    
    # Summary
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}BENCHMARK RESULTS${NC}"
    echo -e "${GREEN}========================================${NC}"
    
    if [ -f "${RESULTS_DIR}/vanilla_time.txt" ] && [ -f "${RESULTS_DIR}/pcr_time.txt" ]; then
        vanilla_time=$(cat "${RESULTS_DIR}/vanilla_time.txt")
        pcr_time=$(cat "${RESULTS_DIR}/pcr_time.txt")
        vanilla_mbps=$(echo "scale=2; 8192 / $vanilla_time" | bc)
        pcr_mbps=$(echo "scale=2; 8192 / $pcr_time" | bc)
        overhead=$(echo "scale=2; (($pcr_time - $vanilla_time) / $vanilla_time) * 100" | bc)
        
        echo "Vanilla QUIC: ${vanilla_time}s (${vanilla_mbps} Mbps)"
        echo "PCR-QUIC:     ${pcr_time}s (${pcr_mbps} Mbps)"
        echo "Overhead:     ${overhead}%"
    fi
    echo
}

# ============================================================================
# Main Execution
# ============================================================================

echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   PCR-QUIC Test Suite             ║${NC}"
echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo

OVERALL_SUCCESS=true

if [ "$RUN_STANDALONE" = true ]; then
    test_standalone || OVERALL_SUCCESS=false
fi

if [ "$RUN_INTEGRATION" = true ]; then
    test_integration || OVERALL_SUCCESS=false
fi

if [ "$RUN_BENCHMARK" = true ]; then
    test_benchmark || OVERALL_SUCCESS=false
fi

# Final summary
echo -e "${GREEN}========================================${NC}"
if [ "$OVERALL_SUCCESS" = true ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    exit 1
fi
