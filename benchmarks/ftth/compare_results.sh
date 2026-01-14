#!/bin/bash
# Compare benchmark results between baseline and PCR-QUIC

RESULTS_DIR="$(pwd)/results"

if [ ! -d "$RESULTS_DIR" ]; then
    echo "No results directory found. Run ./run_tests.sh first."
    exit 1
fi

echo "=== PCR-QUIC Benchmark Results Comparison ==="
echo ""

# Function to extract throughput from JSON
get_throughput() {
    local pattern=$1
    local files=$(ls "$RESULTS_DIR"/${pattern}*.json 2>/dev/null)
    local total=0
    local count=0
    
    for file in $files; do
        mbps=$(jq -r '.throughput_mbps' "$file" 2>/dev/null)
        if [ ! -z "$mbps" ] && [ "$mbps" != "null" ]; then
            total=$(echo "$total + $mbps" | bc)
            count=$((count + 1))
        fi
    done
    
    if [ $count -gt 0 ]; then
        echo "scale=2; $total / $count" | bc
    else
        echo "N/A"
    fi
}

BASELINE_AVG=$(get_throughput "baseline")
PCR_AVG=$(get_throughput "pcr-quic")

echo "Baseline (Stock QUIC):"
echo "  Average Throughput: ${BASELINE_AVG} Mbps"
echo ""

echo "PCR-QUIC:"
echo "  Average Throughput: ${PCR_AVG} Mbps"
echo ""

if [ "$BASELINE_AVG" != "N/A" ] && [ "$PCR_AVG" != "N/A" ]; then
    OVERHEAD=$(echo "scale=2; (($BASELINE_AVG - $PCR_AVG) / $BASELINE_AVG) * 100" | bc)
    echo "Performance Impact:"
    echo "  Overhead: ${OVERHEAD}%"
fi

echo ""
echo "Detailed results available in: $RESULTS_DIR"
