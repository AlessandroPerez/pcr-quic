#!/bin/bash
#
# Test script for PCR-QUIC standalone crate
# Validates that the crate compiles and runs basic_ratchet example
#

set -e

# Check for QUICHE_PATH environment variable
if [ -z "$QUICHE_PATH" ]; then
    echo "Error: QUICHE_PATH environment variable must be set"
    echo "Example: export QUICHE_PATH=\$(pwd)/../quiche"
    exit 1
fi

echo "Testing PCR-QUIC standalone crate..."
echo "QUICHE_PATH: $QUICHE_PATH"
echo

# Run in examples directory
cd examples

# Clean previous build
echo "Cleaning previous build..."
cargo clean

# Build the example
echo "Building basic_ratchet example..."
cargo build --example basic_ratchet

# Run the example
echo
echo "Running basic_ratchet example..."
echo "================================"
cargo run --example basic_ratchet

echo
echo "================================"
echo "✓ Test completed successfully"
