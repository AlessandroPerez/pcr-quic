#!/bin/bash
# Test script for PCR-QUIC enabled quiche client/server

set -e

QUICHE_DIR="../quiche"
SERVER_BIN="$QUICHE_DIR/target/release/quiche-server"
CLIENT_BIN="$QUICHE_DIR/target/release/quiche-client"

echo "PCR-QUIC Integration Test"
echo "========================="
echo

# Check binaries exist
if [ ! -f "$SERVER_BIN" ] || [ ! -f "$CLIENT_BIN" ]; then
    echo "❌ Error: quiche binaries not found"
    echo "   Run: cd ../quiche && cargo build --release --features pcr-quic --bin quiche-server --bin quiche-client"
    exit 1
fi

echo "✅ Binaries found:"
ls -lh "$SERVER_BIN" "$CLIENT_BIN"
echo

# Generate test certificates
echo "📜 Generating test certificates..."
openssl req -x509 -newkey rsa:2048 -keyout /tmp/pcr_key.pem \
    -out /tmp/pcr_cert.pem -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
echo "✅ Certificates created"
echo

# Create test content
mkdir -p /tmp/pcr_test_root
echo "Hello from PCR-QUIC! This message was encrypted with post-quantum forward secrecy." > /tmp/pcr_test_root/test.txt
echo "✅ Test content created: /tmp/pcr_test_root/test.txt"
echo

# Start server in background
echo "🚀 Starting quiche-server with PCR-QUIC support..."
$SERVER_BIN --listen 127.0.0.1:4433 \
    --root /tmp/pcr_test_root \
    --cert /tmp/pcr_cert.pem \
    --key /tmp/pcr_key.pem &
SERVER_PID=$!
echo "   Server PID: $SERVER_PID"
sleep 2

# Test with client
echo
echo "📡 Testing client connection..."
if timeout 10 $CLIENT_BIN --no-verify https://127.0.0.1:4433/test.txt > /tmp/pcr_output.txt 2>&1; then
    echo "✅ Client connected successfully!"
    echo
    echo "📄 Received content:"
    cat /tmp/pcr_output.txt
else
    echo "❌ Client connection failed"
    cat /tmp/pcr_output.txt
fi

# Cleanup
echo
echo "🧹 Cleaning up..."
kill $SERVER_PID 2>/dev/null || true
rm -f /tmp/pcr_cert.pem /tmp/pcr_key.pem
rm -rf /tmp/pcr_test_root /tmp/pcr_output.txt

echo
echo "✅ Test complete!"
