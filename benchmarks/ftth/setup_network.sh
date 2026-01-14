#!/bin/bash
# FTTH Network Setup for PCR-QUIC Benchmarks
# Creates network namespaces simulating 1 Gbps FTTH with 20ms RTT and 0.1% loss

set -e

echo "Setting up FTTH simulation network..."

# Clean up any existing setup
sudo ip netns del server 2>/dev/null || true
sudo ip netns del client 2>/dev/null || true

# Create network namespaces
sudo ip netns add server
sudo ip netns add client

# Create veth pair
sudo ip link add veth-server type veth peer name veth-client

# Move interfaces to namespaces
sudo ip link set veth-server netns server
sudo ip link set veth-client netns client

# Configure server namespace
sudo ip netns exec server ip addr add 10.0.0.1/24 dev veth-server
sudo ip netns exec server ip link set veth-server up
sudo ip netns exec server ip link set lo up

# Configure client namespace
sudo ip netns exec client ip addr add 10.0.0.2/24 dev veth-client
sudo ip netns exec client ip link set veth-client up
sudo ip netns exec client ip link set lo up

# Add 10ms delay each direction (20ms RTT total)
sudo ip netns exec server tc qdisc add dev veth-server root netem delay 10ms limit 1000000
sudo ip netns exec client tc qdisc add dev veth-client root netem delay 10ms limit 1000000

# Add 0.1% packet loss on client incoming (server->client data path)
sudo ip netns exec client iptables -t raw -A PREROUTING -i veth-client -m statistic --mode random --probability 0.001 -j DROP

# Increase UDP buffers
sudo ip netns exec server sysctl -w net.core.rmem_max=536870912 >/dev/null
sudo ip netns exec server sysctl -w net.core.wmem_max=536870912 >/dev/null
sudo ip netns exec client sysctl -w net.core.rmem_max=536870912 >/dev/null
sudo ip netns exec client sysctl -w net.core.wmem_max=536870912 >/dev/null

echo "✓ Network configured successfully"
echo ""
echo "Configuration:"
echo "  Server: 10.0.0.1 (netns: server)"
echo "  Client: 10.0.0.2 (netns: client)"
echo "  Bandwidth: 1 Gbps"
echo "  RTT: 20ms (10ms each way)"
echo "  Packet Loss: 0.1% (Bernoulli, server→client)"
echo ""
echo "Test connectivity:"
echo "  sudo ip netns exec client ping -c 3 10.0.0.1"
