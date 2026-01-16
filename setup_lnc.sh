#!/bin/bash

# setup_lnc.sh - Restart containers and verify setup
set -e

echo "=========================================="
echo "LNC Setup: Restart & Configure"
echo "=========================================="

# Step 1: Stop and remove everything
echo "[1/4] Stopping containers and removing volumes..."
docker-compose down -v

# Step 2: Start containers
echo "[2/4] Starting containers..."
docker-compose up -d

# Step 3: Wait for bitcoind
echo "[3/4] Waiting for bitcoind..."
sleep 15

# Step 4: Create wallet and mine blocks
echo "[4/4] Creating bitcoind wallet and mining 101 blocks..."
docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass createwallet "default" 2>/dev/null || true
ADDR=$(docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass getnewaddress)
docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass generatetoaddress 101 "$ADDR" > /dev/null

echo ""
echo "Waiting for lndnode to auto-create wallet and litd to connect..."
sleep 15

echo ""
echo "=========================================="
echo "✓ Setup Complete!"
echo "=========================================="
echo ""
echo "Services running:"
echo "  • litd UI:      https://localhost:8443 (password: password123)"
echo "  • hashmail:     http://localhost:8085"
echo "  • bitcoind RPC: localhost:18443"
echo "  • cln RPC:      localhost:9835"
echo ""
echo "Check lndnode status:"
echo "  docker exec lndnode lncli --network=regtest getinfo"
echo ""
echo "Check litd logs:"
echo "  docker logs litd"
echo ""
