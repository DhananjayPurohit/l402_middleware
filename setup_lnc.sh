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
echo "Waiting for lndnode to auto-create wallet..."
# Wait for LND to be fully ready - check for both wallet creation and RPC availability
for i in {1..60}; do
  if docker exec lndnode lncli -n regtest getinfo > /dev/null 2>&1; then
    echo "✓ LND is ready and wallet is unlocked!"
    break
  fi
  if [ $i -eq 60 ]; then
    echo "Error: LND did not become ready in time"
    echo "Checking LND logs:"
    docker logs lndnode --tail 20
    exit 1
  fi
  sleep 2
done

echo "Waiting for litd to connect..."
sleep 5

echo ""
echo "=========================================="
echo "✓ Setup Complete!"
echo "=========================================="
echo ""
echo "Services running:"
echo "  • litd UI:      http://localhost:8081 (password: password123)"
echo "  • bitcoind RPC: localhost:18443"
echo "  • cln RPC:      localhost:9835"
echo ""
echo "Check lndnode status:"
echo "  docker exec lndnode lncli --network=regtest getinfo"
echo ""
echo "Check litd logs:"
echo "  docker logs litd"
echo ""
