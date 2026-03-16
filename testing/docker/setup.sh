#!/usr/bin/env bash
# Setup script for Vouch-Dirk integration testing
# Creates test wallet and account using ethdo

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WALLET_NAME="TestWallet"
ACCOUNT_NAME="Validator1"
PASSPHRASE="test-passphrase"
VOLUME_NAME="vouch_dirk-wallets"

echo "=== Vouch-Dirk Integration Test Setup ==="
echo ""

# Check for required tools
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is required but not installed."
        exit 1
    fi
}

check_command docker

echo "Step 1: Creating Docker volume for Dirk wallets..."
docker volume create "${VOLUME_NAME}" 2>/dev/null || echo "Volume already exists"

echo ""
echo "Step 2: Creating test wallet using ethdo..."
docker run --rm \
    -v "${VOLUME_NAME}:/data/wallets" \
    wealdtech/ethdo:latest \
    wallet create \
    --base-dir=/data/wallets \
    --wallet="${WALLET_NAME}" \
    --type=nd \
    --wallet-passphrase="${PASSPHRASE}" 2>/dev/null || echo "Wallet may already exist"

echo ""
echo "Step 3: Creating test account..."
docker run --rm \
    -v "${VOLUME_NAME}:/data/wallets" \
    wealdtech/ethdo:latest \
    account create \
    --base-dir=/data/wallets \
    --account="${WALLET_NAME}/${ACCOUNT_NAME}" \
    --passphrase="${PASSPHRASE}" \
    --wallet-passphrase="${PASSPHRASE}" 2>/dev/null || echo "Account may already exist"

echo ""
echo "Step 4: Verifying wallet creation..."
echo "Wallets:"
docker run --rm \
    -v "${VOLUME_NAME}:/data/wallets" \
    wealdtech/ethdo:latest \
    wallet list \
    --base-dir=/data/wallets

echo ""
echo "Accounts in ${WALLET_NAME}:"
docker run --rm \
    -v "${VOLUME_NAME}:/data/wallets" \
    wealdtech/ethdo:latest \
    wallet accounts \
    --base-dir=/data/wallets \
    --wallet="${WALLET_NAME}"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To run the integration test:"
echo "  cd ${SCRIPT_DIR}"
echo "  docker compose -f docker-compose.test.yml up --build"
echo ""
echo "To cleanup:"
echo "  docker compose -f docker-compose.test.yml down -v"
echo "  docker volume rm ${VOLUME_NAME}"
