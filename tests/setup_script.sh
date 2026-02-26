#!/bin/bash

# Use '--no-install-recommends' to skip heavy, unnecessary bloatware.
echo "Updating packages and installing dependencies..."
sudo apt update && sudo apt install -y --no-install-recommends wget tar gnupg2 curl git ca-certificates

# Create and enter the temporary working directory
echo "Creating temporary workspace..."
mkdir -p ./temp
cd ./temp || exit 1

# Dynamically fetch the latest version number
export VERSION=$(curl -s https://bitcoincore.org/en/download/ | grep -oP 'Latest version: \K[0-9.]+')
echo "Downloading Bitcoin Core v$VERSION..."

# Download ALL necessary files into ./temp
# Use '-q' (quiet) to stop wget from spamming the Docker build logs, speeding up CI/CD
wget -q https://bitcoincore.org/bin/bitcoin-core-${VERSION}/bitcoin-${VERSION}-x86_64-linux-gnu.tar.gz
wget -q https://bitcoincore.org/bin/bitcoin-core-${VERSION}/SHA256SUMS
wget -q https://bitcoincore.org/bin/bitcoin-core-${VERSION}/SHA256SUMS.asc

# Use '--depth 1' to perform a shallow clone.
# This skips years of git history and only downloads a few kilobytes of current keys.
echo "Cloning builder keys repository (Shallow Clone)..."
git clone --depth 1 -q https://github.com/bitcoin-core/guix.sigs
echo "Importing developer GPG keys..."
gpg --import guix.sigs/builder-keys/* 2>/dev/null

# SECURITY STEP 1: Verify the receipt is genuine (The GPG Check)
echo "Verifying developer signatures..."
COUNT=$(gpg --verify SHA256SUMS.asc SHA256SUMS 2>&1 | grep -c "Good signature")

if (( COUNT < 4 )); then
    echo "FATAL ERROR: Critical security threshold failed."
    echo "Only found $COUNT valid signatures, required: 4."
    echo "The checksum file cannot be trusted. STOPPING."
    cd ..
    rm -rf ./temp
    exit 1
else
    echo "SUCCESS: Strong multi-signature threshold met ($COUNT 'Good signatures')."
fi

# SECURITY STEP 2: Verify the binary matches the genuine receipt (The Hash Check)
echo "Verifying binary checksum..."
if sha256sum --ignore-missing --check SHA256SUMS --status; then
    echo "SUCCESS: The binary hash perfectly matches the signed receipt."
else
    echo "FATAL ERROR: Checksum mismatch! The downloaded file is corrupt or compromised."
    cd ..
    rm -rf ./temp
    exit 1
fi

# Extract and Install
echo "Verification passed. Installing Bitcoin Core..."
tar -xf bitcoin-${VERSION}-x86_64-linux-gnu.tar.gz
sudo install -m 0755 -t /usr/local/bin bitcoin-${VERSION}/bin/*

# Clean up the temporary workspace
echo "Cleaning up temporary files..."
cd ..
rm -rf ./temp

echo "Installation Complete! You can now run 'bitcoind -daemon'."
