#!/bin/bash

# Test script for Albator security hardening

echo "Starting Albator security tests..."

# Test privacy.sh
echo "Testing privacy.sh..."
bash ./privacy.sh

# Test firewall.sh
echo "Testing firewall.sh..."
bash ./firewall.sh

# Test encryption.sh
echo "Testing encryption.sh..."
bash ./encryption.sh

# Test app_security.sh
echo "Testing app_security.sh..."
bash ./app_security.sh

# Test cve_fetch.sh
echo "Testing cve_fetch.sh..."
bash ./cve_fetch.sh

# Test apple_updates.sh
echo "Testing apple_updates.sh..."
bash ./apple_updates.sh

echo "All tests executed. Please review output for any errors."
