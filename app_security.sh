#!/bin/bash

# Enable Gatekeeper
echo "Enabling Gatekeeper..."
sudo spctl --master-enable

# Verify Gatekeeper status
echo "Verifying Gatekeeper status..."
if spctl --status | grep -q "assessments enabled"; then
    echo "Gatekeeper successfully enabled!"
else
    echo "Error: Failed to enable Gatekeeper."
    exit 1
fi

# Check for Hardened Runtime (example: check a system app like Safari)
echo "Checking Hardened Runtime for Safari..."
if codesign -dv --verbose /Applications/Safari.app 2>&1 | grep -q "hardened"; then
    echo "Safari uses Hardened Runtime."
else
    echo "Warning: Safari does not use Hardened Runtime."
fi

# macOS 15.5: Additional Hardened Runtime checks (example placeholder)
echo "Performing additional Hardened Runtime checks for macOS 15.5..."
# Placeholder for macOS 15.5 Hardened Runtime verification commands

# Note: Hardened Runtime verification is informational; not all apps may support it
echo "Note: Some third-party apps may not use Hardened Runtime. Check critical apps manually."
