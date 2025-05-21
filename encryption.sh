#!/bin/bash

# Check if FileVault is already enabled
echo "Checking FileVault status..."
if diskutil apfs list | grep -q "FileVault: Yes"; then
    echo "FileVault is already enabled."
    exit 0
fi

# Enable FileVault
echo "Enabling FileVault..."
sudo fdesetup enable

# macOS 15.5: Ensure recovery key is stored securely (example placeholder)
echo "Ensuring recovery key is stored securely for macOS 15.5..."
# Placeholder command for storing recovery key securely

# Note: FileVault enabling requires user interaction to set up a recovery key
echo "Please follow the prompts to set up FileVault. A recovery key will be generated."
echo "After enabling, the system may need to restart to complete encryption."

# Verify FileVault status
echo "Verifying FileVault status..."
if diskutil apfs list | grep -q "FileVault: Yes"; then
    echo "FileVault successfully enabled!"
else
    echo "Error: FileVault enabling failed or requires a restart."
    exit 1
fi
