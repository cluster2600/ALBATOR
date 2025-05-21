#!/bin/bash

# Check if the firewall is already enabled
if sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -q "enabled"; then
    echo "Firewall is already enabled."
else
    # Enable the firewall
    echo "Enabling Application Layer Firewall..."
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
fi

# Block all incoming connections except those explicitly allowed
echo "Blocking all incoming connections..."
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on

# Enable stealth mode (don't respond to pings)
echo "Enabling stealth mode..."
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# Enable logging
echo "Enabling firewall logging..."
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on

# Verify firewall status
echo "Verifying firewall status..."
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode

# Log any errors
log_file="/var/log/firewall_setup.log"
exec 2>>"$log_file" # Redirect stderr to log file
