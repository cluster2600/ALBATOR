#!/bin/bash

# Check for required tools
if ! command -v curl &> /dev/null; then
    echo "Error: curl is required but not installed."
    exit 1
fi

# Check for pup (preferred) or fallback to grep/awk
USE_PUP=false
if command -v pup &> /dev/null; then
    USE_PUP=true
    echo "Using pup for HTML parsing..."
else
    echo "Warning: pup not found. Falling back to grep/awk (less reliable). Install pup with 'brew install pup' for better results."
fi

# Apple Security Updates URL
APPLE_URL="https://support.apple.com/en-us/HT201222"

# Fetch the HTML content
echo "Fetching Apple security updates from $APPLE_URL..."
response=$(curl -s "$APPLE_URL")

# Check if the request was successful
if [ -z "$response" ]; then
    echo "Error: Failed to fetch Apple security updates."
    exit 1
fi

# Parse updates for macOS Sequoia 15 and 15.5 (added 15.5 support)
echo "Parsing updates for macOS Sequoia 15 and 15.5..."
if [ "$USE_PUP" = true ]; then
    # Use pup to extract update entries
    updates=$(echo "$response" | pup 'table tbody tr json{}' | jq -r '
        .[] | 
        select(.children[] | .text | test("macOS Sequoia 15(\\.5)?")) | 
        "Date: \(.children[0].text)\nProduct: \(.children[1].text)\nLink: https://support.apple.com\(.children[1].children[0].href)\n---"
    ')
else
    # Fallback to grep/awk (less precise, matches table rows with "macOS Sequoia 15" or "15.5")
    updates=$(echo "$response" | grep -E -A 2 "macOS Sequoia 15(\.5)?" | awk '
        /<td>/ {
            gsub(/<[^>]+>/, "", $0)
            if (NR % 3 == 1) { date=$0 }
            if (NR % 3 == 2) { product=$0 }
        }
        /href=/ {
            match($0, /href="([^"]+)"/, arr)
            link="https://support.apple.com" arr[1]
            print "Date: " date "\nProduct: " product "\nLink: " link "\n---"
        }
    ')
fi

# Display results
if [ -z "$updates" ]; then
    echo "No recent macOS Sequoia 15 or 15.5 updates found."
else
    echo -e "Found macOS Sequoia 15 and 15.5 updates:\n"
    echo "$updates"
fi

# Note about detailed CVE information
echo "Note: To view detailed CVE information, visit the links above for each update."
