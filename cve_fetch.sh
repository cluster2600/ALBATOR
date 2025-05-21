#!/bin/bash

# Check for required tools
if ! command -v curl &> /dev/null; then
    echo "Error: curl is required but not installed."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed. Install it with 'brew install jq' on macOS."
    exit 1
fi

if ! command -v pup &> /dev/null; then
    echo "Error: pup is required but not installed. Install it with 'brew install pup' on macOS."
    exit 1
fi

# Function to scrape Apple's security updates page
scrape_security_page() {
    local url="https://support.apple.com/en-gb/100100"
    echo "Fetching macOS security updates from $url..."
    response=$(curl -s -L --retry 3 --retry-delay 5 \
        -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15" \
        "$url")

    if [ -z "$response" ]; then
        echo "Error: Failed to fetch security updates page from $url."
        exit 1
    fi

    # Use pup to extract table rows from the security updates table
    macos_updates=$(echo "$response" | \
        pup 'table tbody tr json{}' | \
        jq -r '
            # Function to get all text from a node and its children
            def get_text:
                if .type == "text" then .text
                elif .children then (.children | map(get_text) | join(""))
                else ""
                end;
            # Filter for rows with a link in the first column and macOS in the second column
            .[] | 
            select(
                (.children | length >= 2) and
                (.children[0].children[0].tag == "a") and
                (.children[1] | get_text | test("macOS"; "i"))
            ) | 
            "Title: \(.children[0].children[0].text)\nLink: https://support.apple.com\(.children[0].children[0].href)\n---"
        ' 2>/dev/null)

    # Output results
    if [ -n "$macos_updates" ]; then
        echo -e "Found recent macOS security updates:\n"
        echo "$macos_updates"
    else
        echo "No recent macOS security updates found on $url or parsing failed."
        echo "Dumping raw HTML to debug.html and table JSON to debug_table.json for troubleshooting..."
        echo "$response" > debug.html
        echo "$response" | pup 'table tbody tr json{}' > debug_table.json
        echo "Check debug.html (search for 'macOS') and debug_table.json to verify structure."
    fi
}

# Run the scraper
scrape_security_page

# macOS 15.5: Additional parsing or filtering for CVE data (example placeholder)
echo "Processing CVE data for macOS 15.5..."
# Placeholder for macOS 15.5 CVE parsing and filtering logic
