#!/bin/bash

# Albator Apple Security Updates Script
# Enhanced with caching, error handling, and offline support

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCRIPT_NAME="apple_updates.sh"
LOG_FILE="/tmp/albator_apple_updates.log"
CACHE_DIR="${HOME}/.albator/cache/apple_updates"
CACHE_FILE="$CACHE_DIR/apple_updates_cache.json"
CACHE_EXPIRY=21600  # 6 hours in seconds
DRY_RUN=${DRY_RUN:-false}
OFFLINE_MODE=${OFFLINE_MODE:-false}
VERBOSE=${VERBOSE:-false}

# Apple Security Updates URL
APPLE_URL="https://support.apple.com/en-us/HT201222"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Source common utilities
source "$(dirname "$0")"/utils.sh

# Function to check required tools
check_requirements() {
    show_progress "Checking requirements..."
    
    # Check for curl
    if ! command -v curl &> /dev/null; then
        show_error "curl is required but not installed."
        echo "Install with: brew install curl"
        exit 1
    fi
    
    # Check for jq
    if ! command -v jq &> /dev/null; then
        show_error "jq is required but not installed."
        echo "Install with: brew install jq"
        exit 1
    fi
    
    # Check for pup (preferred) or fallback to grep/awk
    USE_PUP=false
    if command -v pup &> /dev/null; then
        USE_PUP=true
        show_success "Using pup for HTML parsing"
    else
        show_warning "pup not found. Falling back to grep/awk (less reliable)"
        echo "Install pup with: brew install pup"
    fi
}

# Function to setup cache directory
setup_cache() {
    if [[ ! -d "$CACHE_DIR" ]]; then
        mkdir -p "$CACHE_DIR"
        log "INFO" "Created cache directory: $CACHE_DIR"
    fi
}

# Function to check if cache is valid
is_cache_valid() {
    if [[ ! -f "$CACHE_FILE" ]]; then
        return 1
    fi
    
    local cache_age=$(($(date +%s) - $(stat -f %m "$CACHE_FILE" 2>/dev/null || echo 0)))
    
    if [[ $cache_age -lt $CACHE_EXPIRY ]]; then
        return 0
    else
        return 1
    fi
}

# Function to read from cache
read_cache() {
    if [[ -f "$CACHE_FILE" ]]; then
        cat "$CACHE_FILE"
    else
        echo "{}"
    fi
}

# Function to write to cache
write_cache() {
    local data=$1
    echo "$data" > "$CACHE_FILE"
    log "INFO" "Cache updated at $(date)"
}

# Function to clean old cache files
clean_cache() {
    local days=${1:-7}
    if [[ -d "$CACHE_DIR" ]]; then
        find "$CACHE_DIR" -type f -mtime +$days -delete 2>/dev/null || true
        log "INFO" "Cleaned cache files older than $days days"
    fi
}

# Function to fetch updates from Apple
fetch_apple_updates() {
    show_progress "Fetching Apple security updates..."
    
    local response
    local http_status
    
    # Use curl with timeout and retry logic
    response=$(curl -s -w "\n%{http_code}" --connect-timeout 10 --max-time 30 \
        -H "User-Agent: Albator/3.0 Security Scanner" \
        "$APPLE_URL" 2>/dev/null || echo "CURL_ERROR")
    
    # Extract HTTP status code
    http_status=$(echo "$response" | tail -n1)
    response=$(echo "$response" | sed '$d')
    
    if [[ "$response" == "CURL_ERROR" ]] || [[ -z "$response" ]]; then
        show_error "Failed to fetch Apple security updates"
        return 1
    fi
    
    if [[ "$http_status" != "200" ]]; then
        show_error "HTTP error: $http_status"
        return 1
    fi
    
    echo "$response"
}

# Function to parse updates
parse_updates() {
    local html_content=$1
    local updates_json="{\"updates\": [], \"metadata\": {}}"
    
    show_progress "Parsing updates for macOS Sequoia 15.x..."
    
    if [[ "$USE_PUP" == "true" ]]; then
        # Use pup to extract update entries
        local parsed_updates
        parsed_updates=$(echo "$html_content" | pup 'table tbody tr json{}' 2>/dev/null | jq -r '
            .[] | 
            select(.children[] | .text | test("macOS (Sequoia )?15(\\.\\d+)?")) | 
            {
                date: .children[0].text,
                product: .children[1].text,
                link: ("https://support.apple.com" + (.children[1].children[0].href // ""))
            }
        ' 2>/dev/null || echo "")
        
        # Convert to JSON array
        if [[ -n "$parsed_updates" ]]; then
            updates_json=$(echo "$parsed_updates" | jq -s '{
                updates: .,
                metadata: {
                    source: "Apple Security Updates",
                    url: "'$APPLE_URL'",
                    fetched_at: "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"
                }
            }')
        fi
    else
        # Fallback to grep/awk parsing
        local temp_file=$(mktemp)
        echo "$html_content" | grep -E -A 3 -B 1 "macOS (Sequoia )?15(\\.\\d+)?" > "$temp_file" 2>/dev/null || true
        
        # Basic parsing with awk
        local updates_text=""
        while IFS= read -r line; do
            if [[ "$line" =~ \<td\> ]]; then
                updates_text+=$(echo "$line" | sed 's/<[^>]*>//g' | xargs)
                updates_text+="|"
            fi
        done < "$temp_file"
        
        rm -f "$temp_file"
        
        # Create basic JSON structure
        if [[ -n "$updates_text" ]]; then
            updates_json=$(echo '{
                "updates": [{
                    "date": "Check website",
                    "product": "macOS Sequoia 15.x updates available",
                    "link": "'$APPLE_URL'"
                }],
                "metadata": {
                    "source": "Apple Security Updates",
                    "url": "'$APPLE_URL'",
                    "fetched_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
                    "parsing_method": "fallback"
                }
            }')
        fi
    fi
    
    echo "$updates_json"
}

# Function to display updates
display_updates() {
    local updates_json=$1
    local update_count=$(echo "$updates_json" | jq -r '.updates | length')
    
    echo ""
    echo "🍎 Apple Security Updates for macOS Sequoia 15.x"
    echo "================================================"
    
    if [[ "$update_count" -eq 0 ]]; then
        show_warning "No recent macOS Sequoia 15.x updates found"
        return
    fi
    
    show_success "Found $update_count update(s)"
    echo ""
    
    # Display each update
    echo "$updates_json" | jq -r '.updates[] | 
        "📅 Date: \(.date)\n📦 Product: \(.product)\n🔗 Link: \(.link)\n" + 
        "─────────────────────────────────────────────────"'
    
    # Display metadata
    if [[ "$VERBOSE" == "true" ]]; then
        echo ""
        echo "Metadata:"
        echo "$updates_json" | jq -r '.metadata | to_entries[] | "  \(.key): \(.value)"'
    fi
}

# Function to generate summary report
generate_summary() {
    local updates_json=$1
    local summary_file="${CACHE_DIR}/apple_updates_summary_$(date +%Y%m%d_%H%M%S).json"
    
    show_progress "Generating summary report..."
    
    # Create enhanced summary
    local summary=$(echo "$updates_json" | jq '{
        summary: {
            total_updates: (.updates | length),
            latest_update: (.updates[0] // null),
            report_date: "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
            macos_version: "15.x (Sequoia)",
            cache_status: "'$(is_cache_valid && echo "valid" || echo "refreshed")'"
        },
        updates: .updates,
        metadata: .metadata
    }')
    
    # Save summary
    echo "$summary" > "$summary_file"
    show_success "Summary saved to: $summary_file"
    
    # Display summary stats
    echo ""
    echo "📊 Summary Statistics:"
    echo "$summary" | jq -r '.summary | to_entries[] | "  \(.key): \(.value)"'
}

# Main execution
main() {
    echo "Albator Apple Security Updates Scanner"
    echo "======================================"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --offline)
                OFFLINE_MODE=true
                show_warning "Running in offline mode"
                shift
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --clean-cache)
                clean_cache 7
                show_success "Cache cleaned"
                exit 0
                ;;
            --help|-h)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --offline       Use cached data only"
                echo "  --verbose, -v   Enable verbose output"
                echo "  --clean-cache   Clean old cache files"
                echo "  --help, -h      Show this help message"
                exit 0
                ;;
            *)
                show_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Initialize
    mkdir -p "$(dirname "$LOG_FILE")"
    log "INFO" "Starting Apple security updates scan"
    
    # Check requirements
    check_requirements
    
    # Setup cache
    setup_cache
    
    # Clean old cache files
    clean_cache 30
    
    local updates_json=""
    
    # Check cache or fetch new data
    if [[ "$OFFLINE_MODE" == "true" ]]; then
        show_progress "Running in offline mode, using cached data..."
        if is_cache_valid; then
            updates_json=$(read_cache)
            show_success "Using cached data"
        else
            show_error "No valid cache available in offline mode"
            exit 1
        fi
    else
        # Check cache first
        if is_cache_valid; then
            show_progress "Using cached data (expires in $((CACHE_EXPIRY/3600)) hours)..."
            updates_json=$(read_cache)
        else
            # Fetch fresh data
            local html_content
            if html_content=$(fetch_apple_updates); then
                updates_json=$(parse_updates "$html_content")
                write_cache "$updates_json"
                show_success "Data fetched and cached successfully"
            else
                # Try to use stale cache if available
                if [[ -f "$CACHE_FILE" ]]; then
                    show_warning "Using stale cache due to fetch failure"
                    updates_json=$(read_cache)
                else
                    show_error "No data available"
                    exit 1
                fi
            fi
        fi
    fi
    
    # Display updates
    display_updates "$updates_json"
    
    # Generate summary
    generate_summary "$updates_json"
    
    # Note about CVE details
    echo ""
    echo "📌 Note: For detailed CVE information, visit the links above"
    echo "💡 Tip: Use --offline mode for faster results when cache is valid"
    
    log "INFO" "Apple security updates scan completed"
}

# Run main function with all arguments
main "$@"
