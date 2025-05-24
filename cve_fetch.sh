#!/bin/bash

# Albator CVE Fetch Script
# Enhanced with error handling, caching, and offline mode

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCRIPT_NAME="cve_fetch.sh"
LOG_FILE="/tmp/albator_cve_fetch.log"
CACHE_DIR="/tmp/albator_cache/cve"
DRY_RUN=${DRY_RUN:-false}
OFFLINE_MODE=${OFFLINE_MODE:-false}
CACHE_EXPIRY_HOURS=${CACHE_EXPIRY_HOURS:-6}

# API Configuration
GITHUB_API_URL="https://api.github.com/advisories"
APPLE_SECURITY_URL="https://support.apple.com/en-gb/100100"
NVD_API_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Progress indicator
show_progress() {
    local message=$1
    echo -e "${BLUE}[INFO]${NC} $message"
    log "INFO" "$message"
}

# Success indicator
show_success() {
    local message=$1
    echo -e "${GREEN}[SUCCESS]${NC} $message"
    log "SUCCESS" "$message"
}

# Error indicator
show_error() {
    local message=$1
    echo -e "${RED}[ERROR]${NC} $message" >&2
    log "ERROR" "$message"
}

# Warning indicator
show_warning() {
    local message=$1
    echo -e "${YELLOW}[WARNING]${NC} $message"
    log "WARNING" "$message"
}

# Function to check dependencies
check_dependencies() {
    show_progress "Checking dependencies..."
    
    local missing_deps=()
    
    # Check required tools
    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        missing_deps+=("jq")
    fi
    
    # Check optional tools
    if ! command -v pup >/dev/null 2>&1; then
        show_warning "pup not found (optional) - install with: brew install pup"
        show_warning "Will use fallback parsing for Apple security updates"
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        show_error "Missing required dependencies: ${missing_deps[*]}"
        show_error "Install with: brew install ${missing_deps[*]}"
        return 1
    fi
    
    show_success "All required dependencies found"
    return 0
}

# Function to setup cache directory
setup_cache() {
    show_progress "Setting up cache directory..."
    
    mkdir -p "$CACHE_DIR"
    
    # Create cache metadata file if it doesn't exist
    local cache_meta="$CACHE_DIR/metadata.json"
    if [[ ! -f "$cache_meta" ]]; then
        echo '{"created": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'", "sources": {}}' > "$cache_meta"
    fi
    
    log "INFO" "Cache directory: $CACHE_DIR"
}

# Function to check if cache is valid
is_cache_valid() {
    local cache_file=$1
    local expiry_hours=${2:-$CACHE_EXPIRY_HOURS}
    
    if [[ ! -f "$cache_file" ]]; then
        return 1
    fi
    
    # Check file age
    local file_age_seconds
    if [[ "$OSTYPE" == "darwin"* ]]; then
        file_age_seconds=$(( $(date +%s) - $(stat -f %m "$cache_file") ))
    else
        file_age_seconds=$(( $(date +%s) - $(stat -c %Y "$cache_file") ))
    fi
    
    local expiry_seconds=$((expiry_hours * 3600))
    
    if [[ $file_age_seconds -lt $expiry_seconds ]]; then
        return 0
    else
        return 1
    fi
}

# Function to make HTTP request with rate limiting and retries
make_request() {
    local url=$1
    local output_file=$2
    local max_retries=${3:-3}
    local retry_delay=${4:-5}
    
    show_progress "Fetching: $url"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        show_warning "DRY RUN: Would fetch $url"
        return 0
    fi
    
    local attempt=1
    while [[ $attempt -le $max_retries ]]; do
        if curl -s -L --retry 2 --retry-delay 2 \
            --max-time 30 \
            -A "Albator/1.0 (macOS Security Scanner)" \
            -H "Accept: application/json" \
            "$url" -o "$output_file" 2>>"$LOG_FILE"; then
            
            # Verify the response is valid JSON (if expected)
            if [[ "$url" == *"api.github.com"* ]] || [[ "$url" == *"nvd.nist.gov"* ]]; then
                if jq empty "$output_file" 2>/dev/null; then
                    show_success "Successfully fetched and validated JSON from $url"
                    return 0
                else
                    show_warning "Invalid JSON response from $url (attempt $attempt)"
                fi
            else
                show_success "Successfully fetched $url"
                return 0
            fi
        else
            show_warning "Request failed for $url (attempt $attempt/$max_retries)"
        fi
        
        if [[ $attempt -lt $max_retries ]]; then
            show_progress "Retrying in $retry_delay seconds..."
            sleep $retry_delay
        fi
        
        ((attempt++))
    done
    
    show_error "Failed to fetch $url after $max_retries attempts"
    return 1
}

# Function to fetch GitHub Security Advisories
fetch_github_advisories() {
    show_progress "Fetching GitHub Security Advisories..."
    
    local cache_file="$CACHE_DIR/github_advisories.json"
    
    # Check cache first
    if is_cache_valid "$cache_file" && [[ "$OFFLINE_MODE" != "true" ]]; then
        show_success "Using cached GitHub advisories"
        return 0
    fi
    
    if [[ "$OFFLINE_MODE" == "true" ]]; then
        if [[ -f "$cache_file" ]]; then
            show_warning "Offline mode: using existing cache (may be stale)"
            return 0
        else
            show_error "Offline mode: no cached data available"
            return 1
        fi
    fi
    
    # Fetch fresh data
    local api_url="${GITHUB_API_URL}?ecosystem=other&severity=high,critical&per_page=50"
    
    if make_request "$api_url" "$cache_file"; then
        # Update cache metadata
        local cache_meta="$CACHE_DIR/metadata.json"
        jq --arg source "github" --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
           '.sources[$source] = $timestamp' "$cache_meta" > "${cache_meta}.tmp" && \
           mv "${cache_meta}.tmp" "$cache_meta"
        
        return 0
    else
        return 1
    fi
}

# Function to fetch Apple Security Updates
fetch_apple_security_updates() {
    show_progress "Fetching Apple Security Updates..."
    
    local cache_file="$CACHE_DIR/apple_security.html"
    
    # Check cache first
    if is_cache_valid "$cache_file" && [[ "$OFFLINE_MODE" != "true" ]]; then
        show_success "Using cached Apple security updates"
        return 0
    fi
    
    if [[ "$OFFLINE_MODE" == "true" ]]; then
        if [[ -f "$cache_file" ]]; then
            show_warning "Offline mode: using existing cache (may be stale)"
            return 0
        else
            show_error "Offline mode: no cached data available"
            return 1
        fi
    fi
    
    # Fetch fresh data
    if make_request "$APPLE_SECURITY_URL" "$cache_file"; then
        # Update cache metadata
        local cache_meta="$CACHE_DIR/metadata.json"
        jq --arg source "apple" --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
           '.sources[$source] = $timestamp' "$cache_meta" > "${cache_meta}.tmp" && \
           mv "${cache_meta}.tmp" "$cache_meta"
        
        return 0
    else
        return 1
    fi
}

# Function to fetch NVD CVE data
fetch_nvd_cves() {
    show_progress "Fetching NVD CVE data for macOS..."
    
    local cache_file="$CACHE_DIR/nvd_cves.json"
    
    # Check cache first
    if is_cache_valid "$cache_file" 12 && [[ "$OFFLINE_MODE" != "true" ]]; then  # 12 hour cache for NVD
        show_success "Using cached NVD CVE data"
        return 0
    fi
    
    if [[ "$OFFLINE_MODE" == "true" ]]; then
        if [[ -f "$cache_file" ]]; then
            show_warning "Offline mode: using existing cache (may be stale)"
            return 0
        else
            show_warning "Offline mode: no NVD cache available, skipping"
            return 0
        fi
    fi
    
    # Calculate date range (last 30 days)
    local end_date=$(date -u +"%Y-%m-%dT%H:%M:%S.000")
    local start_date
    if [[ "$OSTYPE" == "darwin"* ]]; then
        start_date=$(date -u -v-30d +"%Y-%m-%dT%H:%M:%S.000")
    else
        start_date=$(date -u -d "30 days ago" +"%Y-%m-%dT%H:%M:%S.000")
    fi
    
    # Build NVD API URL with macOS-related keywords
    local nvd_url="${NVD_API_URL}?keywordSearch=macOS&pubStartDate=${start_date}&pubEndDate=${end_date}&resultsPerPage=100"
    
    if make_request "$nvd_url" "$cache_file"; then
        # Update cache metadata
        local cache_meta="$CACHE_DIR/metadata.json"
        jq --arg source "nvd" --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
           '.sources[$source] = $timestamp' "$cache_meta" > "${cache_meta}.tmp" && \
           mv "${cache_meta}.tmp" "$cache_meta"
        
        return 0
    else
        show_warning "Failed to fetch NVD data, continuing without it"
        return 0  # Don't fail the entire script
    fi
}

# Function to parse GitHub advisories
parse_github_advisories() {
    local cache_file="$CACHE_DIR/github_advisories.json"
    
    if [[ ! -f "$cache_file" ]]; then
        show_warning "No GitHub advisories data available"
        return 0
    fi
    
    show_progress "Parsing GitHub Security Advisories..."
    
    # Filter for macOS-related advisories
    local macos_advisories
    macos_advisories=$(jq -r '
        .[] | 
        select(
            (.summary // "" | test("macOS|Mac OS|Apple|Safari|Xcode"; "i")) or
            (.description // "" | test("macOS|Mac OS|Apple|Safari|Xcode"; "i")) or
            (.cve_id // "" | length > 0)
        ) |
        "CVE: \(.cve_id // "N/A")
Severity: \(.severity // "Unknown")
Summary: \(.summary // "No summary")
Published: \(.published_at // "Unknown")
URL: \(.html_url // "N/A")
---"
    ' "$cache_file" 2>/dev/null)
    
    if [[ -n "$macos_advisories" ]]; then
        echo ""
        echo "GitHub Security Advisories (macOS-related):"
        echo "============================================"
        echo "$macos_advisories"
    else
        show_warning "No macOS-related advisories found in GitHub data"
    fi
}

# Function to parse Apple security updates
parse_apple_security_updates() {
    local cache_file="$CACHE_DIR/apple_security.html"
    
    if [[ ! -f "$cache_file" ]]; then
        show_warning "No Apple security updates data available"
        return 0
    fi
    
    show_progress "Parsing Apple Security Updates..."
    
    # Try pup first, then fallback to grep/awk
    if command -v pup >/dev/null 2>&1; then
        local macos_updates
        macos_updates=$(cat "$cache_file" | \
            pup 'table tbody tr json{}' 2>/dev/null | \
            jq -r '
                def get_text:
                    if .type == "text" then .text
                    elif .children then (.children | map(get_text) | join(""))
                    else ""
                    end;
                .[] | 
                select(
                    (.children | length >= 2) and
                    (.children[0].children[0].tag == "a") and
                    (.children[1] | get_text | test("macOS"; "i"))
                ) | 
                "Title: \(.children[0].children[0].text)
Link: https://support.apple.com\(.children[0].children[0].href)
---"
            ' 2>/dev/null)
        
        if [[ -n "$macos_updates" ]]; then
            echo ""
            echo "Apple Security Updates (macOS):"
            echo "==============================="
            echo "$macos_updates"
        else
            show_warning "No macOS security updates found using pup parser"
        fi
    else
        # Fallback parsing with grep/awk
        show_progress "Using fallback parsing for Apple security updates..."
        
        local macos_lines
        macos_lines=$(grep -i "macOS\|Mac OS" "$cache_file" | head -10)
        
        if [[ -n "$macos_lines" ]]; then
            echo ""
            echo "Apple Security Updates (macOS - fallback parsing):"
            echo "=================================================="
            echo "$macos_lines"
        else
            show_warning "No macOS security updates found using fallback parser"
        fi
    fi
}

# Function to parse NVD CVE data
parse_nvd_cves() {
    local cache_file="$CACHE_DIR/nvd_cves.json"
    
    if [[ ! -f "$cache_file" ]]; then
        show_warning "No NVD CVE data available"
        return 0
    fi
    
    show_progress "Parsing NVD CVE data..."
    
    local nvd_cves
    nvd_cves=$(jq -r '
        .vulnerabilities[]? |
        .cve |
        "CVE ID: \(.id)
Published: \(.published)
Modified: \(.lastModified)
Description: \(.descriptions[0].value // "No description")
CVSS Score: \(.metrics.cvssMetricV31[0].cvssData.baseScore // "N/A")
Severity: \(.metrics.cvssMetricV31[0].cvssData.baseSeverity // "N/A")
---"
    ' "$cache_file" 2>/dev/null)
    
    if [[ -n "$nvd_cves" ]]; then
        echo ""
        echo "NVD CVE Database (macOS-related):"
        echo "================================="
        echo "$nvd_cves"
    else
        show_warning "No CVE data found in NVD response"
    fi
}

# Function to generate summary report
generate_summary_report() {
    show_progress "Generating summary report..."
    
    local report_file="$CACHE_DIR/cve_summary_$(date +%Y%m%d_%H%M%S).json"
    local cache_meta="$CACHE_DIR/metadata.json"
    
    # Count advisories from each source
    local github_count=0
    local apple_count=0
    local nvd_count=0
    
    if [[ -f "$CACHE_DIR/github_advisories.json" ]]; then
        github_count=$(jq length "$CACHE_DIR/github_advisories.json" 2>/dev/null || echo 0)
    fi
    
    if [[ -f "$CACHE_DIR/apple_security.html" ]]; then
        apple_count=$(grep -c -i "macOS\|Mac OS" "$CACHE_DIR/apple_security.html" 2>/dev/null || echo 0)
    fi
    
    if [[ -f "$CACHE_DIR/nvd_cves.json" ]]; then
        nvd_count=$(jq '.vulnerabilities | length' "$CACHE_DIR/nvd_cves.json" 2>/dev/null || echo 0)
    fi
    
    # Create summary
    local summary=$(cat <<EOF
{
    "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "sources": {
        "github_advisories": {
            "count": $github_count,
            "last_updated": $(jq -r '.sources.github // "never"' "$cache_meta" 2>/dev/null || echo '"never"')
        },
        "apple_security": {
            "count": $apple_count,
            "last_updated": $(jq -r '.sources.apple // "never"' "$cache_meta" 2>/dev/null || echo '"never"')
        },
        "nvd_cves": {
            "count": $nvd_count,
            "last_updated": $(jq -r '.sources.nvd // "never"' "$cache_meta" 2>/dev/null || echo '"never"')
        }
    },
    "total_advisories": $((github_count + apple_count + nvd_count)),
    "cache_location": "$CACHE_DIR"
}
EOF
)
    
    echo "$summary" > "$report_file"
    
    echo ""
    echo "Summary Report:"
    echo "==============="
    echo "GitHub Advisories: $github_count"
    echo "Apple Security Updates: $apple_count"
    echo "NVD CVEs: $nvd_count"
    echo "Total: $((github_count + apple_count + nvd_count))"
    echo ""
    echo "Detailed report saved to: $report_file"
}

# Function to cleanup old cache files
cleanup_cache() {
    show_progress "Cleaning up old cache files..."
    
    # Remove files older than 7 days
    find "$CACHE_DIR" -name "cve_summary_*.json" -mtime +7 -delete 2>/dev/null || true
    
    show_success "Cache cleanup completed"
}

# Main execution
main() {
    echo "Albator CVE Fetch Script"
    echo "========================"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                show_warning "Running in dry-run mode"
                shift
                ;;
            --offline)
                OFFLINE_MODE=true
                show_warning "Running in offline mode"
                shift
                ;;
            --cache-expiry)
                CACHE_EXPIRY_HOURS=$2
                show_progress "Cache expiry set to $CACHE_EXPIRY_HOURS hours"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [--dry-run] [--offline] [--cache-expiry HOURS] [--help]"
                echo "  --dry-run        Show what would be done without making requests"
                echo "  --offline        Use cached data only, don't make network requests"
                echo "  --cache-expiry   Set cache expiry time in hours (default: 6)"
                echo "  --help           Show this help message"
                exit 0
                ;;
            *)
                show_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")"
    log "INFO" "Starting CVE fetch script"
    
    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Setup cache
    setup_cache
    
    # Fetch data from all sources
    local fetch_errors=0
    
    fetch_github_advisories || ((fetch_errors++))
    fetch_apple_security_updates || ((fetch_errors++))
    fetch_nvd_cves || ((fetch_errors++))
    
    # Parse and display results
    parse_github_advisories
    parse_apple_security_updates
    parse_nvd_cves
    
    # Generate summary
    generate_summary_report
    
    # Cleanup old files
    cleanup_cache
    
    # Final status
    echo ""
    echo "========================"
    if [[ $fetch_errors -eq 0 ]]; then
        show_success "CVE fetch completed successfully!"
        log "INFO" "CVE fetch completed successfully"
        exit 0
    else
        show_warning "CVE fetch completed with $fetch_errors source errors"
        show_warning "Check log file: $LOG_FILE"
        log "WARNING" "CVE fetch completed with $fetch_errors source errors"
        exit 0  # Don't fail completely if some sources work
    fi
}

# Run main function with all arguments
main "$@"
