#!/bin/bash

# Albator Security Test Suite
# Comprehensive testing for macOS hardening operations with validation

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Logging
LOG_FILE="/tmp/albator_test.log"
exec 2> >(tee -a "$LOG_FILE")

# Dry run flag
DRY_RUN=false
VERBOSE=false
MIN_MACOS_VERSION="${MIN_MACOS_VERSION:-26.3}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--verbose] [--help]"
            echo "  --dry-run    Show what would be tested without running scripts"
            echo "  --verbose    Enable verbose output"
            echo "  --help       Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "PASS")
            echo -e "${GREEN}✅ PASS${NC}: $message"
            ((PASSED_TESTS++))
            ;;
        "FAIL")
            echo -e "${RED}❌ FAIL${NC}: $message"
            ((FAILED_TESTS++))
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  INFO${NC}: $message"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️  WARN${NC}: $message"
            ;;
    esac
    ((TOTAL_TESTS++))
}

# Function to run a test command
run_test() {
    local test_name=$1
    local command=$2
    local expected=$3
    local description=$4
    
    echo -e "\n${BLUE}Testing:${NC} $description"
    
    if output=$(eval "$command" 2>&1); then
        if [[ "$output" == *"$expected"* ]]; then
            print_status "PASS" "$test_name"
            echo "  Expected: $expected"
            echo "  Got: $output"
        else
            print_status "FAIL" "$test_name - Expected '$expected' not found"
            echo "  Expected: $expected"
            echo "  Got: $output"
        fi
    else
        print_status "FAIL" "$test_name - Command failed"
        echo "  Command: $command"
        echo "  Error: $output"
    fi
}

# Version comparison helper: returns 0 when $1 >= $2
version_ge() {
    awk -v current="$1" -v minimum="$2" '
        BEGIN {
            split(current, c, ".");
            split(minimum, m, ".");
            n = (length(c) > length(m) ? length(c) : length(m));
            for (i = 1; i <= n; i++) {
                cv = c[i] + 0;
                mv = m[i] + 0;
                if (cv > mv) { print 1; exit }
                if (cv < mv) { print 0; exit }
            }
            print 1;
        }'
}

# Function to test script execution
test_script() {
    local script_name=$1
    local description=$2
    
    echo -e "\n${BLUE}Testing Script:${NC} $description"
    
    if [[ ! -f "$script_name" ]]; then
        print_status "FAIL" "$script_name - Script not found"
        return
    fi
    
    if bash "$script_name" > /tmp/script_output.log 2>&1; then
        print_status "PASS" "$script_name executed successfully"
    else
        print_status "FAIL" "$script_name execution failed"
        echo "  See /tmp/script_output.log for details"
    fi
}

# Function to check dependencies
check_dependencies() {
    echo -e "\n${BLUE}=== DEPENDENCY CHECKS ===${NC}"
    
    # Check macOS version against configured minimum
    local current_macos
    current_macos=$(sw_vers -productVersion)
    if [[ "$(version_ge "$current_macos" "$MIN_MACOS_VERSION")" == "1" ]]; then
        print_status "PASS" "macos_version >= ${MIN_MACOS_VERSION} (current: ${current_macos})"
    else
        print_status "FAIL" "macos_version < ${MIN_MACOS_VERSION} (current: ${current_macos})"
    fi
    
    # Check required tools
    run_test "curl_available" "which curl" "/curl" "curl command availability"
    run_test "jq_available" "which jq" "/jq" "jq command availability"
    
    # Check optional tools
    if which pup > /dev/null 2>&1; then
        print_status "PASS" "pup (optional) - Available"
    else
        print_status "WARN" "pup (optional) - Not available, install with: brew install pup"
    fi
    
    # Check sudo access
    if sudo -n true 2>/dev/null; then
        print_status "PASS" "sudo access available"
    else
        print_status "WARN" "sudo access may require password"
    fi
}

# Function to test firewall configuration
test_firewall() {
    echo -e "\n${BLUE}=== FIREWALL TESTS ===${NC}"
    
    run_test "firewall_enabled" \
        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate" \
        "enabled" \
        "Application Layer Firewall status"
    
    run_test "firewall_stealth" \
        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode" \
        "enabled" \
        "Firewall stealth mode"
    
    run_test "firewall_block_all" \
        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall" \
        "enabled" \
        "Block all incoming connections"
    
    run_test "firewall_logging" \
        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode" \
        "enabled" \
        "Firewall logging"
}

# Function to test privacy settings
test_privacy() {
    echo -e "\n${BLUE}=== PRIVACY TESTS ===${NC}"
    
    run_test "diagnostic_reports" \
        "sudo defaults read /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit 2>/dev/null || echo '0'" \
        "0" \
        "Diagnostic reports disabled"
    
    run_test "siri_analytics" \
        "defaults read com.apple.assistant.analytics AnalyticsEnabled 2>/dev/null || echo '0'" \
        "0" \
        "Siri analytics disabled"
    
    run_test "safari_suggestions" \
        "defaults read com.apple.Safari SuppressSearchSuggestions 2>/dev/null || echo '0'" \
        "1" \
        "Safari search suggestions disabled"
    
    run_test "remote_login" \
        "sudo systemsetup -getremotelogin" \
        "Off" \
        "Remote login (SSH) disabled"
    
    # Test SMB sharing
    if ! sudo launchctl list | grep -q "com.apple.smbd" 2>/dev/null; then
        print_status "PASS" "SMB sharing disabled"
    else
        print_status "FAIL" "SMB sharing still enabled"
    fi
}

# Function to test encryption settings
test_encryption() {
    echo -e "\n${BLUE}=== ENCRYPTION TESTS ===${NC}"
    
    # FileVault test (may not be enabled in all environments)
    if diskutil apfs list 2>/dev/null | grep -q "FileVault: Yes"; then
        print_status "PASS" "FileVault encryption enabled"
    else
        print_status "WARN" "FileVault not enabled (may require user interaction)"
    fi
}

# Function to test app security
test_app_security() {
    echo -e "\n${BLUE}=== APPLICATION SECURITY TESTS ===${NC}"
    
    run_test "gatekeeper_enabled" \
        "spctl --status" \
        "assessments enabled" \
        "Gatekeeper enabled"
    
    # Test Safari hardened runtime (may not always be detectable)
    if codesign -dv --verbose /Applications/Safari.app 2>&1 | grep -q "hardened"; then
        print_status "PASS" "Safari uses Hardened Runtime"
    else
        print_status "WARN" "Safari Hardened Runtime not detected (may be normal)"
    fi
}

# Function to test script execution
test_scripts() {
    echo -e "\n${BLUE}=== SCRIPT EXECUTION TESTS ===${NC}"
    
    # Only test scripts if they exist and we're not in dry-run mode
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        print_status "INFO" "Skipping script execution tests (dry-run mode)"
        return
    fi
    
    # Test individual scripts (with caution)
    local scripts=(
        "cve_fetch.sh:CVE fetching script"
        "apple_updates.sh:Apple updates fetching script"
    )
    
    for script_info in "${scripts[@]}"; do
        IFS=':' read -r script_name description <<< "$script_info"
        if [[ -f "$script_name" ]]; then
            test_script "$script_name" "$description"
        else
            print_status "WARN" "$script_name not found"
        fi
    done
}

# Function to generate summary report
generate_summary() {
    echo -e "\n${BLUE}=== TEST SUMMARY ===${NC}"
    echo "======================================"
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}All tests passed! ✅${NC}"
        SUCCESS_RATE=100
    else
        SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
        echo -e "${YELLOW}Success Rate: ${SUCCESS_RATE}%${NC}"
        if [[ $FAILED_TESTS -gt 0 ]]; then
            echo -e "${RED}Some tests failed. Check the output above for details.${NC}"
        fi
    fi
    
    echo "======================================"
    echo "Log file: $LOG_FILE"
    
    # Create JSON report
    cat > test_report.json << EOF
{
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "total_tests": $TOTAL_TESTS,
    "passed": $PASSED_TESTS,
    "failed": $FAILED_TESTS,
    "success_rate": $SUCCESS_RATE,
    "log_file": "$LOG_FILE"
}
EOF
    
    echo "JSON report: test_report.json"
}

# Main execution
main() {
    echo -e "${BLUE}Starting Albator Security Test Suite...${NC}"
    echo "========================================"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                echo -e "${YELLOW}Running in dry-run mode (no script execution)${NC}"
                shift
                ;;
            --verbose)
                set -x
                shift
                ;;
            --help)
                echo "Usage: $0 [--dry-run] [--verbose] [--help]"
                echo "  --dry-run   Skip script execution tests"
                echo "  --verbose   Enable verbose output"
                echo "  --help      Show this help message"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Run test suites
    check_dependencies
    test_firewall
    test_privacy
    test_encryption
    test_app_security
    test_scripts
    
    # Generate summary
    generate_summary
    
    # Exit with appropriate code
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# Run main function with all arguments
main "$@"
