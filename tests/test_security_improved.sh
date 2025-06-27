#!/bin/bash

# Albator Security Test Suite (Improved)
# Comprehensive testing for macOS hardening operations with validation and rollback

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
SKIPPED_TESTS=0

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

# Function to check for sudo access
check_sudo_access() {
    if sudo -n true 2>/dev/null; then
        return 0 # Sudo access without password
    else
        return 1 # Sudo access requires password or is not available
    fi
}

# Function to get the current state of a setting
get_setting_state() {
    local command=$1
    eval "$command"
}

# Function to run a test with validation and rollback
run_test_validate_rollback() {
    local test_name=$1
    local check_command=$2
    local apply_script=$3
    local expected_state=$4
    local rollback_command=$5
    local requires_sudo=$6 # New argument to indicate if sudo is required

    echo -e "\n${BLUE}Testing:${NC} $test_name"

    if [[ "$requires_sudo" == "true" ]] && ! check_sudo_access; then
        print_status "INFO" "Skipping $test_name (sudo access required)"
        ((SKIPPED_TESTS++))
        return
    fi

    # 1. Establish a baseline
    initial_state=$(get_setting_state "$check_command")
    print_status "INFO" "Initial state: $initial_state"

    # 2. Apply the hardening rule
    print_status "INFO" "Applying hardening rule..."
    if ! bash "$apply_script"; then
        print_status "FAIL" "$test_name - Apply script failed"
        return
    fi

    # 3. Verify the change
    current_state=$(get_setting_state "$check_command")
    print_status "INFO" "Current state: $current_state"
    if [[ "$current_state" == *"$expected_state"* ]]; then
        print_status "PASS" "$test_name"
    else
        print_status "FAIL" "$test_name - Verification failed"
        echo "  Expected: $expected_state"
        echo "  Got: $current_state"
    fi

    # 4. Roll back the change
    print_status "INFO" "Rolling back change..."
    if ! eval "$rollback_command"; then
        print_status "WARN" "$test_name - Rollback command failed"
    else
        final_state=$(get_setting_state "$rollback_command")
        print_status "INFO" "Final state: $final_state"
    fi
}

# Function to test firewall configuration
test_firewall_improved() {
    echo -e "\n${BLUE}=== FIREWALL TESTS (IMPROVED) ===${NC}"

    run_test_validate_rollback "Firewall Enablement" \
        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate" \
        "../firewall.sh --enable" \
        "Firewall is enabled" \
        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off" \
        "true" # This test requires sudo
}

# Function to test privacy settings
test_privacy_improved() {
    echo -e "\n${BLUE}=== PRIVACY TESTS (IMPROVED) ===${NC}"

    run_test_validate_rollback "Diagnostic Reports Disable" \
        "sudo defaults read /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit 2>/dev/null || echo '0'" \
        "../privacy.sh" \
        "0" \
        "sudo defaults write /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit -bool true" \
        "true" # This test requires sudo
}

# Main execution
main() {
    echo -e "${BLUE}Starting Albator Improved Security Test Suite...${NC}"
    echo "========================================="

    # Run test suites
    test_firewall_improved
    test_privacy_improved

    # Generate summary
    echo -e "\n${BLUE}=== TEST SUMMARY ===${NC}"
    echo "======================================"
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Skipped: $SKIPPED_TESTS"

    if [[ $FAILED_TESTS -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function with all arguments
main "$@"