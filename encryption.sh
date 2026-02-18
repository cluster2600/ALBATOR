#!/bin/bash

# Albator Encryption Configuration Script
# Enhanced with error handling, logging, and verification

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCRIPT_NAME="encryption.sh"
LOG_FILE="/tmp/albator_encryption.log"
BACKUP_DIR="/tmp/albator_backup/encryption"
DRY_RUN=${DRY_RUN:-false}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Source common utilities
source "$(dirname "$0")"/utils.sh

# Function to backup current encryption settings
backup_encryption_settings() {
    show_progress "Backing up current encryption settings..."
    
    mkdir -p "$BACKUP_DIR"
    
    local backup_file="$BACKUP_DIR/encryption_settings_$(date +%Y%m%d_%H%M%S).backup"
    
    {
        echo "# Encryption backup created on $(date)"
        echo "FILEVAULT_STATUS=$(fdesetup status 2>/dev/null || echo 'unknown')"
        echo "APFS_ENCRYPTION=$(diskutil apfs list 2>/dev/null | grep -i filevault || echo 'unknown')"
        echo "SECURE_TOKEN_STATUS=$(sysadminctl -secureTokenStatus $(whoami) 2>/dev/null || echo 'unknown')"
        echo "BOOTSTRAP_TOKEN_STATUS=$(profiles status -type bootstraptoken 2>/dev/null || echo 'unknown')"
    } > "$backup_file"
    
    log "INFO" "Encryption settings backed up to $backup_file"
}

# Function to check current FileVault status
check_filevault_status() {
    show_progress "Checking current FileVault status..."
    
    local status
    status=$(fdesetup status 2>/dev/null || echo "unknown")
    
    if [[ "$status" == *"FileVault is On"* ]]; then
        show_success "FileVault is currently enabled"
        return 0
    elif [[ "$status" == *"FileVault is Off"* ]]; then
        show_warning "FileVault is currently disabled"
        return 1
    else
        show_error "Unable to determine FileVault status: $status"
        return 2
    fi
}

# Function to check prerequisites for FileVault
check_filevault_prerequisites() {
    show_progress "Checking FileVault prerequisites..."
    
    local errors=0
    
    # Check if running on APFS
    if ! diskutil info / | grep -q "APFS"; then
        show_error "FileVault requires APFS file system"
        ((errors++))
    else
        show_success "APFS file system detected"
    fi
    
    # Check secure token status
    local secure_token_status
    secure_token_status=$(sysadminctl -secureTokenStatus "$(whoami)" 2>/dev/null || echo "unknown")
    
    if [[ "$secure_token_status" == *"ENABLED"* ]]; then
        show_success "Secure token is enabled for current user"
    else
        show_warning "Secure token status: $secure_token_status"
        show_warning "FileVault setup may require additional steps"
    fi
    
    # Check available disk space
    local available_space
    available_space=$(df -h / | awk 'NR==2 {print $4}' | sed 's/G//')
    
    if [[ "${available_space%.*}" -lt 10 ]]; then
        show_warning "Low disk space detected: ${available_space}GB available"
        show_warning "FileVault encryption may require more space"
    else
        show_success "Sufficient disk space available: ${available_space}GB"
    fi
    
    return $errors
}

# Function to enable FileVault with enhanced options
enable_filevault() {
    local errors=0
    
    show_progress "Configuring FileVault encryption..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        show_warning "DRY RUN: Would enable FileVault encryption"
        record_plan_action "filevault" "Enable FileVault encryption" "sudo fdesetup enable -user $(whoami)"
        return 0
    fi
    
    # Check if already enabled
    if check_filevault_status; then
        show_success "FileVault is already enabled"
        record_noop "FileVault already enabled"
        return 0
    fi
    
    # Check prerequisites
    if ! check_filevault_prerequisites; then
        show_error "Prerequisites check failed"
        return 1
    fi
    
    # Enable FileVault
    show_progress "Enabling FileVault (this may take some time)..."
    show_warning "User interaction may be required for recovery key setup"
    
    # Try different methods based on macOS version and configuration
    if sudo fdesetup enable -user "$(whoami)" 2>>"$LOG_FILE"; then
        show_success "FileVault enable command executed successfully"
        record_rollback_change "filevault" "enabled via user-specific command"
    elif sudo fdesetup enable 2>>"$LOG_FILE"; then
        show_success "FileVault enable command executed successfully (fallback method)"
        record_rollback_change "filevault" "enabled via fallback command"
    else
        show_error "Failed to enable FileVault"
        ((errors++))
    fi
    
    return $errors
}

# Function to configure recovery key enhancements
configure_recovery_key() {
    show_progress "Configuring recovery key settings..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        show_warning "DRY RUN: Would configure recovery key settings"
        record_plan_action "filevault_recovery" "Configure recovery key settings" "sudo fdesetup recoverykey"
        return 0
    fi
    
    # Check if FileVault is enabled first
    if ! check_filevault_status; then
        show_warning "FileVault not enabled, skipping recovery key configuration"
        return 0
    fi
    
    # Get current recovery key information
    local recovery_key_info
    recovery_key_info=$(sudo fdesetup recoverykey 2>/dev/null || echo "unknown")
    
    if [[ "$recovery_key_info" == *"recovery key"* ]]; then
        show_success "Recovery key is configured"
        record_noop "Recovery key already configured"
        
        show_progress "Applying recovery key security enhancements..."
        
        # Placeholder for recovery key enhancements
        # These would include secure storage options, key rotation, etc.
        show_warning "Recovery key enhancements are placeholders"
        show_warning "Implement secure key storage and rotation as needed"
        
    else
        show_warning "Recovery key configuration may need attention"
        show_warning "Consider setting up a recovery key for emergency access"
    fi
}

# Function to verify encryption status
verify_encryption_status() {
    local errors=0
    
    show_progress "Verifying encryption configuration..."
    
    # Check FileVault status
    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "unknown")
    
    if [[ "$fv_status" == *"FileVault is On"* ]]; then
        show_success "✓ FileVault is enabled"
    else
        show_error "✗ FileVault is not enabled: $fv_status"
        ((errors++))
    fi
    
    # Check encryption progress
    local encryption_progress
    encryption_progress=$(fdesetup status 2>/dev/null | grep -i "percent\|progress" || echo "")
    
    if [[ -n "$encryption_progress" ]]; then
        show_warning "Encryption in progress: $encryption_progress"
    fi
    
    # Check APFS encryption
    if diskutil apfs list 2>/dev/null | grep -q "FileVault: Yes"; then
        show_success "✓ APFS FileVault encryption confirmed"
    else
        show_warning "APFS FileVault status unclear"
    fi
    
    # Check recovery key
    if sudo fdesetup recoverykey 2>/dev/null | grep -q "recovery key"; then
        show_success "✓ Recovery key is configured"
    else
        show_warning "Recovery key status unclear"
    fi
    
    return $errors
}

# Function to display encryption summary
display_encryption_summary() {
    show_progress "Encryption Configuration Summary:"
    echo "=================================="
    
    # FileVault status
    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "Error getting status")
    printf "%-25s: %s\n" "FileVault Status" "$fv_status"
    
    # Encryption progress
    local progress
    progress=$(fdesetup status 2>/dev/null | grep -i "percent" | head -1 || echo "Complete or not started")
    printf "%-25s: %s\n" "Encryption Progress" "$progress"
    
    # Recovery key status
    local recovery_status
    if sudo fdesetup recoverykey 2>/dev/null | grep -q "recovery key"; then
        recovery_status="Configured"
    else
        recovery_status="Not configured or unknown"
    fi
    printf "%-25s: %s\n" "Recovery Key" "$recovery_status"
    
    # Secure token status
    local token_status
    token_status=$(sysadminctl -secureTokenStatus "$(whoami)" 2>/dev/null || echo "Unknown")
    printf "%-25s: %s\n" "Secure Token" "$token_status"
    
    echo "=================================="
}

# Function to provide post-encryption guidance
provide_guidance() {
    show_progress "Post-encryption guidance:"
    echo ""
    echo "Important Notes:"
    echo "• FileVault encryption may continue in the background"
    echo "• System restart may be required to complete setup"
    echo "• Keep your recovery key in a secure location"
    echo "• Test recovery key before relying on it"
    echo "• Monitor encryption progress with: fdesetup status"
    echo ""
    
    if ! check_filevault_status >/dev/null 2>&1; then
        echo "Next Steps:"
        echo "• Restart your system to complete FileVault setup"
        echo "• Verify encryption status after restart"
        echo "• Ensure recovery key is properly stored"
    fi
}

# Main execution
main() {
    echo "Albator Encryption Configuration Script"
    echo "======================================="
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                show_warning "Running in dry-run mode"
                shift
                ;;
            --help)
                echo "Usage: $0 [--dry-run] [--help]"
                echo "  --dry-run   Show what would be done without making changes"
                echo "  --help      Show this help message"
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
    log "INFO" "Starting encryption configuration script"
    init_script_state
    
    # Check against configured baseline version
    local macos_version
    macos_version=$(sw_vers -productVersion)
    local min_macos
    min_macos=$(get_min_macos_version)
    if [[ "$macos_version" != "$min_macos"* ]]; then
        show_warning "Configured baseline is macOS >= $min_macos, detected: $macos_version"
    fi
    
    # Check for sudo privileges
    if ! sudo -n true 2>/dev/null; then
        show_error "This script requires sudo privileges"
        exit 1
    fi
    
    # Backup current settings
    backup_encryption_settings
    
    # Check current status
    check_filevault_status || true  # Don't fail if disabled
    
    # Run encryption configuration
    local config_errors=0
    enable_filevault || config_errors=$?
    
    # Configure recovery key
    configure_recovery_key || ((config_errors++))
    
    # Run verification
    local verify_errors=0
    verify_encryption_status || verify_errors=$?
    
    # Display summary
    display_encryption_summary
    
    # Provide guidance
    provide_guidance
    
    # Summary
    local total_errors=$((config_errors + verify_errors))
    
    echo ""
    echo "======================================="
    if [[ $total_errors -eq 0 ]]; then
        show_success "Encryption configuration completed successfully!"
        log "INFO" "Encryption configuration completed successfully"
        exit_with_status 0
    else
        show_error "Encryption configuration completed with $total_errors errors"
        show_error "Check log file: $LOG_FILE"
        log "ERROR" "Encryption configuration completed with $total_errors errors"
        exit_with_status "$total_errors"
    fi
}

# Run main function with all arguments
main "$@"
