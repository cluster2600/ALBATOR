#!/bin/bash

# Albator Privacy Configuration Script
# Enhanced with error handling, logging, and verification

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Source common utilities
source "$(dirname "$0")"/utils.sh

# Configuration
SCRIPT_NAME="privacy.sh"
LOG_FILE="/tmp/albator_privacy.log"
BACKUP_DIR="/tmp/albator_backup/privacy"
DRY_RUN=${DRY_RUN:-false}

# Function to backup current setting
backup_setting() {
    local domain=$1
    local key=$2
    local backup_file="$BACKUP_DIR/${domain}_${key}.backup"
    
    mkdir -p "$BACKUP_DIR"
    
    if [[ "$domain" == "/Library/Preferences/"* ]]; then
        sudo defaults read "$domain" "$key" 2>/dev/null > "$backup_file" || echo "NOT_SET" > "$backup_file"
    else
        defaults read "$domain" "$key" 2>/dev/null > "$backup_file" || echo "NOT_SET" > "$backup_file"
    fi
    
    log "INFO" "Backed up $domain $key to $backup_file"
}

# Function to apply setting with verification
apply_setting() {
    local domain=$1
    local key=$2
    local value=$3
    local value_type=$4
    local description=$5
    local use_sudo=${6:-false}
    
    show_progress "Configuring: $description"
    
    # Backup current setting
    backup_setting "$domain" "$key"
    
    # Apply setting
    if [[ "$DRY_RUN" == "true" ]]; then
        show_warning "DRY RUN: Would set $domain $key to $value"
        return 0
    fi
    
    local cmd
    if [[ "$use_sudo" == "true" ]]; then
        cmd="sudo defaults write \"$domain\" \"$key\" -$value_type $value"
    else
        cmd="defaults write \"$domain\" \"$key\" -$value_type $value"
    fi
    
    if eval "$cmd" 2>>"$LOG_FILE"; then
        # Verify setting was applied
        local current_value
        if [[ "$use_sudo" == "true" ]]; then
            current_value=$(sudo defaults read "$domain" "$key" 2>/dev/null || echo "FAILED")
        else
            current_value=$(defaults read "$domain" "$key" 2>/dev/null || echo "FAILED")
        fi
        
        if [[ "$current_value" == "$value" ]] || [[ "$current_value" == "1" && "$value" == "true" ]] || [[ "$current_value" == "0" && "$value" == "false" ]]; then
            show_success "$description"
            return 0
        else
            show_error "Failed to verify $description (expected: $value, got: $current_value)"
            return 1
        fi
    else
        show_error "Failed to apply $description"
        return 1
    fi
}

# Function to disable system service
disable_service() {
    local service_name=$1
    local description=$2
    
    show_progress "Disabling: $description"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        show_warning "DRY RUN: Would disable $service_name"
        return 0
    fi
    
    if sudo launchctl list | grep -q "$service_name" 2>/dev/null; then
        if sudo launchctl unload -w "/System/Library/LaunchDaemons/$service_name.plist" 2>>"$LOG_FILE"; then
            show_success "$description disabled"
            return 0
        else
            show_error "Failed to disable $description"
            return 1
        fi
    else
        show_success "$description already disabled"
        return 0
    fi
}

# Function to configure system setting
configure_system_setting() {
    local command=$1
    local description=$2
    local verification_cmd=$3
    local expected_output=$4
    
    show_progress "Configuring: $description"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        show_warning "DRY RUN: Would run: $command"
        return 0
    fi
    
    if eval "$command" 2>>"$LOG_FILE"; then
        # Verify the setting
        if [[ -n "$verification_cmd" ]]; then
            local current_value
            current_value=$(eval "$verification_cmd" 2>/dev/null || echo "FAILED")
            if [[ "$current_value" == *"$expected_output"* ]]; then
                show_success "$description"
                return 0
            else
                show_error "Failed to verify $description (expected: $expected_output, got: $current_value)"
                return 1
            fi
        else
            show_success "$description"
            return 0
        fi
    else
        show_error "Failed to configure $description"
        return 1
    fi
}

# Main privacy configuration function
configure_privacy() {
    local errors=0
    
    show_progress "Starting privacy configuration..."
    
    # Disable telemetry (diagnostic reports)
    apply_setting "/Library/Preferences/com.apple.SubmitDiagInfo" "AutoSubmit" "false" "bool" "Diagnostic reports submission" "true" || ((errors++))
    apply_setting "/Library/Preferences/com.apple.SubmitDiagInfo" "AutoSubmitVersion" "0" "int" "Diagnostic reports version submission" "true" || ((errors++))
    
    # Disable Siri analytics
    apply_setting "com.apple.assistant.analytics" "AnalyticsEnabled" "false" "bool" "Siri analytics" "false" || ((errors++))
    
    # Disable new telemetry service for macOS 15.5
    apply_setting "com.apple.newTelemetryService" "AutoSubmit" "false" "bool" "New telemetry service (macOS 15.5)" "true" || ((errors++))
    
    # Configure Safari privacy settings
    apply_setting "com.apple.Safari" "UniversalSearchEnabled" "false" "bool" "Safari universal search" "false" || ((errors++))
    apply_setting "com.apple.Safari" "SuppressSearchSuggestions" "true" "bool" "Safari search suggestions suppression" "false" || ((errors++))
    
    # Disable remote login (SSH)
    configure_system_setting "sudo systemsetup -setremotelogin off" "Remote login (SSH)" "sudo systemsetup -getremotelogin" "Off" || ((errors++))
    
    # Disable remote management
    configure_system_setting "sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop" "Remote management (ARD)" "" "" || ((errors++))
    
    # Disable SMB network sharing
    disable_service "com.apple.smbd" "SMB network sharing" || ((errors++))
    
    # Configure mDNS (Bonjour) to disable multicast advertisements
    show_progress "Configuring mDNS multicast advertisements..."
    if [[ "$DRY_RUN" != "true" ]]; then
        if sudo defaults write /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist ProgramArguments -array-add "-NoMulticastAdvertisements" 2>>"$LOG_FILE"; then
            show_success "mDNS multicast advertisements disabled"
        else
            show_error "Failed to disable mDNS multicast advertisements"
            ((errors++))
        fi
    else
        show_warning "DRY RUN: Would disable mDNS multicast advertisements"
    fi
    
    return $errors
}

# Function to verify all settings
verify_settings() {
    local errors=0
    
    show_progress "Verifying privacy settings..."
    
    # Verification tests
    local tests=(
        "sudo defaults read /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit:0:Diagnostic reports disabled"
        "defaults read com.apple.assistant.analytics AnalyticsEnabled:0:Siri analytics disabled"
        "defaults read com.apple.Safari SuppressSearchSuggestions:1:Safari search suggestions disabled"
        "sudo systemsetup -getremotelogin:Off:Remote login disabled"
    )
    
    for test in "${tests[@]}"; do
        IFS=':' read -r cmd expected description <<< "$test"
        
        local actual
        actual=$(eval "$cmd" 2>/dev/null || echo "FAILED")
        
        if [[ "$actual" == *"$expected"* ]]; then
            show_success "✓ $description"
        else
            show_error "✗ $description (expected: $expected, got: $actual)"
            ((errors++))
        fi
    done
    
    # Check SMB service
    if ! sudo launchctl list | grep -q "com.apple.smbd" 2>/dev/null; then
        show_success "✓ SMB sharing disabled"
    else
        show_error "✗ SMB sharing still enabled"
        ((errors++))
    fi
    
    return $errors
}

# Main execution
main() {
    echo "Albator Privacy Configuration Script"
    echo "===================================="
    
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
    log "INFO" "Starting privacy configuration script"
    
    # Check if running on macOS 15.x
    local macos_version
    macos_version=$(sw_vers -productVersion)
    if [[ ! "$macos_version" == 15.* ]]; then
        show_warning "This script is designed for macOS 15.x, detected: $macos_version"
    fi
    
    # Run configuration
    local config_errors=0
    configure_privacy || config_errors=$?
    
    # Run verification
    local verify_errors=0
    verify_settings || verify_errors=$?
    
    # Summary
    local total_errors=$((config_errors + verify_errors))
    
    echo ""
    echo "===================================="
    if [[ $total_errors -eq 0 ]]; then
        show_success "Privacy configuration completed successfully!"
        log "INFO" "Privacy configuration completed successfully"
        exit 0
    else
        show_error "Privacy configuration completed with $total_errors errors"
        show_error "Check log file: $LOG_FILE"
        log "ERROR" "Privacy configuration completed with $total_errors errors"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
