#!/bin/bash

# Albator Application Security Configuration Script
# Enhanced with error handling, logging, and verification

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCRIPT_NAME="app_security.sh"
LOG_FILE="/tmp/albator_app_security.log"
BACKUP_DIR="/tmp/albator_backup/app_security"
DRY_RUN=${DRY_RUN:-false}
ALBATOR_TEST_ALLOW_DRYRUN_NO_SUDO=${ALBATOR_TEST_ALLOW_DRYRUN_NO_SUDO:-false}

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
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Source common utilities
source "$(dirname "$0")"/utils.sh

# Dependency check
check_dependencies() {
    local missing=()
    for cmd in spctl codesign xattr; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "ERROR: Missing required tools: ${missing[*]}" >&2
        echo "These are macOS system tools. Please ensure you are running on macOS." >&2
        exit 1
    fi
}
check_dependencies

# Function to backup current app security settings
backup_app_security_settings() {
    show_progress "Backing up current application security settings..."
    
    mkdir -p "$BACKUP_DIR"
    
    local backup_file="$BACKUP_DIR/app_security_settings_$(date +%Y%m%d_%H%M%S).backup"
    
    {
        echo "# Application Security backup created on $(date)"
        echo "GATEKEEPER_STATUS=$(spctl --status 2>/dev/null || echo 'unknown')"
        echo "GATEKEEPER_GLOBAL=$(spctl --status --verbose 2>/dev/null || echo 'unknown')"
        echo "SIP_STATUS=$(csrutil status 2>/dev/null || echo 'unknown')"
        echo "QUARANTINE_EVENTS=$(sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV* 'SELECT COUNT(*) FROM LSQuarantineEvent;' 2>/dev/null || echo 'unknown')"
        echo "XPC_SERVICE_STATUS=$(launchctl print system | grep -c 'com.apple.xpc' 2>/dev/null || echo 'unknown')"
    } > "$backup_file"
    
    log "INFO" "Application security settings backed up to $backup_file"
}

# Function to check System Integrity Protection (SIP)
check_sip_status() {
    show_progress "Checking System Integrity Protection (SIP) status..."
    
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    
    if [[ "$sip_status" == *"enabled"* ]]; then
        show_success "System Integrity Protection is enabled"
        return 0
    elif [[ "$sip_status" == *"disabled"* ]]; then
        show_warning "System Integrity Protection is disabled"
        show_warning "SIP provides important security protections"
        return 1
    else
        show_error "Unable to determine SIP status: $sip_status"
        return 2
    fi
}

# Function to configure Gatekeeper
configure_gatekeeper() {
    local errors=0
    
    show_progress "Configuring Gatekeeper..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        show_warning "DRY RUN: Would enable Gatekeeper"
        record_plan_action "gatekeeper" "Enable Gatekeeper" "sudo spctl --master-enable"
        return 0
    fi
    
    # Check current status
    local current_status
    current_status=$(spctl --status 2>/dev/null || echo "unknown")
    
    if [[ "$current_status" == *"assessments enabled"* ]]; then
        show_success "Gatekeeper is already enabled"
        record_noop "Gatekeeper already enabled"
    else
        show_progress "Enabling Gatekeeper..."
        
        if sudo spctl --master-enable 2>>"$LOG_FILE"; then
            show_success "Gatekeeper enabled successfully"
            record_rollback_change "gatekeeper" "enabled"
        else
            show_error "Failed to enable Gatekeeper"
            ((errors++))
        fi
    fi
    
    # Configure additional Gatekeeper settings
    show_progress "Configuring Gatekeeper policies..."
    
    # Enable assessment for all applications
    if sudo spctl --enable 2>>"$LOG_FILE"; then
        show_success "Gatekeeper assessment enabled for all applications"
        record_rollback_change "gatekeeper_assessment" "enabled for all applications"
    else
        show_warning "Failed to enable Gatekeeper assessment"
        ((errors++))
    fi
    
    # Configure developer ID policy
    if sudo spctl --enable --label "Developer ID" 2>>"$LOG_FILE"; then
        show_success "Developer ID policy enabled"
    else
        show_warning "Failed to enable Developer ID policy"
    fi
    
    return $errors
}

# Function to check application signatures
check_application_signatures() {
    show_progress "Checking application signatures..."
    
    local critical_apps=(
        "/Applications/Safari.app"
        "/System/Applications/Mail.app"
        "/System/Applications/Messages.app"
        "/Applications/App Store.app"
        "/System/Applications/System Preferences.app"
    )
    
    local unsigned_apps=()
    local hardened_apps=()
    local non_hardened_apps=()
    
    for app in "${critical_apps[@]}"; do
        if [[ -d "$app" ]]; then
            show_progress "Checking: $(basename "$app")"
            
            # Check code signature
            if codesign -dv "$app" 2>/dev/null; then
                show_success "✓ $(basename "$app") is properly signed"
                
                # Check for Hardened Runtime
                if codesign -dv --verbose "$app" 2>&1 | grep -q "hardened"; then
                    hardened_apps+=("$(basename "$app")")
                    show_success "  ✓ Uses Hardened Runtime"
                else
                    non_hardened_apps+=("$(basename "$app")")
                    show_warning "  ⚠ Does not use Hardened Runtime"
                fi
            else
                unsigned_apps+=("$(basename "$app")")
                show_error "✗ $(basename "$app") signature verification failed"
            fi
        else
            show_warning "Application not found: $app"
        fi
    done
    
    # Summary
    echo ""
    show_progress "Application Security Summary:"
    echo "Signed applications: $((${#critical_apps[@]} - ${#unsigned_apps[@]}))"
    echo "Hardened Runtime apps: ${#hardened_apps[@]}"
    echo "Non-hardened apps: ${#non_hardened_apps[@]}"
    echo "Unsigned/problematic apps: ${#unsigned_apps[@]}"
    
    if [[ ${#unsigned_apps[@]} -gt 0 ]]; then
        show_warning "Unsigned applications detected: ${unsigned_apps[*]}"
        return 1
    fi
    
    return 0
}

# Function to check and configure quarantine system
configure_quarantine_system() {
    show_progress "Configuring quarantine system..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        show_warning "DRY RUN: Would configure quarantine system"
        record_plan_action "quarantine" "Configure quarantine system" "verify quarantine database and xattrs"
        return 0
    fi
    
    # Check quarantine database
    local quarantine_db="$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV*"
    
    if ls $quarantine_db >/dev/null 2>&1; then
        local event_count
        event_count=$(sqlite3 $quarantine_db 'SELECT COUNT(*) FROM LSQuarantineEvent;' 2>/dev/null || echo "0")
        show_success "Quarantine system is active (${event_count} events recorded)"
    else
        show_warning "Quarantine database not found or inaccessible"
    fi
    
    # Verify quarantine attributes on downloaded files
    show_progress "Checking quarantine attribute handling..."
    
    # Test with Downloads folder if it exists
    if [[ -d "$HOME/Downloads" ]]; then
        local quarantined_files
        quarantined_files=$(find "$HOME/Downloads" -maxdepth 1 -type f -exec xattr -l {} \; 2>/dev/null | grep -c "com.apple.quarantine" || echo "0")
        
        if [[ "$quarantined_files" -gt 0 ]]; then
            show_success "Quarantine attributes found on $quarantined_files files"
        else
            show_warning "No quarantine attributes found in Downloads folder"
        fi
    fi
}

# Function to perform modern macOS security checks
macos_modern_security_checks() {
    show_progress "Performing modern macOS security checks..."
    
    local macos_version
    macos_version=$(sw_vers -productVersion)
    
    local min_macos
    min_macos=$(get_min_macos_version)
    if [[ "$macos_version" != "$min_macos"* ]]; then
        show_warning "Modern checks tuned for baseline >= $min_macos (current version: $macos_version)"
        return 0
    fi

    show_progress "Enhanced Hardened Runtime verification..."

    # Check for modern security features
    local security_features=(
        "Library Validation"
        "Runtime Exceptions"
        "JIT Compilation"
        "Debugging Tool Access"
        "DTrace Access"
    )
    
    for feature in "${security_features[@]}"; do
        show_progress "Checking: $feature"
        show_warning "$feature check is a placeholder - implement specific verification"
    done
    
    # Check for new XPC service security
    show_progress "Checking XPC service security..."
    local xpc_services
    xpc_services=$(launchctl print system | grep -c "com.apple.xpc" 2>/dev/null || echo "0")
    show_success "XPC services detected: $xpc_services"
    
    # Check for enhanced code signing requirements
    show_progress "Checking enhanced code signing requirements..."
    if spctl --assess --verbose /Applications/Safari.app 2>&1 | grep -q "accepted"; then
        show_success "Enhanced code signing verification passed"
    else
        show_warning "Enhanced code signing verification needs attention"
    fi

    # Lockdown mode marker check (best-effort non-failing probe)
    show_progress "Checking Lockdown Mode service marker..."
    if defaults read /Library/Preferences/com.apple.configurationprofiles.plist _computerLevel >/dev/null 2>&1; then
        show_success "Lockdown Mode/profile store is reachable"
    else
        show_warning "Lockdown Mode/profile marker not readable in current context"
    fi
}

# Function to verify all application security settings
verify_app_security_settings() {
    local errors=0
    
    show_progress "Verifying application security configuration..."
    
    # Verify Gatekeeper
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    
    if [[ "$gk_status" == *"assessments enabled"* ]]; then
        show_success "✓ Gatekeeper is enabled"
    else
        show_error "✗ Gatekeeper is not enabled: $gk_status"
        ((errors++))
    fi
    
    # Verify SIP
    if check_sip_status >/dev/null 2>&1; then
        show_success "✓ System Integrity Protection is enabled"
    else
        show_warning "⚠ System Integrity Protection status unclear"
    fi
    
    # Verify code signing assessment
    if spctl --assess --verbose /System/Applications/Calculator.app 2>&1 | grep -q "accepted"; then
        show_success "✓ Code signing assessment working"
    else
        show_error "✗ Code signing assessment failed"
        ((errors++))
    fi
    
    # Check for unsigned applications in common locations
    show_progress "Scanning for unsigned applications..."
    local app_dirs=("/Applications" "/System/Applications")
    local unsigned_count=0
    
    for dir in "${app_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' app; do
                if ! codesign -dv "$app" >/dev/null 2>&1; then
                    show_warning "Unsigned application: $(basename "$app")"
                    ((unsigned_count++))
                fi
            done < <(find "$dir" -maxdepth 1 -name "*.app" -print0 2>/dev/null)
        fi
    done
    
    if [[ $unsigned_count -eq 0 ]]; then
        show_success "✓ No unsigned applications found in system directories"
    else
        show_warning "⚠ Found $unsigned_count unsigned applications"
    fi
    
    return $errors
}

# Function to display application security summary
display_app_security_summary() {
    show_progress "Application Security Configuration Summary:"
    echo "============================================="
    
    # Gatekeeper status
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "Error getting status")
    printf "%-30s: %s\n" "Gatekeeper Status" "$gk_status"
    
    # SIP status
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "Error getting status")
    printf "%-30s: %s\n" "System Integrity Protection" "$sip_status"
    
    # Code signing policy
    local cs_policy
    cs_policy=$(spctl --status --verbose 2>/dev/null | head -1 || echo "Unknown")
    printf "%-30s: %s\n" "Code Signing Policy" "$cs_policy"
    
    # Quarantine system
    local quarantine_status="Active"
    if ! ls "$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV*" >/dev/null 2>&1; then
        quarantine_status="Inactive or inaccessible"
    fi
    printf "%-30s: %s\n" "Quarantine System" "$quarantine_status"
    
    echo "============================================="
}

# Function to provide security recommendations
provide_security_recommendations() {
    show_progress "Security Recommendations:"
    echo ""
    echo "Best Practices:"
    echo "• Keep Gatekeeper enabled at all times"
    echo "• Only install applications from trusted sources"
    echo "• Regularly update applications to latest versions"
    echo "• Verify application signatures before installation"
    echo "• Monitor quarantine events for suspicious downloads"
    echo "• Do not disable System Integrity Protection"
    echo ""
    echo "For Developers:"
    echo "• Use Hardened Runtime for your applications"
    echo "• Implement proper code signing practices"
    echo "• Test applications with Gatekeeper enabled"
    echo "• Follow Apple's security guidelines"
    echo ""
}

# Main execution
main() {
    echo "Albator Application Security Configuration Script"
    echo "================================================"
    
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
    log "INFO" "Starting application security configuration script"
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
        if [[ "$DRY_RUN" == "true" && "$ALBATOR_TEST_ALLOW_DRYRUN_NO_SUDO" == "true" ]]; then
            show_warning "Proceeding in dry-run test mode without sudo"
        else
            show_error "This script requires sudo privileges"
            exit 1
        fi
    fi
    
    # Backup current settings
    backup_app_security_settings
    
    # Check System Integrity Protection
    check_sip_status || true  # Don't fail if disabled
    
    # Run application security configuration
    local config_errors=0
    configure_gatekeeper || config_errors=$?
    
    # Check application signatures
    check_application_signatures || ((config_errors++))
    
    # Configure quarantine system
    configure_quarantine_system || ((config_errors++))
    
    # Modern macOS checks
    macos_modern_security_checks || ((config_errors++))
    
    # Run verification
    local verify_errors=0
    if [[ "$DRY_RUN" == "true" ]]; then
        show_warning "Skipping verification in dry-run mode"
    else
        verify_app_security_settings || verify_errors=$?
    fi
    
    # Display summary
    display_app_security_summary
    
    # Provide recommendations
    provide_security_recommendations
    
    # Summary
    local total_errors=$((config_errors + verify_errors))
    
    echo ""
    echo "================================================"
    if [[ $total_errors -eq 0 ]]; then
        show_success "Application security configuration completed successfully!"
        log "INFO" "Application security configuration completed successfully"
        exit_with_status 0
    else
        show_error "Application security configuration completed with $total_errors errors"
        show_error "Check log file: $LOG_FILE"
        log "ERROR" "Application security configuration completed with $total_errors errors"
        exit_with_status "$total_errors"
    fi
}

# Run main function with all arguments
main "$@"
