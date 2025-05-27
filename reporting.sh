#!/bin/bash

# Albator Security Reporting Script
# Enhanced with comprehensive reporting, export formats, and integration

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCRIPT_NAME="reporting.sh"
LOG_FILE="/tmp/albator_reporting.log"
REPORT_DIR="${HOME}/.albator/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DRY_RUN=${DRY_RUN:-false}
VERBOSE=${VERBOSE:-false}
OUTPUT_FORMAT=${OUTPUT_FORMAT:-"console"}  # console, json, html, all

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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

# Function to setup report directory
setup_report_dir() {
    if [[ ! -d "$REPORT_DIR" ]]; then
        mkdir -p "$REPORT_DIR"
        log "INFO" "Created report directory: $REPORT_DIR"
    fi
}

# Function to gather system information
gather_system_info() {
    show_progress "Gathering system information..."
    
    local system_info=$(cat <<EOF
{
    "hostname": "$(hostname)",
    "macos_version": "$(sw_vers -productVersion)",
    "macos_build": "$(sw_vers -buildVersion)",
    "hardware_model": "$(sysctl -n hw.model)",
    "cpu_type": "$(sysctl -n machdep.cpu.brand_string)",
    "memory": "$(sysctl -n hw.memsize | awk '{print $1/1024/1024/1024" GB"}')",
    "disk_usage": "$(df -h / | tail -1 | awk '{print $5}')",
    "uptime": "$(uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')",
    "report_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "albator_version": "3.0.0"
}
EOF
)
    echo "$system_info"
}

# Function to check security status
check_security_status() {
    show_progress "Checking security configurations..."
    
    local security_status=$(cat <<EOF
{
    "firewall": {
        "enabled": $(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled" && echo "true" || echo "false"),
        "stealth_mode": $(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -q "enabled" && echo "true" || echo "false"),
        "logging": $(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode 2>/dev/null | grep -q "on" && echo "true" || echo "false")
    },
    "filevault": {
        "enabled": $(fdesetup status 2>/dev/null | grep -q "On" && echo "true" || echo "false"),
        "status": "$(fdesetup status 2>/dev/null || echo "Unknown")"
    },
    "gatekeeper": {
        "enabled": $(spctl --status 2>/dev/null | grep -q "enabled" && echo "true" || echo "false"),
        "status": "$(spctl --status 2>/dev/null || echo "Unknown")"
    },
    "sip": {
        "enabled": $(csrutil status 2>/dev/null | grep -q "enabled" && echo "true" || echo "false"),
        "status": "$(csrutil status 2>/dev/null || echo "Unknown")"
    },
    "automatic_updates": {
        "enabled": $(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null | grep -q "1" && echo "true" || echo "false"),
        "download": $(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null | grep -q "1" && echo "true" || echo "false"),
        "install": $(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null | grep -q "1" && echo "true" || echo "false")
    }
}
EOF
)
    echo "$security_status"
}

# Function to check privacy settings
check_privacy_settings() {
    show_progress "Checking privacy settings..."
    
    local privacy_status=$(cat <<EOF
{
    "location_services": {
        "enabled": $(defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.*.plist LocationServicesEnabled 2>/dev/null | grep -q "1" && echo "true" || echo "false")
    },
    "analytics": {
        "apple_analytics": $(defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit 2>/dev/null | grep -q "0" && echo "false" || echo "true"),
        "siri_analytics": $(defaults read com.apple.assistant.support "Siri Data Sharing Opt-In Status" 2>/dev/null | grep -q "0" && echo "false" || echo "true")
    },
    "advertising": {
        "personalized_ads": $(defaults read com.apple.AdLib allowApplePersonalizedAdvertising 2>/dev/null | grep -q "0" && echo "false" || echo "true"),
        "ad_tracking": $(defaults read com.apple.AdLib allowIdentifierForAdvertising 2>/dev/null | grep -q "0" && echo "false" || echo "true")
    }
}
EOF
)
    echo "$privacy_status"
}

# Function to generate compliance summary
generate_compliance_summary() {
    show_progress "Generating compliance summary..."
    
    local firewall_status=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled" && echo "true" || echo "false")
    local filevault_status=$(fdesetup status 2>/dev/null | grep -q "On" && echo "true" || echo "false")
    local gatekeeper_status=$(spctl --status 2>/dev/null | grep -q "enabled" && echo "true" || echo "false")
    local sip_status=$(csrutil status 2>/dev/null | grep -q "enabled" && echo "true" || echo "false")
    
    local total_checks=4
    local passed_checks=0
    
    [[ "$firewall_status" == "true" ]] && ((passed_checks++))
    [[ "$filevault_status" == "true" ]] && ((passed_checks++))
    [[ "$gatekeeper_status" == "true" ]] && ((passed_checks++))
    [[ "$sip_status" == "true" ]] && ((passed_checks++))
    
    local compliance_score=$((passed_checks * 100 / total_checks))
    
    local compliance_summary=$(cat <<EOF
{
    "compliance_score": $compliance_score,
    "total_checks": $total_checks,
    "passed_checks": $passed_checks,
    "failed_checks": $((total_checks - passed_checks)),
    "critical_findings": [],
    "recommendations": []
}
EOF
)
    
    # Add findings and recommendations
    if [[ "$firewall_status" == "false" ]]; then
        compliance_summary=$(echo "$compliance_summary" | jq '.critical_findings += ["Firewall is disabled"]')
        compliance_summary=$(echo "$compliance_summary" | jq '.recommendations += ["Enable Application Firewall for network protection"]')
    fi
    
    if [[ "$filevault_status" == "false" ]]; then
        compliance_summary=$(echo "$compliance_summary" | jq '.critical_findings += ["FileVault disk encryption is disabled"]')
        compliance_summary=$(echo "$compliance_summary" | jq '.recommendations += ["Enable FileVault to encrypt disk contents"]')
    fi
    
    if [[ "$gatekeeper_status" == "false" ]]; then
        compliance_summary=$(echo "$compliance_summary" | jq '.critical_findings += ["Gatekeeper is disabled"]')
        compliance_summary=$(echo "$compliance_summary" | jq '.recommendations += ["Enable Gatekeeper to verify app signatures"]')
    fi
    
    if [[ "$sip_status" == "false" ]]; then
        compliance_summary=$(echo "$compliance_summary" | jq '.critical_findings += ["System Integrity Protection is disabled"]')
        compliance_summary=$(echo "$compliance_summary" | jq '.recommendations += ["Enable SIP for system protection"]')
    fi
    
    echo "$compliance_summary"
}

# Function to check recent changes
check_recent_changes() {
    show_progress "Checking recent security-related changes..."
    
    local recent_changes=$(cat <<EOF
{
    "system_log_entries": $(sudo log show --predicate 'eventMessage contains "security" OR eventMessage contains "firewall" OR eventMessage contains "gatekeeper"' --last 24h --style json 2>/dev/null | jq length || echo "0"),
    "software_updates": $(softwareupdate -l 2>&1 | grep -E "^\*" | wc -l | xargs),
    "last_update_check": "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate LastSuccessfulDate 2>/dev/null || echo "Unknown")"
}
EOF
)
    echo "$recent_changes"
}

# Function to generate JSON report
generate_json_report() {
    local system_info=$1
    local security_status=$2
    local privacy_status=$3
    local compliance_summary=$4
    local recent_changes=$5
    
    local json_report=$(cat <<EOF
{
    "report_metadata": {
        "report_id": "albator_security_report_$TIMESTAMP",
        "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
        "report_type": "comprehensive_security_assessment",
        "tool_version": "3.0.0"
    },
    "system_information": $system_info,
    "security_status": $security_status,
    "privacy_settings": $privacy_status,
    "compliance_summary": $compliance_summary,
    "recent_changes": $recent_changes
}
EOF
)
    echo "$json_report"
}

# Function to generate HTML report
generate_html_report() {
    local json_report=$1
    local compliance_score=$(echo "$json_report" | jq -r '.compliance_summary.compliance_score')
    local critical_findings=$(echo "$json_report" | jq -r '.compliance_summary.critical_findings | length')
    
    local html_report=$(cat <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Albator Security Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #2c3e50; margin-bottom: 10px; }
        .score-container { text-align: center; margin: 30px 0; }
        .score { font-size: 72px; font-weight: bold; }
        .score-good { color: #27ae60; }
        .score-warning { color: #f39c12; }
        .score-danger { color: #e74c3c; }
        .section { margin: 30px 0; }
        .section h2 { color: #34495e; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
        .status-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .status-table th, .status-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }
        .status-table th { background: #f8f9fa; font-weight: 600; }
        .status-enabled { color: #27ae60; font-weight: bold; }
        .status-disabled { color: #e74c3c; font-weight: bold; }
        .finding { background: #fee; padding: 15px; margin: 10px 0; border-left: 4px solid #e74c3c; border-radius: 5px; }
        .recommendation { background: #e8f6ff; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; border-radius: 5px; }
        .system-info { background: #f8f9fa; padding: 20px; border-radius: 5px; }
        .system-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .info-item { padding: 10px; }
        .info-label { font-weight: 600; color: #7f8c8d; font-size: 14px; }
        .info-value { font-size: 16px; color: #2c3e50; margin-top: 5px; }
        @media print { body { background: white; } .container { box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Albator Security Report</h1>
            <p>Comprehensive macOS Security Assessment</p>
            <p>Generated: REPORT_DATE</p>
        </div>
        
        <div class="score-container">
            <div class="score SCORE_CLASS">COMPLIANCE_SCORE%</div>
            <p>Overall Security Compliance Score</p>
        </div>
        
        <div class="section">
            <h2>System Information</h2>
            <div class="system-info">
                <div class="system-info-grid">
                    SYSTEM_INFO_CONTENT
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Security Status</h2>
            <table class="status-table">
                <tr>
                    <th>Security Feature</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
                SECURITY_STATUS_ROWS
            </table>
        </div>
        
        <div class="section">
            <h2>Critical Findings</h2>
            CRITICAL_FINDINGS_CONTENT
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            RECOMMENDATIONS_CONTENT
        </div>
    </div>
</body>
</html>
EOF
)
    
    # Determine score class
    local score_class="score-danger"
    if [[ $compliance_score -ge 80 ]]; then
        score_class="score-good"
    elif [[ $compliance_score -ge 60 ]]; then
        score_class="score-warning"
    fi
    
    # Generate system info content
    local system_info_content=""
    system_info_content+="<div class='info-item'><div class='info-label'>Hostname</div><div class='info-value'>$(echo "$json_report" | jq -r '.system_information.hostname')</div></div>"
    system_info_content+="<div class='info-item'><div class='info-label'>macOS Version</div><div class='info-value'>$(echo "$json_report" | jq -r '.system_information.macos_version')</div></div>"
    system_info_content+="<div class='info-item'><div class='info-label'>Hardware Model</div><div class='info-value'>$(echo "$json_report" | jq -r '.system_information.hardware_model')</div></div>"
    system_info_content+="<div class='info-item'><div class='info-label'>Report Date</div><div class='info-value'>$(echo "$json_report" | jq -r '.system_information.report_date')</div></div>"
    
    # Generate security status rows
    local security_status_rows=""
    local firewall_status=$(echo "$json_report" | jq -r '.security_status.firewall.enabled')
    security_status_rows+="<tr><td>Application Firewall</td><td class='$([ "$firewall_status" = "true" ] && echo "status-enabled" || echo "status-disabled")'>"
    security_status_rows+="$([ "$firewall_status" = "true" ] && echo "Enabled" || echo "Disabled")</td>"
    security_status_rows+="<td>$(echo "$json_report" | jq -r '.security_status.firewall | to_entries | map("\(.key): \(.value)") | join(", ")')</td></tr>"
    
    local filevault_status=$(echo "$json_report" | jq -r '.security_status.filevault.enabled')
    security_status_rows+="<tr><td>FileVault Encryption</td><td class='$([ "$filevault_status" = "true" ] && echo "status-enabled" || echo "status-disabled")'>"
    security_status_rows+="$([ "$filevault_status" = "true" ] && echo "Enabled" || echo "Disabled")</td>"
    security_status_rows+="<td>$(echo "$json_report" | jq -r '.security_status.filevault.status')</td></tr>"
    
    local gatekeeper_status=$(echo "$json_report" | jq -r '.security_status.gatekeeper.enabled')
    security_status_rows+="<tr><td>Gatekeeper</td><td class='$([ "$gatekeeper_status" = "true" ] && echo "status-enabled" || echo "status-disabled")'>"
    security_status_rows+="$([ "$gatekeeper_status" = "true" ] && echo "Enabled" || echo "Disabled")</td>"
    security_status_rows+="<td>$(echo "$json_report" | jq -r '.security_status.gatekeeper.status')</td></tr>"
    
    local sip_status=$(echo "$json_report" | jq -r '.security_status.sip.enabled')
    security_status_rows+="<tr><td>System Integrity Protection</td><td class='$([ "$sip_status" = "true" ] && echo "status-enabled" || echo "status-disabled")'>"
    security_status_rows+="$([ "$sip_status" = "true" ] && echo "Enabled" || echo "Disabled")</td>"
    security_status_rows+="<td>$(echo "$json_report" | jq -r '.security_status.sip.status')</td></tr>"
    
    # Generate critical findings
    local critical_findings_content=""
    if [[ $critical_findings -eq 0 ]]; then
        critical_findings_content="<p style='color: #27ae60;'>✅ No critical security findings detected.</p>"
    else
        echo "$json_report" | jq -r '.compliance_summary.critical_findings[]' | while read -r finding; do
            critical_findings_content+="<div class='finding'>⚠️ $finding</div>"
        done
    fi
    
    # Generate recommendations
    local recommendations_content=""
    echo "$json_report" | jq -r '.compliance_summary.recommendations[]' | while read -r recommendation; do
        recommendations_content+="<div class='recommendation'>💡 $recommendation</div>"
    done
    
    if [[ -z "$recommendations_content" ]]; then
        recommendations_content="<p style='color: #27ae60;'>✅ No additional recommendations. System is well configured.</p>"
    fi
    
    # Replace placeholders
    html_report=${html_report//REPORT_DATE/$(date)}
    html_report=${html_report//COMPLIANCE_SCORE/$compliance_score}
    html_report=${html_report//SCORE_CLASS/$score_class}
    html_report=${html_report//SYSTEM_INFO_CONTENT/$system_info_content}
    html_report=${html_report//SECURITY_STATUS_ROWS/$security_status_rows}
    html_report=${html_report//CRITICAL_FINDINGS_CONTENT/$critical_findings_content}
    html_report=${html_report//RECOMMENDATIONS_CONTENT/$recommendations_content}
    
    echo "$html_report"
}

# Function to display console report
display_console_report() {
    local json_report=$1
    
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              🛡️  ALBATOR SECURITY REPORT                         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # System Information
    echo -e "${BLUE}System Information:${NC}"
    echo -e "  Hostname: ${GREEN}$(echo "$json_report" | jq -r '.system_information.hostname')${NC}"
    echo -e "  macOS Version: ${GREEN}$(echo "$json_report" | jq -r '.system_information.macos_version')${NC}"
    echo -e "  Hardware: ${GREEN}$(echo "$json_report" | jq -r '.system_information.hardware_model')${NC}"
    echo ""
    
    # Compliance Score
    local compliance_score=$(echo "$json_report" | jq -r '.compliance_summary.compliance_score')
    echo -e "${BLUE}Security Compliance:${NC}"
    if [[ $compliance_score -ge 80 ]]; then
        echo -e "  Overall Score: ${GREEN}${compliance_score}% ✅${NC}"
    elif [[ $compliance_score -ge 60 ]]; then
        echo -e "  Overall Score: ${YELLOW}${compliance_score}% ⚠️${NC}"
    else
        echo -e "  Overall Score: ${RED}${compliance_score}% ❌${NC}"
    fi
    echo ""
    
    # Security Status
    echo -e "${BLUE}Security Features:${NC}"
    local firewall=$(echo "$json_report" | jq -r '.security_status.firewall.enabled')
    echo -e "  Firewall: $([ "$firewall" = "true" ] && echo -e "${GREEN}Enabled ✓${NC}" || echo -e "${RED}Disabled ✗${NC}")"
    
    local filevault=$(echo "$json_report" | jq -r '.security_status.filevault.enabled')
    echo -e "  FileVault: $([ "$filevault" = "true" ] && echo -e "${GREEN}Enabled ✓${NC}" || echo -e "${RED}Disabled ✗${NC}")"
    
    local gatekeeper=$(echo "$json_report" | jq -r '.security_status.gatekeeper.enabled')
    echo -e "  Gatekeeper: $([ "$gatekeeper" = "true" ] && echo -e "${GREEN}Enabled ✓${NC}" || echo -e "${RED}Disabled ✗${NC}")"
    
    local sip=$(echo "$json_report" | jq -r '.security_status.sip.enabled')
    echo -e "  SIP: $([ "$sip" = "true" ] && echo -e "${GREEN}Enabled ✓${NC}" || echo -e "${RED}Disabled ✗${NC}")"
    echo ""
    
    # Critical Findings
    local findings_count=$(echo "$json_report" | jq -r '.compliance_summary.critical_findings | length')
    if [[ $findings_count -gt 0 ]]; then
        echo -e "${RED}Critical Findings:${NC}"
        echo "$json_report" | jq -r '.compliance_summary.critical_findings[]' | while read -r finding; do
            echo -e "  ${RED}⚠${NC}  $finding"
        done
        echo ""
    fi
    
    # Recommendations
    local recommendations_count=$(echo "$json_report" | jq -r '.compliance_summary.recommendations | length')
    if [[ $recommendations_count -gt 0 ]]; then
        echo -e "${YELLOW}Recommendations:${NC}"
        echo "$json_report" | jq -r '.compliance_summary.recommendations[]' | while read -r recommendation; do
            echo -e "  ${YELLOW}→${NC} $recommendation"
        done
        echo ""
    fi
    
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
}

# Main execution
main() {
    echo "Albator Security Reporting"
    echo "========================="
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --format <format>  Output format: console, json, html, all (default: console)"
                echo "  --verbose, -v      Enable verbose output"
                echo "  --help, -h         Show this help message"
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
    log "INFO" "Starting security report generation"
    
    # Setup report directory
    setup_report_dir
    
    # Gather all information
    local system_info=$(gather_system_info)
    local security_status=$(check_security_status)
    local privacy_status=$(check_privacy_settings)
    local compliance_summary=$(generate_compliance_summary)
    local recent_changes=$(check_recent_changes)
    
    # Generate JSON report
    local json_report=$(generate_json_report "$system_info" "$security_status" "$privacy_status" "$compliance_summary" "$recent_changes")
    
    # Output based on format
    case $OUTPUT_FORMAT in
        json)
            local json_file="$REPORT_DIR/albator_security_report_${TIMESTAMP}.json"
            echo "$json_report" | jq '.' > "$json_file"
            show_success "JSON report saved to: $json_file"
            ;;
        html)
            local html_file="$REPORT_DIR/albator_security_report_${TIMESTAMP}.html"
            generate_html_report "$json_report" > "$html_file"
            show_success "HTML report saved to: $html_file"
            echo "Open in browser: open $html_file"
            ;;
        all)
            # Generate all formats
            local json_file="$REPORT_DIR/albator_security_report_${TIMESTAMP}.json"
            echo "$json_report" | jq '.' > "$json_file"
            show_success "JSON report saved to: $json_file"
            
            local html_file="$REPORT_DIR/albator_security_report_${TIMESTAMP}.html"
            generate_html_report "$json_report" > "$html_file"
            show_success "HTML report saved to: $html_file"
            
            # Also display console report
            display_console_report "$json_report"
            ;;
        console|*)
            display_console_report "$json_report"
            ;;
    esac
    
    # Summary
    echo ""
    show_success "Security report generation completed"
    echo "Reports directory: $REPORT_DIR"
    
    log "INFO" "Security report generation completed"
}

# Run main function with all arguments
main "$@"
