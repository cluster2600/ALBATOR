#!/bin/bash

# Albator Setup Script
# Prepares the environment and sets up the enhanced Albator system

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "SUCCESS")
            echo -e "${GREEN}✅ SUCCESS${NC}: $message"
            ;;
        "ERROR")
            echo -e "${RED}❌ ERROR${NC}: $message"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  INFO${NC}: $message"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️  WARN${NC}: $message"
            ;;
    esac
}

# Function to check dependencies
check_dependencies() {
    print_status "INFO" "Checking dependencies..."
    
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
        print_status "WARN" "pup not found (optional) - install with: brew install pup"
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_status "ERROR" "Missing required dependencies: ${missing_deps[*]}"
        print_status "INFO" "Install with: brew install ${missing_deps[*]}"
        return 1
    fi
    
    print_status "SUCCESS" "All required dependencies found"
    return 0
}

# Function to check macOS version
check_macos_version() {
    print_status "INFO" "Checking macOS version..."
    
    local version
    version=$(sw_vers -productVersion)
    
    if [[ "$version" == 15.* ]]; then
        print_status "SUCCESS" "macOS 15.x (Sequoia) detected: $version"
        return 0
    else
        print_status "WARN" "This tool is designed for macOS 15.x, detected: $version"
        return 1
    fi
}

# Function to set up directories
setup_directories() {
    print_status "INFO" "Setting up directories..."
    
    # Create necessary directories
    mkdir -p config
    mkdir -p lib
    mkdir -p tests
    mkdir -p build/baselines
    mkdir -p /tmp/albator_backup
    
    print_status "SUCCESS" "Directories created"
}

# Function to set permissions
set_permissions() {
    print_status "INFO" "Setting script permissions..."
    
    # Make scripts executable
    chmod +x albator.sh
    chmod +x privacy.sh
    chmod +x firewall.sh
    chmod +x encryption.sh
    chmod +x app_security.sh
    chmod +x cve_fetch.sh
    chmod +x apple_updates.sh
    chmod +x tests/test_security.sh
    
    # Make Python scripts executable
    chmod +x main.py
    chmod +x albator_cli.py
    chmod +x tests/test_framework.py
    chmod +x lib/logger.py
    chmod +x lib/rollback.py
    
    print_status "SUCCESS" "Script permissions set"
}

# Function to validate configuration
validate_config() {
    print_status "INFO" "Validating configuration..."
    
    if [[ -f "config/albator.yaml" ]]; then
        # Test YAML parsing
        if python3 -c "import yaml; yaml.safe_load(open('config/albator.yaml'))" 2>/dev/null; then
            print_status "SUCCESS" "Configuration file is valid"
        else
            print_status "ERROR" "Configuration file has syntax errors"
            return 1
        fi
    else
        print_status "WARN" "Configuration file not found - using defaults"
    fi
    
    return 0
}

# Function to run basic tests
run_basic_tests() {
    print_status "INFO" "Running basic functionality tests..."
    
    # Test Python imports
    if python3 -c "import sys; sys.path.insert(0, 'lib'); from logger import get_logger; print('Logger import successful')" 2>/dev/null; then
        print_status "SUCCESS" "Python logger module working"
    else
        print_status "ERROR" "Python logger module failed"
        return 1
    fi
    
    # Test rollback system
    if python3 -c "import sys; sys.path.insert(0, 'lib'); from rollback import RollbackManager; print('Rollback import successful')" 2>/dev/null; then
        print_status "SUCCESS" "Python rollback module working"
    else
        print_status "ERROR" "Python rollback module failed"
        return 1
    fi
    
    # Test configuration loading
    if python3 -c "
import sys; sys.path.insert(0, 'lib')
from logger import AlbatorLogger
logger = AlbatorLogger()
print('Configuration loading successful')
" 2>/dev/null; then
        print_status "SUCCESS" "Configuration loading working"
    else
        print_status "ERROR" "Configuration loading failed"
        return 1
    fi
    
    return 0
}

# Function to display usage information
show_usage() {
    echo ""
    echo "Albator Enhanced Setup Complete!"
    echo "================================"
    echo ""
    echo "Quick Start Commands:"
    echo ""
    echo "1. Run comprehensive tests:"
    echo "   ./tests/test_security.sh"
    echo ""
    echo "2. Configure privacy settings (dry-run):"
    echo "   ./privacy.sh --dry-run"
    echo ""
    echo "3. Configure firewall (dry-run):"
    echo "   ./firewall.sh --dry-run"
    echo ""
    echo "4. List available rollback points:"
    echo "   python3 lib/rollback.py --list"
    echo ""
    echo "5. Run Python testing framework:"
    echo "   python3 tests/test_framework.py --verbose"
    echo ""
    echo "6. Edit configuration:"
    echo "   vim config/albator.yaml"
    echo ""
    echo "For more information, see README.md"
}

# Main setup function
main() {
    echo "Albator Enhanced Setup"
    echo "====================="
    echo ""
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        print_status "WARN" "Running as root - some features may not work correctly"
    fi
    
    # Run setup steps
    local errors=0
    
    check_macos_version || ((errors++))
    check_dependencies || ((errors++))
    setup_directories || ((errors++))
    set_permissions || ((errors++))
    validate_config || ((errors++))
    run_basic_tests || ((errors++))
    
    echo ""
    echo "Setup Summary:"
    echo "=============="
    
    if [[ $errors -eq 0 ]]; then
        print_status "SUCCESS" "Setup completed successfully!"
        show_usage
        exit 0
    else
        print_status "ERROR" "Setup completed with $errors errors"
        print_status "INFO" "Please resolve the errors above before using Albator"
        exit 1
    fi
}

# Run main function
main "$@"
