#!/bin/bash

# Display the new ASCII art for Albator
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+.             +@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                   .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%     -@@-   .%@@      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  . +@@@@@@  @@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.  -@@@@@@@@  @@@@@@@@.  +@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ .@@@@@@@@@   +@@@@@@@@.  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@. +@@@@@@@@*    @@@@@@@@@: @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  #@@@@@@@%      %@@@@@@@. :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   :@@@@@-  -@@-   @@@@@   =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@          @@@@@@         .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                      .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@   -      +   @@@@  +@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@   *  :   @  .@@@@  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    @@@@@%%  +=  @#@@@@@.      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       +@@@@@@@@@@@@@@@@@   .   .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@. #@%   .@@@@@@@@@@@@:    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  ..@@@@@@@%.  .%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     @@    .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      @@@@ .   +@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+   . @@@@@@@@@% .  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        =@@@@@@@@@@@@@@-        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@@@+   .-@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@%   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+@@@@@@@@@@@@@@@@@@@@  :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

echo " █████╗ ██╗     ██████╗  █████╗ ████████╗ ██████╗ ██████╗ "
echo "██╔══██╗██║     ██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗"
echo "███████║██║     ██████╔╝███████║   ██║   ██║   ██║██████╔╝"
echo "██╔══██║██║     ██╔══██╗██╔══██║   ██║   ██║   ██║██╔══██╗"
echo "██║  ██║███████╗██████╔╝██║  ██║   ██║   ╚██████╔╝██║  ██║"
echo "╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝"

echo "Albator - macOS 15 Hardening Tool"
echo "--------------------------------"

# Function to check macOS version
check_macos_version() {
    if [[ $(sw_vers -productVersion) != "15"* ]]; then
        echo "Error: This tool is designed for macOS 15 (Sequoia)."
        exit 1
    fi
}

# Function to display usage
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -f, --firewall      Enable and configure firewall"
    echo "  -p, --privacy      Adjust privacy settings"
    echo "  -e, --encryption   Enable encryption (FileVault)"
    echo "  -s, --app-security Enable Gatekeeper and verify Hardened Runtime"
    echo "  -c, --cve          Fetch recent CVE advisories relevant to macOS"
    echo "  -a, --apple        Fetch Apple security updates for macOS Sequoia 15"
    echo "  -r, --report         Generate a security report"
    echo "  -n, --ansible        Run the Ansible playbook to automate hardening"
    echo "  -t, --test           Run automated security tests"
    echo "  -h, --help         Display this help message"
    exit 1
}

# Check macOS version
check_macos_version

# Default flags
FIREWALL=false
PRIVACY=false
ENCRYPTION=false
APP_SECURITY=false
CVE=false
APPLE=false
REPORT=false
ANSIBLE=false
TEST=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--firewall)
            FIREWALL=true
            shift
            ;;
        -p|--privacy)
            PRIVACY=true
            shift
            ;;
        -e|--encryption)
            ENCRYPTION=true
            shift
            ;;
        -s|--app-security)
            APP_SECURITY=true
            shift
            ;;
        -c|--cve)
            CVE=true
            shift
            ;;
        -a|--apple)
            APPLE=true
            shift
            ;;
        -r|--report)
            REPORT=true
            shift
            ;;
        -n|--ansible)
            ANSIBLE=true
            shift
            ;;
        -t|--test)
            TEST=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# If no options are provided, show usage
if [ "$FIREWALL" = false ] && [ "$PRIVACY" = false ] && [ "$ENCRYPTION" = false ] && [ "$APP_SECURITY" = false ] && [ "$CVE" = false ] && [ "$APPLE" = false ] && [ "$REPORT" = false ] && [ "$ANSIBLE" = false ] && [ "$TEST" = false ]; then
    usage
fi

# Run selected scripts
if [ "$FIREWALL" = true ]; then
    echo "Configuring firewall..."
    bash ./firewall.sh
fi

if [ "$PRIVACY" = true ]; then
    echo "Adjusting privacy settings..."
    bash ./privacy.sh
fi

if [ "$ENCRYPTION" = true ]; then
    echo "Enabling encryption..."
    bash ./encryption.sh
fi

if [ "$APP_SECURITY" = true ]; then
    echo "Configuring app security (Gatekeeper, Hardened Runtime)..."
    bash ./app_security.sh
fi

if [ "$CVE" = true ]; then
    echo "Fetching CVE advisories..."
    bash ./cve_fetch.sh
fi

if [ "$APPLE" = true ]; then
    echo "Fetching Apple security updates..."
    bash ./apple_updates.sh
fi

if [ "$REPORT" = true ]; then
    echo "Generating security report..."
    bash ./reporting.sh
fi

if [ "$ANSIBLE" = true ]; then
    echo "Running Ansible playbook..."
    cd ansible && ansible-playbook albator.yml && cd ..
fi

if [ "$TEST" = true ]; then
    echo "Running automated security tests..."
    bash ./tests/test_security.sh
fi

echo "Operation complete!"
