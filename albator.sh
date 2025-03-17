#!/bin/bash

<<<<<<< HEAD
# Help function to display usage
show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -f, --firewall      Enable and configure the firewall"
    echo "  -p, --privacy       Adjust privacy settings"
    echo "  -e, --encryption    Enable FileVault encryption"
    echo "  -s, --app-security  Enable Gatekeeper and verify Hardened Runtime"
    echo "  -c, --cve          Fetch recent CVE advisories"
    echo "  -a, --apple        Fetch Apple security updates"
    echo "  -g, --generate     Generate guidance (pass args to generate_guidance.py)"
    echo "  -l, --list_tags    List tags from generate_guidance.py"
    echo "  -k, --keyword      Search by keyword in generate_guidance.py"
    echo "  -h, --help         Display this help message"
    exit 1
}

# Check if any options were provided
if [ $# -eq 0 ]; then
    echo "No options provided. Use -h or --help for usage information."
    exit 1
fi

# Parse command-line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--firewall)
            ./firewall.sh
            exit 0
            ;;
        -p|--privacy)
            ./privacy.sh
            exit 0
            ;;
        -e|--encryption)
            ./encryption.sh
            exit 0
            ;;
        -s|--app-security)
            ./app_security.sh
            exit 0
            ;;
        -c|--cve)
            ./cve_fetch.sh
            exit 0
            ;;
        -a|--apple)
            ./apple_updates.sh
            exit 0
            ;;
        -g|--generate)
            ROOT_DIR="$PWD" python3 generate_guidance.py "${@:2}"
            exit 0
            ;;
        -l|--list_tags)
            ROOT_DIR="$PWD" python3 generate_guidance.py -l
            exit 0
            ;;
        -k|--keyword)
            python3 generate_guidance.py -k "${@:2}"
            exit 0
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            show_help
=======
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
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
>>>>>>> edd7c1348c8bd688ed4da3c14fc23a91ade5dfe4
            ;;
    esac
done
<<<<<<< HEAD
=======

# If no options are provided, show usage
if [ "$FIREWALL" = false ] && [ "$PRIVACY" = false ] && [ "$ENCRYPTION" = false ] && [ "$APP_SECURITY" = false ] && [ "$CVE" = false ] && [ "$APPLE" = false ]; then
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

echo "Operation complete!"
>>>>>>> edd7c1348c8bd688ed4da3c14fc23a91ade5dfe4
