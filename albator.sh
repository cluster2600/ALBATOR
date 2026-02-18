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

echo "Albator - macOS Hardening Tool"
echo "--------------------------------"

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

load_preflight_policy() {
    local config_file="config/albator.yaml"
    MIN_MACOS_VERSION="${MIN_MACOS_VERSION:-26.3}"
    ENFORCE_MIN_VERSION="${ENFORCE_MIN_VERSION:-true}"

    if [[ -f "$config_file" ]]; then
        local min_from_cfg
        min_from_cfg=$(sed -n 's/^[[:space:]]*min_macos_version:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' "$config_file" | head -n1)
        local enforce_from_cfg
        enforce_from_cfg=$(sed -n 's/^[[:space:]]*enforce_min_version:[[:space:]]*\(true\|false\)[[:space:]]*$/\1/p' "$config_file" | head -n1)

        [[ -n "$min_from_cfg" ]] && MIN_MACOS_VERSION="$min_from_cfg"
        [[ -n "$enforce_from_cfg" ]] && ENFORCE_MIN_VERSION="$enforce_from_cfg"
    fi
}

# Function to check macOS version policy
check_macos_version() {
    local current_version
    current_version=$(sw_vers -productVersion)
    if [[ "$(version_ge "$current_version" "$MIN_MACOS_VERSION")" != "1" ]]; then
        if [[ "$ENFORCE_MIN_VERSION" == "true" ]]; then
            echo "Error: macOS version $current_version is below required minimum $MIN_MACOS_VERSION."
            exit 1
        fi
        echo "Warning: macOS version $current_version is below recommended minimum $MIN_MACOS_VERSION."
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
    echo "  -a, --apple        Fetch Apple security updates"
    echo "  -r, --report         Generate a security report"
    echo "  -n, --ansible        Run the Ansible playbook to automate hardening"
    echo "  -t, --test           Run automated security tests"
    echo "  -h, --help         Display this help message"
    exit 1
}

# Check macOS version policy
load_preflight_policy
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
