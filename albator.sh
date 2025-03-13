#!/bin/bash

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
            python3 generate_guidance.py "${@:2}"
            exit 0
            ;;
        -l|--list_tags)
            python3 generate_guidance.py -l
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
            ;;
    esac
    shift
done