#!/bin/bash

# Albator Utility Functions
# Common functions for logging, status messages, and other utilities

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Function to check for sudo access without password prompt
check_sudo_access() {
    if sudo -n true 2>/dev/null; then
        return 0 # Sudo access without password
    else
        return 1 # Sudo access requires password or is not available
    fi
}
