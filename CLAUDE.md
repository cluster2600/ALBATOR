# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Albator is a macOS 15.5 (Sequoia) security hardening framework with multiple interfaces:
- **Bash Scripts**: Core hardening functionality (firewall, privacy, encryption, app security)
- **Enhanced Python CLI**: Enterprise features with fleet management, compliance reporting, analytics
- **Legacy Python Tools**: Original baseline generation and rule handling
- **Web Interface**: Flask-based GUI with real-time monitoring
- **Ansible Integration**: Automated deployment and configuration management

## Common Commands

### Core Hardening Operations
```bash
# Main script with comprehensive hardening
./albator.sh --firewall --privacy --encryption --app-security --report

# Individual component hardening
./firewall.sh
./privacy.sh --dry-run
./encryption.sh
./app_security.sh --test

# Enhanced CLI with enterprise features
python3 albator_enhanced.py harden --profile enterprise --dry-run
python3 albator_enhanced.py compliance --framework nist_800_53 --format html
python3 albator_enhanced.py dashboard --days 30
```

### Testing and Validation
```bash
# Bash test suite
./tests/test_security.sh
./tests/test_security.sh --dry-run --verbose

# Python testing framework
python3 tests/test_framework.py --verbose --include-scripts
```

### Legacy Python Tools
```bash
# Baseline generation
python3 main.py --list
python3 main.py --baseline
python3 main.py --check
python3 main.py --fix

# CLI interface
python3 albator_cli.py privacy
python3 albator_cli.py firewall
python3 albator_cli.py legacy interactive
```

### Web Interface
```bash
# Start Flask web server
python3 web/app.py
# Access at http://localhost:5000
```

### Fleet Management
```bash
# Manage multiple systems
python3 albator_enhanced.py fleet list
python3 albator_enhanced.py fleet deploy --profile advanced
```

## Architecture

### Core Components
- **albator.sh**: Main entry point that orchestrates individual hardening scripts
- **albator_enhanced.py**: Unified CLI with enterprise features (fleet management, compliance, analytics)
- **main.py**: Legacy baseline generator using NIST 800-53 controls
- **Web Interface**: Flask app in `web/` directory with real-time WebSocket communication

### Key Directories
- **config/**: YAML configuration files for profiles and settings
- **includes/**: NIST 800-53 baselines and metadata
- **tests/**: Comprehensive test suites (Bash and Python)
- **ansible/**: Ansible playbook for automated deployment
- **web/**: Flask web interface with templates and static assets
- **lib/**: Python library modules (logging, config management, analytics)

### Security Scripts Structure
Each hardening script follows a consistent pattern:
- Argument parsing (--dry-run, --help, --test flags)
- Configuration validation
- Rollback point creation
- Security operations with verification
- Status reporting and logging

### Data Flow
1. **Configuration**: YAML files in `config/` define security profiles and settings
2. **Execution**: Scripts apply changes with rollback point creation
3. **Validation**: Test suites verify hardening effectiveness
4. **Reporting**: Generate compliance reports and analytics dashboards
5. **Fleet Operations**: SSH-based deployment to multiple systems

## Development Patterns

### Error Handling
- All scripts use `set -e` for immediate error exit
- Python modules use try/catch with detailed logging
- Rollback points created before major changes
- Comprehensive validation before applying changes

### Configuration Management
- YAML-based configuration with profile inheritance
- Environment variable support for deployment flexibility
- Dry-run mode available across all components
- Centralized logging with rotation and compression

### Testing Strategy
- Unit tests for individual security functions
- Integration tests for complete hardening workflows
- Performance impact measurement
- Security effectiveness validation
- Configuration drift detection

## Dependencies

### System Requirements
- macOS 15.5 (Sequoia)
- Administrator privileges (sudo access)
- Python 3.8+ for enhanced features

### External Tools
- `jq`: JSON parsing for CVE advisories
- `pup`: HTML parsing for Apple security updates (optional, fallback available)
- `curl`: HTTP requests for security data fetching

### Python Packages
Install with: `pip3 install -r requirements.txt`
Key dependencies: PyYAML, Flask, Flask-SocketIO, pandas, matplotlib, paramiko

## Security Considerations

- Never commit secrets or API keys
- Use sudo judiciously with explicit privilege escalation
- Create rollback points before major system changes
- Validate all user inputs and configuration parameters
- Log security operations for audit trails
- Support offline operation when network resources unavailable