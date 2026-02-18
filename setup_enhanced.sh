#!/bin/bash

# Albator Enhanced Setup Script
# Installs dependencies and verifies the enhanced platform

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "🛡️  Albator Enhanced Setup Script"
echo "================================="
echo

# Check macOS version
echo "📋 Checking system requirements..."
MACOS_VERSION=$(sw_vers -productVersion)
echo "   macOS Version: $MACOS_VERSION"

if [[ ! "$MACOS_VERSION" == 15.* ]]; then
    echo -e "${YELLOW}⚠️  Warning: This tool is designed for macOS 15.x (Sequoia)${NC}"
    echo "   Current version: $MACOS_VERSION"
    echo "   Some features may not work as expected."
fi

# Check Python version
echo "🐍 Checking Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "   $PYTHON_VERSION"
    
    # Check if Python 3.8+
    PYTHON_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
    PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
    
    if [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -ge 8 ]]; then
        echo -e "   ${GREEN}✅ Python version is compatible${NC}"
    else
        echo -e "   ${RED}❌ Python 3.8+ required${NC}"
        exit 1
    fi
else
    echo -e "   ${RED}❌ Python 3 not found${NC}"
    echo "   Please install Python 3.8+ from https://python.org"
    exit 1
fi

# Check for Homebrew
echo "🍺 Checking Homebrew..."
if command -v brew &> /dev/null; then
    echo -e "   ${GREEN}✅ Homebrew is installed${NC}"
else
    echo -e "   ${YELLOW}⚠️  Homebrew not found${NC}"
    echo "   Install Homebrew from https://brew.sh for system tools"
fi

# Install system tools
echo "🔧 Installing system tools..."
TOOLS=("curl" "jq" "pup")
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "   ${GREEN}✅ $tool is installed${NC}"
    else
        echo -e "   ${YELLOW}⚠️  $tool not found${NC}"
        if command -v brew &> /dev/null; then
            echo "   Installing $tool with Homebrew..."
            brew install "$tool" || echo -e "   ${RED}❌ Failed to install $tool${NC}"
        else
            echo "   Please install $tool manually"
        fi
    fi
done

# Install Python dependencies
echo "📦 Installing Python dependencies..."
if [[ -f "requirements.txt" ]]; then
    echo "   Installing from requirements.txt..."
    pip3 install -r requirements.txt || {
        echo -e "   ${RED}❌ Failed to install Python dependencies${NC}"
        echo "   Try: pip3 install --user -r requirements.txt"
        exit 1
    }
    echo -e "   ${GREEN}✅ Python dependencies installed${NC}"
else
    echo -e "   ${RED}❌ requirements.txt not found${NC}"
    exit 1
fi

# Verify installation
echo "🧪 Verifying installation..."

# Test enhanced CLI
echo "   Testing enhanced CLI..."
if python3 albator_enhanced.py --help > /dev/null 2>&1; then
    echo -e "   ${GREEN}✅ Enhanced CLI is working${NC}"
else
    echo -e "   ${RED}❌ Enhanced CLI failed${NC}"
fi

# Test compliance reporter
echo "   Testing compliance reporter..."
if python3 lib/compliance_reporter.py list > /dev/null 2>&1; then
    echo -e "   ${GREEN}✅ Compliance reporter is working${NC}"
else
    echo -e "   ${RED}❌ Compliance reporter failed${NC}"
fi

# Test analytics dashboard
echo "   Testing analytics dashboard..."
if python3 lib/analytics_dashboard.py --help > /dev/null 2>&1; then
    echo -e "   ${GREEN}✅ Analytics dashboard is working${NC}"
else
    echo -e "   ${RED}❌ Analytics dashboard failed${NC}"
fi

# Test web interface
echo "   Testing web interface..."
if python3 -c "from web.app import app; print('Web interface imports successfully')" > /dev/null 2>&1; then
    echo -e "   ${GREEN}✅ Web interface is ready${NC}"
else
    echo -e "   ${RED}❌ Web interface failed${NC}"
fi

# Create directories
echo "📁 Creating necessary directories..."
mkdir -p logs
mkdir -p reports
mkdir -p backups
echo -e "   ${GREEN}✅ Directories created${NC}"

# Set permissions
echo "🔐 Setting permissions..."
chmod +x albator_enhanced.py
chmod +x demo_enhanced.py
chmod +x *.sh
echo -e "   ${GREEN}✅ Permissions set${NC}"

echo
echo "🎉 Setup completed successfully!"
echo "================================="
echo
echo "📚 Next steps:"
echo "   1. Run the demo: python3 demo_enhanced.py"
echo "   2. Try the enhanced CLI: python3 albator_enhanced.py --help"
echo "   3. Start the web interface: python3 web/app.py"
echo "   4. Generate a compliance report: python3 albator_enhanced.py compliance --framework custom"
echo
echo "🔗 Key commands:"
echo "   • Comprehensive hardening: python3 albator_enhanced.py harden --profile advanced"
echo "   • Security dashboard: python3 albator_enhanced.py dashboard"
echo "   • Profile management: python3 albator_enhanced.py profile list"
echo "   • Fleet operations: python3 albator_enhanced.py fleet list"
echo
echo "📖 Documentation:"
echo "   • README.md - Complete usage guide"
echo "   • CHANGELOG.md - Recent improvements"
echo "   • VALIDATION_AND_TESTING.md - Validation and testing guide"
echo
echo "🛡️  Albator Enhanced is ready for enterprise security hardening!"
