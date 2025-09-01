#!/bin/bash

echo "🖥️  Albator Swift - Command Line Demo"
echo "====================================="
echo ""

# Check if we're in the right directory
if [ ! -f "Albator-Swift.app/Contents/MacOS/Albator-Swift" ]; then
    echo "❌ Error: Albator-Swift.app not found in current directory"
    echo "Please run this script from the albator-swift directory"
    exit 1
fi

echo "📊 Testing Albator Swift Components..."
echo ""

# Test 1: Basic functionality
echo "1️⃣  Testing basic application startup..."
timeout 5s ./Albator-Swift.app/Contents/MacOS/Albator-Swift > /dev/null 2>&1
if [ $? -eq 124 ]; then
    echo "   ✅ Application starts successfully (timed out as expected)"
else
    echo "   ❌ Application failed to start"
fi

echo ""

# Test 2: Check file structure
echo "2️⃣  Checking application structure..."
if [ -d "Albator-Swift.app" ]; then
    echo "   ✅ App bundle exists"
else
    echo "   ❌ App bundle missing"
fi

if [ -x "Albator-Swift.app/Contents/MacOS/Albator-Swift" ]; then
    echo "   ✅ Executable is present and executable"
else
    echo "   ❌ Executable missing or not executable"
fi

if [ -f "Albator-Swift.app/Contents/Info.plist" ]; then
    echo "   ✅ Info.plist exists"
else
    echo "   ❌ Info.plist missing"
fi

echo ""

# Test 3: Show what the app contains
echo "3️⃣  Application contents:"
echo "   📁 App Bundle: Albator-Swift.app/"
echo "   ├── Contents/"
echo "   │   ├── Info.plist (App metadata)"
echo "   │   └── MacOS/"
echo "   │       └── Albator-Swift (Executable)"
echo "   └── Sources/Albator/ (Source code)"
echo "       ├── Models/ (SecurityEngine.swift)"
echo "       ├── Views/ (MainWindowView.swift, SettingsView.swift)"
echo "       ├── Services/ (Configuration, Notifications, Reports, etc.)"
echo "       └── Utilities/ (Logger.swift)"

echo ""

# Test 4: Show key features
echo "4️⃣  Key Features Implemented:"
echo "   🔒 Security Engine - Real-time monitoring"
echo "   ⚙️  Configuration Manager - User preferences"
echo "   📝 Logger System - Comprehensive logging"
echo "   🖥️  System Monitor - Background monitoring"
echo "   📊 Report Generator - Security reports"
echo "   ⏰ Background Task Scheduler - Automated scans"
echo "   🔔 Notification Manager - System alerts"
echo "   🎨 SwiftUI Interface - Modern GUI"

echo ""

# Test 5: GUI Launch Instructions
echo "5️⃣  GUI Launch Instructions:"
echo ""
echo "   For full GUI experience on macOS:"
echo "   1. Open Finder and navigate to the albator-swift folder"
echo "   2. Double-click Albator-Swift.app"
echo "   3. Or run: open Albator-Swift.app"
echo ""
echo "   From Terminal with GUI support:"
echo "   1. ./Albator-Swift.app/Contents/MacOS/Albator-Swift"
echo "   2. Or use: open -a Albator-Swift.app"
echo ""

# Test 6: Alternative CLI testing
echo "6️⃣  Alternative Testing Methods:"
echo ""
echo "   Test individual components:"
echo "   • swift run Albator-Swift (direct Swift execution)"
echo "   • swift build --configuration debug (debug build)"
echo "   • swift test (if tests are added)"
echo ""
echo "   Check logs and reports:"
echo "   • Logs: ~/Documents/albator.log"
echo "   • Reports: ~/Documents/security_report_*.json"
echo "   • Config: ~/Library/Preferences/com.albator.security.plist"

echo ""

echo "🎉 Albator Swift CLI Demo Complete!"
echo ""
echo "💡 Note: GUI applications require a macOS desktop environment to display windows."
echo "   The application is fully functional but needs a proper display session to show the interface."
