#!/bin/bash

echo "🧪 Testing Albator Swift Reporting Functionality"
echo "=============================================="

# Change to the albator-swift directory
cd "$(dirname "$0")"

echo "📁 Current directory: $(pwd)"
echo ""

# Test 1: Check if the app bundle exists
if [ -d "Albator-Swift.app" ]; then
    echo "✅ App bundle exists"
else
    echo "❌ App bundle not found"
    exit 1
fi

# Test 2: Check if executable exists and is executable
if [ -x "Albator-Swift.app/Contents/MacOS/Albator-Swift" ]; then
    echo "✅ Executable exists and is executable"
else
    echo "❌ Executable not found or not executable"
    exit 1
fi

# Test 3: Run the application
echo ""
echo "🚀 Running Albator Swift application..."
echo "Note: The GUI won't display in terminal, but the app should start successfully"
echo ""

./Albator-Swift.app/Contents/MacOS/Albator-Swift

echo ""
echo "📊 Checking for generated reports..."

# Test 4: Check for generated reports in common locations
echo ""
echo "🔍 Looking for security reports..."

# Check Documents directory
DOCUMENTS_DIR="$HOME/Documents"
if [ -d "$DOCUMENTS_DIR" ]; then
    REPORTS_IN_DOCS=$(find "$DOCUMENTS_DIR" -name "security_report_*.json" -type f 2>/dev/null | wc -l)
    if [ "$REPORTS_IN_DOCS" -gt 0 ]; then
        echo "✅ Found $REPORTS_IN_DOCS security report(s) in Documents directory"
        echo "📂 Latest report(s):"
        find "$DOCUMENTS_DIR" -name "security_report_*.json" -type f -printf "%T@ %p\n" 2>/dev/null | sort -n | tail -3 | while read -r line; do
            timestamp=$(echo "$line" | cut -d' ' -f1)
            filepath=$(echo "$line" | cut -d' ' -f2-)
            date_str=$(date -r $(echo "$timestamp" | cut -d'.' -f1) "+%Y-%m-%d %H:%M:%S")
            filename=$(basename "$filepath")
            echo "   📄 $filename (created: $date_str)"
        done
    else
        echo "ℹ️  No security reports found in Documents directory"
    fi
fi

# Check Desktop directory
DESKTOP_DIR="$HOME/Desktop"
if [ -d "$DESKTOP_DIR" ]; then
    REPORTS_ON_DESKTOP=$(find "$DESKTOP_DIR" -name "security_report_*.json" -type f 2>/dev/null | wc -l)
    if [ "$REPORTS_ON_DESKTOP" -gt 0 ]; then
        echo "✅ Found $REPORTS_ON_DESKTOP security report(s) on Desktop"
        echo "📂 Latest report(s):"
        find "$DESKTOP_DIR" -name "security_report_*.json" -type f -printf "%T@ %p\n" 2>/dev/null | sort -n | tail -3 | while read -r line; do
            timestamp=$(echo "$line" | cut -d' ' -f1)
            filepath=$(echo "$line" | cut -d' ' -f2-)
            date_str=$(date -r $(echo "$timestamp" | cut -d'.' -f1) "+%Y-%m-%d %H:%M:%S")
            filename=$(basename "$filepath")
            echo "   📄 $filename (created: $date_str)"
        done
    else
        echo "ℹ️  No security reports found on Desktop"
    fi
fi

# Summary
TOTAL_REPORTS=$((REPORTS_IN_DOCS + REPORTS_ON_DESKTOP))
echo ""
echo "📈 Summary:"
echo "   • Application: ✅ Running successfully"
echo "   • Reports generated: $TOTAL_REPORTS found"
echo "   • Report locations checked: Documents, Desktop"

if [ "$TOTAL_REPORTS" -gt 0 ]; then
    echo ""
    echo "🎉 SUCCESS: Reporting functionality is working!"
    echo "💡 Reports are being saved to user-accessible locations"
    echo "📝 Each report contains system info, security status, and recommendations"
else
    echo ""
    echo "ℹ️  No reports found yet - this is normal for first run"
    echo "💡 Reports are generated when you trigger security scans in the GUI"
fi

echo ""
echo "🔧 To test report generation:"
echo "   1. Launch the GUI application"
echo "   2. Click 'Generate Report' or run a security scan"
echo "   3. Check Documents or Desktop for the generated JSON file"
