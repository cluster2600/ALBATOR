#!/bin/bash

# Albator Swift App Build Script
# This script builds the Swift version of Albator using Swift Package Manager

set -e

echo "🚀 Building Albator Swift Application..."

# Check if Swift is available
if ! command -v swift &> /dev/null; then
    echo "❌ Swift is not installed or not in PATH"
    echo "Please install Xcode and Swift from the Mac App Store"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "Package.swift" ]; then
    echo "❌ Package.swift not found. Please run this script from the albator-swift directory"
    exit 1
fi

echo "📦 Building Albator Swift app..."

# Build the Swift package
if swift build --configuration release; then
    echo "✅ Build successful!"

    # Get the built executable path
    EXECUTABLE_PATH=".build/release/Albator-Swift"

    if [ -f "$EXECUTABLE_PATH" ]; then
        echo "📱 Executable location: $EXECUTABLE_PATH"

        # Create a distribution package
        DIST_DIR="dist"
        rm -rf "$DIST_DIR"
        mkdir -p "$DIST_DIR"

        # Copy the executable to dist directory
        cp "$EXECUTABLE_PATH" "$DIST_DIR/"

        # Create a zip file for distribution
        ZIP_NAME="Albator-Swift-$(date +%Y%m%d-%H%M%S).zip"
        cd "$DIST_DIR"
        zip "../$ZIP_NAME" "Albator-Swift"
        cd ..

        echo "📦 Distribution package created: $ZIP_NAME"
        echo ""
        echo "🎉 Albator Swift app is ready for distribution!"
        echo ""
        echo "To run the app:"
        echo "  swift run Albator-Swift"
        echo ""
        echo "Or run the built executable:"
        echo "  $EXECUTABLE_PATH"
    else
        echo "❌ Executable not found at expected location"
        exit 1
    fi
else
    echo "❌ Build failed!"
    exit 1
fi

echo ""
echo "📋 Build Summary:"
echo "  - Swift Package: Package.swift"
echo "  - Target: Albator-Swift"
echo "  - Configuration: Release"
echo "  - Platform: macOS"
echo "  - Output: $EXECUTABLE_PATH"
