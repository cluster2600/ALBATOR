#!/bin/bash

# Albator Swift App Build Script
# This script builds the Swift version of Albator for macOS

set -e

echo "🚀 Building Albator Swift Application..."

# Check if Xcode is available
if ! command -v xcodebuild &> /dev/null; then
    echo "❌ Xcode is not installed or not in PATH"
    echo "Please install Xcode from the Mac App Store"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "Albator-Swift.xcodeproj/project.pbxproj" ]; then
    echo "❌ Xcode project not found. Please run this script from the albator-swift directory"
    exit 1
fi

# Create build directory
BUILD_DIR="build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "📦 Building Albator Swift app..."

# Build the app
xcodebuild \
    -project Albator-Swift.xcodeproj \
    -scheme Albator-Swift \
    -configuration Release \
    -derivedDataPath "$BUILD_DIR" \
    -destination 'platform=macOS' \
    build

# Find the built app
APP_PATH="$BUILD_DIR/Build/Products/Release/Albator-Swift.app"

if [ -d "$APP_PATH" ]; then
    echo "✅ Build successful!"
    echo "📱 App location: $APP_PATH"

    # Create a distribution package
    DIST_DIR="dist"
    rm -rf "$DIST_DIR"
    mkdir -p "$DIST_DIR"

    # Copy the app to dist directory
    cp -r "$APP_PATH" "$DIST_DIR/"

    # Create a zip file for distribution
    ZIP_NAME="Albator-Swift-$(date +%Y%m%d-%H%M%S).zip"
    cd "$DIST_DIR"
    zip -r "../$ZIP_NAME" "Albator-Swift.app"
    cd ..

    echo "📦 Distribution package created: $ZIP_NAME"
    echo ""
    echo "🎉 Albator Swift app is ready for distribution!"
    echo ""
    echo "To run the app:"
    echo "  open \"$APP_PATH\""
    echo ""
    echo "To install the app system-wide:"
    echo "  sudo cp -r \"$APP_PATH\" /Applications/"
else
    echo "❌ Build failed!"
    echo "Check the build logs above for errors"
    exit 1
fi

echo ""
echo "📋 Build Summary:"
echo "  - Xcode Project: Albator-Swift.xcodeproj"
echo "  - Target: Albator-Swift"
echo "  - Configuration: Release"
echo "  - Platform: macOS"
echo "  - Output: $APP_PATH"
