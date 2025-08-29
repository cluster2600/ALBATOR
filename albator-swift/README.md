# Albator Swift

A comprehensive macOS security hardening and compliance tool built with SwiftUI.

## Overview

Albator Swift is the native macOS version of the Albator security toolkit, providing a modern, user-friendly interface for system security management and compliance monitoring.

## Features

### 🔒 Security Monitoring
- Real-time firewall status monitoring
- FileVault encryption verification
- Gatekeeper and SIP status checking
- System integrity validation

### 📊 Dashboard
- Security risk score calculation
- Recent activity tracking
- Quick action buttons for common tasks
- Visual status indicators

### ⚙️ Configuration Management
- Customizable scan intervals
- Notification preferences
- Theme selection (System/Light/Dark)
- Export/import settings

### 📋 Reporting
- Comprehensive security reports
- JSON export format
- System information gathering
- Security recommendations

### 🔔 Notifications
- Security alert notifications
- Scan completion alerts
- System update notifications
- Customizable notification types

## Requirements

- macOS 13.0 or later
- Xcode 14.0 or later (for building from source)

## Installation

### Option 1: Pre-built Release
1. Download the latest release from GitHub
2. Unzip the downloaded file
3. Drag `Albator-Swift.app` to your Applications folder
4. Launch the app

### Option 2: Build from Source
1. Clone the repository
2. Navigate to the `albator-swift` directory
3. Make the build script executable:
   ```bash
   chmod +x build_swift_app.sh
   ```
4. Run the build script:
   ```bash
   ./build_swift_app.sh
   ```
5. The built app will be available in the `dist` directory

## Usage

### First Launch
1. Open Albator Swift from your Applications folder
2. Grant notification permissions when prompted
3. The app will perform an initial security scan

### Main Interface
- **Dashboard**: Overview of system security status
- **Network Scanner**: Network security analysis tools
- **Compliance**: Security compliance checking
- **Vulnerability**: System vulnerability assessment
- **Reports**: Security report generation and viewing
- **Settings**: Application configuration

### Keyboard Shortcuts
- `⌘ + S`: Start security scan
- `⌘ + R`: Generate report
- `⌘ + E`: Emergency stop
- `⌘ + 1-4`: Switch between main views
- `⌘ + Q`: Quit application

## Architecture

### Core Components

#### Models
- `SecurityEngine`: Core security scanning and monitoring
- `SecurityActivity`: Security event logging and tracking

#### Services
- `ConfigurationManager`: App settings and preferences
- `NotificationManager`: System notifications and alerts
- `SystemMonitor`: Continuous system monitoring
- `SecurityEventHandler`: Security event processing
- `BackgroundTaskScheduler`: Scheduled background tasks
- `ReportGenerator`: Security report creation
- `CoreDataManager`: Data persistence
- `DataMigrationManager`: Version migration handling
- `UserInterfaceStateManager`: UI state persistence

#### Views
- `MainWindowView`: Primary application window
- `SecurityDashboardView`: Main dashboard interface
- `SettingsView`: Configuration interface

#### Utilities
- `Logger`: Centralized logging system

## Security Features

### System Hardening
- Firewall configuration verification
- FileVault encryption status
- Gatekeeper and SIP validation
- Remote login and sharing service checks

### Monitoring
- Real-time security status updates
- Background security scanning
- Event-driven notifications
- Comprehensive logging

### Compliance
- Security baseline checking
- Configuration drift detection
- Automated remediation suggestions
- Compliance report generation

## Development

### Project Structure
```
albator-swift/
├── Albator-Swift/
│   ├── Models/
│   ├── Services/
│   ├── Utilities/
│   ├── Views/
│   ├── AlbatorApp.swift
│   └── Albator-Swift.entitlements
├── Albator-Swift.xcodeproj/
│   └── project.pbxproj
├── build_swift_app.sh
└── README.md
```

### Building
1. Open `Albator-Swift.xcodeproj` in Xcode
2. Select the Albator-Swift target
3. Choose Product > Build (⌘B)
4. Run the app with Product > Run (⌘R)

### Code Style
- Swift 5.0+ syntax
- SwiftUI for user interface
- Combine for reactive programming
- MVVM architecture pattern
- Comprehensive error handling

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the troubleshooting guide

## Changelog

### Version 1.0.0
- Initial SwiftUI implementation
- Core security monitoring features
- Native macOS interface
- Background task scheduling
- Comprehensive reporting system

## Roadmap

- [ ] Advanced vulnerability scanning
- [ ] Network security analysis
- [ ] Automated remediation
- [ ] Integration with security APIs
- [ ] Plugin system for extensions
- [ ] Multi-language support
- [ ] Cloud synchronization
