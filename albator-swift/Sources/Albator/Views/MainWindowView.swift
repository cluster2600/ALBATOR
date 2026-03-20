//
//  MainWindowView.swift
//  Albator-Swift
//
//  Main window view that manages the overall application layout
//  and navigation between different security modules.
//

import SwiftUI

public struct MainWindowView: View {
    @EnvironmentObject var securityEngine: SecurityEngine
    @EnvironmentObject var configManager: ConfigurationManager
    @State private var selectedView: NavigationItem = .dashboard

    public init() {}

    enum NavigationItem: String, CaseIterable, Identifiable {
        case dashboard = "Dashboard"
        case tahoe = "Tahoe Hardening"
        case networkScanner = "Network Scanner"
        case compliance = "Compliance"
        case vulnerability = "Vulnerability"
        case reports = "Reports"
        case settings = "Settings"

        var id: String { self.rawValue }

        var icon: String {
            switch self {
            case .dashboard: return "house.fill"
            case .tahoe: return "mountain.2.fill"
            case .networkScanner: return "network"
            case .compliance: return "checkmark.shield.fill"
            case .vulnerability: return "exclamationmark.triangle.fill"
            case .reports: return "doc.text.fill"
            case .settings: return "gear"
            }
        }
    }

    public var body: some View {
        NavigationSplitView {
            // Sidebar
            List(NavigationItem.allCases, selection: $selectedView) { item in
                NavigationLink(value: item) {
                    Label(item.rawValue, systemImage: item.icon)
                }
            }
            .navigationTitle("Albator")
            .listStyle(.sidebar)

        } detail: {
            // Main content area
            Group {
                switch selectedView {
                case .dashboard:
                    SecurityDashboardView()
                case .tahoe:
                    TahoeHardeningView()
                case .networkScanner:
                    NetworkScannerView()
                case .compliance:
                    ComplianceView()
                case .vulnerability:
                    VulnerabilityView()
                case .reports:
                    ReportsView()
                case .settings:
                    SettingsView()
                }
            }
            .navigationTitle(selectedView.rawValue)
            .navigationSubtitle("macOS Security Hardening")
        }
        .frame(minWidth: 1000, minHeight: 700)
        .onReceive(NotificationCenter.default.publisher(for: .showDashboard)) { _ in
            selectedView = .dashboard
        }
        .onReceive(NotificationCenter.default.publisher(for: .showNetworkScanner)) { _ in
            selectedView = .networkScanner
        }
        .onReceive(NotificationCenter.default.publisher(for: .showCompliance)) { _ in
            selectedView = .compliance
        }
        .onReceive(NotificationCenter.default.publisher(for: .showReports)) { _ in
            selectedView = .reports
        }
    }
}

// MARK: - Dashboard View
struct SecurityDashboardView: View {
    @EnvironmentObject var securityEngine: SecurityEngine

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Header
                VStack(alignment: .leading, spacing: 8) {
                    Text("Security Dashboard")
                        .font(.largeTitle)
                        .fontWeight(.bold)

                    HStack(spacing: 16) {
                        Text("Real-time security status and monitoring")
                            .foregroundColor(.secondary)
                        Spacer()
                        HStack(spacing: 4) {
                            Image(systemName: hardwareIcon)
                                .foregroundColor(hardwareColor)
                            Text("macOS \(securityEngine.macosVersion)")
                                .fontWeight(.medium)
                            Text("•")
                                .foregroundColor(.secondary)
                            Text(securityEngine.hardwareGeneration.rawValue)
                                .foregroundColor(hardwareColor)
                            if securityEngine.hardwareGeneration == .intel {
                                Text("(EOL)")
                                    .font(.caption)
                                    .fontWeight(.bold)
                                    .foregroundColor(.red)
                                    .padding(.horizontal, 4)
                                    .padding(.vertical, 1)
                                    .background(Color.red.opacity(0.15))
                                    .cornerRadius(4)
                            }
                        }
                        .font(.caption)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal)

                // Core Security Status Cards
                VStack(alignment: .leading, spacing: 8) {
                    Text("Core Security")
                        .font(.headline)
                        .foregroundColor(.secondary)
                        .padding(.horizontal)

                    LazyVGrid(columns: [
                        GridItem(.flexible(), spacing: 16),
                        GridItem(.flexible(), spacing: 16),
                        GridItem(.flexible(), spacing: 16),
                        GridItem(.flexible(), spacing: 16),
                        GridItem(.flexible(), spacing: 16),
                        GridItem(.flexible(), spacing: 16)
                    ], spacing: 16) {
                        SecurityStatusCard(
                            title: "Firewall",
                            status: securityEngine.firewallStatus,
                            icon: "shield.fill",
                            color: statusCardColor(securityEngine.firewallStatus)
                        )
                        SecurityStatusCard(
                            title: "FileVault",
                            status: securityEngine.encryptionStatus,
                            icon: "lock.fill",
                            color: statusCardColor(securityEngine.encryptionStatus)
                        )
                        SecurityStatusCard(
                            title: "Gatekeeper",
                            status: securityEngine.gatekeeperStatus,
                            icon: "checkmark.shield.fill",
                            color: statusCardColor(securityEngine.gatekeeperStatus)
                        )
                        SecurityStatusCard(
                            title: "SIP",
                            status: securityEngine.sipStatus,
                            icon: "lock.shield.fill",
                            color: statusCardColor(securityEngine.sipStatus)
                        )
                        SecurityStatusCard(
                            title: "Baseline",
                            status: securityEngine.baselineStatus,
                            icon: "checkmark.seal.fill",
                            color: statusCardColor(securityEngine.baselineStatus)
                        )
                        SecurityStatusCard(
                            title: "Sec Updates",
                            status: securityEngine.securityDataStatus,
                            icon: "arrow.triangle.2.circlepath",
                            color: statusCardColor(securityEngine.securityDataStatus)
                        )
                    }
                    .padding(.horizontal)
                }

                // Tahoe Security Cards
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("macOS Tahoe Hardening")
                            .font(.headline)
                            .foregroundColor(.secondary)
                        Spacer()
                        Text("NEW")
                            .font(.caption2)
                            .fontWeight(.bold)
                            .foregroundColor(.white)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.blue)
                            .cornerRadius(4)
                    }
                    .padding(.horizontal)

                    LazyVGrid(columns: [
                        GridItem(.flexible(), spacing: 16),
                        GridItem(.flexible(), spacing: 16),
                        GridItem(.flexible(), spacing: 16),
                        GridItem(.flexible(), spacing: 16),
                        GridItem(.flexible(), spacing: 16),
                        GridItem(.flexible(), spacing: 16)
                    ], spacing: 16) {
                        SecurityStatusCard(
                            title: "BSI",
                            status: securityEngine.bsiStatus,
                            icon: "bolt.shield.fill",
                            color: statusCardColor(securityEngine.bsiStatus)
                        )
                        SecurityStatusCard(
                            title: "Screen Lock",
                            status: securityEngine.screenLockStatus,
                            icon: "lock.display",
                            color: statusCardColor(securityEngine.screenLockStatus)
                        )
                        SecurityStatusCard(
                            title: "USB Restrict",
                            status: securityEngine.usbRestrictedModeStatus,
                            icon: "cable.connector",
                            color: statusCardColor(securityEngine.usbRestrictedModeStatus)
                        )
                        SecurityStatusCard(
                            title: "Safari AFP",
                            status: securityEngine.safariFingerprintStatus,
                            icon: "hand.raised.fill",
                            color: statusCardColor(securityEngine.safariFingerprintStatus)
                        )
                        SecurityStatusCard(
                            title: "FV Recovery",
                            status: securityEngine.fileVaultRecoveryKeyStatus,
                            icon: "key.fill",
                            color: statusCardColor(securityEngine.fileVaultRecoveryKeyStatus)
                        )
                        SecurityStatusCard(
                            title: "Lockdown",
                            status: securityEngine.lockdownModeStatus,
                            icon: "lock.trianglebadge.exclamationmark.fill",
                            color: lockdownColor
                        )
                    }
                    .padding(.horizontal)
                }

                // Risk Score
                HStack(spacing: 40) {
                    // Score circle
                    VStack(spacing: 16) {
                        Text("Overall Risk Score")
                            .font(.title2)
                            .fontWeight(.semibold)

                        ZStack {
                            Circle()
                                .stroke(Color.gray.opacity(0.2), lineWidth: 20)
                                .frame(width: 150, height: 150)

                            Circle()
                                .trim(from: 0, to: securityEngine.riskScore / 100)
                                .stroke(
                                    scoreColor,
                                    style: StrokeStyle(lineWidth: 20, lineCap: .round)
                                )
                                .frame(width: 150, height: 150)
                                .rotationEffect(.degrees(-90))

                            VStack {
                                Text("\(Int(securityEngine.riskScore))")
                                    .font(.system(size: 36, weight: .bold))
                                    .foregroundColor(scoreColor)
                                Text("/ 100")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }

                    // Score breakdown
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Score Breakdown")
                            .font(.headline)
                            .foregroundColor(.secondary)

                        ScoreRow(label: "Firewall", status: securityEngine.firewallStatus)
                        ScoreRow(label: "FileVault", status: securityEngine.encryptionStatus)
                        ScoreRow(label: "Gatekeeper", status: securityEngine.gatekeeperStatus)
                        ScoreRow(label: "SIP", status: securityEngine.sipStatus)
                        ScoreRow(label: "BSI (Tahoe)", status: securityEngine.bsiStatus)
                        ScoreRow(label: "USB Restricted", status: securityEngine.usbRestrictedModeStatus)
                        ScoreRow(label: "Screen Lock", status: securityEngine.screenLockStatus)
                        ScoreRow(label: "FV Recovery Key", status: securityEngine.fileVaultRecoveryKeyStatus)
                    }
                }
                .padding()
                .background(Color(.windowBackgroundColor))
                .cornerRadius(12)
                .padding(.horizontal)

                // Intel EOL Warning
                if securityEngine.hardwareGeneration == .intel {
                    HStack(spacing: 12) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.title2)
                            .foregroundColor(.orange)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Intel Mac — End of Life")
                                .fontWeight(.semibold)
                            Text("macOS 26 Tahoe is the last major release supporting Intel hardware. Some hardware security features (Secure Enclave, biometric authentication) are unavailable. Plan migration to Apple Silicon.")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                    }
                    .padding()
                    .background(Color.orange.opacity(0.1))
                    .cornerRadius(12)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(Color.orange.opacity(0.3), lineWidth: 1)
                    )
                    .padding(.horizontal)
                }

                // Recent Activity
                VStack(alignment: .leading, spacing: 12) {
                    Text("Recent Activity")
                        .font(.title2)
                        .fontWeight(.semibold)

                    ForEach(securityEngine.recentActivity.prefix(8)) { activity in
                        HStack {
                            Image(systemName: activity.icon)
                                .foregroundColor(activity.color)
                            VStack(alignment: .leading) {
                                Text(activity.title)
                                    .fontWeight(.medium)
                                Text(activity.timestamp, style: .relative)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                        }
                        .padding()
                        .background(Color(.windowBackgroundColor))
                        .cornerRadius(8)
                    }
                }
                .padding(.horizontal)

                // Quick Actions
                VStack(alignment: .leading, spacing: 12) {
                    Text("Quick Actions")
                        .font(.title2)
                        .fontWeight(.semibold)

                    HStack(spacing: 12) {
                        QuickActionButton(
                            title: "Full Scan",
                            icon: "magnifyingglass",
                            color: .blue
                        ) {
                            Task {
                                await securityEngine.performComprehensiveScan()
                            }
                        }

                        QuickActionButton(
                            title: "Generate Report",
                            icon: "doc.text",
                            color: .green
                        ) {
                            Task {
                                _ = await ReportGenerator.shared.generateComprehensiveReport()
                            }
                        }

                        QuickActionButton(
                            title: "Check Updates",
                            icon: "arrow.triangle.2.circlepath",
                            color: .orange
                        ) {
                            // Check for updates action
                        }
                    }
                }
                .padding(.horizontal)
            }
            .padding(.vertical)
        }
    }

    private var scoreColor: Color {
        if securityEngine.riskScore >= 80 { return .green }
        if securityEngine.riskScore >= 50 { return .yellow }
        return .red
    }

    private var hardwareIcon: String {
        securityEngine.hardwareGeneration == .appleSilicon ? "cpu" : "desktopcomputer"
    }

    private var hardwareColor: Color {
        securityEngine.hardwareGeneration == .intel ? .orange : .green
    }

    private var lockdownColor: Color {
        switch securityEngine.lockdownModeStatus {
        case .secure: return .green
        case .unknown: return .gray   // opt-in feature, unknown = not enabled but OK
        default: return .orange
        }
    }

    private func statusCardColor(_ status: SecurityStatus) -> Color {
        switch status {
        case .secure: return .green
        case .warning: return .orange
        case .critical: return .red
        case .unknown: return .gray
        }
    }
}

// MARK: - Score Row
struct ScoreRow: View {
    let label: String
    let status: SecurityStatus

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: status == .secure ? "checkmark.circle.fill" : status == .unknown ? "questionmark.circle" : "xmark.circle.fill")
                .foregroundColor(status == .secure ? .green : status == .unknown ? .gray : .orange)
                .font(.caption)
            Text(label)
                .font(.caption)
            Spacer()
            Text(status.rawValue)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Tahoe Hardening View
struct TahoeHardeningView: View {
    @EnvironmentObject var securityEngine: SecurityEngine

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Header
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("macOS 26 Tahoe Hardening")
                            .font(.largeTitle)
                            .fontWeight(.bold)
                        Spacer()
                        Text("macOS \(securityEngine.macosVersion)")
                            .font(.headline)
                            .foregroundColor(.secondary)
                    }
                    Text("Security features introduced or changed in macOS Tahoe")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal)

                // Tahoe checks detail cards
                VStack(spacing: 16) {
                    TahoeDetailCard(
                        title: "Background Security Improvements (BSI)",
                        status: securityEngine.bsiStatus,
                        icon: "bolt.shield.fill",
                        description: "Automatically downloads and installs critical security patches regardless of Software Update settings. New in Tahoe 26.1.",
                        recommendation: securityEngine.bsiStatus != .secure ? "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true" : nil
                    )

                    TahoeDetailCard(
                        title: "Screen Lock",
                        status: securityEngine.screenLockStatus,
                        icon: "lock.display",
                        description: "Requires password immediately on screen lock/wake. Tahoe uses sysadminctl instead of the deprecated com.apple.screensaver domain.",
                        recommendation: securityEngine.screenLockStatus != .secure ? "sysadminctl -screenLock immediate" : nil
                    )

                    TahoeDetailCard(
                        title: "USB Restricted Mode",
                        status: securityEngine.usbRestrictedModeStatus,
                        icon: "cable.connector",
                        description: "Prevents USB accessories from enumerating when the Mac is locked. In Tahoe, this setting now extends into macOS Recovery mode for enhanced physical security.",
                        recommendation: securityEngine.usbRestrictedModeStatus != .secure ? "Enable USB Restricted Mode in System Settings > Privacy & Security" : nil
                    )

                    TahoeDetailCard(
                        title: "Safari Advanced Fingerprinting Protection",
                        status: securityEngine.safariFingerprintStatus,
                        icon: "hand.raised.fill",
                        description: "Restricts fingerprinting scripts from accessing high-entropy APIs. Tahoe enables this for all browsing by default (previously only Private Browsing).",
                        recommendation: securityEngine.safariFingerprintStatus != .secure ? "defaults write com.apple.Safari EnableEnhancedPrivacyInRegularBrowsing -bool true" : nil
                    )

                    TahoeDetailCard(
                        title: "FileVault Recovery Key",
                        status: securityEngine.fileVaultRecoveryKeyStatus,
                        icon: "key.fill",
                        description: "Tahoe auto-enables FileVault during setup. Verifies that a personal or institutional recovery key is escrowed to prevent data loss.",
                        recommendation: securityEngine.fileVaultRecoveryKeyStatus == .warning ? "Generate a recovery key: sudo fdesetup changerecovery -personal" : nil
                    )

                    TahoeDetailCard(
                        title: "Lockdown Mode",
                        status: securityEngine.lockdownModeStatus,
                        icon: "lock.trianglebadge.exclamationmark.fill",
                        description: "Apple's extreme protection mode — disables JIT, complex web technologies, wired connections with unknown accessories, and more. Opt-in for high-risk users.",
                        recommendation: securityEngine.lockdownModeStatus != .secure ? "Enable in System Settings > Privacy & Security > Lockdown Mode" : nil
                    )

                    TahoeDetailCard(
                        title: "Hardware Generation",
                        status: securityEngine.hardwareGeneration == .intel ? .warning : .secure,
                        icon: securityEngine.hardwareGeneration == .appleSilicon ? "cpu" : "desktopcomputer",
                        description: securityEngine.hardwareGeneration == .intel
                            ? "This Mac uses Intel hardware. macOS 26 Tahoe is the last major release supporting Intel. Hardware security features like Secure Enclave are unavailable."
                            : "Apple Silicon with Secure Enclave — full hardware security feature support including biometric authentication and hardware key management.",
                        recommendation: securityEngine.hardwareGeneration == .intel ? "Plan migration to Apple Silicon for continued macOS updates and hardware security features" : nil
                    )
                }
                .padding(.horizontal)

                // Deprecated APIs warning
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Image(systemName: "exclamationmark.bubble.fill")
                            .foregroundColor(.yellow)
                        Text("Tahoe API Changes")
                            .font(.headline)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        DeprecationRow(api: "com.apple.screensaver askForPassword", replacement: "sysadminctl -screenLock", status: "Removed")
                        DeprecationRow(api: "com.apple.SoftwareUpdate MDM payload", replacement: "Declarative Device Management (DDM)", status: "Deprecated")
                        DeprecationRow(api: "socketfilterfw --getloggingmode", replacement: "Unified Logging (log stream)", status: "Removed")
                        DeprecationRow(api: "IKEv2 DES/3DES/SHA1-96", replacement: "AES-256/SHA2-256+/DH≥14", status: "Removed")
                    }
                }
                .padding()
                .background(Color(.windowBackgroundColor))
                .cornerRadius(12)
                .padding(.horizontal)
            }
            .padding(.vertical)
        }
    }
}

// MARK: - Tahoe Detail Card
struct TahoeDetailCard: View {
    let title: String
    let status: SecurityStatus
    let icon: String
    let description: String
    let recommendation: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(statusColor)

                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.headline)
                    Text(status.rawValue)
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(statusColor)
                }

                Spacer()

                Image(systemName: statusIcon)
                    .font(.title2)
                    .foregroundColor(statusColor)
            }

            Text(description)
                .font(.caption)
                .foregroundColor(.secondary)

            if let recommendation = recommendation {
                HStack(spacing: 8) {
                    Image(systemName: "lightbulb.fill")
                        .foregroundColor(.yellow)
                        .font(.caption)
                    Text(recommendation)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.primary)
                }
                .padding(8)
                .background(Color.yellow.opacity(0.08))
                .cornerRadius(6)
            }
        }
        .padding()
        .background(Color(.windowBackgroundColor))
        .cornerRadius(12)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(statusColor.opacity(0.3), lineWidth: 1)
        )
    }

    private var statusColor: Color {
        switch status {
        case .secure: return .green
        case .warning: return .orange
        case .critical: return .red
        case .unknown: return .gray
        }
    }

    private var statusIcon: String {
        switch status {
        case .secure: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .critical: return "xmark.circle.fill"
        case .unknown: return "questionmark.circle"
        }
    }
}

// MARK: - Deprecation Row
struct DeprecationRow: View {
    let api: String
    let replacement: String
    let status: String

    var body: some View {
        HStack {
            Text(status)
                .font(.caption2)
                .fontWeight(.bold)
                .foregroundColor(.white)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(status == "Removed" ? Color.red : Color.orange)
                .cornerRadius(4)

            VStack(alignment: .leading) {
                Text(api)
                    .font(.system(.caption, design: .monospaced))
                    .strikethrough()
                    .foregroundColor(.secondary)
                HStack(spacing: 4) {
                    Image(systemName: "arrow.right")
                        .font(.caption2)
                    Text(replacement)
                        .font(.system(.caption, design: .monospaced))
                }
                .foregroundColor(.green)
            }
            Spacer()
        }
    }
}

// MARK: - Supporting Views
struct SecurityStatusCard: View {
    let title: String
    let status: SecurityStatus
    let icon: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 24))
                .foregroundColor(color)

            Text(title)
                .font(.headline)

            Text(status.rawValue)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(Color(.windowBackgroundColor))
        .cornerRadius(12)
    }
}

struct QuickActionButton: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 20))
                    .foregroundColor(color)

                Text(title)
                    .font(.caption)
                    .foregroundColor(.primary)
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(Color(.windowBackgroundColor))
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(color.opacity(0.3), lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Placeholder Views
struct NetworkScannerView: View {
    var body: some View {
        VStack {
            Image(systemName: "network")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text("Network Scanner")
                .font(.title)
            Text("Network security scanning functionality")
                .foregroundColor(.secondary)
        }
    }
}

struct ComplianceView: View {
    var body: some View {
        VStack {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text("Compliance Checker")
                .font(.title)
            Text("Security compliance validation")
                .foregroundColor(.secondary)
        }
    }
}

struct VulnerabilityView: View {
    var body: some View {
        VStack {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text("Vulnerability Scanner")
                .font(.title)
            Text("System vulnerability assessment")
                .foregroundColor(.secondary)
        }
    }
}

struct ReportsView: View {
    var body: some View {
        VStack {
            Image(systemName: "doc.text.fill")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text("Security Reports")
                .font(.title)
            Text("Comprehensive security reporting")
                .foregroundColor(.secondary)
        }
    }
}
