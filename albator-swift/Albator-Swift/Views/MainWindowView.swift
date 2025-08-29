//
//  MainWindowView.swift
//  Albator-Swift
//
//  Main window view that manages the overall application layout
//  and navigation between different security modules.
//

import SwiftUI

struct MainWindowView: View {
    @EnvironmentObject var securityEngine: SecurityEngine
    @EnvironmentObject var configManager: ConfigurationManager
    @State private var selectedView: NavigationItem = .dashboard
    
    enum NavigationItem: String, CaseIterable, Identifiable {
        case dashboard = "Dashboard"
        case networkScanner = "Network Scanner"
        case compliance = "Compliance"
        case vulnerability = "Vulnerability"
        case reports = "Reports"
        case settings = "Settings"
        
        var id: String { self.rawValue }
        
        var icon: String {
            switch self {
            case .dashboard: return "house.fill"
            case .networkScanner: return "network"
            case .compliance: return "checkmark.shield.fill"
            case .vulnerability: return "exclamationmark.triangle.fill"
            case .reports: return "doc.text.fill"
            case .settings: return "gear"
            }
        }
    }
    
    var body: some View {
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
                    
                    Text("Real-time security status and monitoring")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal)
                
                // Security Status Cards
                LazyVGrid(columns: [
                    GridItem(.flexible(), spacing: 16),
                    GridItem(.flexible(), spacing: 16),
                    GridItem(.flexible(), spacing: 16)
                ], spacing: 16) {
                    SecurityStatusCard(
                        title: "Firewall",
                        status: securityEngine.firewallStatus,
                        icon: "shield.fill",
                        color: securityEngine.firewallStatus == .secure ? .green : .red
                    )
                    
                    SecurityStatusCard(
                        title: "FileVault",
                        status: securityEngine.encryptionStatus,
                        icon: "lock.fill",
                        color: securityEngine.encryptionStatus == .secure ? .green : .red
                    )
                    
                    SecurityStatusCard(
                        title: "Gatekeeper",
                        status: securityEngine.gatekeeperStatus,
                        icon: "checkmark.shield.fill",
                        color: securityEngine.gatekeeperStatus == .secure ? .green : .red
                    )
                }
                .padding(.horizontal)
                
                // Risk Score
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
                                securityEngine.riskScore < 30 ? Color.green :
                                securityEngine.riskScore < 70 ? Color.yellow : Color.red,
                                lineWidth: 20
                            )
                            .frame(width: 150, height: 150)
                            .rotationEffect(.degrees(-90))
                        
                        VStack {
                            Text("\(Int(securityEngine.riskScore))")
                                .font(.system(size: 36, weight: .bold))
                            Text("Risk Score")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }
                .padding()
                .background(Color(.windowBackgroundColor))
                .cornerRadius(12)
                .padding(.horizontal)
                
                // Recent Activity
                VStack(alignment: .leading, spacing: 12) {
                    Text("Recent Activity")
                        .font(.title2)
                        .fontWeight(.semibold)
                    
                    ForEach(securityEngine.recentActivity) { activity in
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
                            // Generate report action
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

struct SettingsView: View {
    var body: some View {
        VStack {
            Image(systemName: "gear")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text("Settings")
                .font(.title)
            Text("Application configuration")
                .foregroundColor(.secondary)
        }
    }
}
