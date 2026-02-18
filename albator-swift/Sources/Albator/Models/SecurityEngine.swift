import Foundation
import SwiftUI
import Combine

public enum SecurityStatus: String {
    case secure = "Secure"
    case warning = "Warning"
    case critical = "Critical"
    case unknown = "Unknown"
}

public struct SecurityActivity: Identifiable, Codable {
    public var id = UUID()
    public let title: String
    public let timestamp: Date
    public let icon: String
    public let colorString: String
    public let details: String?

    public var color: Color {
        switch colorString {
        case "green": return .green
        case "red": return .red
        case "blue": return .blue
        case "yellow": return .yellow
        case "orange": return .orange
        default: return .gray
        }
    }

    public init(title: String, timestamp: Date, icon: String, color: Color, details: String? = nil) {
        self.title = title
        self.timestamp = timestamp
        self.icon = icon
        self.details = details

        switch color {
        case .green: self.colorString = "green"
        case .red: self.colorString = "red"
        case .blue: self.colorString = "blue"
        case .yellow: self.colorString = "yellow"
        case .orange: self.colorString = "orange"
        default: self.colorString = "gray"
        }
    }
}

public final class SecurityEngine: ObservableObject {
    public static let shared = SecurityEngine()

    @Published public var isScanning = false
    @Published public var riskScore: Double = 0.0
    @Published public var firewallStatus: SecurityStatus = .unknown
    @Published public var encryptionStatus: SecurityStatus = .unknown
    @Published public var gatekeeperStatus: SecurityStatus = .unknown
    @Published public var sipStatus: SecurityStatus = .unknown
    @Published public var baselineStatus: SecurityStatus = .unknown
    @Published public var securityDataStatus: SecurityStatus = .unknown
    @Published public var macosVersion: String = "unknown"
    @Published public var minimumBaselineVersion: String = SystemSecurityProbe.defaultBaselineVersion()
    @Published public var recentActivity: [SecurityActivity] = []

    private var cancellables = Set<AnyCancellable>()

    private init() {
        addActivity("Security engine initialized", icon: "gearshape.fill", color: .blue)
        startPeriodicUpdates()
        Task { await refreshFromSystemProbe(reason: "initial") }
    }

    private func startPeriodicUpdates() {
        Timer.publish(every: 60, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                Task { await self?.refreshFromSystemProbe(reason: "periodic") }
            }
            .store(in: &cancellables)
    }

    public func performComprehensiveScan() async {
        guard !isScanning else { return }

        await MainActor.run {
            isScanning = true
            addActivity("Starting comprehensive security scan", icon: "magnifyingglass", color: .blue)
        }

        await refreshFromSystemProbe(reason: "manual_scan")

        await MainActor.run {
            addActivity("Comprehensive security scan completed", icon: "checkmark.circle.fill", color: .green)
            isScanning = false
        }
    }

    public func emergencyStop() {
        isScanning = false
        addActivity("Emergency stop activated", icon: "exclamationmark.triangle.fill", color: .red)
    }

    @discardableResult
    public func refreshFromSystemProbe(reason: String) async -> SystemSecuritySnapshot {
        let snapshot = await Task.detached(priority: .userInitiated) {
            SystemSecurityProbe.shared.captureSnapshot(minimumBaselineVersion: SystemSecurityProbe.defaultBaselineVersion())
        }.value

        await MainActor.run {
            self.minimumBaselineVersion = snapshot.minimumBaselineVersion
            self.macosVersion = snapshot.macosVersion
            self.firewallStatus = snapshot.firewallStatus
            self.encryptionStatus = snapshot.fileVaultStatus
            self.gatekeeperStatus = snapshot.gatekeeperStatus
            self.sipStatus = snapshot.sipStatus
            self.baselineStatus = snapshot.baselineStatus
            self.securityDataStatus = snapshot.securityDataStatus
            self.riskScore = self.calculateRiskScore(from: snapshot)
            self.addActivity(
                "Security snapshot updated",
                icon: "shield.lefthalf.filled",
                color: self.riskScore >= 80 ? .green : .orange,
                details: "reason=\(reason), macOS=\(snapshot.macosVersion), baseline=\(snapshot.minimumBaselineVersion)"
            )
        }

        return snapshot
    }

    private func calculateRiskScore(from snapshot: SystemSecuritySnapshot) -> Double {
        var score = 100.0
        if snapshot.firewallStatus != .secure { score -= 20 }
        if snapshot.fileVaultStatus != .secure { score -= 20 }
        if snapshot.gatekeeperStatus != .secure { score -= 15 }
        if snapshot.sipStatus != .secure { score -= 20 }
        if snapshot.baselineStatus != .secure { score -= 10 }
        if snapshot.securityDataStatus != .secure { score -= 15 }
        return max(0, min(100, score))
    }

    private func addActivity(_ title: String, icon: String, color: Color, details: String? = nil) {
        let activity = SecurityActivity(
            title: title,
            timestamp: Date(),
            icon: icon,
            color: color,
            details: details
        )
        recentActivity.insert(activity, at: 0)
        if recentActivity.count > 20 {
            recentActivity.removeLast()
        }
    }
}
