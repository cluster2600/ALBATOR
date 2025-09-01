//
//  ReportGenerator.swift
//  Albator-Swift
//
//  Generates security reports and documentation.
//

import Foundation

class ReportGenerator {
    static let shared = ReportGenerator()

    private init() {}

    func generateComprehensiveReport() async {
        Logger.shared.info("Generating comprehensive security report")

        let report = await createReport()

        // Save report to file
        saveReportToFile(report)

        // Show notification
        NotificationManager.shared.showScanComplete()

        Logger.shared.info("Comprehensive security report generated")
    }

    private func createReport() async -> SecurityReport {
        // Gather system information
        let systemInfo = await gatherSystemInformation()

        // Gather security status
        let securityStatus = await gatherSecurityStatus()

        // Gather recent activity
        let recentActivity = SecurityEngine.shared.recentActivity

        return SecurityReport(
            generatedAt: Date(),
            systemInfo: systemInfo,
            securityStatus: securityStatus,
            recentActivity: recentActivity,
            recommendations: generateRecommendations(securityStatus)
        )
    }

    private func gatherSystemInformation() async -> SystemInfo {
        // In a real implementation, this would gather actual system information
        return SystemInfo(
            osVersion: "macOS 14.0",
            hardwareModel: "MacBook Pro",
            processor: "Apple M3",
            memory: "16 GB",
            storage: "512 GB SSD"
        )
    }

    private func gatherSecurityStatus() async -> SecurityStatusReport {
        return SecurityStatusReport(
            firewallEnabled: SecurityEngine.shared.firewallStatus == .secure,
            fileVaultEnabled: SecurityEngine.shared.encryptionStatus == .secure,
            gatekeeperEnabled: SecurityEngine.shared.gatekeeperStatus == .secure,
            sipEnabled: true,
            remoteLoginDisabled: true,
            bluetoothSharingDisabled: true,
            overallRiskScore: SecurityEngine.shared.riskScore
        )
    }

    private func generateRecommendations(_ status: SecurityStatusReport) -> [String] {
        var recommendations: [String] = []

        if !status.firewallEnabled {
            recommendations.append("Enable firewall for better network protection")
        }

        if !status.fileVaultEnabled {
            recommendations.append("Enable FileVault to encrypt your disk")
        }

        if !status.gatekeeperEnabled {
            recommendations.append("Enable Gatekeeper to prevent unauthorized applications")
        }

        if status.overallRiskScore > 70 {
            recommendations.append("High risk detected - review all security settings")
        }

        return recommendations
    }

    private func saveReportToFile(_ report: SecurityReport) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .prettyPrinted

        do {
            let data = try encoder.encode(report)
            let filename = "security_report_\(Int(Date().timeIntervalSince1970)).json"

            // Try to save to Documents directory first, fallback to Desktop
            var fileURL: URL?

            if let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
                fileURL = documentsDirectory.appendingPathComponent(filename)
            } else if let desktopDirectory = FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first {
                fileURL = desktopDirectory.appendingPathComponent(filename)
            }

            guard let finalURL = fileURL else {
                Logger.shared.error("Could not find suitable directory to save report")
                return
            }

            try data.write(to: finalURL)

            Logger.shared.info("Security report saved to: \(finalURL.path)")

            // Show success notification with file path
            NotificationManager.shared.showImmediateNotification(
                title: "Report Generated",
                body: "Security report saved to \(finalURL.lastPathComponent)",
                type: .info
            )

        } catch {
            Logger.shared.error("Failed to save security report: \(error.localizedDescription)")

            // Show error notification
            NotificationManager.shared.showImmediateNotification(
                title: "Report Generation Failed",
                body: "Could not save security report: \(error.localizedDescription)",
                type: .criticalAlert
            )
        }
    }
}

// MARK: - Report Models
struct SecurityReport: Codable {
    let generatedAt: Date
    let systemInfo: SystemInfo
    let securityStatus: SecurityStatusReport
    let recentActivity: [SecurityActivity]
    let recommendations: [String]
}

struct SystemInfo: Codable {
    let osVersion: String
    let hardwareModel: String
    let processor: String
    let memory: String
    let storage: String
}

struct SecurityStatusReport: Codable {
    let firewallEnabled: Bool
    let fileVaultEnabled: Bool
    let gatekeeperEnabled: Bool
    let sipEnabled: Bool
    let remoteLoginDisabled: Bool
    let bluetoothSharingDisabled: Bool
    let overallRiskScore: Double
}
