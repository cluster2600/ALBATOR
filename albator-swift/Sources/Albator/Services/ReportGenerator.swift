import Foundation

public final class ReportGenerator {
    public static let shared = ReportGenerator()

    private init() {}

    @discardableResult
    public func generateComprehensiveReport() async -> URL? {
        Logger.shared.info("Generating comprehensive security report")

        let report = await createReport()
        let outputURL = saveReportToFile(report)

        if outputURL != nil {
            NotificationManager.shared.showScanComplete()
            Logger.shared.info("Comprehensive security report generated")
        }

        return outputURL
    }

    private func createReport() async -> SecurityReport {
        let snapshot = await SecurityEngine.shared.refreshFromSystemProbe(reason: "report")
        let systemInfo = gatherSystemInformation(using: snapshot)
        let securityStatus = gatherSecurityStatus(using: snapshot)
        let recentActivity = SecurityEngine.shared.recentActivity

        return SecurityReport(
            generatedAt: Date(),
            systemInfo: systemInfo,
            securityStatus: securityStatus,
            recentActivity: recentActivity,
            recommendations: generateRecommendations(securityStatus)
        )
    }

    private func gatherSystemInformation(using snapshot: SystemSecuritySnapshot) -> SystemInfo {
        let hardwareModel = commandOutput(["/usr/sbin/sysctl", "-n", "hw.model"]) ?? "unknown"
        let processor = commandOutput(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"]) ?? "Apple Silicon"
        let memBytesString = commandOutput(["/usr/sbin/sysctl", "-n", "hw.memsize"]) ?? "0"
        let memGB = (Double(memBytesString) ?? 0) / 1_073_741_824
        let memory = memGB > 0 ? String(format: "%.0f GB", memGB) : "unknown"
        let storage = commandOutput(["/bin/df", "-h", "/"])?.split(separator: "\n").dropFirst().first.map(String.init) ?? "unknown"

        return SystemInfo(
            osVersion: "macOS \(snapshot.macosVersion)",
            hardwareModel: hardwareModel,
            processor: processor,
            memory: memory,
            storage: storage
        )
    }

    private func gatherSecurityStatus(using snapshot: SystemSecuritySnapshot) -> SecurityStatusReport {
        let remoteLogin = commandOutput(["/usr/sbin/systemsetup", "-getremotelogin"]) ?? "unknown"
        let bluetoothSharing = commandOutput(["/usr/bin/defaults", "read", "com.apple.Bluetooth", "PrefKeyServicesEnabled"]) ?? "unknown"

        return SecurityStatusReport(
            firewallEnabled: snapshot.firewallStatus == .secure,
            fileVaultEnabled: snapshot.fileVaultStatus == .secure,
            gatekeeperEnabled: snapshot.gatekeeperStatus == .secure,
            sipEnabled: snapshot.sipStatus == .secure,
            remoteLoginDisabled: remoteLogin.lowercased().contains("off"),
            bluetoothSharingDisabled: bluetoothSharing == "0",
            overallRiskScore: SecurityEngine.shared.riskScore,
            baselineVersion: snapshot.minimumBaselineVersion,
            currentMacOSVersion: snapshot.macosVersion,
            baselineCompliant: snapshot.baselineStatus == .secure,
            securityDataUpdatesEnabled: snapshot.securityDataStatus == .secure
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
        if !status.sipEnabled {
            recommendations.append("Re-enable SIP to strengthen runtime protections")
        }
        if !status.baselineCompliant {
            recommendations.append("Upgrade macOS to at least \(status.baselineVersion) (current: \(status.currentMacOSVersion))")
        }
        if !status.securityDataUpdatesEnabled {
            recommendations.append("Enable ConfigDataInstall and CriticalUpdateInstall in Software Update settings")
        }
        if status.overallRiskScore < 70 {
            recommendations.append("Run Albator shell baseline hardening and re-scan")
        }

        return recommendations
    }

    private func saveReportToFile(_ report: SecurityReport) -> URL? {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .prettyPrinted

        do {
            let data = try encoder.encode(report)
            let filename = "security_report_\(Int(Date().timeIntervalSince1970)).json"

            let targetDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
                ?? FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first

            guard let directory = targetDirectory else {
                Logger.shared.error("Could not find suitable directory to save report")
                return nil
            }

            let finalURL = directory.appendingPathComponent(filename)
            try data.write(to: finalURL)

            Logger.shared.info("Security report saved to: \(finalURL.path)")
            NotificationManager.shared.showImmediateNotification(
                title: "Report Generated",
                body: "Security report saved to \(finalURL.lastPathComponent)",
                type: .info
            )
            return finalURL
        } catch {
            Logger.shared.error("Failed to save security report: \(error.localizedDescription)")
            NotificationManager.shared.showImmediateNotification(
                title: "Report Generation Failed",
                body: "Could not save security report: \(error.localizedDescription)",
                type: .criticalAlert
            )
            return nil
        }
    }

    private func commandOutput(_ command: [String]) -> String? {
        let process = Process()
        if command[0].hasPrefix("/") {
            process.executableURL = URL(fileURLWithPath: command[0])
            process.arguments = Array(command.dropFirst())
        } else {
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = command
        }

        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }

        let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

public struct SecurityReport: Codable {
    public let generatedAt: Date
    public let systemInfo: SystemInfo
    public let securityStatus: SecurityStatusReport
    public let recentActivity: [SecurityActivity]
    public let recommendations: [String]
}

public struct SystemInfo: Codable {
    public let osVersion: String
    public let hardwareModel: String
    public let processor: String
    public let memory: String
    public let storage: String
}

public struct SecurityStatusReport: Codable {
    public let firewallEnabled: Bool
    public let fileVaultEnabled: Bool
    public let gatekeeperEnabled: Bool
    public let sipEnabled: Bool
    public let remoteLoginDisabled: Bool
    public let bluetoothSharingDisabled: Bool
    public let overallRiskScore: Double
    public let baselineVersion: String
    public let currentMacOSVersion: String
    public let baselineCompliant: Bool
    public let securityDataUpdatesEnabled: Bool
}
