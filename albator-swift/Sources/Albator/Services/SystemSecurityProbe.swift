import Foundation

public struct SystemSecuritySnapshot {
    public let timestamp: Date
    public let macosVersion: String
    public let minimumBaselineVersion: String
    public let firewallStatus: SecurityStatus
    public let fileVaultStatus: SecurityStatus
    public let gatekeeperStatus: SecurityStatus
    public let sipStatus: SecurityStatus
    public let baselineStatus: SecurityStatus
    public let securityDataStatus: SecurityStatus
    public let details: [String: String]
}

public final class SystemSecurityProbe {
    public static let shared = SystemSecurityProbe()

    private init() {}

    public static func versionMeetsMinimum(current: String, minimum: String) -> Bool {
        let currentParts = current.split(separator: ".").map { Int($0) ?? 0 }
        let minimumParts = minimum.split(separator: ".").map { Int($0) ?? 0 }
        let count = max(currentParts.count, minimumParts.count)

        for idx in 0..<count {
            let currentValue = idx < currentParts.count ? currentParts[idx] : 0
            let minimumValue = idx < minimumParts.count ? minimumParts[idx] : 0
            if currentValue > minimumValue { return true }
            if currentValue < minimumValue { return false }
        }
        return true
    }

    public static func statusFromOutput(_ output: String, expectedTokens: [String]) -> SecurityStatus {
        let lowered = output.lowercased()
        for token in expectedTokens {
            if lowered.contains(token.lowercased()) {
                return .secure
            }
        }
        return .warning
    }

    public func captureSnapshot(minimumBaselineVersion: String = SystemSecurityProbe.defaultBaselineVersion()) -> SystemSecuritySnapshot {
        let macosVersion = commandOutput(["/usr/bin/sw_vers", "-productVersion"])?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "unknown"

        let firewallOutput = commandOutput(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]) ?? "unavailable"
        let fileVaultOutput = commandOutput(["/usr/bin/fdesetup", "status"]) ?? "unavailable"
        let gatekeeperOutput = commandOutput(["/usr/sbin/spctl", "--status"]) ?? "unavailable"
        let sipOutput = commandOutput(["/usr/bin/csrutil", "status"]) ?? "unavailable"

        let configData = commandOutput(["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"])?.trimmingCharacters(in: .whitespacesAndNewlines)
        let criticalData = commandOutput(["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"])?.trimmingCharacters(in: .whitespacesAndNewlines)

        let firewallStatus = Self.statusFromOutput(firewallOutput, expectedTokens: ["enabled"])
        let fileVaultStatus = Self.statusFromOutput(fileVaultOutput, expectedTokens: ["filevault is on", "filevault: yes"])
        let gatekeeperStatus = Self.statusFromOutput(gatekeeperOutput, expectedTokens: ["assessments enabled"])
        let sipStatus = Self.statusFromOutput(sipOutput, expectedTokens: ["enabled"])

        let baselineStatus: SecurityStatus
        if macosVersion == "unknown" {
            baselineStatus = .unknown
        } else {
            baselineStatus = Self.versionMeetsMinimum(current: macosVersion, minimum: minimumBaselineVersion) ? .secure : .warning
        }

        let securityDataStatus: SecurityStatus
        if configData == "1" && criticalData == "1" {
            securityDataStatus = .secure
        } else if configData == nil || criticalData == nil {
            securityDataStatus = .unknown
        } else {
            securityDataStatus = .warning
        }

        let details: [String: String] = [
            "firewall": firewallOutput,
            "filevault": fileVaultOutput,
            "gatekeeper": gatekeeperOutput,
            "sip": sipOutput,
            "config_data_install": configData ?? "unavailable",
            "critical_update_install": criticalData ?? "unavailable"
        ]

        return SystemSecuritySnapshot(
            timestamp: Date(),
            macosVersion: macosVersion,
            minimumBaselineVersion: minimumBaselineVersion,
            firewallStatus: firewallStatus,
            fileVaultStatus: fileVaultStatus,
            gatekeeperStatus: gatekeeperStatus,
            sipStatus: sipStatus,
            baselineStatus: baselineStatus,
            securityDataStatus: securityDataStatus,
            details: details
        )
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
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }

        let stdout = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

        if !stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if !stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return nil
    }

    public static func defaultBaselineVersion() -> String {
        if let fromEnv = ProcessInfo.processInfo.environment["ALBATOR_MIN_MACOS_VERSION"], !fromEnv.isEmpty {
            return fromEnv
        }
        return "26.3"
    }
}
