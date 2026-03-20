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

    // Tahoe-specific checks
    public let bsiStatus: SecurityStatus              // Background Security Improvements
    public let lockdownModeStatus: SecurityStatus     // Lockdown Mode
    public let usbRestrictedModeStatus: SecurityStatus // USB Restricted Mode
    public let safariFingerprintStatus: SecurityStatus // Safari Advanced Fingerprinting Protection
    public let fileVaultRecoveryKeyStatus: SecurityStatus // FileVault recovery key escrow
    public let screenLockStatus: SecurityStatus       // Screen lock (sysadminctl)
    public let hardwareGeneration: HardwareGeneration // Intel vs Apple Silicon

    public let details: [String: String]
}

public enum HardwareGeneration: String {
    case appleSilicon = "Apple Silicon"
    case intel = "Intel"
    case unknown = "Unknown"
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

        // Core probes
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

        // Tahoe: Background Security Improvements (BSI)
        let bsiOutput = commandOutput(["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"])?.trimmingCharacters(in: .whitespacesAndNewlines)
        let bsiStatus: SecurityStatus
        if bsiOutput == "1" {
            bsiStatus = .secure
        } else if bsiOutput == nil {
            // On Tahoe 26.1+ BSI is enabled by default even if the key is absent
            if Self.versionMeetsMinimum(current: macosVersion, minimum: "26.1") {
                bsiStatus = .secure
            } else {
                bsiStatus = .unknown
            }
        } else {
            bsiStatus = .warning
        }

        // Tahoe: Lockdown Mode
        let lockdownOutput = commandOutput(["/usr/bin/defaults", "read", ".GlobalPreferences", "LDMGlobalEnabled"])?.trimmingCharacters(in: .whitespacesAndNewlines)
        let lockdownModeStatus: SecurityStatus
        if lockdownOutput == "1" {
            lockdownModeStatus = .secure
        } else {
            // Lockdown Mode is opt-in, so absent/0 is not a warning — it's just "not enabled"
            lockdownModeStatus = .unknown
        }

        // Tahoe: USB Restricted Mode
        let usbOutput = commandOutput(["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.security", "USBRestrictedMode"])?.trimmingCharacters(in: .whitespacesAndNewlines)
        let usbRestrictedModeStatus: SecurityStatus
        // On macOS 26+ USB Restricted Mode is enabled by default; key absent = enabled
        if usbOutput == "0" {
            usbRestrictedModeStatus = .warning
        } else {
            usbRestrictedModeStatus = .secure
        }

        // Tahoe: Safari Advanced Fingerprinting Protection (all browsing)
        let safariAFPOutput = commandOutput(["/usr/bin/defaults", "read", "com.apple.Safari", "EnableEnhancedPrivacyInRegularBrowsing"])?.trimmingCharacters(in: .whitespacesAndNewlines)
        let safariFingerprintStatus: SecurityStatus
        if safariAFPOutput == "0" {
            // User explicitly disabled it
            safariFingerprintStatus = .warning
        } else {
            // On Tahoe this is ON by default (key absent or "1")
            safariFingerprintStatus = .secure
        }

        // Tahoe: FileVault recovery key verification
        // Note: fdesetup haspersonalrecoverykey requires root; if we get an error, treat as unknown
        let hasPersonalKey = commandOutput(["/usr/bin/fdesetup", "haspersonalrecoverykey"])?.trimmingCharacters(in: .whitespacesAndNewlines)
        let hasInstitutionalKey = commandOutput(["/usr/bin/fdesetup", "hasinstitutionalrecoverykey"])?.trimmingCharacters(in: .whitespacesAndNewlines)
        let fileVaultRecoveryKeyStatus: SecurityStatus
        if fileVaultStatus != .secure {
            fileVaultRecoveryKeyStatus = .unknown
        } else if (hasPersonalKey?.lowercased().contains("true") == true) || (hasInstitutionalKey?.lowercased().contains("true") == true) {
            fileVaultRecoveryKeyStatus = .secure
        } else if (hasPersonalKey?.lowercased().contains("error") == true) || (hasInstitutionalKey?.lowercased().contains("error") == true) {
            // Requires root to check — don't penalise
            fileVaultRecoveryKeyStatus = .unknown
        } else {
            fileVaultRecoveryKeyStatus = .warning
        }

        // Tahoe: Screen lock via sysadminctl (replaces com.apple.screensaver)
        let screenLockOutput = commandOutput(["/usr/sbin/sysadminctl", "-screenLock", "status"])?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "unavailable"
        let screenLockStatus: SecurityStatus
        if screenLockOutput.lowercased().contains("delay is") {
            screenLockStatus = .secure
        } else if screenLockOutput.lowercased().contains("off") {
            screenLockStatus = .warning
        } else {
            screenLockStatus = .unknown
        }

        // Hardware generation detection
        let archOutput = commandOutput(["/usr/sbin/sysctl", "-n", "hw.optional.arm64"])?.trimmingCharacters(in: .whitespacesAndNewlines)
        let hardwareGeneration: HardwareGeneration
        if archOutput == "1" {
            hardwareGeneration = .appleSilicon
        } else if archOutput == "0" || archOutput == nil {
            // Check if we can determine it another way
            let cpuBrand = commandOutput(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"])?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if cpuBrand.lowercased().contains("apple") {
                hardwareGeneration = .appleSilicon
            } else if cpuBrand.lowercased().contains("intel") {
                hardwareGeneration = .intel
            } else {
                hardwareGeneration = .unknown
            }
        } else {
            hardwareGeneration = .unknown
        }

        var details: [String: String] = [
            "firewall": firewallOutput,
            "filevault": fileVaultOutput,
            "gatekeeper": gatekeeperOutput,
            "sip": sipOutput,
            "config_data_install": configData ?? "unavailable",
            "critical_update_install": criticalData ?? "unavailable",
            "bsi_auto_install": bsiOutput ?? "default",
            "lockdown_mode": lockdownOutput ?? "not set",
            "usb_restricted_mode": usbOutput ?? "default (enabled)",
            "safari_afp": safariAFPOutput ?? "default (enabled)",
            "filevault_personal_key": hasPersonalKey ?? "unavailable",
            "filevault_institutional_key": hasInstitutionalKey ?? "unavailable",
            "screen_lock": screenLockOutput,
            "hardware_generation": hardwareGeneration.rawValue,
        ]

        if hardwareGeneration == .intel {
            details["intel_eol_warning"] = "macOS 26 Tahoe is the last release supporting Intel Macs"
        }

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
            bsiStatus: bsiStatus,
            lockdownModeStatus: lockdownModeStatus,
            usbRestrictedModeStatus: usbRestrictedModeStatus,
            safariFingerprintStatus: safariFingerprintStatus,
            fileVaultRecoveryKeyStatus: fileVaultRecoveryKeyStatus,
            screenLockStatus: screenLockStatus,
            hardwareGeneration: hardwareGeneration,
            details: details
        )
    }

    private func commandOutput(_ command: [String], timeout: TimeInterval = 5) -> String? {
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
        process.standardInput = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return nil
        }

        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if process.isRunning {
            process.terminate()
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
