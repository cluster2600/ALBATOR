import Foundation
import AlbatorCore

// MARK: - ANSI Colors
enum ANSIColor: String {
    case reset = "\u{001B}[0m"
    case bold = "\u{001B}[1m"
    case dim = "\u{001B}[2m"
    case red = "\u{001B}[31m"
    case green = "\u{001B}[32m"
    case yellow = "\u{001B}[33m"
    case blue = "\u{001B}[34m"
    case magenta = "\u{001B}[35m"
    case cyan = "\u{001B}[36m"
    case white = "\u{001B}[37m"
    case boldRed = "\u{001B}[1;31m"
    case boldGreen = "\u{001B}[1;32m"
    case boldYellow = "\u{001B}[1;33m"
    case boldCyan = "\u{001B}[1;36m"
    case boldWhite = "\u{001B}[1;37m"
    case bgRed = "\u{001B}[41m"
    case bgGreen = "\u{001B}[42m"
    case bgYellow = "\u{001B}[43m"
}

func c(_ color: ANSIColor, _ text: String) -> String {
    return "\(color.rawValue)\(text)\(ANSIColor.reset.rawValue)"
}

func statusIcon(_ status: SecurityStatus) -> String {
    switch status {
    case .secure: return c(.boldGreen, "✔")
    case .warning: return c(.boldYellow, "⚠")
    case .critical: return c(.boldRed, "✘")
    case .unknown: return c(.dim, "?")
    }
}

func statusColor(_ status: SecurityStatus, _ text: String) -> String {
    switch status {
    case .secure: return c(.green, text)
    case .warning: return c(.yellow, text)
    case .critical: return c(.red, text)
    case .unknown: return c(.dim, text)
    }
}

func riskBar(_ score: Double) -> String {
    let total = 30
    let filled = Int(score / 100.0 * Double(total))
    let empty = total - filled

    let color: ANSIColor
    if score >= 80 { color = .boldGreen }
    else if score >= 50 { color = .boldYellow }
    else { color = .boldRed }

    let bar = c(color, String(repeating: "█", count: filled)) + c(.dim, String(repeating: "░", count: empty))
    return "[\(bar)] \(c(color, String(format: "%.0f%%", score)))"
}

// MARK: - Extended Probes

func probeRemoteLogin() -> (enabled: Bool, raw: String) {
    // Check if sshd is running instead of calling systemsetup (which requires root)
    let output = shellOutput("/bin/launchctl", "list") ?? ""
    let enabled = output.contains("com.openssh.sshd")
    return (enabled, enabled ? "sshd running" : "sshd not loaded")
}

func probeBluetoothSharing() -> (enabled: Bool, raw: String) {
    let output = shellOutput("/usr/bin/defaults", "read", "com.apple.Bluetooth", "PrefKeyServicesEnabled") ?? "unknown"
    let enabled = output.trimmingCharacters(in: .whitespacesAndNewlines) != "0"
    return (enabled, output.trimmingCharacters(in: .whitespacesAndNewlines))
}

func probeAutoUpdate() -> (enabled: Bool, raw: String) {
    let output = shellOutput("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled") ?? "unknown"
    let enabled = output.trimmingCharacters(in: .whitespacesAndNewlines) == "1"
    return (enabled, output.trimmingCharacters(in: .whitespacesAndNewlines))
}

func probeAirDrop() -> (mode: String, raw: String) {
    let output = shellOutput("/usr/bin/defaults", "read", "com.apple.NetworkBrowser", "DisableAirDrop") ?? "unknown"
    let disabled = output.trimmingCharacters(in: .whitespacesAndNewlines) == "1"
    return (disabled ? "Disabled" : "Enabled", output.trimmingCharacters(in: .whitespacesAndNewlines))
}

func probeHttpServer() -> (running: Bool, raw: String) {
    let output = shellOutput("/usr/bin/curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--connect-timeout", "1", "http://localhost:80") ?? "000"
    let running = output.trimmingCharacters(in: .whitespacesAndNewlines) != "000"
    return (running, output.trimmingCharacters(in: .whitespacesAndNewlines))
}

func systemInfo() -> (model: String, chip: String, memory: String) {
    let model = shellOutput("/usr/sbin/sysctl", "-n", "hw.model") ?? "unknown"
    let chip = shellOutput("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string") ?? "Apple Silicon"
    let memBytes = shellOutput("/usr/sbin/sysctl", "-n", "hw.memsize") ?? "0"
    let memGB = (Double(memBytes.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0) / 1_073_741_824
    let memory = memGB > 0 ? String(format: "%.0f GB", memGB) : "unknown"
    return (
        model.trimmingCharacters(in: .whitespacesAndNewlines),
        chip.trimmingCharacters(in: .whitespacesAndNewlines),
        memory
    )
}

func shellOutput(_ args: String..., timeout: TimeInterval = 5) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: args[0])
    process.arguments = Array(args.dropFirst())

    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    process.standardOutput = stdoutPipe
    process.standardError = stderrPipe
    // Prevent commands from prompting for input
    process.standardInput = FileHandle.nullDevice

    do {
        try process.run()
    } catch {
        return nil
    }

    // Wait with timeout to avoid hanging on commands that need root
    let deadline = Date().addingTimeInterval(timeout)
    while process.isRunning && Date() < deadline {
        Thread.sleep(forTimeInterval: 0.05)
    }
    if process.isRunning {
        process.terminate()
        return nil
    }

    // Return stdout if non-empty, otherwise fall back to stderr
    // (some macOS tools like sysadminctl write to stderr)
    let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if !stdout.isEmpty { return stdout }

    let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return stderr.isEmpty ? nil : stderr
}

// MARK: - Commands

func printBanner() {
    let banner = """
    \(c(.boldCyan, "    _    _ _           _             "))
    \(c(.boldCyan, "   / \\  | | |__   __ _| |_ ___  _ __ "))
    \(c(.boldCyan, "  / _ \\ | | '_ \\ / _` | __/ _ \\| '__|"))
    \(c(.boldCyan, " / ___ \\| | |_) | (_| | || (_) | |   "))
    \(c(.boldCyan, "/_/   \\_\\_|_.__/ \\__,_|\\__\\___/|_|   "))
    \(c(.dim, "                macOS Security Toolkit"))
    """
    print(banner)
    print()
}

func printChecks(_ checks: [(String, SecurityStatus, String)], verbose: Bool) {
    for (name, status, detail) in checks {
        let icon = statusIcon(status)
        let label = statusColor(status, status.rawValue.padding(toLength: 8, withPad: " ", startingAt: 0))
        let line = "  \(icon) \(name.padding(toLength: 22, withPad: " ", startingAt: 0)) \(label)"
        if verbose {
            print("\(line)  \(c(.dim, detail))")
        } else {
            print(line)
        }
    }
}

func cmdScan(verbose: Bool) {
    printBanner()

    let snapshot = SystemSecurityProbe.shared.captureSnapshot(minimumBaselineVersion: SystemSecurityProbe.defaultBaselineVersion())

    // System info
    let info = systemInfo()
    print(c(.boldWhite, "  System Information"))
    print(c(.dim, "  ─────────────────────────────────────"))
    print("  macOS        \(c(.boldWhite, snapshot.macosVersion))")
    print("  Model        \(info.model)")
    print("  Chip         \(info.chip)")
    print("  Memory       \(info.memory)")
    let hwLabel = snapshot.hardwareGeneration == .intel
        ? c(.boldYellow, "Intel") + c(.dim, " (EOL — last supported macOS)")
        : c(.boldGreen, snapshot.hardwareGeneration.rawValue)
    print("  Hardware     \(hwLabel)")
    print()

    // Core security checks
    print(c(.boldWhite, "  Core Security Posture"))
    print(c(.dim, "  ─────────────────────────────────────"))

    let coreChecks: [(String, SecurityStatus, String)] = [
        ("Firewall", snapshot.firewallStatus, snapshot.details["firewall"] ?? ""),
        ("FileVault", snapshot.fileVaultStatus, snapshot.details["filevault"] ?? ""),
        ("Gatekeeper", snapshot.gatekeeperStatus, snapshot.details["gatekeeper"] ?? ""),
        ("SIP", snapshot.sipStatus, snapshot.details["sip"] ?? ""),
        ("Baseline (\(snapshot.minimumBaselineVersion))", snapshot.baselineStatus, "macOS \(snapshot.macosVersion)"),
        ("Security Updates", snapshot.securityDataStatus, "ConfigData=\(snapshot.details["config_data_install"] ?? "?"), CriticalUpdate=\(snapshot.details["critical_update_install"] ?? "?")"),
    ]
    printChecks(coreChecks, verbose: verbose)
    print()

    // Tahoe-specific checks
    print(c(.boldWhite, "  macOS Tahoe Hardening") + "  " + c(.blue, "[NEW]"))
    print(c(.dim, "  ─────────────────────────────────────"))

    let tahoeChecks: [(String, SecurityStatus, String)] = [
        ("BSI Auto-Patch", snapshot.bsiStatus, "AutomaticallyInstallMacOSUpdates=\(snapshot.details["bsi_auto_install"] ?? "?")"),
        ("Screen Lock", snapshot.screenLockStatus, snapshot.details["screen_lock"] ?? ""),
        ("USB Restricted Mode", snapshot.usbRestrictedModeStatus, snapshot.details["usb_restricted_mode"] ?? ""),
        ("Safari Anti-FP", snapshot.safariFingerprintStatus, "EnableEnhancedPrivacyInRegularBrowsing=\(snapshot.details["safari_afp"] ?? "?")"),
        ("FV Recovery Key", snapshot.fileVaultRecoveryKeyStatus, "personal=\(snapshot.details["filevault_personal_key"] ?? "?"), institutional=\(snapshot.details["filevault_institutional_key"] ?? "?")"),
        ("Lockdown Mode", snapshot.lockdownModeStatus, snapshot.details["lockdown_mode"] ?? ""),
    ]
    printChecks(tahoeChecks, verbose: verbose)
    print()

    // Extended checks
    print(c(.boldWhite, "  Extended Checks"))
    print(c(.dim, "  ─────────────────────────────────────"))

    let remoteLogin = probeRemoteLogin()
    let bluetooth = probeBluetoothSharing()
    let autoUpdate = probeAutoUpdate()
    let airdrop = probeAirDrop()

    let extended: [(String, SecurityStatus, String)] = [
        ("Remote Login", !remoteLogin.enabled ? .secure : .warning, remoteLogin.enabled ? "SSH enabled — exposed" : "Disabled"),
        ("Bluetooth Sharing", !bluetooth.enabled ? .secure : .warning, bluetooth.enabled ? "Sharing on" : "Disabled"),
        ("Auto Updates", autoUpdate.enabled ? .secure : .warning, autoUpdate.enabled ? "Enabled" : "Disabled"),
        ("AirDrop", airdrop.mode == "Disabled" ? .secure : .warning, airdrop.mode),
    ]
    printChecks(extended, verbose: verbose)
    print()

    // Risk score
    var score = 100.0
    // Core
    if snapshot.firewallStatus != .secure { score -= 15 }
    if snapshot.fileVaultStatus != .secure { score -= 15 }
    if snapshot.gatekeeperStatus != .secure { score -= 12 }
    if snapshot.sipStatus != .secure { score -= 15 }
    if snapshot.baselineStatus != .secure { score -= 8 }
    if snapshot.securityDataStatus != .secure { score -= 10 }
    // Tahoe
    if snapshot.bsiStatus == .warning { score -= 5 }
    if snapshot.usbRestrictedModeStatus == .warning { score -= 5 }
    if snapshot.safariFingerprintStatus == .warning { score -= 3 }
    if snapshot.fileVaultRecoveryKeyStatus == .warning { score -= 5 }
    if snapshot.screenLockStatus == .warning { score -= 5 }
    if snapshot.hardwareGeneration == .intel { score -= 2 }
    // Extended
    if remoteLogin.enabled { score -= 4 }
    if bluetooth.enabled { score -= 3 }
    if !autoUpdate.enabled { score -= 4 }
    score = max(0, min(100, score))

    print(c(.boldWhite, "  Overall Risk Score"))
    print(c(.dim, "  ─────────────────────────────────────"))
    print("  \(riskBar(score))")
    print()

    // Recommendations
    var recommendations: [String] = []
    if snapshot.firewallStatus != .secure { recommendations.append("Enable the application firewall: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on") }
    if snapshot.fileVaultStatus != .secure { recommendations.append("Enable FileVault disk encryption: sudo fdesetup enable") }
    if snapshot.gatekeeperStatus != .secure { recommendations.append("Re-enable Gatekeeper: sudo spctl --master-enable") }
    if snapshot.sipStatus != .secure { recommendations.append("Re-enable SIP: boot to Recovery and run csrutil enable") }
    if snapshot.securityDataStatus != .secure { recommendations.append("Enable security data updates: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true && sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true") }
    // Tahoe
    if snapshot.bsiStatus == .warning { recommendations.append("Enable BSI auto-patching: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true") }
    if snapshot.screenLockStatus == .warning { recommendations.append("Require password on screen lock: sysadminctl -screenLock immediate") }
    if snapshot.usbRestrictedModeStatus == .warning { recommendations.append("Enable USB Restricted Mode in System Settings > Privacy & Security") }
    if snapshot.safariFingerprintStatus == .warning { recommendations.append("Enable Safari anti-fingerprinting: defaults write com.apple.Safari EnableEnhancedPrivacyInRegularBrowsing -bool true") }
    if snapshot.fileVaultRecoveryKeyStatus == .warning { recommendations.append("Generate FileVault recovery key: sudo fdesetup changerecovery -personal") }
    if snapshot.hardwareGeneration == .intel { recommendations.append("Plan migration to Apple Silicon — macOS 26 Tahoe is the last release for Intel Macs") }
    // Extended
    if remoteLogin.enabled { recommendations.append("Disable remote login: sudo systemsetup -setremotelogin off") }
    if bluetooth.enabled { recommendations.append("Disable Bluetooth sharing in System Settings > General > Sharing") }
    if !autoUpdate.enabled { recommendations.append("Enable automatic update checks: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true") }

    if recommendations.isEmpty {
        print("  \(c(.boldGreen, "✔ No recommendations — system is well hardened"))")
    } else {
        print(c(.boldWhite, "  Recommendations (\(recommendations.count))"))
        print(c(.dim, "  ─────────────────────────────────────"))
        for (idx, rec) in recommendations.enumerated() {
            print("  \(c(.yellow, "\(idx + 1).")) \(rec)")
        }
    }
    print()
}

func cmdReport() async {
    print(c(.dim, "Generating comprehensive security report..."))
    if let reportURL = await ReportGenerator.shared.generateComprehensiveReport() {
        print("\(c(.boldGreen, "✔")) Report saved: \(c(.cyan, reportURL.path))")
    } else {
        fputs("\(c(.boldRed, "✘")) Failed to generate report\n", stderr)
    }
}

func cmdMonitor(interval: Int) async {
    printBanner()
    print(c(.boldWhite, "  Continuous Security Monitor"))
    print(c(.dim, "  Polling every \(interval)s — press Ctrl+C to stop"))
    print()

    while true {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let snapshot = SystemSecurityProbe.shared.captureSnapshot(minimumBaselineVersion: SystemSecurityProbe.defaultBaselineVersion())

        var score = 100.0
        if snapshot.firewallStatus != .secure { score -= 15 }
        if snapshot.fileVaultStatus != .secure { score -= 15 }
        if snapshot.gatekeeperStatus != .secure { score -= 12 }
        if snapshot.sipStatus != .secure { score -= 15 }
        if snapshot.baselineStatus != .secure { score -= 8 }
        if snapshot.securityDataStatus != .secure { score -= 10 }
        if snapshot.bsiStatus == .warning { score -= 5 }
        if snapshot.usbRestrictedModeStatus == .warning { score -= 5 }
        if snapshot.screenLockStatus == .warning { score -= 5 }
        score = max(0, min(100, score))

        let allSecure = [snapshot.firewallStatus, snapshot.fileVaultStatus, snapshot.gatekeeperStatus, snapshot.sipStatus, snapshot.baselineStatus, snapshot.securityDataStatus, snapshot.bsiStatus, snapshot.usbRestrictedModeStatus, snapshot.screenLockStatus].allSatisfy { $0 == .secure }
        let overallIcon = allSecure ? c(.boldGreen, "✔") : c(.boldYellow, "⚠")

        print("  \(c(.dim, "[\(timestamp)]")) \(overallIcon) score=\(c(score >= 80 ? .green : .yellow, String(format: "%.0f%%", score)))  FW=\(statusIcon(snapshot.firewallStatus)) FV=\(statusIcon(snapshot.fileVaultStatus)) GK=\(statusIcon(snapshot.gatekeeperStatus)) SIP=\(statusIcon(snapshot.sipStatus)) BSI=\(statusIcon(snapshot.bsiStatus)) USB=\(statusIcon(snapshot.usbRestrictedModeStatus)) SL=\(statusIcon(snapshot.screenLockStatus))")

        try? await Task.sleep(nanoseconds: UInt64(interval) * 1_000_000_000)
    }
}

func cmdJSON() {
    let snapshot = SystemSecurityProbe.shared.captureSnapshot(minimumBaselineVersion: SystemSecurityProbe.defaultBaselineVersion())
    let remoteLogin = probeRemoteLogin()
    let bluetooth = probeBluetoothSharing()
    let autoUpdate = probeAutoUpdate()
    let airdrop = probeAirDrop()
    let info = systemInfo()

    var score = 100.0
    if snapshot.firewallStatus != .secure { score -= 15 }
    if snapshot.fileVaultStatus != .secure { score -= 15 }
    if snapshot.gatekeeperStatus != .secure { score -= 12 }
    if snapshot.sipStatus != .secure { score -= 15 }
    if snapshot.baselineStatus != .secure { score -= 8 }
    if snapshot.securityDataStatus != .secure { score -= 10 }
    if snapshot.bsiStatus == .warning { score -= 5 }
    if snapshot.usbRestrictedModeStatus == .warning { score -= 5 }
    if snapshot.safariFingerprintStatus == .warning { score -= 3 }
    if snapshot.fileVaultRecoveryKeyStatus == .warning { score -= 5 }
    if snapshot.screenLockStatus == .warning { score -= 5 }
    if snapshot.hardwareGeneration == .intel { score -= 2 }
    if remoteLogin.enabled { score -= 4 }
    if bluetooth.enabled { score -= 3 }
    if !autoUpdate.enabled { score -= 4 }
    score = max(0, min(100, score))

    let formatter = ISO8601DateFormatter()
    let payload: [String: Any] = [
        "timestamp": formatter.string(from: Date()),
        "system": [
            "macos_version": snapshot.macosVersion,
            "model": info.model,
            "chip": info.chip,
            "memory": info.memory,
            "hardware_generation": snapshot.hardwareGeneration.rawValue,
        ],
        "core_checks": [
            "firewall": snapshot.firewallStatus.rawValue,
            "filevault": snapshot.fileVaultStatus.rawValue,
            "gatekeeper": snapshot.gatekeeperStatus.rawValue,
            "sip": snapshot.sipStatus.rawValue,
            "baseline": snapshot.baselineStatus.rawValue,
            "security_data_updates": snapshot.securityDataStatus.rawValue,
        ],
        "tahoe_checks": [
            "bsi_auto_patch": snapshot.bsiStatus.rawValue,
            "screen_lock": snapshot.screenLockStatus.rawValue,
            "usb_restricted_mode": snapshot.usbRestrictedModeStatus.rawValue,
            "safari_fingerprint_protection": snapshot.safariFingerprintStatus.rawValue,
            "filevault_recovery_key": snapshot.fileVaultRecoveryKeyStatus.rawValue,
            "lockdown_mode": snapshot.lockdownModeStatus.rawValue,
        ],
        "extended_checks": [
            "remote_login_disabled": !remoteLogin.enabled,
            "bluetooth_sharing_disabled": !bluetooth.enabled,
            "auto_updates_enabled": autoUpdate.enabled,
            "airdrop_disabled": airdrop.mode == "Disabled",
        ],
        "risk_score": score,
        "minimum_baseline_version": snapshot.minimumBaselineVersion,
        "details": snapshot.details,
    ]

    guard JSONSerialization.isValidJSONObject(payload),
          let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]),
          let encoded = String(data: data, encoding: .utf8) else {
        print("{}")
        return
    }
    print(encoded)
}

func cmdLogs(limit: Int) {
    let logs = Logger.shared.getRecentLogs(limit: limit)
    if logs.isEmpty {
        print(c(.dim, "No log entries found."))
    } else {
        for line in logs where !line.isEmpty {
            print(line)
        }
    }
}

func printUsage() {
    printBanner()
    print(c(.boldWhite, "  Usage: ") + "albator-swift " + c(.cyan, "<command>") + " [options]")
    print()
    print(c(.boldWhite, "  Commands:"))
    print("    \(c(.cyan, "scan"))       Full security audit with risk scoring (default)")
    print("    \(c(.cyan, "report"))     Generate comprehensive JSON report to ~/Documents")
    print("    \(c(.cyan, "monitor"))    Continuous security monitoring (Ctrl+C to stop)")
    print("    \(c(.cyan, "json"))       Machine-readable JSON output of all checks")
    print("    \(c(.cyan, "logs"))       Show recent Albator log entries")
    print("    \(c(.cyan, "version"))    Show version information")
    print("    \(c(.cyan, "help"))       Show this help message")
    print()
    print(c(.boldWhite, "  Options:"))
    print("    \(c(.dim, "--verbose, -v"))      Show detailed probe output with scan")
    print("    \(c(.dim, "--interval N"))       Monitor polling interval in seconds (default: 60)")
    print("    \(c(.dim, "--limit N"))          Number of log entries to show (default: 50)")
    print()
    print(c(.boldWhite, "  Environment:"))
    print("    \(c(.dim, "ALBATOR_MIN_MACOS_VERSION"))  Override minimum baseline version (default: 26.3)")
    print()
}

// MARK: - Entry Point

@main
struct AlbatorCLI {
    static func main() async {
        let args = Array(CommandLine.arguments.dropFirst())

        let command = args.first ?? "scan"
        let argSet = Set(args)
        let verbose = argSet.contains("--verbose") || argSet.contains("-v")

        // Parse --interval N
        var interval = 60
        if let idx = args.firstIndex(of: "--interval"), idx + 1 < args.count, let val = Int(args[idx + 1]) {
            interval = max(5, val)
        }

        // Parse --limit N
        var limit = 50
        if let idx = args.firstIndex(of: "--limit"), idx + 1 < args.count, let val = Int(args[idx + 1]) {
            limit = max(1, val)
        }

        switch command {
        case "scan", "--verbose", "-v":
            cmdScan(verbose: verbose)
        case "report", "--report":
            await cmdReport()
        case "monitor", "watch":
            await cmdMonitor(interval: interval)
        case "json", "--json":
            cmdJSON()
        case "logs", "log":
            cmdLogs(limit: limit)
        case "version", "--version":
            print("Albator-Swift 3.1.0")
            print("macOS Security Toolkit")
            print("https://github.com/cluster2600/albator")
        case "help", "--help", "-h":
            printUsage()
        default:
            fputs(c(.red, "Unknown command: \(command)\n"), stderr)
            printUsage()
        }
    }
}
