import Foundation
import AlbatorCore

@main
struct AlbatorCLI {
    static func main() async {
        let arguments = Set(CommandLine.arguments.dropFirst())

        if arguments.contains("--help") {
            printHelp()
            return
        }

        let snapshot = SystemSecurityProbe.shared.captureSnapshot(minimumBaselineVersion: SystemSecurityProbe.defaultBaselineVersion())

        if arguments.contains("--json") {
            print(snapshotAsJSON(snapshot))
        } else {
            printHumanReadable(snapshot)
        }

        if arguments.contains("--report") {
            if let reportURL = await ReportGenerator.shared.generateComprehensiveReport() {
                print("Report generated at: \(reportURL.path)")
            } else {
                fputs("Failed to generate report\n", stderr)
            }
        }
    }

    private static func printHelp() {
        print("Albator-Swift CLI")
        print("Usage: Albator-Swift [--json] [--report] [--help]")
        print("  --json    Print snapshot as JSON")
        print("  --report  Generate a security JSON report in Documents/Desktop")
        print("  --help    Show this help")
    }

    private static func printHumanReadable(_ snapshot: SystemSecuritySnapshot) {
        print("Albator Swift Security Snapshot")
        print("===============================")
        print("Timestamp: \(snapshot.timestamp)")
        print("macOS: \(snapshot.macosVersion)")
        print("Baseline: \(snapshot.minimumBaselineVersion) -> \(snapshot.baselineStatus.rawValue)")
        print("Firewall: \(snapshot.firewallStatus.rawValue)")
        print("FileVault: \(snapshot.fileVaultStatus.rawValue)")
        print("Gatekeeper: \(snapshot.gatekeeperStatus.rawValue)")
        print("SIP: \(snapshot.sipStatus.rawValue)")
        print("Security Data Updates: \(snapshot.securityDataStatus.rawValue)")
    }

    private static func snapshotAsJSON(_ snapshot: SystemSecuritySnapshot) -> String {
        let formatter = ISO8601DateFormatter()
        let payload: [String: Any] = [
            "timestamp": formatter.string(from: snapshot.timestamp),
            "macos_version": snapshot.macosVersion,
            "minimum_baseline_version": snapshot.minimumBaselineVersion,
            "firewall_status": snapshot.firewallStatus.rawValue,
            "filevault_status": snapshot.fileVaultStatus.rawValue,
            "gatekeeper_status": snapshot.gatekeeperStatus.rawValue,
            "sip_status": snapshot.sipStatus.rawValue,
            "baseline_status": snapshot.baselineStatus.rawValue,
            "security_data_status": snapshot.securityDataStatus.rawValue,
            "details": snapshot.details,
        ]

        guard JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted]),
              let encoded = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return encoded
    }
}
