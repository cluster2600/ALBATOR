import Foundation

public final class SystemMonitor {
    public static let shared = SystemMonitor()

    private var isMonitoring = false
    private var monitoringTimer: Timer?

    private init() {}

    public func startMonitoring() {
        guard !isMonitoring else { return }

        isMonitoring = true
        Logger.shared.info("System monitoring started")
        performSystemCheck()

        monitoringTimer = Timer.scheduledTimer(withTimeInterval: 120, repeats: true) { [weak self] _ in
            self?.performSystemCheck()
        }
    }

    public func stopMonitoring() {
        isMonitoring = false
        monitoringTimer?.invalidate()
        monitoringTimer = nil
        Logger.shared.info("System monitoring stopped")
    }

    private func performSystemCheck() {
        let snapshot = SystemSecurityProbe.shared.captureSnapshot(minimumBaselineVersion: SystemSecurityProbe.defaultBaselineVersion())
        Logger.shared.info("System check completed: macOS=\(snapshot.macosVersion), baseline=\(snapshot.baselineStatus.rawValue), security_data=\(snapshot.securityDataStatus.rawValue)")

        if snapshot.baselineStatus != .secure {
            SecurityEventHandler.shared.handleSecurityEvent(
                "baseline_noncompliant",
                details: [
                    "current": snapshot.macosVersion,
                    "minimum": snapshot.minimumBaselineVersion,
                ]
            )
        }

        if snapshot.securityDataStatus == .warning {
            NotificationManager.shared.showSystemUpdateAvailable()
        }
    }
}
